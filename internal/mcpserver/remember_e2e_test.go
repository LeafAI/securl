package mcpserver_test

import (
	"encoding/base32"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site/archery/archerytest"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// The upstream fake validates a real generated RFC6238 code, rather than a fixed OTP.
func TestRememberedGitLabDailyApproval(t *testing.T) {
	seed := []byte("12345678901234567890")
	var logins atomic.Int32
	var serial atomic.Int32
	mux := http.NewServeMux()
	const form = `<form><input type="hidden" name="authenticity_token" value="T1"/></form>`
	const otp = `<form><input type="hidden" name="authenticity_token" value="T2"/><input name="user[otp_attempt]"/></form>`
	mux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			fmt.Fprint(w, form)
			return
		}
		r.ParseForm()
		if code := r.PostForm.Get("user[otp_attempt]"); code != "" {
			now := time.Now()
			if code != totp.Code(seed, now, 30*time.Second, 6) && code != totp.Code(seed, now.Add(-30*time.Second), 30*time.Second, 6) {
				fmt.Fprint(w, otp)
				return
			}
			logins.Add(1)
			id := serial.Add(1)
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: fmt.Sprint(id), Path: "/", Secure: true})
			http.Redirect(w, r, "/", 302)
			return
		}
		if r.PostForm.Get("user[login]") == "alice" && r.PostForm.Get("user[password]") == "secret-password" {
			fmt.Fprint(w, otp)
			return
		}
		fmt.Fprint(w, form)
	})
	mux.HandleFunc("/api/v4/user", func(w http.ResponseWriter, r *http.Request) {
		c, err := r.Cookie("_gitlab_session")
		if err != nil || c.Value != fmt.Sprint(serial.Load()) {
			http.Error(w, "expired", 401)
			return
		}
		fmt.Fprint(w, "ok")
	})
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) { fmt.Fprint(w, "home") })
	upstream := httptest.NewTLSServer(mux)
	defer upstream.Close()
	var cfgDir string
	e := setupWithClient(t, upstream.Client(), func(c *config.Config) { cfgDir = c.Vault.Dir })
	v := vault.New(cfgDir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": upstream.URL, "site": "gitlab", "max_block_seconds": 1}
	out, bad := e.call(t, "session_open", args)
	if bad || out["status"] != "pending" || out["waiting_for"] != "credential_setup" {
		t.Fatal(out)
	}
	if logins.Load() != 0 {
		t.Fatal("upstream contacted before consent")
	}
	other, bad := e.call(t, "session_open", args)
	if bad || other["login_id"] != out["login_id"] {
		t.Fatal("did not join pending flow", other)
	}
	msg := e.rec.wait(t, 1)
	if !strings.Contains(msg, "24h0m0s") {
		t.Fatal("missing consent duration", msg)
	}
	human(t, msg, e.dir, "submit", `{"username":"alice","password":"secret-password","remember":"yes","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}`, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" || logins.Load() != 1 {
		t.Fatal("approved login failed", out)
	}
	approved, err := remember.Load(v, upstream.URL)
	if err != nil {
		t.Fatal(err)
	}
	serial.Add(1) // upstream cookie expires, human grant remains valid
	out, bad = e.call(t, "session_open", args)
	if bad || out["status"] != "ok" || logins.Load() != 2 || len(e.rec.all()) != 1 {
		t.Fatal("silent login failed", out, logins.Load(), len(e.rec.all()))
	}
	refreshed, err := remember.Load(v, upstream.URL)
	if err != nil || refreshed.Revision != approved.Revision || !refreshed.ApprovedAt.Equal(approved.ApprovedAt) {
		t.Fatal("renewal extended approval", err)
	}
	// Persist an expired approval without changing the upstream cookie.
	if _, err = remember.Approve(v, upstream.URL, refreshed, time.Now().Add(-remember.Lifetime), remember.Lifetime); err != nil {
		t.Fatal(err)
	}
	out, bad = e.call(t, "session_open", args)
	if bad || out["status"] != "pending" || out["waiting_for"] != "daily_approval" {
		t.Fatal("valid upstream cookie bypassed expired grant", out)
	}
	human(t, e.rec.wait(t, 2), e.dir, "reject", "{}", "not now")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !bad || out["code"] != "user_rejected" || logins.Load() != 2 {
		t.Fatal("rejection ignored", out)
	}
	out, bad = e.call(t, "request", map[string]any{"url": upstream.URL, "path": "/api/v4/user"})
	if !bad {
		t.Fatal("request bypassed rejected consent", out)
	}
}

func TestRememberedArcheryDailyApproval(t *testing.T) {
	seed := []byte("12345678901234567890")
	fake := &archerytest.Fake{TwoFA: true}
	handler := fake.Handler()
	var otpSeen atomic.Bool
	// The existing Archery fake expects a fixed code; verify the generated code first.
	upstream := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/api/v1/user/2fa/verify/" {
			r.ParseForm()
			if r.PostForm.Get("otp") != totp.Code(seed, time.Now(), 30*time.Second, 6) && r.PostForm.Get("otp") != totp.Code(seed, time.Now().Add(-30*time.Second), 30*time.Second, 6) {
				http.Error(w, "invalid OTP", 400)
				return
			}
			otpSeen.Store(true)
			r.PostForm.Set("otp", "123456")
		}
		handler.ServeHTTP(w, r)
	}))
	defer upstream.Close()
	var cfgDir string
	e := setupWithClient(t, upstream.Client(), func(c *config.Config) { cfgDir = c.Vault.Dir; c.Security.CredentialAuthorizationTTL = 6 * time.Hour })
	v := vault.New(cfgDir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	out, bad := e.call(t, "session_open", map[string]any{"url": upstream.URL, "site": "archery"})
	if bad || out["waiting_for"] != "credential_setup" {
		t.Fatal(out)
	}
	msg := e.rec.wait(t, 1)
	if !strings.Contains(msg, "6h0m0s") {
		t.Fatal("configured duration missing from approval message", msg)
	}
	human(t, msg, e.dir, "submit", `{"username":"alice","password":"pw","remember":"yes","totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}`, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" || !otpSeen.Load() {
		t.Fatal("Archery login failed", out)
	}
	out, bad = e.call(t, "archery_instances", map[string]any{"url": upstream.URL})
	if bad {
		t.Fatal(out)
	}
	// A management request bypasses the cache but cannot modify the record without the human.
	manage := map[string]any{"url": upstream.URL, "site": "archery", "manage_credentials": true}
	before, err := remember.Load(v, upstream.URL)
	if err != nil || before.Duration != 6*time.Hour {
		t.Fatal("configured duration was not persisted", err)
	}
	out, bad = e.call(t, "session_open", manage)
	if bad || out["waiting_for"] != "daily_approval" {
		t.Fatal("management page unavailable", out)
	}
	human(t, e.rec.wait(t, 2), e.dir, "submit", "{}", "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" {
		t.Fatal("approval failed", out)
	}
	after, err := remember.Load(v, upstream.URL)
	if err != nil || after.Revision == before.Revision {
		t.Fatal("human approval did not renew grant", err)
	}
	// An explicit close requires human confirmation and revokes the daily grant.
	out, bad = e.call(t, "session_close", map[string]any{"url": upstream.URL})
	if bad || out["status"] != "pending" {
		t.Fatal("close did not request confirmation", out)
	}
	human(t, e.rec.wait(t, 3), e.dir, "submit", `{"confirm":"DELETE"}`, "")
	out, bad = e.call(t, "session_close", map[string]any{"url": upstream.URL, "close_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "closed" {
		t.Fatal("close failed", out)
	}
	rec, err := remember.Load(v, upstream.URL)
	if err != nil || rec.Valid(time.Now()) {
		t.Fatal("close did not revoke", err)
	}
	// The browser can replace credentials after revocation and forget them later.
	out, bad = e.call(t, "session_open", manage)
	if bad || out["waiting_for"] != "daily_approval" {
		t.Fatal(out)
	}
	human(t, e.rec.wait(t, 4), e.dir, "replace", "{}", "")
	replacement := e.rec.wait(t, 5)
	// Use the same synthetic account and seed as the initial enrollment.
	values := fmt.Sprintf(`{"username":"alice","password":"pw","totp_secret":"%s"}`, base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(seed))
	human(t, replacement, e.dir, "submit", values, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" {
		t.Fatal("replacement failed", out)
	}
	updated, err := remember.Load(v, upstream.URL)
	if err != nil || updated.Revision == rec.Revision || updated.Duration != 6*time.Hour {
		t.Fatal("replacement did not create a new grant", err)
	}
	out, bad = e.call(t, "session_open", manage)
	if bad || out["waiting_for"] != "daily_approval" {
		t.Fatal(out)
	}
	human(t, e.rec.wait(t, 6), e.dir, "forget", "{}", "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !bad || out["code"] != "user_rejected" {
		t.Fatal("forget did not terminate request", out)
	}
	if _, err = remember.Load(v, upstream.URL); !errors.Is(err, remember.ErrRemoved) {
		t.Fatal("credential not removed", err)
	}

}
