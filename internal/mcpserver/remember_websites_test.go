package mcpserver_test

import (
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/generic"
	_ "github.com/LeafAI/securl/internal/site/jenkins"
	_ "github.com/LeafAI/securl/internal/site/kibana"
	_ "github.com/LeafAI/securl/internal/site/nightingale"
	"github.com/LeafAI/securl/internal/site/oauth2flow"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// Each server accepts only the synthetic account and issues a session that can
// be invalidated independently of the saved authorization.
func TestRememberedAdditionalWebsites(t *testing.T) {
	for _, name := range []string{"jenkins", "kibana", "kubesphere", "nightingale", "remember-test-generic"} {
		t.Run(name, func(t *testing.T) {
			var logins atomic.Int32
			var current atomic.Int32
			var needsCaptcha atomic.Bool
			const png = "iVBORw0KGgoAAAANSUhEUgAAAAEAAAABCAYAAAAfFcSJAAAADUlEQVR42mP8z8BQDwAEhQGAhKmMIQAAAABJRU5ErkJggg=="
			token := func() string { logins.Add(1); return fmt.Sprintf("session-%d-long-value", current.Add(1)) }
			valid := func(r *http.Request) bool {
				want := fmt.Sprintf("session-%d-long-value", current.Load())
				c, _ := r.Cookie("sid")
				return (c != nil && c.Value == want) || r.Header.Get("Authorization") == "Bearer "+want
			}
			fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				switch r.URL.Path {
				case "/login":
					fmt.Fprint(w, `<form name="login" action="j_spring_security_check"></form>`)
				case "/j_spring_security_check":
					r.ParseForm()
					if r.PostForm.Get("j_username") != "alice" || r.PostForm.Get("j_password") != "pw" {
						http.Error(w, "invalid", 401)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: token(), Path: "/", Secure: true})
					http.Redirect(w, r, "/", 302)
				case "/whoAmI/api/json":
					if valid(r) {
						fmt.Fprint(w, `{"authenticated":true,"name":"alice"}`)
					} else {
						fmt.Fprint(w, `{"anonymous":true,"name":"anonymous"}`)
					}
				case "/internal/security/login":
					var in struct{ Params map[string]string }
					json.NewDecoder(r.Body).Decode(&in)
					if in.Params["username"] != "alice" || in.Params["password"] != "pw" {
						http.Error(w, "invalid", 401)
						return
					}
					http.SetCookie(w, &http.Cookie{Name: "sid", Value: token(), Path: "/", Secure: true})
					fmt.Fprint(w, `{}`)
				case "/kapis/config.kubesphere.io/v1alpha2/configs/oauth":
					fmt.Fprint(w, `{"identityProviders":[]}`)
				case "/oauth/token", "/generic/login":
					r.ParseForm()
					if r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
						http.Error(w, "invalid", 401)
						return
					}
					fmt.Fprintf(w, `{"access_token":%q,"expires_in":3600}`, token())
				case "/api/n9e/auth/ifshowcaptcha":
					fmt.Fprintf(w, `{"dat":{"show":%t}}`, needsCaptcha.Load())
				case "/api/n9e/auth/captcha":
					fmt.Fprintf(w, `{"dat":{"imgdata":"data:image/png;base64,%s","captchaid":"challenge-id"}}`, png)
				case "/api/n9e/auth/login":
					var in map[string]string
					json.NewDecoder(r.Body).Decode(&in)
					if in["username"] != "alice" || in["password"] != "pw" || (needsCaptcha.Load() && (in["verifyvalue"] != "7" || in["captchaid"] != "challenge-id")) {
						fmt.Fprint(w, `{"err":"invalid"}`)
						return
					}
					fmt.Fprintf(w, `{"dat":{"access_token":%q}}`, token())
				case "/internal/security/me", "/kapis/resources.kubesphere.io/v1alpha2/namespaces", "/api/n9e/self/profile", "/generic/probe":
					if !valid(r) {
						http.Error(w, "expired", 401)
						return
					}
					fmt.Fprint(w, `{}`)
				case "/":
					fmt.Fprint(w, "home")
				default:
					http.NotFound(w, r)
				}
			}))
			defer fake.Close()
			var dir string
			e := setupFull(t, fake.Client(), mcpserver.Options{SessionFreshness: -1}, func(c *config.Config) {
				dir = c.Vault.Dir
				if name == "remember-test-generic" {
					c.Sites = []generic.Spec{{Name: name, Steps: []generic.Step{{Path: "/generic/login", Form: map[string]string{"username": "{{username}}", "password": "{{password}}"}}}, Collect: generic.Collect{Tokens: map[string]string{"access": "access_token"}, Headers: map[string]string{"Authorization": "Bearer {{token:access}}"}}, Probe: generic.Probe{Path: "/generic/probe"}}}
				}
			})
			v := vault.New(dir)
			if err := v.Unlock("correct horse battery staple"); err != nil {
				t.Fatal(err)
			}
			args := map[string]any{"url": fake.URL, "site": name}
			out, bad := e.call(t, "session_open", args)
			if bad || out["waiting_for"] != "credential_setup" {
				t.Fatal(out)
			}
			human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw","remember":"yes"}`, "")
			out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
			if bad || out["status"] != "ok" || logins.Load() != 1 {
				t.Fatal("enrollment failed", out, logins.Load())
			}
			original, err := remember.Load(v, fake.URL)
			if err != nil || len(original.Secret) != 0 || !original.Valid(time.Now()) {
				t.Fatal("bad stored password-only grant", err)
			}
			current.Add(1)
			out, bad = e.call(t, "session_open", args)
			if bad || out["status"] != "ok" || logins.Load() != 2 || len(e.rec.all()) != 1 {
				t.Fatal("silent renewal failed", out)
			}
			again, err := remember.Load(v, fake.URL)
			if err != nil || again.Revision != original.Revision {
				t.Fatal("renewal changed grant", err)
			}
			if name == "nightingale" {
				needsCaptcha.Store(true)
				current.Add(1)
				out, bad = e.call(t, "session_open", args)
				if bad || out["waiting_for"] != "custom" {
					t.Fatal("CAPTCHA must be human", out)
				}
				human(t, e.rec.wait(t, 2), e.dir, "submit", `{"verifyvalue":"7"}`, "")
				out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
				if bad || out["status"] != "ok" || logins.Load() != 3 {
					t.Fatal("CAPTCHA renewal failed", out)
				}
				after, err := remember.Load(v, fake.URL)
				if err != nil || after.Revision != original.Revision || len(after.Secret) != 0 {
					t.Fatal("CAPTCHA changed stored grant", err)
				}
				current.Add(1)
				out, bad = e.call(t, "request", map[string]any{"url": fake.URL, "method": "GET", "path": "/api/n9e/self/profile"})
				if !bad || out["code"] != "human_challenge_required" {
					t.Fatal("request bypassed CAPTCHA", out)
				}
			}
		})
	}
}

// A site that requires TOTP after password submission asks for the seed in a
// second protected page if it wasn't supplied during initial enrollment.
func TestRememberedOptionalTOTPSetup(t *testing.T) {
	seed := []byte("12345678901234567890")
	fake := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/internal/security/login" {
			http.NotFound(w, r)
			return
		}
		var in struct{ Params map[string]string }
		json.NewDecoder(r.Body).Decode(&in)
		code := in.Params["otp"]
		now := time.Now()
		if in.Params["username"] != "alice" || in.Params["password"] != "pw" || (code != totp.Code(seed, now, 30*time.Second, 6) && code != totp.Code(seed, now.Add(-30*time.Second), 30*time.Second, 6)) {
			http.Error(w, "otp required", 401)
			return
		}
		http.SetCookie(w, &http.Cookie{Name: "sid", Value: "test-session-token", Path: "/", Secure: true})
		fmt.Fprint(w, `{}`)
	}))
	defer fake.Close()
	var dir string
	e := setupWithClient(t, fake.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	out, bad := e.call(t, "session_open", map[string]any{"url": fake.URL, "site": "kibana"})
	if bad || out["waiting_for"] != "credential_setup" {
		t.Fatal(out)
	}
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw","remember":"yes"}`, "")
	if _, err := remember.Load(v, fake.URL); !errors.Is(err, vault.ErrNoEntry) {
		t.Fatal("credentials persisted before validation", err)
	}
	msg := e.rec.wait(t, 2)
	if !strings.Contains(msg, "TOTP setup secret") {
		t.Fatal("missing seed round", msg)
	}
	human(t, msg, e.dir, "submit", `{"totp_secret":"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ"}`, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" {
		t.Fatal(out)
	}
	rec, err := remember.Load(v, fake.URL)
	if err != nil || string(rec.Secret) != string(seed) {
		t.Fatal("seed was not persisted", err)
	}
}

func TestRememberCapabilityExcludesNonWebDrivers(t *testing.T) {
	for _, name := range []string{"gitlab", "archery", "jenkins", "kibana", "kubesphere", "nightingale"} {
		d, err := site.Resolve(name, nil)
		if err != nil || !remember.Supports(d) {
			t.Fatal("missing web capability", name, err)
		}
	}
	d, err := site.Resolve("skywalking", nil)
	if err != nil || remember.Supports(d) {
		t.Fatal("no-auth site must not offer enrollment", err)
	}

}

// An OAuth login may cross to its configured HTTPS IDP only. The page shows
// both origins, the grant applies to the destination, and config changes
// cannot reuse a saved record under a different IDP or login definition.
func TestRememberedOAuth2Website(t *testing.T) {
	o := newOAuthStack(t, true)
	orig, err := site.Resolve("skywalking", nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { site.Replace(orig) })
	spec := oauth2flow.Spec{Name: "skywalking", IDP: oauth2flow.IDP{Type: "gitlab", URL: o.idpURL()}}
	var dir string
	e := setupWithClient(t, o.gl.Client(), func(c *config.Config) { dir = c.Vault.Dir; c.OAuth2Sites = []oauth2flow.Spec{spec} })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": o.alb.URL, "site": "skywalking"}
	out, bad := e.call(t, "session_open", args)
	if bad || out["waiting_for"] != "credential_setup" {
		t.Fatal(out)
	}
	msg := e.rec.wait(t, 1)
	if !strings.Contains(msg, o.idpURL()) {
		t.Fatal("identity provider missing from notice")
	}
	human(t, msg, e.dir, "submit", `{"username":"alice","password":"oauth-Pass-1234","remember":"yes"}`, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" {
		t.Fatal("OAuth enrollment failed", out)
	}
	r, err := remember.Load(v, o.alb.URL)
	if err != nil || r.Binding == "" || !r.Valid(time.Now()) {
		t.Fatal("missing scoped record", err)
	}
	if _, err := remember.Load(v, o.idpURL()); !errors.Is(err, vault.ErrNoEntry) {
		t.Fatal("grant incorrectly shared with identity provider", err)
	}
	args["force_refresh"] = true
	out, bad = e.call(t, "session_open", args)
	if bad || out["status"] != "ok" || len(e.rec.all()) != 1 {
		t.Fatal("OAuth silent renewal failed", out)
	}
	updated, err := remember.Load(v, o.alb.URL)
	if err != nil || updated.Revision != r.Revision {
		t.Fatal("grant extended by renewal", err)
	}
	spec.IDP.URL = "https://different-idp.example"
	changed, err := oauth2flow.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	site.Replace(changed)
	if r.Matches(changed) {
		t.Fatal("old grant matched changed IDP")
	}
	out, bad = e.call(t, "session_open", args)
	if !bad || out["code"] != "credential_configuration_changed" {
		t.Fatal("changed identity provider accepted", out)
	}
}
