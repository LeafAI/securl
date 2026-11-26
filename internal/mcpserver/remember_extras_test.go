package mcpserver_test

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/vault"
)

// saltedDriver is a driver that logs in with a username, a password and a salt typed with them, as a private admin console does.
// The login is a JSON post of the three, and what the server sent back is the session.
type saltedDriver struct {
	extras []site.Field
	calls  *atomic.Int32
}

func (saltedDriver) Name() string                      { return "salted-test" }
func (saltedDriver) Match(u *url.URL) bool             { return false }
func (saltedDriver) NeedsLogin() bool                  { return true }
func (saltedDriver) RememberScope() (string, *url.URL) { return "", nil }
func (d saltedDriver) LoginExtraFields() []site.Field  { return d.extras }

func (d saltedDriver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	fields := append(append([]site.Field{}, site.LoginFields...), d.extras...)
	got, err := ask.Ask(ctx, "custom", fields)
	if err != nil {
		return nil, err
	}
	d.calls.Add(1)
	body, _ := json.Marshal(map[string]string{"username": got["username"], "password": got["password"], "salt": got["salt"]})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/login", strings.NewReader(string(body)))
	resp, err := hc.Do(req)
	if err != nil {
		return nil, site.Unreachable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, site.ErrBadCredentials
	}
	var out struct{ UUID string }
	json.NewDecoder(resp.Body).Decode(&out)
	return &site.Session{Headers: map[string]string{"x-session": out.UUID}}, nil
}

func (saltedDriver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/me", nil)
	req.Header.Set("x-session", s.Headers["x-session"])
	resp, err := hc.Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	resp.Body.Close()
	return site.ProbeStatus("salted-test", resp.StatusCode)
}

// saltedSite is the console: it logs in only with the right username, password and salt.
func saltedSite(t *testing.T) (*httptest.Server, *atomic.Int32) {
	var logins atomic.Int32
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["username"] != "alice" || b["password"] != "pw-1" || b["salt"] != "SALT-1234" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		logins.Add(1)
		json.NewEncoder(w).Encode(map[string]string{"UUID": "uuid-" + string(rune('a'+logins.Load()))})
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("x-session"), "uuid-") {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
	})
	s := httptest.NewTLSServer(mux)
	t.Cleanup(s.Close)
	return s, &logins
}

func registerSalted(t *testing.T, extras []site.Field) *atomic.Int32 {
	t.Helper()
	calls := &atomic.Int32{}
	site.Replace(saltedDriver{extras: extras, calls: calls})
	t.Cleanup(func() { site.Replace(saltedDriver{calls: calls}) })
	return calls
}

var saltExtra = []site.Field{{Name: "salt", Label: "Salt"}}

func TestASaltTypedWithTheCredentialsIsSavedAndUsedToRenewTheLoginWithNobodyAsked(t *testing.T) {
	up, logins := saltedSite(t)
	registerSalted(t, saltExtra)
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1}
	out, bad := e.call(t, "session_open", args)
	if bad || out["waiting_for"] != "credential_setup_x" {
		t.Fatalf("the person is asked on the step that has the salt: %v", out)
	}
	msg := e.rec.wait(t, 1)
	if !strings.Contains(msg, "24h0m0s") {
		t.Errorf("the message says how long the grant lasts: %s", msg)
	}
	human(t, msg, e.dir, "submit", `{"username":"alice","password":"pw-1","remember":"yes","salt":"SALT-1234"}`, "")
	out, bad = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || out["status"] != "ok" || logins.Load() != 1 {
		t.Fatalf("the first login with the salt: %v", out)
	}
	rec, err := remember.Load(v, up.URL)
	if err != nil || rec.Extras["salt"] != "SALT-1234" || rec.Username != "alice" || rec.Password != "pw-1" {
		t.Fatalf("the salt is saved with the credentials: %+v %v", rec, err)
	}
	if !strings.Contains(rec.Binding, "extras:salt") {
		t.Errorf("the record says which extras it was made with: %q", rec.Binding)
	}
	// the upstream session ends; the grant is still good, so the login is renewed with nobody asked and the saved salt
	args["force_refresh"] = true
	out, bad = e.call(t, "session_open", args)
	if bad || out["status"] != "ok" || logins.Load() != 2 || len(e.rec.all()) != 1 {
		t.Fatalf("silent renewal with the saved salt: %v (logins %d, messages %d)", out, logins.Load(), len(e.rec.all()))
	}
}

func TestTheSaltIsNeverInAnAnswerAnErrorTheAuditLogOrTheMessage(t *testing.T) {
	up, _ := saltedSite(t)
	registerSalted(t, saltExtra)
	var dir, audit string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir; audit = c.Audit.File })
	_ = dir
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1}
	out, _ := e.call(t, "session_open", args)
	first := e.rec.wait(t, 1)
	human(t, first, e.dir, "submit", `{"username":"alice","password":"pw-1","remember":"yes","salt":"SALT-1234"}`, "")
	done, _ := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	args["force_refresh"] = true
	renewed, _ := e.call(t, "session_open", args)
	seen := []string{first, fmt.Sprint(out), fmt.Sprint(done), fmt.Sprint(renewed)}
	if b, err := os.ReadFile(audit); err == nil {
		seen = append(seen, string(b))
	}
	for _, what := range seen {
		for _, secret := range []string{"SALT-1234", "pw-1"} {
			if strings.Contains(what, secret) {
				t.Errorf("%q is in what an agent, the team or the log can read:\n%.300s", secret, what)
			}
		}
	}
}

// Without consent to remember, the salt is used for this one login and kept nowhere, as the password is.
func TestWithoutConsentTheSaltIsUsedOnceAndNotSaved(t *testing.T) {
	up, logins := saltedSite(t)
	registerSalted(t, saltExtra)
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1}
	out, _ := e.call(t, "session_open", args)
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw-1","salt":"SALT-1234"}`, "")
	done, bad := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || done["status"] != "ok" || logins.Load() != 1 {
		t.Fatalf("%v", done)
	}
	if _, err := remember.Load(v, up.URL); !errors.Is(err, vault.ErrNoEntry) {
		t.Errorf("nothing is saved without consent: %v", err)
	}
}

func TestAWrongSaltIsABadLoginAndIsNotSaved(t *testing.T) {
	up, logins := saltedSite(t)
	registerSalted(t, saltExtra)
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1}
	out, _ := e.call(t, "session_open", args)
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw-1","remember":"yes","salt":"WRONG"}`, "")
	done, bad := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !bad || logins.Load() != 0 {
		t.Fatalf("a wrong salt logged in: %v", done)
	}
	if _, err := remember.Load(v, up.URL); !errors.Is(err, vault.ErrNoEntry) {
		t.Errorf("a login that failed saves nothing: %v", err)
	}
}

// A record saved before the driver asked for a salt has none. It must not be used to log in without one, and it must not be sent
// empty: the person is asked again, on the step that has the salt.
func TestARecordSavedBeforeTheDriverAskedForASaltIsNotUsedAndThePersonIsAsked(t *testing.T) {
	up, logins := saltedSite(t)
	registerSalted(t, nil) // the driver, at first, asked for nothing more
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	b, _ := remember.BindingOf(saltedDriver{})
	if _, err := remember.EnrollApproved(v, up.URL, remember.Record{Site: "salted-test", Binding: b, Username: "alice", Password: "pw-1"}, nil, false, time.Now(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	registerSalted(t, saltExtra) // and now it asks for a salt
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1, "force_refresh": true}
	out, bad := e.call(t, "session_open", args)
	if !bad || out["code"] != "credential_configuration_changed" {
		t.Fatalf("a record without the salt is not used: %v", out)
	}
	if logins.Load() != 0 {
		t.Error("the site was contacted with a record that has no salt")
	}
}

// A driver that asks for a field securl uses itself would have the page ask for it twice, or ask for something under another name:
// nothing is asked of anyone, and no login is started, whatever the reason the driver gave.
func TestADriverWhoseExtrasAreNotAllowedIsRefusedBeforeAnyoneIsAsked(t *testing.T) {
	for name, extras := range map[string][]site.Field{
		"a field called password":   {{Name: "password", Label: "Password again"}},
		"a field called remember":   {{Name: "remember", Label: "Remember"}},
		"a field with a bad name":   {{Name: "Salt!", Label: "Salt"}},
		"a field with no label":     {{Name: "salt", Label: ""}},
		"the same field twice":      {{Name: "salt", Label: "Salt"}, {Name: "salt", Label: "Salt"}},
		"a field that is a captcha": {{Name: "salt", Label: "Salt", Image: "data:image/png;base64,AAAA"}},
	} {
		up, logins := saltedSite(t)
		registerSalted(t, extras)
		e := setupWithClient(t, up.Client(), nil)
		out, bad := e.call(t, "session_open", map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1})
		if n := len(e.rec.all()); n != 0 {
			t.Errorf("%s: %d messages were sent to a person", name, n)
		}
		if !bad || out["status"] == "pending" || logins.Load() != 0 {
			t.Errorf("%s: the login went ahead: %v", name, out)
		}
		if !strings.Contains(fmt.Sprint(out["message"]), "login field it asks for is not allowed") {
			t.Errorf("%s: the refusal does not say why: %v", name, out["message"])
		}
	}
}

// Replacing a saved login whose driver asks for a salt is a step of its own, with the salt on it: the person is asked on
// credential_replace_x, the new salt is saved, and the old record (and its salt) is gone.
func TestReplacingTheCredentialsOfASaltedLoginAsksOnTheReplaceStepAndSavesTheNewSalt(t *testing.T) {
	up, logins := saltedSite(t)
	registerSalted(t, saltExtra)
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": up.URL, "site": "salted-test", "max_block_seconds": 1}
	out, _ := e.call(t, "session_open", args)
	human(t, e.rec.wait(t, 1), e.dir, "submit", `{"username":"alice","password":"pw-1","remember":"yes","salt":"SALT-1234"}`, "")
	if done, bad := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20}); bad || done["status"] != "ok" {
		t.Fatal(done)
	}
	before, err := remember.Load(v, up.URL)
	if err != nil {
		t.Fatal(err)
	}
	manage := map[string]any{"url": up.URL, "site": "salted-test", "manage_credentials": true, "max_block_seconds": 1}
	out, bad := e.call(t, "session_open", manage)
	if bad || out["waiting_for"] != "daily_approval" {
		t.Fatal(out)
	}
	human(t, e.rec.wait(t, 2), e.dir, "replace", "{}", "")
	replacement := e.rec.wait(t, 3)
	human(t, replacement, e.dir, "submit", `{"username":"alice","password":"pw-1","salt":"SALT-1234"}`, "")
	done, bad := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if bad || done["status"] != "ok" || logins.Load() < 2 {
		t.Fatalf("the replacement login: %v", done)
	}
	after, err := remember.Load(v, up.URL)
	if err != nil || after.Revision == before.Revision || after.Extras["salt"] != "SALT-1234" {
		t.Fatalf("the salt is saved again with the replacement: %+v %v", after, err)
	}
}
