package mcpserver_test

import (
	"context"
	"encoding/base32"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

// gaDriver is a driver for a site that wants the code of an authenticator in a header of its calls, as the admin console does: it
// logs in with a username and a password and then ignores or checks the code according to the path.
type gaDriver struct{}

func (gaDriver) Name() string                      { return "ga-test" }
func (gaDriver) Match(*url.URL) bool               { return false }
func (gaDriver) NeedsLogin() bool                  { return true }
func (gaDriver) RememberScope() (string, *url.URL) { return "", nil }
func (gaDriver) SecondFactorHeader() (string, int) { return "x-ga-code", 6 }
func (gaDriver) CodeRefused(status int, body []byte) bool {
	return strings.Contains(string(body), `"code":304009`) // the site's own number for a code that is wrong
}

func (gaDriver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	got, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	body, _ := json.Marshal(map[string]string{"username": got["username"], "password": got["password"]})
	req, _ := http.NewRequestWithContext(ctx, http.MethodPost, base.String()+"/login", strings.NewReader(string(body)))
	resp, err := hc.Do(req)
	if err != nil {
		return nil, site.Unreachable(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		return nil, site.ErrBadCredentials
	}
	return &site.Session{Headers: map[string]string{"x-session": "s-" + got["username"]}}, nil
}

func (gaDriver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, base.String()+"/me", nil)
	req.Header.Set("x-session", s.Headers["x-session"])
	resp, err := hc.Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	resp.Body.Close()
	return site.ProbeStatus("ga-test", resp.StatusCode)
}

// plainDriver is the same site without the second factor: nothing about the header may happen for it.
type plainGA struct{ gaDriver }

func (plainGA) Name() string { return "plain-test" }

// A driver that implements SecondFactor only by name does not make the header a fact: it is the driver type that carries it.
var _ site.SecondFactor = gaDriver{}

type gaSite struct {
	*httptest.Server
	mu       sync.Mutex
	codes    []string // what each call to /management/* carried in x-ga-code, in order
	seedKnow []byte   // the seed the person gave: the site accepts a code of this seed
	rejects  atomic.Int32
	login    atomic.Int32
}

func newGASite(t *testing.T, seed []byte) *gaSite {
	g := &gaSite{seedKnow: seed}
	mux := http.NewServeMux()
	mux.HandleFunc("/login", func(w http.ResponseWriter, r *http.Request) {
		var b map[string]string
		json.NewDecoder(r.Body).Decode(&b)
		if b["username"] != "alice" || b["password"] != "pw-1" {
			http.Error(w, "no", http.StatusUnauthorized)
			return
		}
		g.login.Add(1)
	})
	mux.HandleFunc("/me", func(w http.ResponseWriter, r *http.Request) {
		if !strings.HasPrefix(r.Header.Get("x-session"), "s-") {
			http.Error(w, "no", http.StatusUnauthorized)
		}
	})
	mux.HandleFunc("/management/", func(w http.ResponseWriter, r *http.Request) {
		code := r.Header.Get("x-ga-code")
		g.mu.Lock()
		g.codes = append(g.codes, code)
		g.mu.Unlock()
		now := time.Now()
		ok := code == totp.Code(g.seedKnow, now, 30*time.Second, 6) || code == totp.Code(g.seedKnow, now.Add(-30*time.Second), 30*time.Second, 6)
		if strings.HasSuffix(r.URL.Path, "/open") { // a path that does not look at the code
			fmt.Fprint(w, `{"ok":true}`)
			return
		}
		if !ok {
			g.rejects.Add(1)
			w.Header().Set("Content-Type", "application/json")
			fmt.Fprintf(w, `{"code":304009,"message":"bad code %s"}`, code)
			return
		}
		fmt.Fprint(w, `{"ok":true,"echo":"`+code+`"}`)
	})
	g.Server = httptest.NewTLSServer(mux)
	t.Cleanup(g.Close)
	return g
}

func (g *gaSite) seen() []string {
	g.mu.Lock()
	defer g.mu.Unlock()
	return append([]string(nil), g.codes...)
}

var gaSeed = []byte("12345678901234567890")

func b32(b []byte) string { return base32.StdEncoding.WithPadding(base32.NoPadding).EncodeToString(b) }

func registerGA(t *testing.T, d site.Driver) {
	t.Helper()
	site.Replace(d)
	t.Cleanup(func() { site.Replace(gaDriver{}) })
}

// enrolViaPage logs in through the real page: the person ticks Remember credentials (and Remember TOTP, with the seed, if withSeed).
// It takes a few seconds (a browser), so only the test of that path uses it; the rest save the same record directly.
func enrolViaPage(t *testing.T, e *env, up *gaSite, withSeed bool, dir string) *vault.Vault {
	t.Helper()
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	args := map[string]any{"url": up.URL, "site": "ga-test", "max_block_seconds": 1}
	out, _ := e.call(t, "session_open", args)
	vals := `{"username":"alice","password":"pw-1","remember":"yes"}`
	if withSeed {
		vals = fmt.Sprintf(`{"username":"alice","password":"pw-1","remember":"yes","remember_totp":"yes","totp_secret":%q}`, b32(gaSeed))
	}
	human(t, e.rec.wait(t, 1), e.dir, "submit", vals, "")
	if done, bad := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20}); bad || done["status"] != "ok" {
		t.Fatalf("enrol: %v", done)
	}
	return v
}

// enrol saves what the page would have saved, with a grant that has just been given: the same record, without the browser.
func enrol(t *testing.T, e *env, up *gaSite, withSeed bool, dir string) *vault.Vault {
	t.Helper()
	return enrolAsDriver(t, up, withSeed, dir, gaDriver{})
}

func enrolAsDriver(t *testing.T, up *gaSite, withSeed bool, dir string, d site.Driver) *vault.Vault {
	t.Helper()
	v := vault.New(dir)
	if err := v.Unlock("correct horse battery staple"); err != nil {
		t.Fatal(err)
	}
	binding, err := remember.BindingOf(d)
	if err != nil {
		t.Fatal(err)
	}
	rec := remember.Record{Site: d.Name(), Binding: binding, Username: "alice", Password: "pw-1"}
	if withSeed {
		rec.Secret = append([]byte(nil), gaSeed...)
	}
	if _, err := remember.EnrollApproved(v, up.URL, rec, nil, false, time.Now(), 24*time.Hour); err != nil {
		t.Fatal(err)
	}
	return v
}

func ga(t *testing.T, e *env, up *gaSite, path string) (map[string]any, bool) {
	t.Helper()
	return e.call(t, "request", map[string]any{"url": up.URL, "method": "POST", "path": path, "json": map[string]any{"bizContent": map[string]any{}}})
}

func setupGA(t *testing.T, up *gaSite) (*env, string) {
	t.Helper()
	var dir string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir })
	return e, dir
}

func TestWithAGrantAndASavedSeedEveryRequestCarriesTheCurrentCodeAndNobodyIsAsked(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrol(t, e, up, true, dir)
	out, bad := ga(t, e, up, "/management/user/info")
	if bad || !strings.Contains(fmt.Sprint(out["body"]), `"ok":true`) {
		t.Fatalf("the call with the code: %v", out)
	}
	codes := up.seen()
	if len(codes) != 1 || len(codes[0]) != 6 {
		t.Fatalf("the site saw %v", codes)
	}
	if len(e.rec.all()) != 0 {
		t.Errorf("nobody is asked, not even once: %d messages", len(e.rec.all()))
	}
}

// The saved record that the page makes is the one the tests above write directly: the person's own path ends in the same call.
func TestAPersonWhoSavesTheSeedOnThePageGetsACodeOnTheNextRequest(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrolViaPage(t, e, up, true, dir)
	out, bad := ga(t, e, up, "/management/user/info")
	if bad || !strings.Contains(fmt.Sprint(out["body"]), `"ok":true`) {
		t.Fatalf("the call after the page: %v", out)
	}
	if c := up.seen(); len(c) != 1 || len(c[0]) != 6 {
		t.Fatalf("the site saw %v", c)
	}
}

// The code is on every request, including the ones the site does not look at it for: the site decides, not securl.
func TestTheCodeIsOnARequestTheSiteDoesNotCheckItOnToo(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrol(t, e, up, true, dir)
	if out, bad := ga(t, e, up, "/management/anything/open"); bad || !strings.Contains(fmt.Sprint(out["body"]), "ok") {
		t.Fatalf("%v", out)
	}
	if c := up.seen(); len(c) != 1 || c[0] == "" {
		t.Errorf("a code is always sent: %v", c)
	}
}

func TestTheCodeIsNeverInTheAnswerTheAuditLogOrTheError(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	var dir, audit string
	e := setupWithClient(t, up.Client(), func(c *config.Config) { dir = c.Vault.Dir; audit = c.Audit.File })
	enrol(t, e, up, true, dir)
	out, _ := ga(t, e, up, "/management/user/info")
	code := up.seen()[0]
	seen := []string{fmt.Sprint(out)}
	if b, err := os.ReadFile(audit); err == nil {
		seen = append(seen, string(b))
	}
	for _, s := range seen {
		if strings.Contains(s, code) || strings.Contains(s, b32(gaSeed)) {
			t.Errorf("the code or the seed is in what the agent or the log can read:\n%.300s", s)
		}
	}
	if !strings.Contains(strings.Join(seen, "\n"), "second_factor") {
		t.Errorf("the audit log says that a second factor was used, so that it can be told from a call without one")
	}
}

// A seed was not saved: the code cannot be made, and the agent is told what the person has to do. No request goes out.
func TestWithoutASavedSeedTheRequestIsRefusedAndTheAnswerSaysWhatThePersonMustDo(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrol(t, e, up, false, dir)
	out, bad := ga(t, e, up, "/management/user/info")
	if !bad || out["code"] != "second_factor_required" {
		t.Fatalf("%v", out)
	}
	if h := fmt.Sprint(out["hint"]) + fmt.Sprint(out["message"]); !strings.Contains(h, "TOTP") || !strings.Contains(h, "seed") {
		t.Errorf("the answer does not say a saved TOTP seed is what is missing: %v", out)
	}
	if n := len(up.seen()); n != 0 {
		t.Errorf("a request went out with no code: %v", up.seen())
	}
}

// The grant has run out: nothing is sent, and the person is asked, on the page that already exists for it, not on a new one.
func TestWhenTheGrantHasExpiredNothingIsSentAndTheAnswerAsksForApproval(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	v := enrol(t, e, up, true, dir)
	if out, bad := e.call(t, "session_open", map[string]any{"url": up.URL, "site": "ga-test", "max_block_seconds": 20}); bad || out["status"] != "ok" {
		t.Fatalf("a session from the saved credentials: %v", out)
	}
	rec, err := remember.Load(v, up.URL)
	if err != nil {
		t.Fatal(err)
	}
	if _, err = remember.Approve(v, up.URL, rec, time.Now().Add(-remember.Lifetime-time.Hour), remember.Lifetime); err != nil {
		t.Fatal(err)
	}
	out, bad := ga(t, e, up, "/management/user/info")
	if !bad || (out["code"] != "session_expired" && out["code"] != "second_factor_required") {
		t.Fatalf("%v", out)
	}
	if !strings.Contains(fmt.Sprint(out["hint"])+fmt.Sprint(out["message"]), "session_open") {
		t.Errorf("the answer says how the person is asked: %v", out)
	}
	if n := len(up.seen()); n != 0 {
		t.Errorf("a call went out after the grant ended: %v", up.seen())
	}
}

// A code the site refuses is not made again and again: a site that locks an account after a few wrong codes would lock it, so after
// one refusal securl sends nothing more with a code until the person has approved again.
func TestAfterTheSiteRefusesACodeNothingMoreIsSentWithOneUntilThePersonApprovesAgain(t *testing.T) {
	wrong := []byte("98765432109876543210") // the site knows another seed: every code securl makes is wrong
	up := newGASite(t, wrong)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrol(t, e, up, true, dir)
	first, _ := ga(t, e, up, "/management/user/info")
	if up.rejects.Load() != 1 {
		t.Fatalf("the first call reaches the site: %v (rejects %d)", first, up.rejects.Load())
	}
	for i := 0; i < 4; i++ {
		out, bad := ga(t, e, up, "/management/user/info")
		if !bad || out["code"] != "second_factor_refused" {
			t.Errorf("call %d after a refused code: %v", i+2, out)
		}
	}
	if n := up.rejects.Load(); n != 1 {
		t.Errorf("the site was shown %d wrong codes; a site that locks after a few would be locked", n)
	}
	if n := len(up.seen()); n != 1 {
		t.Errorf("%d requests carried a code after the first was refused: %v", n, up.seen())
	}
}

// A request that does not go to a site with a second factor carries no code, whatever else is true.
func TestADriverWithoutASecondFactorSendsNoCodeAtAll(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, plainDriverOnly{})
	e, dir := setupGA(t, up)
	enrolAs(t, e, up, dir, "plain-test")
	ga(t, e, up, "/management/anything/open")
	for _, c := range up.seen() {
		if c != "" {
			t.Errorf("a code went to a site whose driver asked for none: %q", c)
		}
	}
}

// plainDriverOnly is a driver that does not implement SecondFactor at all.
type plainDriverOnly struct{}

func (plainDriverOnly) Name() string                      { return "plain-test" }
func (plainDriverOnly) Match(*url.URL) bool               { return false }
func (plainDriverOnly) NeedsLogin() bool                  { return true }
func (plainDriverOnly) RememberScope() (string, *url.URL) { return "", nil }
func (d plainDriverOnly) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	return gaDriver{}.Login(ctx, base, ask, hc)
}
func (plainDriverOnly) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	return gaDriver{}.Probe(ctx, base, s, hc)
}

func enrolAs(t *testing.T, e *env, up *gaSite, dir, siteName string) {
	t.Helper()
	u, err := url.Parse(up.URL)
	if err != nil {
		t.Fatal(err)
	}
	d, err := site.Resolve(siteName, u)
	if err != nil {
		t.Fatal(err)
	}
	enrolAsDriver(t, up, true, dir, d)
}

// An agent that tries to send its own code is refused before the site sees anything (the header is refused everywhere).
func TestAnAgentCannotSendItsOwnCodeEvenWhenSecurlSendsOne(t *testing.T) {
	up := newGASite(t, gaSeed)
	registerGA(t, gaDriver{})
	e, dir := setupGA(t, up)
	enrol(t, e, up, true, dir)
	out, bad := e.call(t, "request", map[string]any{"url": up.URL, "method": "POST", "path": "/management/user/info",
		"headers": map[string]any{"x-ga-code": "000000"}, "json": map[string]any{}})
	if !bad || out["code"] != "invalid_argument" {
		t.Fatalf("%v", out)
	}
	if n := len(up.seen()); n != 0 {
		t.Errorf("a request carried the agent's code: %v", up.seen())
	}
}
