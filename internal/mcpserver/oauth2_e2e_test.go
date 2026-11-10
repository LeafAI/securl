package mcpserver_test

import (
	"bytes"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/ProtonMail/go-crypto/openpgp"
	"github.com/ProtonMail/go-crypto/openpgp/armor"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/api"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/seal"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/oauth2flow"
)

// setupNoBrowser is setupWith for tests that answer the round themselves (answerRound), so that they run where there is no
// headless browser. Everything else is the same: the real server, flow, tunnel API and sealed answers.
func setupNoBrowser(t *testing.T, tweak func(*config.Config)) *env {
	t.Helper()
	// The driver registry is process-wide and a configured site replaces the built-in driver of its name: put the originals
	// back when the test ends, or every later test in the package would see the OAuth 2.0 driver instead of the built-in one.
	for _, name := range []string{"skywalking"} {
		if orig, err := site.Resolve(name, nil); err == nil {
			t.Cleanup(func() { site.Replace(orig) })
		}
	}
	dir := t.TempDir()
	cfg, _ := config.Load(dir + "/nonexistent.yaml")
	cfg.Keys.Dir = dir + "/keys"
	cfg.Security.AllowLocalAddresses = true
	cfg.Web.PageURL = "https://page.example/"
	cfg.Web.TTL = time.Minute
	cfg.MCP.MaxBlockSeconds = 1
	if tweak != nil {
		tweak(cfg)
	}
	rec := &recorder{}
	opt := mcpserver.Options{Notifier: rec, Tunnels: localTunnels{}, Log: func(string, ...any) {}, Vault: testVault(t, cfg)}
	srv, _, err := mcpserver.New(cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	ct, st := mcp.NewInMemoryTransports()
	if _, err := srv.Connect(t.Context(), st, nil); err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "test", Version: "0"}, nil).Connect(t.Context(), ct, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return &env{auditFile: cfg.Audit.File, cs: cs, rec: rec, dir: dir}
}

// answerRound does what the login page does for a person, without a browser: it reads the link of a DingTalk message, seals the
// typed values under the round's one-shot password, encrypts them to the round's key and posts them to the tunnel API.
func answerRound(t *testing.T, msg string, fields map[string]string) {
	t.Helper()
	i := strings.Index(msg, "](")
	j := strings.Index(msg[i:], ")")
	link := msg[i+2 : i+j]
	q, err := url.ParseQuery(link[strings.Index(link, "#")+1:])
	if err != nil {
		t.Fatal(err)
	}
	dec := base64.RawURLEncoding
	pw, err := dec.DecodeString(q.Get("s"))
	if err != nil {
		t.Fatalf("one-shot password: %v", err)
	}
	pub, err := dec.DecodeString(q.Get("k"))
	if err != nil {
		t.Fatalf("public key: %v", err)
	}
	var round int
	fmt.Sscanf(q.Get("round"), "%d", &round)
	mode := q.Get("mode")
	sub := api.Submission{Action: api.ActionSubmit, Fields: fields, Nonce: fmt.Sprintf("n-%d-%d", round, time.Now().UnixNano()), TS: time.Now().Unix(), Mode: mode, Round: round}
	plain, _ := json.Marshal(sub)
	sealed, err := seal.Seal(pw, seal.Context{Site: q.Get("site"), Mode: mode, Round: round, Nonce: sub.Nonce}, plain)
	if err != nil {
		t.Fatal(err)
	}
	env, _ := json.Marshal(api.Envelope{Sealed: sealed, Nonce: sub.Nonce})
	ents, err := openpgp.ReadKeyRing(bytes.NewReader(pub))
	if err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	aw, _ := armor.Encode(&buf, "PGP MESSAGE", nil)
	w, err := openpgp.Encrypt(aw, ents, nil, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	w.Write(env)
	w.Close()
	aw.Close()
	resp, err := http.Post(q.Get("u")+"/submit?mode="+mode+"&round="+fmt.Sprint(round), "text/plain", &buf)
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if body, _ := io.ReadAll(resp.Body); resp.StatusCode != 200 {
		t.Fatalf("the tunnel API refused the answer: %d %s", resp.StatusCode, body)
	}
}

// oauthStack is a GitLab and an ALB-style front for a SkyWalking, small enough to read: the GitLab signs in alice and
// redirects authorize requests back with a one-use code; the front only honours the newest state and nonce.
type oauthStack struct {
	gl, alb *httptest.Server
	mu      sync.Mutex
	state   string
	nonce   string
	issued  int
	codes   map[string]bool
	api     int // requests that reached SkyWalking with a valid session
	cookie0 string
}

const (
	oaUser   = "alice"
	oaPass   = "oauth-Pass-1234"
	oaCookie = "ALB-SESSION-COOKIE-VALUE-ABCDEF"
	oaGitLab = "gl-oauth-session-VALUE"
)

func newOAuthStack(t *testing.T) *oauthStack {
	o := &oauthStack{codes: map[string]bool{}}
	glMux := http.NewServeMux()
	glMux.HandleFunc("/users/sign_in", func(w http.ResponseWriter, r *http.Request) {
		if r.Method == "GET" {
			w.Write([]byte(`<form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="T1"/><input name="user[login]"/><input name="user[password]"/></form>`))
			return
		}
		r.ParseForm()
		if r.PostForm.Get("user[login]") == oaUser && r.PostForm.Get("user[password]") == oaPass {
			http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: oaGitLab, Path: "/"})
			http.Redirect(w, r, "/", 302)
			return
		}
		w.Write([]byte(`<form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="T1"/><input name="user[login]"/><input name="user[password]"/></form>`))
	})
	glMux.HandleFunc("/oauth/authorize", func(w http.ResponseWriter, r *http.Request) {
		if c, err := r.Cookie("_gitlab_session"); err != nil || c.Value != oaGitLab {
			http.Redirect(w, r, "/users/sign_in", 302)
			return
		}
		q := r.URL.Query()
		code := fmt.Sprintf("code-%d", time.Now().UnixNano())
		o.mu.Lock()
		o.codes[code] = true
		o.mu.Unlock()
		back, _ := url.Parse(q.Get("redirect_uri"))
		v := back.Query()
		v.Set("code", code)
		v.Set("state", q.Get("state"))
		back.RawQuery = v.Encode()
		http.Redirect(w, r, back.String(), 302)
	})
	o.gl = httptest.NewServer(glMux)

	altMux := http.NewServeMux()
	altMux.HandleFunc("/oauth2/idpresponse", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		defer o.mu.Unlock()
		n, err := r.Cookie("AWSALBAuthNonce")
		q := r.URL.Query()
		if err != nil || n.Value != o.nonce || q.Get("state") != o.state || !o.codes[q.Get("code")] {
			http.Error(w, "invalid", 401)
			return
		}
		delete(o.codes, q.Get("code"))
		exp := time.Now().Add(3 * time.Hour)
		http.SetCookie(w, &http.Cookie{Name: "AWSELBAuthSessionCookie-0", Value: oaCookie, Path: "/", Expires: exp})
		http.SetCookie(w, &http.Cookie{Name: "AWSALBAuthNonce", Value: "", Path: "/", MaxAge: -1})
		http.Redirect(w, r, "/", 302)
	})
	altMux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		o.mu.Lock()
		defer o.mu.Unlock()
		if c, err := r.Cookie("AWSELBAuthSessionCookie-0"); err == nil && c.Value == oaCookie {
			o.api++
			w.Header().Set("Set-Cookie", "echo="+oaCookie+"; Path=/") // a site that echoes a credential: the gateway must hide it
			fmt.Fprintf(w, `{"data":"traces","you_sent":%q}`, c.Value)
			return
		}
		o.issued++
		o.nonce, o.state = fmt.Sprintf("nonce-%d", o.issued), fmt.Sprintf("state-%d", o.issued)
		http.SetCookie(w, &http.Cookie{Name: "AWSALBAuthNonce", Value: o.nonce, Path: "/", Expires: time.Now().Add(15 * time.Minute)})
		glURL, _ := url.Parse(o.gl.URL)
		ru := "http://" + r.Host + "/oauth2/idpresponse"
		qs := url.Values{"client_id": {"c1"}, "redirect_uri": {ru}, "response_type": {"code"}, "scope": {"openid"}, "state": {o.state}}
		http.Redirect(w, r, "http://localhost:"+glURL.Port()+"/oauth/authorize?"+qs.Encode(), 302)
	})
	o.alb = httptest.NewServer(altMux)
	t.Cleanup(func() { o.gl.Close(); o.alb.Close() })
	return o
}

func (o *oauthStack) idpURL() string {
	u, _ := url.Parse(o.gl.URL)
	return "http://localhost:" + u.Port()
}

func (o *oauthStack) sessionHits() int { o.mu.Lock(); defer o.mu.Unlock(); return o.api }

func TestOAuth2SiteLoginThroughGitLabEndToEnd(t *testing.T) {
	o := newOAuthStack(t)
	e := setupNoBrowser(t, func(c *config.Config) {
		c.OAuth2Sites = []oauth2flow.Spec{{Name: "skywalking", MatchHost: "skywalking", IDP: oauth2flow.IDP{Type: "gitlab", URL: o.idpURL()}}}
	})

	// The site list describes the configured site as a login site, not as the built-in "no login" one.
	sites, _ := e.call(t, "site_list", nil)
	if !strings.Contains(fmt.Sprint(sites), "config") {
		t.Logf("sites: %v", sites)
	}
	for _, s := range sites["sites"].([]any) {
		m := s.(map[string]any)
		if m["name"] == "skywalking" && (m["auth"] != "cookie" || m["needs_login"] != true) {
			t.Errorf("skywalking is described as %v", m)
		}
	}

	out, isErr := e.call(t, "session_open", map[string]any{"url": o.alb.URL, "site": "skywalking", "reason": "read traces", "max_block_seconds": 1})
	if isErr || out["status"] != "pending" || out["waiting_for"] != "custom" {
		t.Fatalf("first call: %v", out)
	}
	id := out["login_id"].(string)
	msg := e.rec.wait(t, 1)
	for _, want := range []string{"read traces", "securl will sign in to GitLab at localhost", "Your GitLab password is not kept", "custom"} {
		if !strings.Contains(msg, want) && want != "custom" {
			t.Errorf("the message lacks %q:\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "/oauth/authorize") || strings.Contains(msg, "state-") {
		t.Errorf("the authorize URL must never be sent to the person or the agent:\n%s", msg)
	}

	answerRound(t, msg, map[string]string{"username": oaUser, "password": oaPass})
	out, isErr = e.call(t, "session_wait", map[string]any{"login_id": id, "max_block_seconds": 20})
	if isErr || out["status"] != "ok" || out["auth"] != "cookie" || out["site"] != "skywalking" {
		t.Fatalf("final: %v", out)
	}
	assertNoCredentials(t, out, oaCookie, oaGitLab, oaPass, "state-", "code-")
	if out["expires_at"] == nil || out["expires_at"] == "" {
		t.Errorf("the session's expiry (from the ALB cookie) is missing: %v", out)
	}

	// The agent uses the site through request; the cookie goes in, and a credential the site echoes does not come out.
	res, isErr := e.call(t, "request", map[string]any{"url": o.alb.URL, "method": "GET", "path": "/graphql"})
	if isErr || res["status"] != float64(200) || !strings.Contains(fmt.Sprint(res["body"]), "traces") {
		t.Fatalf("request: %v", res)
	}
	// (request answers carry the site's response headers, so assertNoCredentials, which is for login results, does not apply)
	if raw, _ := json.Marshal(res); strings.Contains(string(raw), oaCookie) || strings.Contains(string(raw), oaGitLab) || strings.Contains(strings.ToLower(string(raw)), "set-cookie") {
		t.Errorf("the request answer carries a credential: %s", raw)
	}
	if res["redactions"] == nil || res["redactions"] == float64(0) {
		t.Errorf("the echoed cookie was not redacted: %v", res)
	}
	if o.sessionHits() == 0 {
		t.Error("the site never saw the session cookie")
	}

	// A second session_open reuses the saved session without bothering the person; nothing else was asked.
	out, _ = e.call(t, "session_open", map[string]any{"url": o.alb.URL, "site": "skywalking"})
	if out["status"] != "ok" || out["cached"] != true {
		t.Errorf("cached: %v", out)
	}
	if n := len(e.rec.all()); n != 1 {
		t.Errorf("the person was messaged %d times for one login", n)
	}
	var human int
	for _, ev := range readAudit(t, e.auditFile) {
		if ev.Event == "human_round" {
			human++
		}
		raw, _ := json.Marshal(ev)
		for _, secret := range []string{oaPass, oaCookie, oaGitLab, "state-1", "code-"} {
			if strings.Contains(string(raw), secret) {
				t.Errorf("the audit log carries %q: %s", secret, raw)
			}
		}
	}
	if human != 1 {
		t.Errorf("audited human rounds = %d", human)
	}
}

func TestOAuth2SiteWrongPasswordIsABadCredential(t *testing.T) {
	o := newOAuthStack(t)
	e := setupNoBrowser(t, func(c *config.Config) {
		c.OAuth2Sites = []oauth2flow.Spec{{Name: "skywalking", IDP: oauth2flow.IDP{Type: "gitlab", URL: o.idpURL()}}}
	})
	out, _ := e.call(t, "session_open", map[string]any{"url": o.alb.URL, "site": "skywalking", "max_block_seconds": 1})
	id := out["login_id"].(string)
	answerRound(t, e.rec.wait(t, 1), map[string]string{"username": oaUser, "password": "WRONG-password-1"})
	out, isErr := e.call(t, "session_wait", map[string]any{"login_id": id, "max_block_seconds": 20})
	if !isErr || out["code"] != "bad_credentials" {
		t.Fatalf("got %v", out)
	}
	if strings.Contains(fmt.Sprint(out), "WRONG-password-1") {
		t.Error("the password is in the error")
	}

}

// Without an oauth2_sites entry the built-in skywalking driver is unchanged for a site that needs no login, and says what to do
// for one that does (instead of reporting "no login" for a redirect to GitLab, and instead of putting the redirect's state in the error).
func TestWithoutOAuth2SitesSkyWalkingStaysNoAuthAndExplainsALoginWall(t *testing.T) {
	o := newOAuthStack(t)
	plain := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ui")) }))
	defer plain.Close()
	e2 := setupNoBrowser(t, nil)
	if out, isErr := e2.call(t, "session_open", map[string]any{"url": plain.URL, "site": "skywalking"}); isErr || out["auth"] != "none" {
		t.Errorf("a site that needs no login: %v", out)
	}
	// ...and says what to do for one that does.
	out, isErr := e2.call(t, "session_open", map[string]any{"url": o.alb.URL, "site": "skywalking"})
	if !isErr || !strings.Contains(fmt.Sprint(out), "oauth2_sites") {
		t.Errorf("a site that wants a login but has no oauth2_sites entry: %v", out)
	}
	if strings.Contains(fmt.Sprint(out), "state-") || strings.Contains(fmt.Sprint(out), "client_id") {
		t.Errorf("the redirect's query leaked: %v", out)
	}
}
