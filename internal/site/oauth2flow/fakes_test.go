package oauth2flow

import (
	"context"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

// The two fakes live on different host names (127.0.0.1 for the site, localhost for GitLab), so that, as in real life,
// a cookie of one is never sent to the other: the cookie jar is per host name.

const (
	userName = "alice"
	userPass = "S3cretPw!"
	userCode = "424242"
)

type gitlabOpts struct {
	twoFA        bool
	consent      bool   // first use of the application: GitLab shows the Authorize page
	tamperClient bool   // the consent form carries another client_id than the request
	signInBroken bool   // authorize answers with the sign-in page even for a signed-in session
	otherPath    string // authorize redirects to this path of GitLab itself instead of the callback
}

type fakeGitLab struct {
	*httptest.Server
	o gitlabOpts

	mu        sync.Mutex
	consented bool
	approvals int
	denials   int
	hits      int
	codes     map[string]bool // issued, unused
}

func newGitLab(o gitlabOpts) *fakeGitLab {
	g := &fakeGitLab{o: o, codes: map[string]bool{}}
	mux := http.NewServeMux()
	mux.HandleFunc("/users/sign_in", g.signIn)
	mux.HandleFunc("/oauth/authorize", g.authorize)
	g.Server = httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		g.mu.Lock()
		g.hits++
		g.mu.Unlock()
		mux.ServeHTTP(w, r)
	}))
	// the test server listens on 127.0.0.1; name it localhost so the jar keeps it apart from the site
	return g
}

func (g *fakeGitLab) host() string { return "localhost:" + portOf(g.URL) }
func (g *fakeGitLab) base() string { return "http://" + g.host() }

func portOf(raw string) string { u, _ := url.Parse(raw); return u.Port() }

const signInForm = `<form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="TOK1"/><input name="user[login]"/><input name="user[password]"/></form>`
const otpForm = `<form action="/users/sign_in" method="post"><input type="hidden" name="authenticity_token" value="TOK2"/><input name="user[otp_attempt]"/></form>`

func (g *fakeGitLab) signIn(w http.ResponseWriter, r *http.Request) {
	if r.Method == "GET" {
		w.Write([]byte(signInForm))
		return
	}
	r.ParseForm()
	grant := func() {
		http.SetCookie(w, &http.Cookie{Name: "_gitlab_session", Value: "gl-session-value", Path: "/"})
		http.Redirect(w, r, "/", 302)
	}
	if code := r.PostForm.Get("user[otp_attempt]"); code != "" {
		if r.PostForm.Get("authenticity_token") == "TOK2" && code == userCode {
			grant()
		} else {
			w.Write([]byte(otpForm))
		}
		return
	}
	if r.PostForm.Get("authenticity_token") != "TOK1" || r.PostForm.Get("user[login]") != userName || r.PostForm.Get("user[password]") != userPass {
		w.Write([]byte(signInForm))
		return
	}
	if g.o.twoFA {
		w.Write([]byte(otpForm))
		return
	}
	grant()
}

func (g *fakeGitLab) signedIn(r *http.Request) bool {
	c, err := r.Cookie("_gitlab_session")
	return err == nil && c.Value == "gl-session-value" && !g.o.signInBroken
}

func (g *fakeGitLab) authorize(w http.ResponseWriter, r *http.Request) {
	if !g.signedIn(r) {
		http.Redirect(w, r, "/users/sign_in", 302)
		return
	}
	if r.Method == "POST" {
		r.ParseForm()
		if r.PostForm.Get("_method") == "delete" {
			g.mu.Lock()
			g.denials++
			g.mu.Unlock()
			http.Error(w, "denied", 403)
			return
		}
		g.mu.Lock()
		g.approvals++
		g.consented = true
		g.mu.Unlock()
		g.redirectBack(w, r, r.PostForm)
		return
	}
	q := r.URL.Query()
	if q.Get("response_type") != "code" || q.Get("client_id") == "" {
		http.Error(w, "bad request", 400)
		return
	}
	if g.o.otherPath != "" {
		http.Redirect(w, r, g.o.otherPath, 302)
		return
	}
	g.mu.Lock()
	need := g.o.consent && !g.consented
	g.mu.Unlock()
	if need {
		w.Write([]byte(g.consentPage(q)))
		return
	}
	g.redirectBack(w, r, q)
}

func (g *fakeGitLab) consentPage(q url.Values) string {
	clientID := q.Get("client_id")
	if g.o.tamperClient {
		clientID = "someone-elses-app"
	}
	hidden := func(name, value string) string {
		return fmt.Sprintf(`<input type="hidden" name="%s" id="%s" value="%s" autocomplete="off" />`, name, name, value)
	}
	fields := hidden("authenticity_token", "TOK3") + hidden("client_id", clientID) + hidden("redirect_uri", q.Get("redirect_uri")) +
		hidden("state", q.Get("state")) + hidden("response_type", "code") + hidden("scope", q.Get("scope"))
	return `<div class="doorkeeper"><form class="inline" action="/oauth/authorize" accept-charset="UTF-8" method="post">` + hidden("_method", "delete") + fields +
		`<input type="submit" name="commit" value="Deny"></form>` +
		`<form class="inline" action="/oauth/authorize" accept-charset="UTF-8" method="post">` + fields +
		`<input type="submit" name="commit" value="Authorize"></form></div>`
}

func (g *fakeGitLab) redirectBack(w http.ResponseWriter, r *http.Request, q url.Values) {
	code := fmt.Sprintf("code-%d", time.Now().UnixNano())
	g.mu.Lock()
	g.codes[code] = true
	g.mu.Unlock()
	back, _ := url.Parse(q.Get("redirect_uri"))
	v := back.Query()
	v.Set("code", code)
	v.Set("state", q.Get("state"))
	back.RawQuery = v.Encode()
	http.Redirect(w, r, back.String(), 302)
}

func (g *fakeGitLab) redeem(code string) bool {
	g.mu.Lock()
	defer g.mu.Unlock()
	ok := g.codes[code]
	delete(g.codes, code)
	return ok
}

func (g *fakeGitLab) stats() (approvals, denials, hits int) {
	g.mu.Lock()
	defer g.mu.Unlock()
	return g.approvals, g.denials, g.hits
}

type albOpts struct {
	callbackStatus int    // when set, the callback answers this instead of logging in
	redirectTo     string // when set, "/" redirects to this URL instead of the identity provider
	noRedirect     bool   // "/" answers 200 to everybody
	loop           bool   // "/" redirects to itself forever
	authQuery      string // appended to the authorize query (replaces the defaults when it starts with "!")
	redirectURI    string // overrides the redirect_uri the site announces
	sessionTTL     time.Duration
	extraCookies   []string // Set-Cookie lines sent with the callback answer
}

// fakeALB mimics an AWS ALB with an authenticate-oidc action in front of SkyWalking: anonymous requests get a nonce cookie
// and a redirect to the identity provider with a NEW state each time; the callback needs the latest nonce and state and an
// unused code, then sets sharded session cookies and deletes the nonce.
type fakeALB struct {
	*httptest.Server
	o  albOpts
	gl *fakeGitLab

	mu       sync.Mutex
	nonce    string
	state    string
	issued   int
	callback int
	skyHits  int
}

const sessionCookieValue = "alb-session-VALUE-0123456789"

func newALB(gl *fakeGitLab, o albOpts) *fakeALB {
	a := &fakeALB{o: o, gl: gl}
	if o.sessionTTL == 0 {
		a.o.sessionTTL = 7 * 24 * time.Hour
	}
	mux := http.NewServeMux()
	mux.HandleFunc("/oauth2/idpresponse", a.idpResponse)
	mux.HandleFunc("/", a.root)
	a.Server = httptest.NewServer(mux)
	return a
}

func (a *fakeALB) base() string { return a.URL }

func (a *fakeALB) hasSession(r *http.Request) bool {
	c0, e0 := r.Cookie("AWSELBAuthSessionCookie-0")
	c1, e1 := r.Cookie("AWSELBAuthSessionCookie-1")
	return e0 == nil && e1 == nil && c0.Value == sessionCookieValue+"-a" && c1.Value == sessionCookieValue+"-b"
}

func (a *fakeALB) root(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	switch {
	case a.o.loop:
		http.Redirect(w, r, a.URL+"/", 302)
		return
	case a.o.noRedirect:
		w.Write([]byte("skywalking"))
		return
	case a.o.redirectTo != "":
		http.Redirect(w, r, a.o.redirectTo, 302)
		return
	case a.hasSession(r):
		a.skyHits++
		w.Write([]byte("skywalking ui"))
		return
	}
	a.issued++
	a.nonce = fmt.Sprintf("nonce-%d", a.issued)
	a.state = fmt.Sprintf("state-%d", a.issued)
	http.SetCookie(w, &http.Cookie{Name: "AWSALBAuthNonce", Value: a.nonce, Path: "/", HttpOnly: true, Expires: time.Now().Add(15 * time.Minute)})
	ru := a.o.redirectURI
	if ru == "" {
		ru = a.URL + "/oauth2/idpresponse"
	}
	q := url.Values{"client_id": {"client-1"}, "redirect_uri": {ru}, "response_type": {"code"}, "scope": {"openid"}, "state": {a.state}}
	loc := a.gl.base() + "/oauth/authorize?" + q.Encode()
	if strings.HasPrefix(a.o.authQuery, "!") {
		loc = a.gl.base() + "/oauth/authorize?" + a.o.authQuery[1:]
	}
	http.Redirect(w, r, loc, 302)
}

func (a *fakeALB) idpResponse(w http.ResponseWriter, r *http.Request) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.callback++
	if a.o.callbackStatus != 0 {
		http.Error(w, "no", a.o.callbackStatus)
		return
	}
	n, err := r.Cookie("AWSALBAuthNonce")
	q := r.URL.Query()
	if err != nil || n.Value != a.nonce || q.Get("state") != a.state || !a.gl.redeem(q.Get("code")) {
		http.Error(w, "invalid state, nonce or code", 401)
		return
	}
	exp := time.Now().Add(a.o.sessionTTL)
	http.SetCookie(w, &http.Cookie{Name: "AWSELBAuthSessionCookie-0", Value: sessionCookieValue + "-a", Path: "/", Expires: exp, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "AWSELBAuthSessionCookie-1", Value: sessionCookieValue + "-b", Path: "/", Expires: exp, HttpOnly: true})
	http.SetCookie(w, &http.Cookie{Name: "AWSALBAuthNonce", Value: "", Path: "/", MaxAge: -1, Expires: time.Unix(0, 0)})
	http.Redirect(w, r, "/", 302)
}

func (a *fakeALB) counts() (issued, callback int) {
	a.mu.Lock()
	defer a.mu.Unlock()
	return a.issued, a.callback
}

// stack is a fake GitLab behind a fake ALB, and the spec that points at them.
type stack struct {
	gl   *fakeGitLab
	alb  *fakeALB
	spec Spec
	base *url.URL
}

func newStack(t *testing.T, go_ gitlabOpts, ao albOpts, edit func(*Spec)) *stack {
	t.Helper()
	gl := newGitLab(go_)
	alb := newALB(gl, ao)
	t.Cleanup(func() { gl.Close(); alb.Close() })
	spec := Spec{Name: "skywalking", MatchHost: "skywalking", IDP: IDP{Type: "gitlab", URL: gl.base()}}
	if edit != nil {
		edit(&spec)
	}
	base, _ := url.Parse(alb.base())
	return &stack{gl: gl, alb: alb, spec: spec, base: base}
}

func (s *stack) driver(t *testing.T) site.Driver {
	t.Helper()
	d, err := New(s.spec)
	if err != nil {
		t.Fatal(err)
	}
	return d
}

func (s *stack) login(t *testing.T, ask site.Asker) (*site.Session, error) {
	t.Helper()
	return s.driver(t).Login(context.Background(), s.base, ask, &http.Client{Timeout: 10 * time.Second})
}

// answers is an Asker for custom rounds: it answers by field name, and remembers what was asked.
type answers struct {
	mu       sync.Mutex
	user     string
	pass     string
	code     string
	rejectAt int // reject the n-th round (1-based); 0 never
	rounds   [][]site.Field
	modes    []string
}

func goodAnswers() *answers { return &answers{user: userName, pass: userPass, code: userCode} }

func (a *answers) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	a.mu.Lock()
	defer a.mu.Unlock()
	a.modes = append(a.modes, mode)
	a.rounds = append(a.rounds, fields)
	if a.rejectAt == len(a.rounds) {
		return nil, fmt.Errorf("rejected by the person")
	}
	out := site.Credentials{}
	for _, f := range fields {
		switch f.Name {
		case "username":
			out["username"] = a.user
		case "password":
			out["password"] = a.pass
		case "code":
			out["code"] = a.code
		}
	}
	return out, nil
}

func (a *answers) asked() int { a.mu.Lock(); defer a.mu.Unlock(); return len(a.rounds) }

func cookieNames(s *site.Session) []string {
	var out []string
	for _, c := range s.Cookies {
		out = append(out, c.Name)
	}
	return out
}
