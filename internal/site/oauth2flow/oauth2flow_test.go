package oauth2flow

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

var errRejected = errors.New("rejected by the person")

func has(names []string, want string) bool {
	for _, n := range names {
		if n == want {
			return true
		}
	}
	return false
}

func TestLoginKeepsOnlyTheSiteCookies(t *testing.T) {
	s := newStack(t, gitlabOpts{}, albOpts{}, nil)
	a := goodAnswers()
	sess, err := s.login(t, a)
	if err != nil {
		t.Fatal(err)
	}
	names := cookieNames(sess)
	if !has(names, "AWSELBAuthSessionCookie-0") || !has(names, "AWSELBAuthSessionCookie-1") {
		t.Fatalf("session cookies missing: %v", names)
	}
	if has(names, "_gitlab_session") || has(names, "AWSALBAuthNonce") {
		t.Errorf("GitLab's cookie or the deleted nonce was kept: %v", names)
	}
	if len(a.modes) != 1 || a.modes[0] != "custom" {
		t.Fatalf("rounds: %v", a.modes)
	}
	for _, f := range a.rounds[0] {
		if len(f.Label) > 60 || !strings.Contains(f.Label, "localhost") {
			t.Errorf("label %q must name the identity provider and fit the page's 60 characters", f.Label)
		}
		if f.Name == "password" && !f.Secret {
			t.Error("the password field is not secret")
		}
	}
	if err := s.driver(t).Probe(context.Background(), s.base, sess, &http.Client{}); err != nil {
		t.Errorf("probe of the new session: %v", err)
	}
}

// The state and nonce of the first request were issued before a human round that can last minutes: the driver must start
// over, and the fake only honours the newest of them.
func TestLoginStartsAFreshChainAfterTheHumanRound(t *testing.T) {
	s := newStack(t, gitlabOpts{}, albOpts{}, nil)
	if _, err := s.login(t, goodAnswers()); err != nil {
		t.Fatal(err)
	}
	if issued, callback := s.alb.counts(); issued < 2 || callback != 1 {
		t.Errorf("states issued = %d, callbacks = %d: the chain was not restarted after the sign-in", issued, callback)
	}
}

func TestLoginAsksForTheSecondFactorWhenGitLabDoes(t *testing.T) {
	s := newStack(t, gitlabOpts{twoFA: true}, albOpts{}, nil)
	a := goodAnswers()
	if _, err := s.login(t, a); err != nil {
		t.Fatal(err)
	}
	if len(a.rounds) != 2 || a.rounds[1][0].Name != "code" || !strings.Contains(a.rounds[1][0].Label, "localhost") {
		t.Fatalf("rounds: %+v", a.rounds)
	}
	bad := goodAnswers()
	bad.code = "000000"
	if _, err := s.login(t, bad); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("wrong code: %v", err)
	}
}

func TestExpiryComesFromTheSessionCookies(t *testing.T) {
	s := newStack(t, gitlabOpts{}, albOpts{sessionTTL: 2 * time.Hour}, nil)
	sess, err := s.login(t, goodAnswers())
	if err != nil {
		t.Fatal(err)
	}
	if d := time.Until(sess.ExpiresAt); d < 119*time.Minute || d > 121*time.Minute {
		t.Errorf("expires in %v, want about 2h (the nonce cookie's 15 minutes must not count: it is deleted)", d)
	}
}

func TestBadPasswordAndRejectionAreClassified(t *testing.T) {
	s := newStack(t, gitlabOpts{}, albOpts{}, nil)
	a := goodAnswers()
	a.pass = "WRONG-pass-123"
	_, err := s.login(t, a)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("wrong password: %v", err)
	}
	if strings.Contains(err.Error(), a.pass) {
		t.Error("the password is in the error")
	}
	rej := &rejectingAsker{}
	if _, err := s.login(t, rej); !errors.Is(err, errRejected) {
		t.Errorf("a rejection by the person must come through unchanged: %v", err)
	}
}

type rejectingAsker struct{}

func (rejectingAsker) Ask(context.Context, string, []site.Field) (site.Credentials, error) {
	return nil, errRejected
}

// Everything that is wrong with the redirect must end the login before any person is asked and before anything is sent to
// the host the site pointed at.
func TestPreflightRefusesBeforeAskingAnyone(t *testing.T) {
	var foreign atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { foreign.Add(1) }))
	defer other.Close()
	otherAuth := strings.Replace(other.URL, "127.0.0.1", "localhost", 1) + "/oauth/authorize?response_type=code&client_id=c&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb&state=s"

	cases := []struct {
		name string
		alb  albOpts
		want string
	}{
		{"redirect to a host that is not the idp", albOpts{redirectTo: otherAuth}, "not the configured idp"},
		{"wrong path on the idp host", albOpts{authQuery: "!"}, ""},
		{"no state", albOpts{authQuery: "!response_type=code&client_id=c&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb"}, "state"},
		{"no client_id", albOpts{authQuery: "!response_type=code&state=s&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb"}, "client_id"},
		{"not the code flow", albOpts{authQuery: "!response_type=token&client_id=c&state=s&redirect_uri=http%3A%2F%2F127.0.0.1%2Fcb"}, "response_type"},
		{"the code would return to another host", albOpts{redirectURI: "http://evil.example/oauth2/idpresponse"}, "redirect_uri"},
		{"the site does not ask for a login", albOpts{noRedirect: true}, "did not ask for a login"},
		{"endless redirects", albOpts{loop: true}, "redirect"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			s := newStack(t, gitlabOpts{}, tc.alb, nil)
			a := goodAnswers()
			_, err := s.login(t, a)
			if !errors.Is(err, site.ErrLoginRejected) {
				t.Fatalf("err = %v", err)
			}
			if tc.want != "" && !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want it to mention %q", err, tc.want)
			}
			if a.asked() != 0 {
				t.Error("a person was asked although the redirect was refused")
			}
			if _, _, hits := s.gl.stats(); hits != 0 {
				t.Errorf("the identity provider received %d requests", hits)
			}
			if foreign.Load() != 0 {
				t.Error("the host the site pointed at received a request")
			}
			for _, secret := range []string{"state=", "client-1", "state-1", userPass} {
				if strings.Contains(err.Error(), secret) {
					t.Errorf("error leaks %q: %v", secret, err)
				}
			}
		})
	}
}

func TestFirstTimeConsentIsApprovedByDefault(t *testing.T) {
	s := newStack(t, gitlabOpts{consent: true}, albOpts{}, nil)
	if _, err := s.login(t, goodAnswers()); err != nil {
		t.Fatal(err)
	}
	if ap, de, _ := s.gl.stats(); ap != 1 || de != 0 {
		t.Errorf("approvals = %d, denials = %d: securl must press Authorize, once, and never Deny", ap, de)
	}
}

func TestConsentCanBeRefusedByConfiguration(t *testing.T) {
	s := newStack(t, gitlabOpts{consent: true}, albOpts{}, func(sp *Spec) { sp.OnConsent = "fail" })
	_, err := s.login(t, goodAnswers())
	if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "for the first time") {
		t.Fatalf("err = %v", err)
	}
	if ap, _, _ := s.gl.stats(); ap != 0 {
		t.Error("the application was approved although on_consent is fail")
	}
}

func TestConsentFormThatDiffersFromTheRequestIsNotApproved(t *testing.T) {
	s := newStack(t, gitlabOpts{consent: true, tamperClient: true}, albOpts{}, nil)
	_, err := s.login(t, goodAnswers())
	if !errors.Is(err, site.ErrLoginRejected) {
		t.Fatalf("err = %v", err)
	}
	if ap, _, _ := s.gl.stats(); ap != 0 {
		t.Error("a consent form for another client was approved")
	}
}

func TestFailuresAfterTheSignIn(t *testing.T) {
	t.Run("GitLab does not honour the sign-in", func(t *testing.T) {
		s := newStack(t, gitlabOpts{signInBroken: true}, albOpts{}, nil)
		_, err := s.login(t, goodAnswers())
		if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "did not send securl back") {
			t.Errorf("GitLab sends the jar to its own sign-in page; the message must say so, not blame the redirect: %v", err)
		}
	})
	t.Run("callback 503", func(t *testing.T) {
		s := newStack(t, gitlabOpts{}, albOpts{callbackStatus: 503}, nil)
		if _, err := s.login(t, goodAnswers()); !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("callback 403", func(t *testing.T) {
		s := newStack(t, gitlabOpts{}, albOpts{callbackStatus: 403}, nil)
		_, err := s.login(t, goodAnswers())
		if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "403") {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("GitLab unreachable", func(t *testing.T) {
		s := newStack(t, gitlabOpts{}, albOpts{}, nil)
		s.gl.Close()
		if _, err := s.login(t, goodAnswers()); !errors.Is(err, site.ErrUnreachable) {
			t.Errorf("err = %v", err)
		}
	})
	t.Run("nothing in any error", func(t *testing.T) {
		s := newStack(t, gitlabOpts{}, albOpts{callbackStatus: 403}, nil)
		_, err := s.login(t, goodAnswers())
		for _, secret := range []string{userPass, "gl-session-value", "code-", "state-", sessionCookieValue} {
			if err != nil && strings.Contains(err.Error(), secret) {
				t.Errorf("error leaks %q: %v", secret, err)
			}
		}
	})
}

func TestLoginRefusesAChainThatLeavesTheSiteAndTheIdp(t *testing.T) {
	s := newStack(t, gitlabOpts{otherPath: "http://elsewhere.example/steal"}, albOpts{}, nil)
	_, err := s.login(t, goodAnswers())
	if !errors.Is(err, site.ErrLoginRejected) || !strings.Contains(err.Error(), "neither the site nor the idp") {
		t.Errorf("err = %v", err)
	}
}

func TestProbe(t *testing.T) {
	var status atomic.Int32
	var gotCookie atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotCookie.Store(r.Header.Get("Cookie"))
		if st := int(status.Load()); st >= 300 && st < 400 {
			w.Header().Set("Location", "https://gitlab.corp.example/oauth/authorize")
		}
		w.WriteHeader(int(status.Load()))
	}))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	d, err := New(Spec{Name: "sw", IDP: IDP{Type: "gitlab", URL: "https://gitlab.corp.example"}})
	if err != nil {
		t.Fatal(err)
	}
	sess := &site.Session{Cookies: []*http.Cookie{{Name: "AWSELBAuthSessionCookie-0", Value: "v0"}, {Name: "AWSELBAuthSessionCookie-1", Value: "v1"}}}
	for _, tc := range []struct {
		status      int
		ok          bool
		unreachable bool
	}{{200, true, false}, {204, true, false}, {302, false, false}, {401, false, false}, {403, false, false},
		{429, false, true}, {502, false, true}, {503, false, true}, {504, false, true}, {500, false, false}} {
		status.Store(int32(tc.status))
		err := d.Probe(context.Background(), base, sess, &http.Client{})
		switch {
		case tc.ok && err != nil:
			t.Errorf("%d: %v", tc.status, err)
		case !tc.ok && err == nil:
			t.Errorf("%d: accepted", tc.status)
		case !tc.ok && errors.Is(err, site.ErrUnreachable) != tc.unreachable:
			t.Errorf("%d: unreachable = %v, want %v (%v)", tc.status, !tc.unreachable, tc.unreachable, err)
		}
	}
	if c, _ := gotCookie.Load().(string); !strings.Contains(c, "AWSELBAuthSessionCookie-0=v0") || !strings.Contains(c, "AWSELBAuthSessionCookie-1=v1") {
		t.Errorf("the probe did not send the cookies: %q", c)
	}
	srv.Close()
	if err := d.Probe(context.Background(), base, sess, &http.Client{Timeout: time.Second}); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("network error: %v", err)
	}
}

func TestProbeHonoursTheConfiguredPathAndStatus(t *testing.T) {
	var path atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { path.Store(r.URL.Path); w.WriteHeader(202) }))
	defer srv.Close()
	base, _ := url.Parse(srv.URL)
	d, _ := New(Spec{Name: "sw", IDP: IDP{Type: "gitlab", URL: "https://gitlab.corp.example"}, Probe: Probe{Path: "/graphql", ExpectStatus: 202}})
	if err := d.Probe(context.Background(), base, &site.Session{}, &http.Client{}); err != nil {
		t.Fatal(err)
	}
	if p, _ := path.Load().(string); p != "/graphql" {
		t.Errorf("path = %q", p)
	}
}

func TestSpecValidation(t *testing.T) {
	ok := Spec{Name: "sw", IDP: IDP{Type: "gitlab", URL: "https://gitlab.corp.example"}}
	if _, err := New(ok); err != nil {
		t.Fatalf("a valid spec: %v", err)
	}
	cases := map[string]func(*Spec){
		"no name":                func(s *Spec) { s.Name = "" },
		"no idp url":             func(s *Spec) { s.IDP.URL = "" },
		"idp url without scheme": func(s *Spec) { s.IDP.URL = "gitlab.corp.example" },
		"idp over http":          func(s *Spec) { s.IDP.URL = "http://gitlab.corp.example" },
		"idp with credentials":   func(s *Spec) { s.IDP.URL = "https://u:p@gitlab.corp.example" },
		"idp with a query":       func(s *Spec) { s.IDP.URL = "https://gitlab.corp.example/?a=b" },
		"unknown idp type":       func(s *Spec) { s.IDP.Type = "keycloak" },
		"no idp type":            func(s *Spec) { s.IDP.Type = "" },
		"unknown login_method":   func(s *Spec) { s.IDP.LoginMethod = "sso" },
		"unknown on_consent":     func(s *Spec) { s.OnConsent = "maybe" },
		"start_path not a path":  func(s *Spec) { s.StartPath = "login" },
		"probe path not a path":  func(s *Spec) { s.Probe.Path = "graphql" },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			sp := ok
			mutate(&sp)
			if _, err := New(sp); err == nil {
				t.Error("accepted")
			}
		})
	}
	local := Spec{Name: "sw", IDP: IDP{Type: "gitlab", URL: "http://localhost:8080"}}
	if _, err := New(local); err != nil {
		t.Errorf("http is allowed for a local idp (labs, tests): %v", err)
	}
}

func TestMatchAndDetail(t *testing.T) {
	d, _ := New(Spec{Name: "sw", MatchHost: "SkyWalking", IDP: IDP{Type: "gitlab", URL: "https://gitlab.corp.example"}})
	for host, want := range map[string]bool{"skywalking.corp.example": true, "SKYWALKING.x": true, "kibana.corp.example": false} {
		u, _ := url.Parse("https://" + host)
		if d.Match(u) != want {
			t.Errorf("Match(%s) = %v", host, !want)
		}
	}
	if !d.NeedsLogin() || d.Name() != "sw" {
		t.Error("name or NeedsLogin")
	}
	u, _ := url.Parse("https://skywalking.corp.example")
	det := d.(site.Detailer).Detail(u)
	for _, want := range []string{"gitlab.corp.example", "skywalking.corp.example", "not kept"} {
		if !strings.Contains(det, want) {
			t.Errorf("detail %q lacks %q", det, want)
		}
	}
}

func TestInspectDescribesTheRedirectWithoutValues(t *testing.T) {
	s := newStack(t, gitlabOpts{}, albOpts{}, nil)
	out, err := s.driver(t).(site.Inspector).Inspect(context.Background(), s.base, &http.Client{})
	if err != nil {
		t.Fatal(err)
	}
	text := strings.Join(out, "\n")
	for _, want := range []string{"localhost", "AWSALBAuthNonce", "redirect_uri"} {
		if !strings.Contains(text, want) {
			t.Errorf("inspection lacks %q:\n%s", want, text)
		}
	}
	for _, secret := range []string{"state-1", "client-1", "nonce-1"} {
		if strings.Contains(text, secret) {
			t.Errorf("inspection leaks %q:\n%s", secret, text)
		}
	}
	bad := newStack(t, gitlabOpts{}, albOpts{redirectTo: "http://localhost:1/oauth/authorize?response_type=code"}, nil)
	out, err = bad.driver(t).(site.Inspector).Inspect(context.Background(), bad.base, &http.Client{})
	if err != nil || !strings.Contains(strings.Join(out, "\n"), "NOT") {
		t.Errorf("a redirect to another host must be reported as a problem: %v %v", out, err)
	}
}
