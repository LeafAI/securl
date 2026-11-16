package nacos

import (
	"context"
	"encoding/json"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

const secretToken = "eyJhbGciOiJIUzI1NiJ9.TOKEN-ONE.sig"

// fakeNacos imitates the login, the namespace list and the server state of one Nacos generation under one context path.
type fakeNacos struct {
	mu     sync.Mutex
	hits   map[string]int
	prefix string
	gen    string
}

func (f *fakeNacos) hit(path string) {
	f.mu.Lock()
	defer f.mu.Unlock()
	if f.hits == nil {
		f.hits = map[string]int{}
	}
	f.hits[path]++
}

func (f *fakeNacos) count(path string) int {
	f.mu.Lock()
	defer f.mu.Unlock()
	return f.hits[path]
}

func (f *fakeNacos) handler() http.Handler {
	login, check, state := "/v1/auth/login", "/v1/console/namespaces", "/v1/console/server/state"
	if f.gen == "v3" {
		login, check, state = "/v3/auth/user/login", "/v3/console/core/namespace/list", "/v3/console/server/state"
	}
	mux := http.NewServeMux()
	mux.HandleFunc(f.prefix+login, func(w http.ResponseWriter, r *http.Request) {
		f.hit(r.URL.Path)
		if r.Method != http.MethodPost {
			w.WriteHeader(http.StatusMethodNotAllowed)
			return
		}
		if err := r.ParseForm(); err != nil {
			w.WriteHeader(http.StatusBadRequest)
			return
		}
		if r.PostForm.Get("username") != "alice" || r.PostForm.Get("password") != "pw" {
			http.Error(w, "unknown user!", http.StatusForbidden)
			return
		}
		json.NewEncoder(w).Encode(map[string]any{"accessToken": secretToken, "tokenTtl": 18000, "globalAdmin": false})
	})
	mux.HandleFunc(f.prefix+check, func(w http.ResponseWriter, r *http.Request) {
		f.hit(r.URL.Path)
		if r.Header.Get("accessToken") != secretToken || r.Header.Get("Authorization") != "Bearer "+secretToken {
			http.Error(w, "token invalid", http.StatusForbidden)
			return
		}
		w.Write([]byte("[]"))
	})
	mux.HandleFunc(f.prefix+state, func(w http.ResponseWriter, r *http.Request) {
		json.NewEncoder(w).Encode(map[string]any{"version": "2.2.3", "auth_enabled": "true"})
	})
	return mux
}

// asker answers the login round with one account and counts how often a person was asked.
type asker struct {
	user  string
	pass  string
	asked int
}

func (a *asker) Ask(_ context.Context, mode string, _ []site.Field) (site.Credentials, error) {
	a.asked++
	if mode != "login" {
		return nil, errors.New("unexpected round " + mode)
	}
	return site.Credentials{"username": a.user, "password": a.pass}, nil
}

func serve(t *testing.T, h http.Handler) (*url.URL, *http.Client) {
	t.Helper()
	srv := httptest.NewServer(h)
	t.Cleanup(srv.Close)
	u, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	return u, srv.Client()
}

func login(u *url.URL, hc *http.Client, a *asker) (*site.Session, error) {
	return driver{}.Login(context.Background(), u, a, hc)
}

var combos = []struct {
	gen    string
	prefix string
}{{"v1", "/nacos"}, {"v1", ""}, {"v3", "/nacos"}, {"v3", ""}}

func TestLoginOnEveryGenerationAndContextPath(t *testing.T) {
	for _, c := range combos {
		t.Run(c.gen+c.prefix, func(t *testing.T) {
			u, hc := serve(t, (&fakeNacos{gen: c.gen, prefix: c.prefix}).handler())
			a := &asker{user: "alice", pass: "pw"}
			s, err := login(u, hc, a)
			if err != nil {
				t.Fatal(err)
			}
			if s.Headers["accessToken"] != secretToken || s.Headers["Authorization"] != "Bearer "+secretToken {
				t.Errorf("headers: %v", s.Headers)
			}
			if s.Tokens["api"] != c.gen {
				t.Errorf("api generation = %q, want %q", s.Tokens["api"], c.gen)
			}
			if !s.ExpiresAt.After(time.Now().Add(time.Hour)) {
				t.Errorf("expiry = %v: the token lives 18000 seconds", s.ExpiresAt)
			}
			if a.asked != 1 {
				t.Errorf("a person was asked %d times", a.asked)
			}
			if err := (driver{}).Probe(context.Background(), u, s, hc); err != nil {
				t.Errorf("probe of a fresh session: %v", err)
			}
		})
	}
}

func TestAWrongPasswordIsBadCredentialsAndTheServerIsAskedOnce(t *testing.T) {
	f := &fakeNacos{gen: "v1", prefix: "/nacos"}
	u, hc := serve(t, f.handler())
	a := &asker{user: "alice", pass: "Wrong-Pa55word!"}
	_, err := login(u, hc, a)
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("want bad credentials, got %v", err)
	}
	if strings.Contains(err.Error(), a.pass) {
		t.Errorf("the error holds the password: %v", err)
	}
	if n := f.count("/nacos/v1/auth/login"); n != 1 {
		t.Errorf("the login address was asked %d times, want 1", n)
	}
}

func TestNothingIsSentWithoutBothFields(t *testing.T) {
	f := &fakeNacos{gen: "v1", prefix: "/nacos"}
	u, hc := serve(t, f.handler())
	_, err := login(u, hc, &asker{user: "alice"})
	if !errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("want bad credentials, got %v", err)
	}
	if n := f.count("/nacos/v1/auth/login"); n != 0 {
		t.Errorf("%d requests went out", n)
	}
}

func TestAServerWithoutALoginAddressIsNotNacos(t *testing.T) {
	u, hc := serve(t, http.NotFoundHandler())
	_, err := login(u, hc, &asker{user: "alice", pass: "pw"})
	if !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("want login rejected, got %v", err)
	}
}

func TestAnswerWithoutATokenIsRejected(t *testing.T) {
	u, hc := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"globalAdmin":false}`))
	}))
	_, err := login(u, hc, &asker{user: "alice", pass: "pw"})
	if !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("want login rejected, got %v", err)
	}
}

func TestAGatewayErrorIsUnreachableAndNotBadCredentials(t *testing.T) {
	u, hc := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	_, err := login(u, hc, &asker{user: "alice", pass: "pw"})
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("want unreachable, got %v", err)
	}
}

func TestARootsPathIsUsedAsGiven(t *testing.T) {
	f := &fakeNacos{gen: "v1", prefix: "/corp/nacos"}
	u, hc := serve(t, f.handler())
	u.Path = "/corp/nacos"
	s, err := login(u, hc, &asker{user: "alice", pass: "pw"})
	if err != nil {
		t.Fatal(err)
	}
	if n := f.count("/corp/nacos/v1/auth/login"); n != 1 {
		t.Errorf("the login address under the given path was asked %d times, want 1", n)
	}
	if err := (driver{}).Probe(context.Background(), u, s, hc); err != nil {
		t.Errorf("probe: %v", err)
	}
}

func TestProbeRefusesATokenTheServerDoesNotKnow(t *testing.T) {
	u, hc := serve(t, (&fakeNacos{gen: "v1", prefix: "/nacos"}).handler())
	stale := &site.Session{Headers: map[string]string{"accessToken": "old", "Authorization": "Bearer old"}, Tokens: map[string]string{"api": "v1"}}
	err := (driver{}).Probe(context.Background(), u, stale, hc)
	if err == nil || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a token the server does not know must be refused, and not called unreachable: %v", err)
	}
}

func TestProbeKeepsTheSessionWhenTheSiteCannotAnswer(t *testing.T) {
	busy, busyClient := serve(t, http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusServiceUnavailable)
	}))
	s := &site.Session{Headers: map[string]string{"accessToken": "t"}, Tokens: map[string]string{"api": "v1"}}
	if err := (driver{}).Probe(context.Background(), busy, s, busyClient); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("503 says nothing about the session: %v", err)
	}

	srv := httptest.NewServer(http.NotFoundHandler())
	gone, err := url.Parse(srv.URL)
	if err != nil {
		t.Fatal(err)
	}
	goneClient := srv.Client()
	srv.Close()
	if err := (driver{}).Probe(context.Background(), gone, s, goneClient); !errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a server that is down says nothing about the session: %v", err)
	}

	none, noneClient := serve(t, http.NotFoundHandler())
	if err := (driver{}).Probe(context.Background(), none, s, noneClient); err != nil {
		t.Errorf("an address that is not there says nothing about the session: %v", err)
	}
}

func TestInspectSaysWhatTheServerSaysAboutItself(t *testing.T) {
	u, hc := serve(t, (&fakeNacos{gen: "v3", prefix: ""}).handler())
	out, err := (driver{}).Inspect(context.Background(), u, hc)
	got := strings.Join(out, " | ")
	if err != nil || !strings.Contains(got, "version: 2.2.3") || !strings.Contains(got, "auth_enabled: true") || !strings.Contains(got, "generation v3") {
		t.Errorf("%q %v", got, err)
	}
}

func TestMatch(t *testing.T) {
	for host, want := range map[string]bool{
		"https://nacos.corp.example:8848": true,
		"http://NACOS-test.corp.example":  true,
		"https://gitlab.corp.example":     false,
	} {
		u, err := url.Parse(host)
		if err != nil {
			t.Fatal(err)
		}
		if got := (driver{}).Match(u); got != want {
			t.Errorf("Match(%s) = %v, want %v", host, got, want)
		}
	}
}
