package noauth

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"
)

func probe(t *testing.T, h http.HandlerFunc) error {
	t.Helper()
	srv := httptest.NewServer(h)
	defer srv.Close()
	u, _ := url.Parse(srv.URL)
	return driver{}.Probe(context.Background(), u, nil, srv.Client())
}

func TestProbeAcceptsASiteThatNeedsNoLogin(t *testing.T) {
	if err := probe(t, func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("ui")) }); err != nil {
		t.Errorf("200: %v", err)
	}
	// a redirect inside the site (to its own UI path) is not a login
	if err := probe(t, func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/" {
			http.Redirect(w, r, "/ui/", 302)
			return
		}
		w.Write([]byte("ui"))
	}); err != nil {
		t.Errorf("redirect inside the site: %v", err)
	}
}

func TestProbeSaysWhenTheSiteWantsALogin(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"redirect to another host": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "https://gitlab.corp.example/oauth/authorize?state=s3cr3t", 302)
		},
		"401": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 401) },
		"403": func(w http.ResponseWriter, r *http.Request) { http.Error(w, "no", 403) },
	} {
		t.Run(name, func(t *testing.T) {
			err := probe(t, h)
			if err == nil || !strings.Contains(err.Error(), "oauth2_sites") {
				t.Fatalf("err = %v, want a hint to add an oauth2_sites entry", err)
			}
			if strings.Contains(err.Error(), "s3cr3t") || strings.Contains(err.Error(), "gitlab.corp.example") {
				t.Errorf("the redirect target leaked into the error: %v", err)
			}
		})
	}
}

func TestProbeOtherErrorsKeepTheOldMessage(t *testing.T) {
	err := probe(t, func(w http.ResponseWriter, r *http.Request) { http.Error(w, "x", 500) })
	if err == nil || !strings.Contains(err.Error(), "500") {
		t.Errorf("err = %v", err)
	}
}
