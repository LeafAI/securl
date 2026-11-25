package remember

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/generic"
	_ "github.com/LeafAI/securl/internal/site/jenkins"
)

type answerFunc func(context.Context, string, []site.Field) (site.Credentials, error)

func (f answerFunc) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	return f(ctx, mode, fields)
}

func TestOneTimeChallengeIsNeverSaved(t *testing.T) {
	r := &Record{Username: "test-user", Password: "test-password"}
	if _, err := r.Ask(context.Background(), "totp", site.TOTPFields); !errors.Is(err, ErrHumanChallenge) {
		t.Fatal(err)
	}
	human := answerFunc(func(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
		if mode != "totp" || len(fields) != 1 || fields[0].Name != "code" {
			t.Fatal("unexpected human fields", mode, fields)
		}
		return site.Credentials{"code": "123456"}, nil
	})
	values, err := (savedAsker{r: r, human: human}).Ask(context.Background(), "totp", site.TOTPFields)
	if err != nil || values["code"] != "123456" || len(r.Secret) != 0 {
		t.Fatal("one-time challenge was not handled correctly", err)
	}
}

func TestRememberedLoginRefusesForeignFormAction(t *testing.T) {
	var hits atomic.Int32
	foreign := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hits.Add(1) }))
	defer foreign.Close()
	target := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		fmt.Fprintf(w, `<form name="login" action="%s/submit"></form>`, foreign.URL)
	}))
	defer target.Close()
	base, _ := url.Parse(target.URL)
	d, err := site.Resolve("jenkins", base)
	if err != nil {
		t.Fatal(err)
	}
	r := &Record{Site: d.Name(), Username: "example-user", Password: "example-password"}
	_, err = Login(context.Background(), d, base, r, target.Client(), nil)
	if err == nil || hits.Load() != 0 {
		t.Fatal("foreign form action was not blocked", err, hits.Load())
	}
	if strings.Contains(err.Error(), r.Password) {
		t.Fatal("credential in error")
	}
}

func TestGenericAuthenticationDefinitionBinding(t *testing.T) {
	spec := generic.Spec{Name: "custom-app", Steps: []generic.Step{{Path: "/login", Form: map[string]string{"username": "{{username}}", "password": "{{password}}"}}}}
	d, err := generic.New(spec)
	if err != nil {
		t.Fatal(err)
	}
	b, _, ok := Scope(d)
	if !ok || b == "" {
		t.Fatal("missing scope")
	}
	record := Record{Site: d.Name(), Binding: b}
	equivalent, err := generic.New(spec)
	if err != nil || !record.Matches(equivalent) {
		t.Fatal("stable definition did not match", err)
	}
	spec.Steps[0].Path = "/another-login"
	changed, err := generic.New(spec)
	if err != nil || record.Matches(changed) {
		t.Fatal("changed definition matched", err)
	}
}
