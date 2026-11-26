package driver_test

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"reflect"
	"strings"
	"testing"

	"github.com/LeafAI/securl/driver"
	"github.com/LeafAI/securl/internal/site"
)

// A driver written outside this module can only name what this package exports, and securl runs it through the internal site
// package. The two must therefore be the very same types: an alias, never a copy that could drift.
func TestEveryExportedTypeIsTheSameTypeAsTheInternalOne(t *testing.T) {
	for name, pair := range map[string][2]reflect.Type{
		"Driver":          {reflect.TypeFor[driver.Driver](), reflect.TypeFor[site.Driver]()},
		"Session":         {reflect.TypeFor[driver.Session](), reflect.TypeFor[site.Session]()},
		"Field":           {reflect.TypeFor[driver.Field](), reflect.TypeFor[site.Field]()},
		"Credentials":     {reflect.TypeFor[driver.Credentials](), reflect.TypeFor[site.Credentials]()},
		"Asker":           {reflect.TypeFor[driver.Asker](), reflect.TypeFor[site.Asker]()},
		"CredentialScope": {reflect.TypeFor[driver.CredentialScope](), reflect.TypeFor[site.CredentialScope]()},
		"Detailer":        {reflect.TypeFor[driver.Detailer](), reflect.TypeFor[site.Detailer]()},
		"Inspector":       {reflect.TypeFor[driver.Inspector](), reflect.TypeFor[site.Inspector]()},
		"Configurable":    {reflect.TypeFor[driver.Configurable](), reflect.TypeFor[site.Configurable]()},
	} {
		if pair[0] != pair[1] {
			t.Errorf("driver.%s is %v, not %v: it must be an alias", name, pair[0], pair[1])
		}
	}
}

func TestTheErrorsAreTheOnesTheCallersTestFor(t *testing.T) {
	if driver.ErrBadCredentials != site.ErrBadCredentials || driver.ErrLoginRejected != site.ErrLoginRejected || driver.ErrUnreachable != site.ErrUnreachable {
		t.Fatal("a driver that wraps these must be recognised by errors.Is in securl")
	}
}

// The fields are handed out as copies: an outside driver that changes what it was given must not change what the next login asks.
func TestTheFieldListsAreCopiesSoNoDriverCanChangeWhatTheNextOneAsks(t *testing.T) {
	a := driver.LoginFields()
	if len(a) != 2 || a[0].Name != "username" || a[1].Name != "password" || !a[1].Secret {
		t.Fatalf("%+v", a)
	}
	a[1].Secret, a[0].Name = false, "tampered"
	if b := driver.LoginFields(); b[0].Name != "username" || !b[1].Secret {
		t.Errorf("a change leaked into the shared list: %+v", b)
	}
	c := driver.TOTPFields()
	if len(c) != 1 || c[0].Name != "code" {
		t.Fatalf("%+v", c)
	}
	c[0].Name = "tampered"
	if d := driver.TOTPFields(); d[0].Name != "code" {
		t.Errorf("%+v", d)
	}
}

func TestTheClientHelpersBehaveAsTheInternalOnes(t *testing.T) {
	jc := driver.JarClient(nil)
	if jc == nil || jc.Jar == nil {
		t.Fatal("a jar client keeps cookies")
	}
	nr := driver.NoRedirect(&http.Client{})
	if nr.CheckRedirect == nil || nr.CheckRedirect(nil, nil) != http.ErrUseLastResponse {
		t.Error("a no-redirect client stops at the first answer")
	}
	cs := []*http.Cookie{{Name: "a", Value: "1"}, {Name: "b", Value: "2"}}
	if got := driver.CookieHeader(cs); got != "a=1; b=2" {
		t.Errorf("%q", got)
	}
	u, _ := url.Parse("https://h.example")
	jc.Jar.SetCookies(u, []*http.Cookie{{Name: "k", Value: "v", Path: "/"}})
	if got := driver.CookiesFrom(jc, u); len(got) != 1 || got[0].Name != "k" {
		t.Errorf("%v", got)
	}
}

func TestTheHelpersAreTheInternalOnes(t *testing.T) {
	if driver.Clip("abcdef", 3) != site.Clip("abcdef", 3) || driver.Clip("abc", 3) != "abc" {
		t.Error("Clip")
	}
	for _, code := range []int{200, 301, 400, 401, 403, 404, 429, 500, 502, 503, 504} {
		if driver.TemporaryStatus(code) != site.TemporaryStatus(code) {
			t.Errorf("TemporaryStatus(%d) differs from the internal one", code)
		}
	}
	for _, code := range []int{429, 502, 503, 504} {
		if !driver.TemporaryStatus(code) {
			t.Errorf("%d says only that the site could not answer", code)
		}
	}
	if driver.TemporaryStatus(500) || driver.TemporaryStatus(401) {
		t.Error("a 500 or a 401 is the site saying no")
	}
	if err := driver.ProbeStatus("x", 200); err != nil {
		t.Error(err)
	}
	if err := driver.ProbeStatus("x", 503); err == nil || !strings.Contains(err.Error(), "x") {
		t.Error(err)
	}
	if driver.Unreachable(nil) != nil {
		t.Error("Unreachable(nil)")
	}
	cause := errors.New("connection refused")
	if err := driver.Unreachable(cause); !errors.Is(err, driver.ErrUnreachable) || !strings.Contains(err.Error(), "connection refused") {
		t.Errorf("a failure to ask is marked unreachable and keeps what the transport said: %v", err)
	}
	already := driver.Unreachable(cause)
	if driver.Unreachable(already) != already {
		t.Error("an error already marked is not marked twice")
	}
	u, _ := url.Parse("https://h.example/p/")
	if driver.Key(u) != site.Key(u) || driver.Key(u) != "https://h.example/p" {
		t.Error("Key")
	}
}

type fake struct{ name string }

func (f fake) Name() string                    { return f.name }
func (fake) Match(u *url.URL) bool             { return u.Hostname() == "match.example" }
func (fake) NeedsLogin() bool                  { return true }
func (fake) RememberScope() (string, *url.URL) { return "", nil }
func (fake) Login(context.Context, *url.URL, driver.Asker, *http.Client) (*driver.Session, error) {
	return &driver.Session{Headers: map[string]string{"x-test": "1"}}, nil
}
func (fake) Probe(context.Context, *url.URL, *driver.Session, *http.Client) error { return nil }

// What an outside module does: register through this package and be found by the internal registry, by name and by address.
func TestADriverRegisteredHereIsFoundByTheInternalRegistry(t *testing.T) {
	driver.Register(fake{name: "driver-pkg-test"})
	u, _ := url.Parse("https://match.example")
	d, err := site.Resolve("driver-pkg-test", u)
	if err != nil || d.Name() != "driver-pkg-test" {
		t.Fatalf("by name: %v %v", d, err)
	}
	if got, err := site.Resolve("", u); err != nil || got.Name() != "driver-pkg-test" {
		t.Fatalf("by address: %v %v", got, err)
	}
	if _, ok := d.(site.CredentialScope); !ok {
		t.Error("a driver that implements RememberScope takes part in remembered credentials")
	}
	if !contains(driver.Names(), "driver-pkg-test") {
		t.Errorf("%v", driver.Names())
	}
}

func TestRegisteringTheSameNameTwicePanicsAsItDoesInside(t *testing.T) {
	driver.Register(fake{name: "driver-pkg-dup"})
	defer func() {
		if recover() == nil {
			t.Error("a duplicate name must not silently replace a driver")
		}
	}()
	driver.Register(fake{name: "driver-pkg-dup"})
}

func contains(l []string, s string) bool {
	for _, x := range l {
		if x == s {
			return true
		}
	}
	return false
}
