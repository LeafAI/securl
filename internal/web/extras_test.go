package web_test

import (
	"encoding/base64"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/api"
	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/web"
)

var saltFields = []web.Field{{Name: "salt", Label: "Salt", Secret: true}}

// grantSite is what the managed steps are opened with: the address the person agrees to and how long the grant lasts.
const grantSite = "https://gitlab.example | Grant: 24h0m0s"

func managedRig(t *testing.T, mode string, fields []web.Field) *rig {
	t.Helper()
	return newRigSite(t, grantSite, mode, fields, nil, nil, 0)
}

// The static steps keep a field list of their own, and a link may not give them another: only the two steps that exist for it take
// the fields a driver asks for beside the username and the password.
func TestOnlyTheTwoExtrasStepsCarryAFieldListInTheLink(t *testing.T) {
	for _, mode := range []string{"credential_setup_x", "credential_replace_x"} {
		r := web.Round{Site: "h.example | Grant: 24h0m0s", Mode: mode, N: 1, APIBase: "https://abc.example/0123", PublicKey: []byte("k"),
			Fingerprint: strings.Repeat("AB", 20), Password: make([]byte, 32), Fields: saltFields}
		v := fragmentOf(t, web.Link("https://page.example/", r))
		if v.Get("fields") == "" {
			t.Errorf("%s: the link carries no field list", mode)
		}
	}
	for _, mode := range []string{"login", "totp", "credential_setup", "credential_replace", "credential_totp", "daily_approval", "vault"} {
		r := web.Round{Site: "h.example", Mode: mode, N: 1, APIBase: "https://abc.example/0123", PublicKey: []byte("k"),
			Fingerprint: strings.Repeat("AB", 20), Password: make([]byte, 32), Fields: saltFields}
		if v := fragmentOf(t, web.Link("https://page.example/", r)); v.Has("fields") {
			t.Errorf("%s: a step with a field list of its own must not carry one in the link", mode)
		}
	}
	r := web.Round{Site: "h.example", Mode: "custom", N: 1, APIBase: "https://abc.example/0123", PublicKey: []byte("k"), Fingerprint: strings.Repeat("AB", 20), Password: make([]byte, 32), Fields: saltFields}
	if !fragmentOf(t, web.Link("https://page.example/", r)).Has("fields") {
		t.Error("custom is the step that always carried one")
	}
}

func fragmentOf(t *testing.T, link string) url.Values {
	t.Helper()
	i := strings.Index(link, "#")
	if i < 0 {
		t.Fatalf("no fragment in %q", link)
	}
	v, err := url.ParseQuery(link[i+1:])
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// ---- in a real browser ----

func TestBrowserTheSetupStepWithExtrasAsksForTheUsernamePasswordRememberChoicesAndTheSalt(t *testing.T) {
	r := managedRig(t, "credential_setup_x", saltFields)
	res := browsertest.Drive(t, r.dir, r.frag, "probe", "", "")
	want := []string{"Username", "Password", "Remember credentials", "Remember TOTP (optional)", "Upstream TOTP setup secret (Base32)", "Salt"}
	if strings.Join(res.FieldLabels, "|") != strings.Join(want, "|") {
		t.Errorf("fields: %q, want %q", res.FieldLabels, want)
	}
	if got := strings.Join(res.FieldTypes, ","); got != "text,password,checkbox,checkbox,password,password" {
		t.Errorf("types: %s (the salt is shown as a secret, like the password)", got)
	}
	for _, ac := range res.Autocomplete {
		if ac != "off" {
			t.Errorf("autocomplete %q: a password manager must not file a salt under this page's origin", ac)
		}
	}
	if len(res.Errors) > 0 {
		t.Errorf("page errors: %v", res.Errors)
	}
}

func TestBrowserTheReplaceStepWithExtrasHasItsOwnFieldsAndTheSalt(t *testing.T) {
	r := managedRig(t, "credential_replace_x", saltFields)
	res := browsertest.Drive(t, r.dir, r.frag, "probe", "", "")
	want := []string{"Username", "Password", "Remember TOTP (optional)", "Upstream TOTP setup secret (Base32)", "Salt"}
	if strings.Join(res.FieldLabels, "|") != strings.Join(want, "|") {
		t.Errorf("fields: %q, want %q", res.FieldLabels, want)
	}
}

func TestBrowserTheSaltIsSubmittedWithTheCredentialsAndOnlyThroughTheSealedEnvelope(t *testing.T) {
	r := managedRig(t, "credential_setup_x", saltFields)
	res, sub, err := r.drive(r.frag, "submit", `{"username":"alice","password":"s3cr3t!","remember":"yes","salt":"SALT-VALUE-1234"}`, "")
	if err != nil {
		t.Fatalf("%v (page said %+v)", err, res)
	}
	if sub.Action != api.ActionSubmit || sub.Fields["username"] != "alice" || sub.Fields["password"] != "s3cr3t!" || sub.Fields["salt"] != "SALT-VALUE-1234" || sub.Fields["remember"] != "yes" {
		t.Errorf("submission %+v", sub)
	}
	if strings.Contains(res.RequestBody, "SALT-VALUE-1234") || strings.Contains(res.RequestBody, "s3cr3t!") {
		t.Errorf("what the page posted holds a value in the clear: %.120s", res.RequestBody)
	}
	if len(res.Errors) > 0 {
		t.Errorf("page errors: %v", res.Errors)
	}
}

func TestBrowserTheSaltIsRequiredAndNothingIsSentWithoutIt(t *testing.T) {
	r := managedRig(t, "credential_setup_x", saltFields)
	res, _, err := r.drive(r.frag, "submit", `{"username":"alice","password":"pw"}`, "")
	if err == nil {
		t.Fatal("a submission arrived without the salt")
	}
	if res.RequestBody != "" {
		t.Errorf("something was posted: %.80s", res.RequestBody)
	}
}

func TestBrowserSeveralExtrasAreAllShownAllSecretAndAllSent(t *testing.T) {
	fs := []web.Field{{Name: "salt", Label: "Salt", Secret: true}, {Name: "pepper", Label: "Pepper", Secret: true}, {Name: "region", Label: "Region", Secret: true}}
	r := managedRig(t, "credential_setup_x", fs)
	res, sub, err := r.drive(r.frag, "submit", `{"username":"a","password":"p","salt":"s1","pepper":"p1","region":"r1"}`, "")
	if err != nil {
		t.Fatalf("%v %+v", err, res)
	}
	if sub.Fields["salt"] != "s1" || sub.Fields["pepper"] != "p1" || sub.Fields["region"] != "r1" {
		t.Errorf("%+v", sub.Fields)
	}
	if got := strings.Join(res.FieldTypes, ","); got != "text,password,checkbox,checkbox,password,password,password,password" {
		t.Errorf("%s", got)
	}
}

// What a link may not do: the step with extras takes a field list, and nothing about that list may let a link ask for more than a
// secret of a plain name. A hostile link is refused, with the page's explanation, and shows no form.
func TestBrowserAHostileFieldListInTheExtrasStepIsRefused(t *testing.T) {
	good := web.Field{Name: "salt", Label: "Salt", Secret: true}
	for name, fs := range map[string][]web.Field{
		"a name that is not a plain name": {{Name: "Salt!", Label: "Salt", Secret: true}},
		"a name that is a security field": {{Name: "password", Label: "Password again", Secret: true}},
		"a name that is a consent field":  {{Name: "remember", Label: "Remember", Secret: true}},
		"a name that is the totp seed":    {{Name: "totp_secret", Label: "Seed", Secret: true}},
		"a name that is the code":         {{Name: "code", Label: "Code", Secret: true}},
		"a name that is the captcha":      {{Name: "verifyvalue", Label: "Captcha", Secret: true}},
		"the same name twice":             {good, good},
		"a field with an image":           {{Name: "salt", Label: "Salt", Secret: true, Image: "data:image/png;base64,AAAA"}},
		"a field that is not secret":      {{Name: "salt", Label: "Salt"}},
		"an empty list":                   {},
	} {
		for _, mode := range []string{"credential_setup_x", "credential_replace_x"} {
			r := managedRig(t, mode, fs)
			res := browsertest.Drive(t, r.dir, r.frag, "refuse", "", "")
			if !res.MainHidden || strings.TrimSpace(res.Msg) == "" {
				t.Errorf("%s (%s): the page showed a form: %+v", name, mode, res)
			}
		}
	}
}

// A step that has fields of its own takes no field list from the link: the vault step always refused one, and now every fixed step
// does, so a link cannot add an input to a page that shows a fixed form. The server never sends one for these steps.
func TestBrowserEveryFixedStepRefusesAFieldListInTheLink(t *testing.T) {
	stray := "W3sibmFtZSI6InNhbHQiLCJsYWJlbCI6IlNhbHQiLCJzZWNyZXQiOnRydWV9XQ" // [{"name":"salt","label":"Salt","secret":true}]
	for _, mode := range []string{"credential_setup", "credential_replace", "credential_totp", "daily_approval", "login", "totp"} {
		var r *rig
		if strings.HasPrefix(mode, "credential") || mode == "daily_approval" {
			r = managedRig(t, mode, nil)
		} else {
			r = newRig(t, mode, nil)
		}
		res := browsertest.Drive(t, r.dir, r.mutate(func(v url.Values) { v.Set("fields", stray) }), "refuse", "", "")
		if !res.MainHidden || !strings.Contains(res.Msg, "field list") {
			t.Errorf("%s: a field list was accepted by a step that has fields of its own: %+v", mode, res)
		}
	}
}

// An extras step without a field list is not a form with the salt left out.
func TestBrowserAnExtrasStepWithNoFieldListIsRefused(t *testing.T) {
	r := managedRig(t, "credential_setup_x", saltFields)
	frag := r.mutate(func(v url.Values) { v.Del("fields") })
	res := browsertest.Drive(t, r.dir, frag, "refuse", "", "")
	if !res.MainHidden {
		t.Errorf("a form without the salt: %+v", res.FieldLabels)
	}
}

func b64(s string) string { return base64.RawURLEncoding.EncodeToString([]byte(s)) }

// A list of fields that is not a list is refused for that reason, and not by the page falling over on it.
func TestBrowserAFieldListThatIsNotAListIsRefusedWithTheRightWords(t *testing.T) {
	for name, raw := range map[string]string{
		"an object": `{"name":"salt"}`, "a string": `"salt"`, "a number": `5`, "null": `null`, "an object with a length": `{"length":3}`,
		"text that is not json": `salt`,
	} {
		r := managedRig(t, "credential_setup_x", saltFields)
		res := browsertest.Drive(t, r.dir, r.mutate(func(v url.Values) { v.Set("fields", b64(raw)) }), "refuse", "", "")
		if !res.MainHidden || !strings.Contains(res.Msg, "Bad field list in link") {
			t.Errorf("%s: %+v", name, res)
		}
	}
}

// Each name the page or the server uses itself is refused on its own, in each of the two steps.
func TestBrowserEachReservedNameIsRefusedOnItsOwn(t *testing.T) {
	for _, name := range []string{"username", "password", "remember", "remember_totp", "totp_secret", "code", "verifyvalue", "confirm"} {
		for _, mode := range []string{"credential_setup_x", "credential_replace_x"} {
			r := managedRig(t, mode, []web.Field{{Name: name, Label: "X", Secret: true}})
			res := browsertest.Drive(t, r.dir, r.frag, "refuse", "", "")
			if !res.MainHidden || !strings.Contains(res.Msg, "Bad field name in link") {
				t.Errorf("%s (%s): %+v", name, mode, res)
			}
		}
	}
	r := managedRig(t, "credential_setup_x", []web.Field{{Name: "salt", Label: "Salt", Secret: true}})
	if res := browsertest.Drive(t, r.dir, r.frag, "probe", "", ""); len(res.FieldLabels) != 6 {
		t.Errorf("an ordinary name is fine: %+v", res.FieldLabels)
	}
}

// An extras step shows the same address and grant as the step it extends, and the page refuses it without them, as it does the
// steps it extends: a person must never be asked for credentials by a page that does not say what they are agreeing to.
func TestBrowserAnExtrasStepWithoutTheGrantInItsSiteIsRefused(t *testing.T) {
	for _, mode := range []string{"credential_setup_x", "credential_replace_x"} {
		for name, siteText := range map[string]string{
			"no grant at all":        "https://gitlab.example",
			"a bare host":            "gitlab.example",
			"a grant not at the end": "https://gitlab.example | Grant: 24h0m0s | more",
			"not https":              "http://gitlab.example | Grant: 24h0m0s",
		} {
			r := newRigSite(t, siteText, mode, saltFields, nil, nil, 0)
			res := browsertest.Drive(t, r.dir, r.frag, "refuse", "", "")
			if !res.MainHidden || !strings.Contains(res.Msg, "authorization duration") {
				t.Errorf("%s (%s): the page showed a form: %+v", name, mode, res)
			}
		}
		r := managedRig(t, mode, saltFields)
		res := browsertest.Drive(t, r.dir, r.frag, "probe", "", "")
		if !strings.Contains(res.BodyText, "24h0m0s") || !strings.Contains(res.BodyText, "gitlab.example") {
			t.Errorf("%s: the page does not say the address and the grant: %q", mode, res.BodyText)
		}
	}
}
