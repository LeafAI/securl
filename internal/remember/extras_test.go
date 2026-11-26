package remember

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/site"
)

// withSalt is a driver that asks for a salt beside the username and the password.
type withSalt struct {
	fields []site.Field
}

func (withSalt) Name() string        { return "salted" }
func (withSalt) Match(*url.URL) bool { return false }
func (withSalt) NeedsLogin() bool    { return true }
func (withSalt) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return nil, nil
}
func (withSalt) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }
func (withSalt) RememberScope() (string, *url.URL)                                  { return "", nil }
func (d withSalt) LoginExtraFields() []site.Field                                   { return d.fields }

var saltField = site.Field{Name: "salt", Label: "Salt"}

type plainDriver struct{}

func (plainDriver) Name() string        { return "plain" }
func (plainDriver) Match(*url.URL) bool { return false }
func (plainDriver) NeedsLogin() bool    { return true }
func (plainDriver) Login(context.Context, *url.URL, site.Asker, *http.Client) (*site.Session, error) {
	return nil, nil
}
func (plainDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }
func (plainDriver) RememberScope() (string, *url.URL)                                  { return "", nil }

func TestADriverWithoutExtrasHasNone(t *testing.T) {
	if got, err := Extras(plainDriver{}); err != nil || len(got) != 0 {
		t.Errorf("%v %v", got, err)
	}
	if got, err := Extras(nil); err != nil || len(got) != 0 {
		t.Errorf("%v %v", got, err)
	}
}

func TestTheExtrasAreTheDriversFieldsInTheOrderItGaveThemAndAlwaysSecret(t *testing.T) {
	got, err := Extras(withSalt{fields: []site.Field{{Name: "salt", Label: "Salt"}, {Name: "pepper", Label: "Pepper", Secret: false}}})
	if err != nil || len(got) != 2 || got[0].Name != "salt" || got[1].Name != "pepper" {
		t.Fatalf("%v %v", got, err)
	}
	for _, f := range got {
		if !f.Secret {
			t.Errorf("%s is not secret: a page cannot tell a salt from a password", f.Name)
		}
	}
}

// There is no limit on how many a driver may ask for here: the page's own limit on the fields of a link is the only bound.
func TestThereIsNoLimitOfOurOwnOnHowManyExtrasADriverAsksFor(t *testing.T) {
	var fs []site.Field
	for i := 0; i < 40; i++ {
		fs = append(fs, site.Field{Name: "x" + strings.Repeat("a", i%5) + string(rune('a'+i%26)) + string(rune('a'+i/26)), Label: "L"})
	}
	if got, err := Extras(withSalt{fields: fs}); err != nil || len(got) != 40 {
		t.Errorf("%d %v", len(got), err)
	}
}

func TestAnExtraWithAnUnusableNameOrLabelIsRefused(t *testing.T) {
	long := strings.Repeat("a", 33)
	for name, f := range map[string]site.Field{
		"empty": {Name: "", Label: "L"}, "upper case": {Name: "Salt", Label: "L"}, "a hyphen": {Name: "my-salt", Label: "L"},
		"a space": {Name: "my salt", Label: "L"}, "a digit first": {Name: "1salt", Label: "L"}, "an underscore first": {Name: "_salt", Label: "L"},
		"too long": {Name: long, Label: "L"}, "a dot": {Name: "a.b", Label: "L"}, "non ascii": {Name: "sälz", Label: "L"}, "a newline": {Name: "a\nb", Label: "L"},
		"no label": {Name: "salt", Label: ""}, "a long label": {Name: "salt", Label: strings.Repeat("x", 61)}, "a label with a newline": {Name: "salt", Label: "a\nb"},
		"an image": {Name: "salt", Label: "L", Image: "data:image/png;base64,AAAA"},
	} {
		if _, err := Extras(withSalt{fields: []site.Field{f}}); err == nil {
			t.Errorf("%s: %+v was accepted", name, f)
		}
	}
	if _, err := Extras(withSalt{fields: []site.Field{{Name: "s", Label: "L"}, {Name: "x" + strings.Repeat("a", 31), Label: strings.Repeat("x", 60)}}}); err != nil {
		t.Errorf("the longest ones that are allowed: %v", err)
	}
}

func TestAnExtraCannotBeCalledWhatSecurlItselfUses(t *testing.T) {
	for name := range site.ReservedFieldNames {
		if _, err := Extras(withSalt{fields: []site.Field{{Name: name, Label: "L"}}}); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	for _, name := range []string{"username", "password", "remember", "remember_totp", "totp_secret", "code", "verifyvalue", "confirm"} {
		if !site.ReservedFieldNames[name] {
			t.Errorf("%s is used by securl's own pages and is not reserved", name)
		}
	}
	if _, err := Extras(withSalt{fields: []site.Field{{Name: "salt", Label: "L"}, {Name: "salt", Label: "L"}}}); err == nil {
		t.Error("two extras of one name")
	}
}

func TestARefusedExtraIsNotRepeated(t *testing.T) {
	_, err := Extras(withSalt{fields: []site.Field{{Name: "hunter2-SECRET key", Label: "L"}}})
	if err == nil || strings.Contains(err.Error(), "hunter2") {
		t.Errorf("%v", err)
	}
}

func TestTheBindingSaysWhichExtrasTheRecordWasMadeWith(t *testing.T) {
	plain := &Record{Site: "plain", Username: "u", Password: "p"}
	if !plain.Matches(plainDriver{}) {
		t.Fatal("a plain record matches a plain driver")
	}
	salted := &Record{Site: "salted", Binding: ExtrasBinding([]site.Field{saltField}), Username: "u", Password: "p", Extras: map[string]string{"salt": "s"}}
	if !salted.Matches(withSalt{fields: []site.Field{saltField}}) {
		t.Error("a record made with the salt matches the driver that asks for the salt")
	}
	if salted.Matches(withSalt{fields: []site.Field{{Name: "pepper", Label: "Pepper"}}}) {
		t.Error("a driver that now asks for another field must not use the old record")
	}
	if salted.Matches(withSalt{fields: []site.Field{saltField, {Name: "pepper", Label: "Pepper"}}}) {
		t.Error("a driver that now asks for one more field must not use the old record")
	}
	if salted.Matches(withSalt{}) {
		t.Error("a driver that stopped asking for the salt")
	}
	old := &Record{Site: "salted", Username: "u", Password: "p"}
	if old.Matches(withSalt{fields: []site.Field{saltField}}) {
		t.Error("a record saved before the driver asked for a salt has none, and cannot log in")
	}
}

func TestTheBindingOfNoExtrasIsEmptyAndOfExtrasDependsOnNamesAndOrderNotOnLabels(t *testing.T) {
	if ExtrasBinding(nil) != "" || ExtrasBinding([]site.Field{}) != "" {
		t.Error("no extras, no binding: a record saved before extras existed stays valid")
	}
	a := ExtrasBinding([]site.Field{{Name: "salt", Label: "Salt"}})
	b := ExtrasBinding([]site.Field{{Name: "salt", Label: "A different label"}})
	if a == "" || a != b {
		t.Errorf("a label is not what the record depends on: %q %q", a, b)
	}
	if ExtrasBinding([]site.Field{{Name: "a", Label: "x"}, {Name: "b", Label: "x"}}) == ExtrasBinding([]site.Field{{Name: "b", Label: "x"}, {Name: "a", Label: "x"}}) {
		t.Error("the order is part of what was asked")
	}
}

func TestARecordWithExtrasIsOnlyValidWhenTheyAreNamedAndNotEmpty(t *testing.T) {
	good := Record{Site: "s", Username: "u", Password: "p", Revision: strings.Repeat("a", 32), Extras: map[string]string{"salt": "x"}}
	if err := good.validate(); err != nil {
		t.Fatal(err)
	}
	for name, ex := range map[string]map[string]string{
		"an empty value": {"salt": ""}, "an empty name": {"": "x"}, "a bad name": {"Salt": "x"}, "a reserved name": {"password": "x"},
		"a huge value": {"salt": strings.Repeat("x", maxExtraBytes+1)},
	} {
		r := good
		r.Extras = ex
		if err := r.validate(); err == nil {
			t.Errorf("%s was accepted", name)
		}
	}
	r := good
	r.Extras = map[string]string{"salt": strings.Repeat("x", maxExtraBytes)}
	if err := r.validate(); err != nil {
		t.Errorf("the largest value that is allowed: %v", err)
	}
	r.Extras = nil
	if err := r.validate(); err != nil {
		t.Errorf("a record with none is what every record was: %v", err)
	}
}

// A record does not know which fields the driver declared, so it answers only the standard rounds; the extras are the asker's to add,
// from what the driver declared (savedAsker), never everything that happens to be saved.
func TestARecordAloneAnswersOnlyTheUsernameAndPasswordAndTheCode(t *testing.T) {
	r := &Record{Username: "u", Password: "p", Extras: map[string]string{"salt": "s1", "pepper": "p1"}}
	got, err := r.Ask(context.Background(), "login", site.LoginFields)
	if err != nil || len(got) != 2 || got["username"] != "u" || got["password"] != "p" {
		t.Fatalf("%v %v", got, err)
	}
	if _, err := r.Ask(context.Background(), "totp", site.TOTPFields); !errors.Is(err, ErrHumanChallenge) {
		t.Errorf("a one-time code round with no seed: %v", err)
	}
	r.Secret = []byte("12345678901234567890")
	got, err = r.Ask(context.Background(), "totp", site.TOTPFields)
	if err != nil || len(got) != 1 || got["code"] == "" {
		t.Errorf("%v %v", got, err)
	}
}

func TestALoginRoundThatAsksForTheExtrasIsStillALoginRound(t *testing.T) {
	fields := []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "salt", Secret: true}}
	login, challenge := LoginChallengeWith("custom", fields, []site.Field{saltField})
	if !login || len(challenge) != 0 {
		t.Errorf("%v %v", login, challenge)
	}
	if login, _ := LoginChallengeWith("custom", fields, nil); login {
		t.Error("a field the driver did not declare is not part of a login")
	}
	if login, _ := LoginChallengeWith("custom", fields, []site.Field{{Name: "pepper"}}); login {
		t.Error("a field that is not the one declared")
	}
	if login, _ := LoginChallengeWith("custom", []site.Field{{Name: "username"}, {Name: "password"}}, []site.Field{saltField}); login {
		t.Error("the declared field is missing, so it is not the round the driver asks")
	}
	withCaptcha := append(append([]site.Field{}, fields...), site.Field{Name: "verifyvalue", Image: "data:image/png;base64,AAAA"})
	if login, challenge := LoginChallengeWith("custom", withCaptcha, []site.Field{saltField}); !login || len(challenge) != 1 {
		t.Errorf("a captcha beside the extras: %v %v", login, challenge)
	}
}

func TestTheBindingOfARecordMadeNowIsTheOneItMatchesWith(t *testing.T) {
	for name, d := range map[string]site.Driver{
		"plain": plainDriver{}, "salted": withSalt{fields: []site.Field{saltField}},
		"two": withSalt{fields: []site.Field{saltField, {Name: "pepper", Label: "P"}}},
	} {
		b, err := BindingOf(d)
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		r := &Record{Site: d.Name(), Binding: b, Username: "u", Password: "p"}
		if !r.Matches(d) {
			t.Errorf("%s: a record made now does not match the driver it was made for", name)
		}
	}
	b1, _ := BindingOf(withSalt{fields: []site.Field{saltField}})
	b2, _ := BindingOf(withSalt{fields: []site.Field{saltField, {Name: "pepper", Label: "P"}}})
	if b1 == b2 || b1 != "extras:salt" || b2 != "extras:salt,pepper" {
		t.Errorf("%q %q", b1, b2)
	}
	if _, err := BindingOf(withSalt{fields: []site.Field{{Name: "Bad", Label: "L"}}}); err == nil {
		t.Error("a driver whose extras are refused has no binding")
	}
	if _, err := BindingOf(noLoginDriver{}); err == nil {
		t.Error("a driver that does not remember has no binding")
	}
}

type noLoginDriver struct{ plainDriver }

func (noLoginDriver) NeedsLogin() bool { return false }

// A driver whose extras are refused cannot have a record that matches it, and cannot be worked around by a record that was saved
// with an empty binding.
func TestADriverWhoseExtrasAreRefusedMatchesNoRecord(t *testing.T) {
	bad := withSalt{fields: []site.Field{{Name: "Bad", Label: "L"}}}
	for _, b := range []string{"", ExtrasBinding([]site.Field{{Name: "Bad"}})} {
		if (&Record{Site: "salted", Binding: b, Username: "u", Password: "p"}).Matches(bad) {
			t.Errorf("binding %q matched a driver whose extras are refused", b)
		}
	}
}

func TestARecordForAnotherSiteDoesNotMatchEvenWithTheSameBinding(t *testing.T) {
	d := withSalt{fields: []site.Field{saltField}}
	b, _ := BindingOf(d)
	if (&Record{Site: "another", Binding: b, Username: "u", Password: "p"}).Matches(d) {
		t.Error("the site is part of what a record matches")
	}
}

func TestTheNameOfAnExtraMayHoldDigitsAndUnderscoresAfterTheFirstLetter(t *testing.T) {
	for _, n := range []string{"a", "salt2", "my_salt", "s1_2_3", "z", "a" + strings.Repeat("9", 31)} {
		if _, err := Extras(withSalt{fields: []site.Field{{Name: n, Label: "L"}}}); err != nil {
			t.Errorf("%q: %v", n, err)
		}
	}
	for _, n := range []string{"2salt", "salt!", "sa-lt", "sa lt", "sa.lt"} {
		if _, err := Extras(withSalt{fields: []site.Field{{Name: n, Label: "L"}}}); err == nil {
			t.Errorf("%q was accepted", n)
		}
	}
}

func TestTheBindingJoinsTheNamesWithCommasSoTwoListsNeverRunTogether(t *testing.T) {
	ab := ExtrasBinding([]site.Field{{Name: "a"}, {Name: "b"}})
	one := ExtrasBinding([]site.Field{{Name: "ab"}})
	if ab == one || ab != "extras:a,b" {
		t.Errorf("%q %q", ab, one)
	}
}

// The standard login round is the one that asks for the username and the password; a driver that declared extras asks for them in
// that same round, whether the round is named "login" or "custom", and a round that lacks one of them is not what the driver asks.
func TestALoginRoundIsTheOneThatAsksForExactlyTheUsernamePasswordAndTheDeclaredExtras(t *testing.T) {
	if login, ch := LoginChallengeWith("login", nil, nil); !login || len(ch) != 0 {
		t.Errorf("the standard round with no field list: %v %v", login, ch)
	}
	if login, ch := LoginChallengeWith("login", site.LoginFields, nil); !login || len(ch) != 0 {
		t.Errorf("%v %v", login, ch)
	}
	salted := []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}}
	for _, mode := range []string{"login", "custom"} {
		if login, _ := LoginChallengeWith(mode, salted, []site.Field{saltField}); !login {
			t.Errorf("%s: a round that carries the declared salt is the login", mode)
		}
		if login, _ := LoginChallengeWith(mode, site.LoginFields, []site.Field{saltField}); login {
			t.Errorf("%s: a driver that declared a salt asks for it: a round without it is not its login", mode)
		}
		if login, _ := LoginChallengeWith(mode, salted, nil); login {
			t.Errorf("%s: a field the driver did not declare is not part of a login", mode)
		}
	}
	if login, _ := LoginChallenge("login", nil); !login {
		t.Error("LoginChallenge is the no-extras case")
	}
	for _, mode := range []string{"totp", "credential_setup", "daily_approval", ""} {
		if login, _ := LoginChallengeWith(mode, site.LoginFields, nil); login {
			t.Errorf("mode %q is not a login round", mode)
		}
		if login, _ := LoginChallengeWith(mode, salted, []site.Field{saltField}); login {
			t.Errorf("mode %q is not a login round, with extras either", mode)
		}
	}
}

func TestACaptchaFieldWithoutAnImageIsNotAChallengeAndNotALogin(t *testing.T) {
	fields := []site.Field{{Name: "username"}, {Name: "password"}, {Name: "verifyvalue"}}
	if login, _ := LoginChallengeWith("custom", fields, nil); login {
		t.Error("a verifyvalue with no image is something else")
	}
	fields = []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}, {Name: "verifyvalue"}}
	if login, _ := LoginChallengeWith("custom", fields, []site.Field{saltField}); login {
		t.Error("a verifyvalue with no image is something else, with extras too")
	}
}

func TestEverySavedExtraNeedsNoLimitOnItsCountButEveryOneIsHeldToItsValueLimit(t *testing.T) {
	ex := map[string]string{}
	for i := 0; i < 30; i++ {
		ex["f"+string(rune('a'+i%26))+string(rune('a'+i/26))] = "v"
	}
	r := Record{Site: "s", Username: "u", Password: "p", Revision: strings.Repeat("a", 32), Extras: ex}
	if err := r.validate(); err != nil {
		t.Errorf("30 extras: %v", err)
	}
}

// bound is a driver that has a binding of its own (as a configured generic site has) and asks for a salt too.
type bound struct{ withSalt }

func (bound) RememberScope() (string, *url.URL) { return "generic:abc", nil }

func TestADriversOwnBindingAndItsExtrasAreBothPartOfTheBindingAndNeverRunTogether(t *testing.T) {
	d := bound{withSalt{fields: []site.Field{saltField}}}
	b, err := BindingOf(d)
	if err != nil || b != "generic:abc|extras:salt" {
		t.Fatalf("%q %v", b, err)
	}
	if !(&Record{Site: "salted", Binding: b, Username: "u", Password: "p"}).Matches(d) {
		t.Error("a record made for it matches")
	}
	for _, other := range []string{"generic:abcextras:salt", "generic:abc", "extras:salt", "generic:abd|extras:salt", ""} {
		if (&Record{Site: "salted", Binding: other, Username: "u", Password: "p"}).Matches(d) {
			t.Errorf("binding %q matched", other)
		}
	}
}

func TestALoginRoundNeedsTheUsernameAndThePasswordAndNotOnlyTheExtras(t *testing.T) {
	extras := []site.Field{saltField}
	for name, fields := range map[string][]site.Field{
		"no username": {{Name: "password"}, {Name: "salt"}},
		"no password": {{Name: "username"}, {Name: "salt"}},
		"only extras": {{Name: "salt"}},
	} {
		if login, _ := LoginChallengeWith("custom", fields, extras); login {
			t.Errorf("%s was taken for a login", name)
		}
	}
	if login, _ := LoginChallengeWith("custom", []site.Field{{Name: "username"}, {Name: "password"}}, nil); !login {
		t.Error("the plain pair is a login")
	}
	if login, _ := LoginChallengeWith("custom", []site.Field{{Name: "password"}}, nil); login {
		t.Error("a password alone is not")
	}
	if login, _ := LoginChallengeWith("custom", []site.Field{{Name: "username"}}, nil); login {
		t.Error("a username alone is not")
	}
}

// ---- the renewal path: a saved login is answered with the saved extras, and a captcha still asks the person ----

func TestASavedLoginAnswersWithTheSavedExtrasWhenTheDriverAsksForThem(t *testing.T) {
	r := &Record{Username: "u", Password: "p", Extras: map[string]string{"salt": "s1"}}
	a := savedAsker{r: r, extras: []site.Field{saltField}}
	for _, mode := range []string{"login", "custom"} {
		got, err := a.Ask(context.Background(), mode, []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "salt", Secret: true}})
		if err != nil || got["username"] != "u" || got["password"] != "p" || got["salt"] != "s1" || len(got) != 3 {
			t.Errorf("%s: %v %v", mode, got, err)
		}
	}
}

func TestASavedLoginWithACaptchaAsksThePersonForTheAnswerAndKeepsTheExtras(t *testing.T) {
	r := &Record{Username: "u", Password: "p", Extras: map[string]string{"salt": "s1"}}
	var asked []site.Field
	human := answerFunc(func(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
		asked = fields
		return site.Credentials{"verifyvalue": "42"}, nil
	})
	a := savedAsker{r: r, human: human, extras: []site.Field{saltField}}
	fields := []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}, {Name: "verifyvalue", Image: "data:image/png;base64,AAAA"}}
	got, err := a.Ask(context.Background(), "custom", fields)
	if err != nil || got["salt"] != "s1" || got["verifyvalue"] != "42" || got["password"] != "p" {
		t.Fatalf("%v %v", got, err)
	}
	if len(asked) != 1 || asked[0].Name != "verifyvalue" {
		t.Errorf("only the captcha goes to the person, never the saved values: %+v", asked)
	}
	if _, err := (savedAsker{r: r, extras: []site.Field{saltField}}).Ask(context.Background(), "custom", fields); !errors.Is(err, ErrHumanChallenge) {
		t.Errorf("a captcha with nobody to ask: %v", err)
	}
}

// A record saved before the driver asked for a salt has none: it must not log in with the salt left out, or with an empty one.
func TestASavedLoginThatLacksADeclaredExtraIsRefusedAndNothingIsSent(t *testing.T) {
	r := &Record{Username: "u", Password: "p"}
	a := savedAsker{r: r, extras: []site.Field{saltField}}
	got, err := a.Ask(context.Background(), "login", []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}})
	if err == nil || got != nil {
		t.Errorf("%v %v", got, err)
	}
	r2 := &Record{Username: "u", Password: "p", Extras: map[string]string{"pepper": "x"}}
	if got, err := (savedAsker{r: r2, extras: []site.Field{saltField}}).Ask(context.Background(), "login", []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}}); err == nil || got != nil {
		t.Errorf("another extra is not the salt: %v %v", got, err)
	}
}

func TestOnlyTheDeclaredExtrasAreEverSentAndOnlyInTheLoginRound(t *testing.T) {
	r := &Record{Username: "u", Password: "p", Secret: []byte("12345678901234567890"), Extras: map[string]string{"salt": "s1", "other": "o"}}
	a := savedAsker{r: r, extras: []site.Field{saltField}}
	got, err := a.Ask(context.Background(), "login", []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}})
	if err != nil || got["salt"] != "s1" || got["other"] != "" {
		t.Errorf("a saved value the driver did not declare is not sent: %v %v", got, err)
	}
	got, err = a.Ask(context.Background(), "totp", site.TOTPFields)
	if err != nil || got["salt"] != "" || got["code"] == "" {
		t.Errorf("a one-time code round carries a code and nothing of the login: %v %v", got, err)
	}
}

func TestLoginWithExtrasTakesTheDriversDeclaredFieldsFromTheDriver(t *testing.T) {
	d := withSalt{fields: []site.Field{saltField}}
	b, _ := BindingOf(d)
	r := &Record{Site: "salted", Binding: b, Username: "u", Password: "p", Extras: map[string]string{"salt": "s1"}}
	if !r.Matches(d) {
		t.Fatal("setup")
	}
	if _, err := Login(context.Background(), d, mustURL("https://h.example"), &Record{Site: "salted", Username: "u", Password: "p"}, nil, nil); !errors.Is(err, ErrBindingChanged) {
		t.Errorf("a record without the binding of its extras is not used: %v", err)
	}
}

func mustURL(s string) *url.URL {
	u, _ := url.Parse(s)
	return u
}

// A value that was saved empty cannot be sent: validate refuses to save one, and if one is ever read the answer is an error, not an
// empty salt that the site would take for a wrong password.
func TestAnEmptySavedExtraIsNeverSentAsTheSalt(t *testing.T) {
	r := &Record{Username: "u", Password: "p", Extras: map[string]string{"salt": ""}}
	got, err := (savedAsker{r: r, extras: []site.Field{saltField}}).Ask(context.Background(), "login", []site.Field{{Name: "username"}, {Name: "password"}, {Name: "salt"}})
	if err == nil || got != nil {
		t.Errorf("%v %v", got, err)
	}
}
