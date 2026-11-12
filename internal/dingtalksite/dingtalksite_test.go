package dingtalksite

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk/dingtalktest"
	"github.com/LeafAI/securl/internal/site"
)

const (
	tok    = "c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	secret = "SECabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	hook   = "https://oapi.dingtalk.com/robot/send?access_token=" + tok
)

// asker answers the one round of the login with what it is given, as the page does, and keeps the map so that a test can see what
// the driver did to it afterwards.
type asker struct {
	vals  map[string]string
	err   error
	got   []site.Field
	mode  string
	given site.Credentials
	calls int
}

func (a *asker) Ask(_ context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	a.calls++
	a.mode, a.got = mode, fields
	if a.err != nil {
		return nil, a.err
	}
	a.given = site.Credentials{}
	for k, v := range a.vals {
		a.given[k] = v
	}
	return a.given, nil
}

func setup(groups ...config.DingTalkGroup) *Driver {
	cfg := &config.Config{}
	cfg.DingTalk.Groups = groups
	return New(cfg.DingTalkGroup, Options{})
}

func TestTheKeyOfAGroupIsDingtalkColonSlashSlashItsName(t *testing.T) {
	if BaseURL("ops").String() != "dingtalk://ops" || Key("ops") != "dingtalk://ops" {
		t.Errorf("%s %s", BaseURL("ops"), Key("ops"))
	}
}

func TestTheDriverIsNeverMatchedFromAURLSoNoToolReachesAGroupByAccident(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	for _, raw := range []string{"dingtalk://ops", hook, "https://oapi.dingtalk.com/", "http://ops"} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%s is matched: a group is chosen by name, never recognised from a URL", raw)
		}
	}
	if !d.NeedsLogin() || d.Name() != "dingtalk" {
		t.Errorf("%v %q", d.NeedsLogin(), d.Name())
	}
}

func TestLoginAsksForTheWebhookAloneOnASecretFieldWhenTheGroupHasNoSecret(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	a := &asker{vals: map[string]string{"webhook": hook}}
	s, err := d.Login(context.Background(), BaseURL("ops"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if a.mode != "custom" || len(a.got) != 1 || a.got[0].Name != "webhook" || !a.got[0].Secret {
		t.Errorf("one secret field, in custom mode: %q %+v", a.mode, a.got)
	}
	if s.Tokens[TokenWebhook] != tok || s.Tokens[TokenSecret] != "" {
		t.Errorf("only the access_token is kept, not the address: %v", s.Tokens)
	}
	if strings.Contains(strings.Join(mapValues(s.Tokens), " "), "oapi.dingtalk.com") {
		t.Errorf("the session keeps the host: %v", s.Tokens)
	}
	if a.given["webhook"] != "" {
		t.Error("the typed address is wiped from the map the page handed over")
	}
}

func TestAGroupWithASigningSecretAsksForItToo(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops", Sign: true})
	a := &asker{vals: map[string]string{"webhook": hook, "secret": secret}}
	s, err := d.Login(context.Background(), BaseURL("ops"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if len(a.got) != 2 || a.got[0].Name != "webhook" || a.got[1].Name != "secret" || !a.got[0].Secret || !a.got[1].Secret {
		t.Errorf("%+v", a.got)
	}
	if s.Tokens[TokenWebhook] != tok || s.Tokens[TokenSecret] != secret {
		t.Errorf("%v", s.Tokens)
	}
	if a.given["webhook"] != "" || a.given["secret"] != "" {
		t.Errorf("both are wiped: %v", a.given)
	}
	// without the secret it is refused, so a session that cannot sign is never made
	a2 := &asker{vals: map[string]string{"webhook": hook, "secret": ""}}
	if _, err := d.Login(context.Background(), BaseURL("ops"), a2, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a signed group needs its secret: %v", err)
	}
}

func TestAGroupWithoutAnySecretNeverAsksForOne(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	a := &asker{vals: map[string]string{"webhook": hook, "secret": secret}}
	s, _ := d.Login(context.Background(), BaseURL("ops"), a, nil)
	if s.Tokens[TokenSecret] != "" {
		t.Errorf("a secret nobody asked for is not kept: %v", s.Tokens)
	}
}

// The page's value goes through ParseWebhook, so an address that is not the robot's is refused before anything is kept or sent.
func TestAnAddressThatIsNotTheRobotEndpointIsRefusedAndNothingIsKept(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	for name, v := range map[string]string{
		"other host": "https://evil.example/robot/send?access_token=" + tok,
		"http":       "http://oapi.dingtalk.com/robot/send?access_token=" + tok,
		"empty":      "",
		"a sentence": "here you go",
		"just token": tok,
	} {
		s, err := d.Login(context.Background(), BaseURL("ops"), &asker{vals: map[string]string{"webhook": v}}, nil)
		if !errors.Is(err, site.ErrBadCredentials) || s != nil {
			t.Errorf("%s: %v %v", name, s, err)
		}
		if err != nil && (strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "evil.example")) {
			t.Errorf("%s: the refusal repeats what was typed: %v", name, err)
		}
	}
}

func TestAPageThatFailsIsTheCallersErrorAndNothingIsKept(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	boom := errors.New("rejected by the person")
	if s, err := d.Login(context.Background(), BaseURL("ops"), &asker{err: boom}, nil); !errors.Is(err, boom) || s != nil {
		t.Errorf("%v %v", s, err)
	}
}

func TestAKeyThatIsNotAConfiguredGroupIsRefusedBeforeAnyoneIsAsked(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	for _, base := range []*url.URL{BaseURL("nope"), {Scheme: "telegram", Host: "ops"}, {Scheme: "https", Host: "ops"}, nil} {
		a := &asker{vals: map[string]string{"webhook": hook}}
		if _, err := d.Login(context.Background(), base, a, nil); !errors.Is(err, site.ErrLoginRejected) {
			t.Errorf("%v: %v", base, err)
		}
		if a.calls != 0 {
			t.Errorf("%v: the person was asked", base)
		}
	}
}

// DingTalk has no call that checks a robot without posting a message, and a person typing an address must not make the group see a
// test message they did not ask for. So nothing is sent at login and nothing is probed: the first real send is what finds out.
func TestLoginSendsNothingAndProbeSendsNothingBecauseThereIsNoWayToCheckWithoutPosting(t *testing.T) {
	api := dingtalktest.New(dingtalktest.Robot{Token: tok})
	defer api.Close()
	cfg := &config.Config{}
	cfg.DingTalk.Groups = []config.DingTalkGroup{{Name: "ops"}}
	d := New(cfg.DingTalkGroup, Options{BaseURL: api.URL, HTTP: api.Client()})
	s, err := d.Login(context.Background(), BaseURL("ops"), &asker{vals: map[string]string{"webhook": hook}}, nil)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Probe(context.Background(), BaseURL("ops"), s, nil); err != nil {
		t.Errorf("a kept session is still taken to be good until a send says otherwise: %v", err)
	}
	if n := len(api.Requests()); n != 0 {
		t.Errorf("%d requests were made: a login or a probe posted something", n)
	}
}

func TestProbeRefusesASessionThatHoldsNoTokenOrBelongsToNoGroup(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	if err := d.Probe(context.Background(), BaseURL("ops"), &site.Session{Tokens: map[string]string{}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("ops"), nil, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("gone"), &site.Session{Tokens: map[string]string{TokenWebhook: tok}}, nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("a group that was removed from the configuration: %v", err)
	}
	if err := d.Probe(context.Background(), BaseURL("ops"), &site.Session{Tokens: map[string]string{TokenWebhook: tok}}, nil); err != nil {
		t.Errorf("%v", err)
	}
}

func TestAGroupThatNeedsASecretWhoseSessionLacksOneIsNotUsable(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops", Sign: true})
	if err := d.Probe(context.Background(), BaseURL("ops"), &site.Session{Tokens: map[string]string{TokenWebhook: tok}}, nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a session that cannot sign would be refused by every message: %v", err)
	}
}

func TestClientIsMadeFromTheSessionAndRefusesOneWithoutAToken(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"})
	if _, err := d.Client(nil); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if _, err := d.Client(&site.Session{Tokens: map[string]string{}}); !errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if c, err := d.Client(&site.Session{Tokens: map[string]string{TokenWebhook: tok}}); err != nil || c == nil {
		t.Errorf("%v %v", c, err)
	}
}

// The message to the person says, in securl's own words, what the address will let an agent do, and by name.
func TestTheDetailSaysWhatTheWebhookWillLetAnAgentDo(t *testing.T) {
	d := setup(config.DingTalkGroup{Name: "ops"}, config.DingTalkGroup{Name: "sec", Sign: true})
	got := d.Detail(BaseURL("ops"))
	for _, want := range []string{"ops", "vault", "send messages", "never sees", "Nothing is sent now"} {
		if !strings.Contains(got, want) {
			t.Errorf("the detail does not say %q: %s", want, got)
		}
	}
	if !strings.Contains(strings.ToLower(got), "everyone in the group") && !strings.Contains(strings.ToLower(got), "anyone in the group") {
		t.Errorf("it must say that the whole group sees it: %s", got)
	}
	if strings.Contains(got, "signing") {
		t.Errorf("a group without a secret does not mention one: %s", got)
	}
	if got := d.Detail(BaseURL("sec")); !strings.Contains(got, "signing secret") {
		t.Errorf("%s", got)
	}
	if d.Detail(BaseURL("nope")) != "" || d.Detail(nil) != "" {
		t.Error("an unknown group has no detail")
	}
}

func TestTheLabelsFitWhatThePageShowsAndNameTheGroup(t *testing.T) {
	long := strings.Repeat("a", 64)
	d := setup(config.DingTalkGroup{Name: long, Sign: true})
	a := &asker{vals: map[string]string{"webhook": hook, "secret": secret}}
	d.Login(context.Background(), BaseURL(long), a, nil)
	for _, f := range a.got {
		if n := len([]rune(f.Label)); n > 60 {
			t.Errorf("%q is %d characters, the page cuts at 60", f.Label, n)
		}
	}
	a2 := &asker{vals: map[string]string{"webhook": hook}}
	setup(config.DingTalkGroup{Name: "ops"}).Login(context.Background(), BaseURL("ops"), a2, nil)
	if !strings.Contains(a2.got[0].Label, "ops") {
		t.Errorf("the label names the group: %q", a2.got[0].Label)
	}
}

func mapValues(m map[string]string) []string {
	var out []string
	for _, v := range m {
		out = append(out, v)
	}
	return out
}
