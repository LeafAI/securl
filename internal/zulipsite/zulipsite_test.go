package zulipsite

import (
	"context"
	"errors"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/zulip/zulipfake"
)

const (
	email = "robot-bot@example.invalid"
	key   = "k3y-SECRET-0123456789abcdefghijklmnopqrstu"
)

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

func setup(t *testing.T) (*zulipfake.Server, *Driver) {
	t.Helper()
	s := zulipfake.New(zulipfake.Bot{Email: email, Key: key, ID: 77, Name: "Robot", Channels: map[string]bool{"engineering": true, "ops": true}})
	t.Cleanup(s.Close)
	cfg := &config.Config{Zulip: []config.Zulip{{Name: "team", Site: s.URL, Email: email, Channels: []config.ZulipChannel{
		{Name: "general", Channel: "engineering"}, {Name: "alerts", Channel: "ops", Send: boolp(false)},
	}}}}
	return s, New(cfg.ZulipServer, Options{HTTP: s.Client(), AllowInsecure: true})
}

func boolp(b bool) *bool { return &b }

func login(d *Driver, k string) (*site.Session, error) {
	return d.Login(context.Background(), BaseURL("team"), &asker{vals: map[string]string{TokenKey: k}}, nil)
}

func TestTheKeyOfAServerIsZulipColonSlashSlashItsName(t *testing.T) {
	if BaseURL("team").String() != "zulip://team" || Key("team") != "zulip://team" {
		t.Errorf("%s %s", BaseURL("team"), Key("team"))
	}
}

func TestTheDriverIsNeverMatchedFromAURLSoNoToolReachesAServerByAccident(t *testing.T) {
	_, d := setup(t)
	for _, raw := range []string{"zulip://team", "http://team", "https://example.zulipchat.com/", "tcp://127.0.0.1:9"} {
		u, _ := url.Parse(raw)
		if d.Match(u) {
			t.Errorf("%s is matched: a server is chosen by name, never recognised from a URL", raw)
		}
	}
	if !d.NeedsLogin() || d.Name() != "zulip" {
		t.Errorf("%v %q", d.NeedsLogin(), d.Name())
	}
}

func TestLoginAsksForTheKeyAloneHiddenAndChecksItWithTheServer(t *testing.T) {
	s, d := setup(t)
	a := &asker{vals: map[string]string{TokenKey: "  " + key + "  "}}
	sess, err := d.Login(context.Background(), BaseURL("team"), a, nil)
	if err != nil {
		t.Fatal(err)
	}
	if sess.Tokens[TokenKey] != key || sess.Tokens[TokenName] != "Robot" {
		t.Errorf("%v", sess.Tokens)
	}
	if len(a.got) != 1 || !a.got[0].Secret || a.got[0].Name != TokenKey || len([]rune(a.got[0].Label)) > 60 || !strings.Contains(a.got[0].Label, "team") {
		t.Errorf("%+v", a.got)
	}
	if a.mode != "custom" {
		t.Errorf("mode %q", a.mode)
	}
	if a.given[TokenKey] != "" {
		t.Errorf("what was typed is left in the answer: %v", a.given)
	}
	if s.Calls["GET /api/v1/users/me"] != 1 {
		t.Errorf("the key was checked %d times", s.Calls["GET /api/v1/users/me"])
	}
}

// The email is the bot's own and is in the configuration, so the person types only the key: what they could be tricked into pasting
// somewhere else is one value, and it goes to the one site the owner wrote down.
func TestLoginSendsTheKeyOnlyToTheConfiguredSiteWithTheConfiguredEmail(t *testing.T) {
	s, d := setup(t)
	login(d, key)
	if len(s.Auths()) != 1 || !strings.HasPrefix(s.Auths()[0], "Basic ") {
		t.Errorf("%v", s.Auths())
	}
}

func TestLoginTellsApartWhatWentWrongAndNeverRepeatsTheKey(t *testing.T) {
	_, d := setup(t)
	cases := []struct {
		name, key string
		want      error
		say       string
	}{
		{"the wrong key", "wrong-wrong-wrong-wrong-wrong-wrong-xx", site.ErrBadCredentials, "refused that key"},
		{"nothing typed", "", site.ErrBadCredentials, "not a bot's key"},
		{"too short", "abc", site.ErrBadCredentials, "not a bot's key"},
		{"a sentence", "this is not a key at all, it has spaces in it", site.ErrBadCredentials, "not a bot's key"},
		{"a line break", "abcdefghijklmnopqrstuvwxyz0123456789\nabc", site.ErrBadCredentials, "not a bot's key"},
		{"a URL", "https://example.zulipchat.com/api/v1/messages", site.ErrBadCredentials, "not a bot's key"},
		{"too long", strings.Repeat("a", 300), site.ErrBadCredentials, "not a bot's key"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			_, err := login(d, tc.key)
			if !errors.Is(err, tc.want) || !strings.Contains(err.Error(), tc.say) {
				t.Fatalf("%v", err)
			}
			if tc.key != "" && strings.Contains(err.Error(), tc.key) {
				t.Errorf("the error repeats what was typed: %v", err)
			}
		})
	}
}

func TestLoginRefusesWhatCannotBeAKeyBeforeAskingTheServer(t *testing.T) {
	s, d := setup(t)
	for _, k := range []string{"", "abc", "has space in it 0123456789012345678901", strings.Repeat("a", 300), "line\nbreak0123456789012345678901234567"} {
		login(d, k)
	}
	if n := len(s.Auths()); n != 0 {
		t.Errorf("the server was asked %d times about things that cannot be keys", n)
	}
}

func TestAnAskerThatFailsEndsTheLoginAsItIs(t *testing.T) {
	_, d := setup(t)
	boom := errors.New("closed")
	if _, err := d.Login(context.Background(), BaseURL("team"), &asker{err: boom}, nil); !errors.Is(err, boom) {
		t.Errorf("%v", err)
	}
}

func TestAnUnknownServerAndAForeignKeyAreRefusedAndNobodyIsAsked(t *testing.T) {
	_, d := setup(t)
	for _, u := range []*url.URL{BaseURL("other"), {Scheme: "telegram", Host: "team"}, nil} {
		a := &asker{vals: map[string]string{TokenKey: key}}
		if _, err := d.Login(context.Background(), u, a, nil); !errors.Is(err, site.ErrLoginRejected) || a.calls != 0 {
			t.Errorf("%v: %v (asked %d times)", u, err, a.calls)
		}
		if d.Detail(u) != "" {
			t.Errorf("a detail for %v", u)
		}
	}
}

func TestAnUnreachableServerIsToldAsSuchAndNotAsAWrongKey(t *testing.T) {
	s, d := setup(t)
	s.Close()
	_, err := login(d, key)
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) || !strings.Contains(err.Error(), "could not be reached") {
		t.Errorf("%v", err)
	}
	if strings.Contains(err.Error(), key) || strings.Contains(err.Error(), s.URL) {
		t.Errorf("%v", err)
	}
}

func TestADetailSaysWhatTheKeyLetsAnAgentDoAndInWhichChannels(t *testing.T) {
	_, d := setup(t)
	got := d.Detail(BaseURL("team"))
	for _, want := range []string{"team", "never sees", "send", "general", "read", "general, alerts", "Anyone"} {
		if !strings.Contains(got, want) {
			t.Errorf("%q is not said: %s", want, got)
		}
	}
	if strings.Contains(got, "engineering") || strings.Contains(got, email) {
		t.Errorf("a name the owner chose for the agent is said, not the Zulip channel or email: %s", got)
	}
}

func TestProbeKeepsTheSessionWhenTheNetworkIsDownAndEndsItWhenTheKeyIsRevoked(t *testing.T) {
	s, d := setup(t)
	sess, err := login(d, key)
	if err != nil {
		t.Fatal(err)
	}
	if err := d.Probe(context.Background(), BaseURL("team"), sess, nil); err != nil {
		t.Errorf("a good session is probed bad: %v", err)
	}
	for _, empty := range []*site.Session{nil, {}, {Tokens: map[string]string{}}} {
		if err := d.Probe(context.Background(), BaseURL("team"), empty, nil); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%+v: %v", empty, err)
		}
	}
	if err := d.Probe(context.Background(), BaseURL("other"), sess, nil); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("%v", err)
	}
	s.Revoke(email)
	if err := d.Probe(context.Background(), BaseURL("team"), sess, nil); !errors.Is(err, site.ErrBadCredentials) || errors.Is(err, site.ErrUnreachable) {
		t.Errorf("a revoked key: %v", err)
	}
	s.Close()
	good := &site.Session{Tokens: map[string]string{TokenKey: key}}
	err = d.Probe(context.Background(), BaseURL("team"), good, nil)
	if !errors.Is(err, site.ErrUnreachable) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("a server that is down is not a key that is wrong: %v", err)
	}
}

func TestTheClientOfASessionIsMadeFromTheKeptKeyAndTheConfiguredSite(t *testing.T) {
	_, d := setup(t)
	sess, _ := login(d, key)
	c, z, err := d.Client(BaseURL("team"), sess)
	if err != nil || c == nil || z.Name != "team" {
		t.Fatalf("%v %v %+v", c, err, z)
	}
	if _, err := c.Me(context.Background()); err != nil {
		t.Errorf("%v", err)
	}
	for _, bad := range []*site.Session{nil, {}, {Tokens: map[string]string{}}, {Tokens: map[string]string{TokenKey: ""}}} {
		if _, _, err := d.Client(BaseURL("team"), bad); !errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%+v: %v", bad, err)
		}
	}
	if _, _, err := d.Client(BaseURL("other"), sess); !errors.Is(err, site.ErrLoginRejected) {
		t.Errorf("%v", err)
	}
}

func TestALongServerNameStillFitsTheLabelOfThePage(t *testing.T) {
	long := strings.Repeat("n", 64)
	s := zulipfake.New(zulipfake.Bot{Email: email, Key: key, ID: 1, Name: "R", Channels: map[string]bool{"c": true}})
	defer s.Close()
	cfg := &config.Config{Zulip: []config.Zulip{{Name: long, Site: s.URL, Email: email, Channels: []config.ZulipChannel{{Name: "a", Channel: "c"}}}}}
	d := New(cfg.ZulipServer, Options{HTTP: s.Client(), AllowInsecure: true})
	a := &asker{vals: map[string]string{TokenKey: key}}
	if _, err := d.Login(context.Background(), BaseURL(long), a, nil); err != nil {
		t.Fatal(err)
	}
	if n := len([]rune(a.got[0].Label)); n > 60 || n < 20 {
		t.Errorf("the label is %d characters: %q", n, a.got[0].Label)
	}
}

// Each character that can break a header or a path is refused on its own: a key is sent as the password of an HTTP Basic header, where a
// colon would end the user name, and a slash or a non-ASCII letter is never part of one.
func TestEachCharacterThatCannotBePartOfAKeyIsRefusedOnItsOwn(t *testing.T) {
	good := strings.Repeat("a", 32)
	for name, k := range map[string]string{"slash": good[:16] + "/" + good[16:], "colon": good[:16] + ":" + good[16:], "non-ascii": good[:16] + "é" + good[16:], "emoji": good[:16] + "🙂" + good[16:], "tab": good[:16] + "\t" + good[16:], "nul": good[:16] + "\x00" + good[16:]} {
		if keyShape(k) {
			t.Errorf("%s is accepted in a key", name)
		}
	}
	for _, k := range []string{good, strings.Repeat("Ab3_-", 8), strings.Repeat("a", minKeyRunes), strings.Repeat("a", maxKeyRunes)} {
		if !keyShape(k) {
			t.Errorf("%q was refused", k)
		}
	}
	if keyShape(strings.Repeat("a", minKeyRunes-1)) || keyShape(strings.Repeat("a", maxKeyRunes+1)) {
		t.Error("the length bounds are off by one")
	}
}

// The product reaches only a site over https: the test's fake is http:// on this machine, and it is reached only because the test says
// so. Without that the same configured site is refused, whatever the configuration says.
func TestWithoutTheTestSwitchAnHTTPSiteIsNotReachedAtAll(t *testing.T) {
	s, _ := setup(t)
	cfg := &config.Config{Zulip: []config.Zulip{{Name: "team", Site: s.URL, Email: email, Channels: []config.ZulipChannel{{Name: "a", Channel: "c"}}}}}
	d := New(cfg.ZulipServer, Options{HTTP: s.Client()})
	_, err := login(d, key)
	if err == nil || errors.Is(err, site.ErrBadCredentials) {
		t.Fatalf("an http site on this machine was used: %v", err)
	}
	if n := len(s.Auths()); n != 0 {
		t.Errorf("the server was asked %d times with the key", n)
	}
	if _, _, err := d.Client(BaseURL("team"), &site.Session{Tokens: map[string]string{TokenKey: key}}); err == nil {
		t.Error("a client was made for an http site")
	}
}

// What Detail says about sending is said only about the channels that can be sent to, and about reading only of the ones that can be read.
func TestDetailNamesTheChannelsThatCanBeSentToApartFromTheOnesThatCanBeRead(t *testing.T) {
	_, d := setup(t) // general: both; alerts: read only
	got := d.Detail(BaseURL("team"))
	send := got[strings.Index(got, "send messages to ")+len("send messages to "):]
	send = send[:strings.Index(send, " and it can read")]
	if send != "general" {
		t.Errorf("the channels it can send to: %q in: %s", send, got)
	}
	read := got[strings.Index(got, "what is said in ")+len("what is said in "):]
	read = read[:strings.Index(read, ".")]
	if read != "general, alerts" {
		t.Errorf("the channels it can read: %q in: %s", read, got)
	}
	cfg := &config.Config{Zulip: []config.Zulip{{Name: "ro", Site: "https://x.example.com", Email: email, Channels: []config.ZulipChannel{{Name: "a", Channel: "c", Send: boolp(false)}}}}}
	only := New(cfg.ZulipServer, Options{}).Detail(BaseURL("ro"))
	if strings.Contains(only, "send messages") || !strings.Contains(only, ": it can read what is said in a") {
		t.Errorf("a server that cannot be sent to does not say it can: %s", only)
	}
}

// A server that is unknown is refused in Probe by the probe itself and not only by what it calls: a probe of a server that is not
// configured never asks anything of the network.
func TestAProbeOfAServerThatIsNotConfiguredAsksNothing(t *testing.T) {
	s, d := setup(t)
	err := d.Probe(context.Background(), BaseURL("ghost"), &site.Session{Tokens: map[string]string{TokenKey: key}}, nil)
	if !errors.Is(err, site.ErrLoginRejected) || errors.Is(err, site.ErrBadCredentials) {
		t.Errorf("%v", err)
	}
	if len(s.Auths()) != 0 {
		t.Errorf("the network was asked")
	}
}

// A server that is not configured is said to be so before anything is said of the session: with nothing kept either, the answer is that
// the server is not configured, which is what the person has to fix first, and not that a key is missing.
func TestAProbeOfAServerThatIsNotConfiguredSaysSoBeforeItSaysTheSessionIsEmpty(t *testing.T) {
	_, d := setup(t)
	for _, empty := range []*site.Session{nil, {}, {Tokens: map[string]string{}}} {
		err := d.Probe(context.Background(), BaseURL("ghost"), empty, nil)
		if !errors.Is(err, site.ErrLoginRejected) || errors.Is(err, site.ErrBadCredentials) {
			t.Errorf("%+v: %v", empty, err)
		}
	}
}
