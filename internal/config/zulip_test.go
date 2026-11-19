package config

import (
	"strings"
	"testing"
	"time"
)

const goodZulip = `
zulip:
  - name: team
    site: https://example.zulipchat.com
    email: robot-bot@example.zulipchat.com
    channels:
      - {name: general, channel: engineering}
      - {name: all-topics, channel: Dev Team, read: true, send: false}
      - {name: alerts, channel: ops, read: false}
`

func parseZ(t *testing.T, y string) (*Config, error) {
	t.Helper()
	if err := ParseStrict([]byte(y)); err != nil {
		return nil, err
	}
	c, err := Parse([]byte(y), t.TempDir())
	if err != nil {
		return nil, err
	}
	return c, c.Validate()
}

func TestAZulipServerAndItsChannelsAreReadFromTheConfiguration(t *testing.T) {
	c, err := parseZ(t, goodZulip)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Zulip) != 1 {
		t.Fatalf("%+v", c.Zulip)
	}
	z := c.Zulip[0]
	if z.Name != "team" || z.Site != "https://example.zulipchat.com" || z.Email != "robot-bot@example.zulipchat.com" || len(z.Channels) != 3 {
		t.Fatalf("%+v", z)
	}
	g, ok := z.Channel("general")
	if !ok || g.Channel != "engineering" || !g.CanRead() || !g.CanSend() {
		t.Errorf("%+v", g)
	}
	a, _ := z.Channel("all-topics")
	if a.Channel != "Dev Team" || !a.CanRead() || a.CanSend() {
		t.Errorf("a channel name may have a space, and send: false means no sending: %+v", a)
	}
	al, _ := z.Channel("alerts")
	if al.CanRead() || !al.CanSend() {
		t.Errorf("%+v", al)
	}
	if got, ok := c.ZulipServer("team"); !ok || got.Name != "team" {
		t.Errorf("%+v %v", got, ok)
	}
	if _, ok := c.ZulipServer("nope"); ok {
		t.Error("a server that is not configured was found")
	}
	if _, ok := c.ZulipServer(""); ok {
		t.Error("an empty name found a server")
	}
}

func TestOnlyANamedChannelIsFoundAndAnIdOrAnotherSpellingIsNot(t *testing.T) {
	c, _ := parseZ(t, goodZulip)
	z := c.Zulip[0]
	for _, name := range []string{"", "General", "engineering", "general ", "Dev Team", "../general"} {
		if _, ok := z.Channel(name); ok {
			t.Errorf("%q found a channel: the agent names the owner's name, exactly", name)
		}
	}
}

func TestTheDefaultsAndTheLimitsOfAZulipServer(t *testing.T) {
	c, _ := parseZ(t, goodZulip)
	z := c.Zulip[0]
	if z.SendLimit() != 20 || z.SendWindow() != time.Minute || z.ReadMessages() != 50 || z.MaxReadMessages() != 100 || z.MaxTextRunes() != 9000 {
		t.Errorf("%d %v %d %d %d", z.SendLimit(), z.SendWindow(), z.ReadMessages(), z.MaxReadMessages(), z.MaxTextRunes())
	}
	c2, err := parseZ(t, "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    send_limit: 5\n    send_window: 2m\n    read_messages: 7\n    channels: [{name: a, channel: c}]\n")
	if err != nil {
		t.Fatal(err)
	}
	z2 := c2.Zulip[0]
	if z2.SendLimit() != 5 || z2.SendWindow() != 2*time.Minute || z2.ReadMessages() != 7 {
		t.Errorf("%d %v %d", z2.SendLimit(), z2.SendWindow(), z2.ReadMessages())
	}
}

func zulipWith(extra string) string {
	return "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n" + extra + "    channels: [{name: a, channel: c}]\n"
}

func TestWhatACheckedZulipConfigurationRefuses(t *testing.T) {
	cases := map[string]struct{ y, want string }{
		"no name":                                {"zulip:\n  - site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "name"},
		"a name with a space":                    {"zulip:\n  - name: my team\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "name"},
		"the same name twice":                    {"zulip:\n  - {name: t, site: 'https://x.example.com', email: b@x.example.com, channels: [{name: a, channel: c}]}\n  - {name: t, site: 'https://y.example.com', email: b@y.example.com, channels: [{name: a, channel: c}]}\n", "used twice"},
		"no site":                                {"zulip:\n  - name: t\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "site"},
		"http site":                              {"zulip:\n  - name: t\n    site: http://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "https"},
		"a site with a path":                     {"zulip:\n  - name: t\n    site: https://x.example.com/api\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "site"},
		"a site on this host":                    {"zulip:\n  - name: t\n    site: https://127.0.0.1\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n", "machine"},
		"no email":                               {"zulip:\n  - name: t\n    site: https://x.example.com\n    channels: [{name: a, channel: c}]\n", "email"},
		"an email with a space":                  {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: 'b @x.example.com'\n    channels: [{name: a, channel: c}]\n", "email"},
		"no channels":                            {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n", "channel"},
		"a channel with no channel name":         {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a}]\n", "channel"},
		"a channel name that is a number":        {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: '123'}]\n", "channel"},
		"a channel name with a line break":       {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: \"c\\nd\"}]\n", "channel"},
		"a channel that can do nothing":          {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c, read: false, send: false}]\n", "neither"},
		"the same channel name twice":            {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}, {name: a, channel: d}]\n", "twice"},
		"a topic in the file":                    {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c, topic: x}]\n", "topic"},
		"the same zulip channel under two names": {"zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}, {name: b, channel: c}]\n", "same"},
		"a send limit over the hard one":         {zulipWith("    send_limit: 5000\n"), "send_limit"},
		"a negative send limit":                  {zulipWith("    send_limit: -1\n"), "send_limit"},
		"a window over a day":                    {zulipWith("    send_window: 48h\n"), "send_window"},
		"too many messages to read":              {zulipWith("    read_messages: 5000\n"), "read_messages"},
		"a key in the file":                      {zulipWith("    api_key: abcdef\n"), "api_key"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			_, err := parseZ(t, tc.y)
			if err == nil {
				t.Fatalf("it was accepted")
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("the error does not name the problem (%q): %v", tc.want, err)
			}
			if strings.Contains(err.Error(), "abcdef") {
				t.Errorf("the error repeats the key: %v", err)
			}
		})
	}
}

// A channel's name in Zulip is free text with spaces and non-Latin letters, and two channels may differ by case in what a person
// types, so what is checked is only what could break a request or a log line.
func TestAChannelMayBeAnyNameThatIsOneLineOfText(t *testing.T) {
	y := "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels:\n      - {name: a, channel: '开发 Team #1'}\n      - {name: b, channel: 'ops-alerts_2'}\n"
	c, err := parseZ(t, y)
	if err != nil {
		t.Fatal(err)
	}
	if g, _ := c.Zulip[0].Channel("a"); g.Channel != "开发 Team #1" {
		t.Errorf("%+v", g)
	}
}

func TestAZulipTargetIsFoundByItsOwnNameAndNeverByTheNameOfAnother(t *testing.T) {
	y := "zulip:\n  - {name: one, site: 'https://a.example.com', email: a@a.example.com, channels: [{name: x, channel: c1}]}\n  - {name: two, site: 'https://b.example.com', email: b@b.example.com, channels: [{name: x, channel: c2}]}\n"
	c, err := parseZ(t, y)
	if err != nil {
		t.Fatal(err)
	}
	one, _ := c.ZulipServer("one")
	two, _ := c.ZulipServer("two")
	if g, _ := one.Channel("x"); g.Channel != "c1" {
		t.Errorf("%+v", g)
	}
	if g, _ := two.Channel("x"); g.Channel != "c2" {
		t.Errorf("%+v", g)
	}
}

// Each address that is this machine or its network is refused on its own: the bot's key is sent to a site, and a site on the
// machine itself, or on the network behind it, is not a Zulip server but a way to reach what is there.
func TestEachAddressOnThisMachineOrItsNetworkIsRefusedOnItsOwn(t *testing.T) {
	for _, host := range []string{"localhost", "127.0.0.1", "[::1]", "10.1.2.3", "192.168.0.5", "172.16.0.9", "169.254.169.254", "0.0.0.0", "[fe80::1]"} {
		y := "zulip:\n  - name: t\n    site: https://" + host + "\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n"
		_, err := parseZ(t, y)
		if err == nil || !strings.Contains(err.Error(), "machine") {
			t.Errorf("%s: %v", host, err)
		}
	}
	for _, host := range []string{"example.zulipchat.com", "8.8.8.8", "chat.example.com:8443"} {
		y := "zulip:\n  - name: t\n    site: https://" + host + "\n    email: b@x.example.com\n    channels: [{name: a, channel: c}]\n"
		if _, err := parseZ(t, y); err != nil {
			t.Errorf("%s was refused: %v", host, err)
		}
	}
}

// The topic is not the owner's to fix: it is the conversation, and what a topic is for is that the agent says which one it means. So a
// channel is one entry whatever topics it has, and the same Zulip channel named twice is a mistake whatever the owner meant by it.
func TestAChannelIsOneEntryWhateverTopicsItHasAndTwiceIsAMistake(t *testing.T) {
	ok := "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}, {name: b, channel: d}]\n"
	if _, err := parseZ(t, ok); err != nil {
		t.Errorf("two channels: %v", err)
	}
	dup := "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c}, {name: b, channel: c}]\n"
	if _, err := parseZ(t, dup); err == nil || !strings.Contains(err.Error(), "same") {
		t.Errorf("%v", err)
	}
	if _, err := parseZ(t, "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: c, topic: x}]\n"); err == nil || !strings.Contains(err.Error(), "topic") {
		t.Errorf("a topic written in the file is an unknown key, not a setting: %v", err)
	}
}

// A channel name over Zulip's own limit is refused on its own, and so is one that runs to the limit exactly: the boundary is Zulip's.
func TestAChannelNameIsAtMostSixtyCharacters(t *testing.T) {
	at := strings.Repeat("c", 60)
	over := strings.Repeat("c", 61)
	for name, tc := range map[string]struct {
		ch string
		ok bool
	}{"at the limit": {at, true}, "over it": {over, false}, "in characters, not bytes": {strings.Repeat("开", 60), true}, "over in characters": {strings.Repeat("开", 61), false}} {
		y := "zulip:\n  - name: t\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: a, channel: '" + tc.ch + "'}]\n"
		_, err := parseZ(t, y)
		if (err == nil) != tc.ok {
			t.Errorf("%s: %v", name, err)
		}
	}
}

// What the agent names is found by the exact name and by nothing shorter, so a name that starts like another does not reach it, and
// nothing is found by an empty name.
func TestAChannelAndAServerAreFoundOnlyByTheirWholeName(t *testing.T) {
	y := "zulip:\n  - name: team\n    site: https://x.example.com\n    email: b@x.example.com\n    channels: [{name: general, channel: c}]\n"
	c, err := parseZ(t, y)
	if err != nil {
		t.Fatal(err)
	}
	z := c.Zulip[0]
	for _, n := range []string{"gen", "g", "general2", "eneral", ""} {
		if _, ok := z.Channel(n); ok {
			t.Errorf("the channel %q was found", n)
		}
	}
	for _, n := range []string{"tea", "t", "team2", "eam", ""} {
		if _, ok := c.ZulipServer(n); ok {
			t.Errorf("the server %q was found", n)
		}
	}
	if _, ok := (Zulip{Channels: []ZulipChannel{{Name: ""}}}).Channel(""); ok {
		t.Error("a channel with no name was found by an empty name")
	}
	if _, ok := (&Config{Zulip: []Zulip{{Name: ""}}}).ZulipServer(""); ok {
		t.Error("a server with no name was found by an empty name")
	}
}

func TestWhatAnAgentMayUseAsATopic(t *testing.T) {
	ok := []string{"x", "deploy notes", "周报 / week 3", strings.Repeat("好", 60), "a  b"}
	for _, s := range ok {
		if err := ValidZulipTopic(s); err != nil {
			t.Errorf("%q: %v", s, err)
		}
	}
	bad := map[string]string{
		"empty":            "",
		"blank":            "   ",
		"a tab only":       "\t",
		"61 characters":    strings.Repeat("a", 61),
		"61 wide":          strings.Repeat("好", 61),
		"a line break":     "a\nb",
		"a carriage":       "a\rb",
		"a line separator": "a\u2028b",
		"a null":           "a\x00b",
		"a leading space":  " a",
		"a trailing space": "a ",
	}
	for n, s := range bad {
		if err := ValidZulipTopic(s); err == nil {
			t.Errorf("%s was accepted", n)
		}
	}
}
