package configcli

import (
	"os"
	"regexp"
	"strings"
	"testing"
	"time"
)

// The guided questions, in order: the server's name, its site, the bot's email, then for each channel the name an agent will call it,
// Zulip's name for it, and whether the agent may read and send; an empty name ends the list.
const guidedZulip = "team\nhttps://acme.zulipchat.com\nbot-bot@acme.zulipchat.com\ndev\nDev Team\n\n\n\n"

func TestZulipAddGuidedWritesAServerAndItsChannels(t *testing.T) {
	r := run(t, "", guidedZulip, "zulip", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	z, ok := c.ZulipServer("team")
	if !ok || len(c.Zulip) != 1 || z.Site != "https://acme.zulipchat.com" || z.Email != "bot-bot@acme.zulipchat.com" || len(z.Channels) != 1 {
		t.Fatalf("%+v", c.Zulip)
	}
	if ch, _ := z.Channel("dev"); ch.Channel != "Dev Team" || !ch.CanRead() || !ch.CanSend() {
		t.Errorf("%+v", ch)
	}
	raw, _ := os.ReadFile(r.path)
	for _, def := range []string{"send_limit", "send_window", "read_messages", "read:", "send:", "topic"} {
		if strings.Contains(string(raw), def) {
			t.Errorf("defaults are not written, and there is no topic (%s):\n%s", def, raw)
		}
	}
	for _, want := range []string{"session_open", "zulip://team", "Generic"} {
		if !strings.Contains(r.out, want) {
			t.Errorf("the output says how the key is given and which kind of bot to make (%s):\n%s", want, r.out)
		}
	}
}

func TestZulipAddGuidedWithTwoChannelsAndRestrictions(t *testing.T) {
	r := run(t, "", "team\nhttps://acme.zulipchat.com\nb@acme.zulipchat.com\ndev\nDev Team\n\n\nnews\nannounce\ny\nn\n\n", "zulip", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	z, _ := load(t, r.path).ZulipServer("team")
	n, _ := z.Channel("news")
	if len(z.Channels) != 2 || n.Channel != "announce" || !n.CanRead() || n.CanSend() {
		t.Errorf("%+v", z.Channels)
	}
}

// A key is typed by a person on a page and kept in the vault: nothing here asks for one, takes one as a flag, or writes one. And a
// topic is not set up here at all, because the agent chooses it on every call.
func TestZulipAddNeverAsksForOrTakesOrWritesAKeyOrATopic(t *testing.T) {
	r := run(t, "", guidedZulip, "zulip", "add")
	for _, prompt := range regexp.MustCompile(`(?m)^[^\n]*?(?:\[[^\]]*\])?: ?$`).FindAllString(r.out, -1) {
		l := strings.ToLower(prompt)
		for _, w := range []string{"api key", "password", "secret", "token", "topic"} {
			if strings.Contains(l, w) {
				t.Errorf("a question asks for a credential or a topic (%s): %q", w, prompt)
			}
		}
	}
	if !strings.Contains(r.out, "No key is needed here") {
		t.Errorf("it says plainly that no key is asked for:\n%s", r.out)
	}
	for _, flagName := range []string{"--key", "--api-key", "--apikey", "--password", "--secret", "--token", "--zuliprc", "--topic", "--stream", "--url", "--proxy"} {
		x := run(t, "", "", "zulip", "add", "--name", "a", "--site", "https://a.zulipchat.com", "--email", "b@a.zulipchat.com", "--channel", "c=C", flagName, "hunter2-VERY-secret")
		if x.code == 0 {
			t.Errorf("%s was accepted", flagName)
		}
		if strings.Contains(x.out+x.err, "hunter2") {
			t.Errorf("%s: the refusal repeats the value:\n%s%s", flagName, x.out, x.err)
		}
		if raw, _ := os.ReadFile(x.path); strings.Contains(string(raw), "zulip:") {
			t.Errorf("%s: a server was written although the call was refused:\n%s", flagName, raw)
		}
	}
}

func TestZulipAddByFlagsNeedsNoQuestions(t *testing.T) {
	r := run(t, "", "", "zulip", "add", "--name", "team", "--site", "https://acme.zulipchat.com", "--email", "b@acme.zulipchat.com",
		"--channel", "dev=Dev Team", "--channel", "news=announce:read", "--channel", "out=outbox:send", "--send-limit", "5", "--send-window", "2m", "--read-messages", "20")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	z, _ := load(t, r.path).ZulipServer("team")
	if z.SendLimit() != 5 || z.SendWindow() != 2*time.Minute || z.ReadMessages() != 20 || len(z.Channels) != 3 {
		t.Fatalf("%+v", z)
	}
	dev, _ := z.Channel("dev")
	news, _ := z.Channel("news")
	out, _ := z.Channel("out")
	if dev.Channel != "Dev Team" || !dev.CanRead() || !dev.CanSend() || news.CanSend() || !news.CanRead() || out.CanRead() || !out.CanSend() {
		t.Errorf("%+v %+v %+v", dev, news, out)
	}
}

func TestZulipAddByFlagsNamesWhatIsMissing(t *testing.T) {
	full := []string{"--name", "t", "--site", "https://a.zulipchat.com", "--email", "b@a.zulipchat.com", "--channel", "c=C"}
	for _, drop := range []string{"--name", "--site", "--email", "--channel"} {
		var args []string
		for i := 0; i < len(full); i += 2 {
			if full[i] != drop {
				args = append(args, full[i], full[i+1])
			}
		}
		r := run(t, "", "", append([]string{"zulip", "add"}, args...)...)
		if r.code == 0 || !strings.Contains(r.err, drop) {
			t.Errorf("without %s: exit %d: %s", drop, r.code, r.err)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "zulip:") {
			t.Errorf("without %s a server was written", drop)
		}
	}
}

// Every answer is checked with the check the configuration applies when it loads, so that the questions and the file cannot disagree.
func TestZulipAddChecksEveryAnswerWithTheConfigurationsOwnCheck(t *testing.T) {
	base := func(extra ...string) []string {
		return append([]string{"zulip", "add", "--name", "t", "--site", "https://a.zulipchat.com", "--email", "b@a.zulipchat.com", "--channel", "c=C"}, extra...)
	}
	swap := func(flag, val string) []string {
		a := base()
		for i := range a {
			if a[i] == flag {
				a[i+1] = val
			}
		}
		return a
	}
	for name, args := range map[string][]string{
		"name with a space":           swap("--name", "a b"),
		"name too long":               swap("--name", strings.Repeat("a", 65)),
		"a site over http":            swap("--site", "http://a.zulipchat.com"),
		"a site that is local":        swap("--site", "https://127.0.0.1"),
		"a site with a path":          swap("--site", "https://a.zulipchat.com/x"),
		"a site with a user":          swap("--site", "https://u:p@a.zulipchat.com"),
		"an email with a space":       swap("--email", "b @a.zulipchat.com"),
		"no @ in the email":           swap("--email", "bot"),
		"a channel with no =":         swap("--channel", "justaname"),
		"a numeric channel":           swap("--channel", "c=123"),
		"a bad channel mode":          swap("--channel", "c=C:both"),
		"a channel that does nothing": append(base(), "--channel", "x=X:read:send"),
		"the same channel twice":      append(base(), "--channel", "d=C"),
		"the same name twice":         append(base(), "--channel", "c=D"),
		"rate over the limit":         append(base(), "--send-limit", "500"),
		"negative limit":              append(base(), "--send-limit", "-1"),
		"window over a day":           append(base(), "--send-window", "48h"),
		"reading too many":            append(base(), "--read-messages", "500"),
		"unknown flag":                append(base(), "--parse-mode", "markdown"),
		"extra argument":              append(base(), "stray"),
	} {
		r := run(t, "", "", args...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
			continue
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "zulip:") {
			t.Errorf("%s: written although refused:\n%s", name, raw)
		}
	}
}

func TestZulipAddAsksBeforeReplacingAServerOfTheSameName(t *testing.T) {
	first := run(t, "", guidedZulip, "zulip", "add")
	no := run(t, first.path, "n\n", "zulip", "add", "--name", "team", "--site", "https://other.zulipchat.com", "--email", "x@other.zulipchat.com", "--channel", "z=Z")
	if no.code == 0 {
		t.Fatalf("a refused replacement ends the command: %s", no.out)
	}
	if z, _ := load(t, first.path).ZulipServer("team"); z.Site != "https://acme.zulipchat.com" {
		t.Errorf("the server was replaced although the answer was no: %+v", z)
	}
	yes := run(t, first.path, "y\n", "zulip", "add", "--name", "team", "--site", "https://other.zulipchat.com", "--email", "x@other.zulipchat.com", "--channel", "z=Z")
	if yes.code != 0 {
		t.Fatalf("%s", yes.err)
	}
	c := load(t, first.path)
	if z, _ := c.ZulipServer("team"); z.Site != "https://other.zulipchat.com" || len(c.Zulip) != 1 {
		t.Errorf("%+v", c.Zulip)
	}
}

func TestZulipListShowsServersAndChannelsAndNeverAKey(t *testing.T) {
	r := run(t, "", "", "zulip", "list")
	if r.code != 0 || !strings.Contains(r.out, "no Zulip") {
		t.Errorf("%d %s", r.code, r.out)
	}
	run(t, r.path, "", "zulip", "add", "--name", "team", "--site", "https://acme.zulipchat.com", "--email", "b@acme.zulipchat.com", "--channel", "dev=Dev Team", "--channel", "news=announce:read")
	l := run(t, r.path, "", "zulip", "list")
	for _, want := range []string{"team", "dev", "news", "Dev Team", "announce", "acme.zulipchat.com"} {
		if !strings.Contains(l.out, want) {
			t.Errorf("%q is not listed:\n%s", want, l.out)
		}
	}
	if !strings.Contains(l.out, "yes") || !strings.Contains(l.out, "no") {
		t.Errorf("read and send are shown:\n%s", l.out)
	}
}

func TestZulipRemoveForgetsAServerAndSaysWhereTheKeyIs(t *testing.T) {
	r := run(t, "", guidedZulip, "zulip", "add")
	if x := run(t, r.path, "", "zulip", "remove", "nope"); x.code == 0 || !strings.Contains(x.err, "nope") {
		t.Errorf("%d %s", x.code, x.err)
	}
	x := run(t, r.path, "", "zulip", "remove", "team")
	if x.code != 0 || !strings.Contains(x.out, "session_close") || !strings.Contains(x.out, "zulip://team") {
		t.Errorf("%d %s", x.code, x.out)
	}
	if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "zulip") {
		t.Errorf("%s", raw)
	}
	if y := run(t, r.path, "", "zulip", "remove"); y.code == 0 {
		t.Error("remove needs a name")
	}
	if y := run(t, r.path, "", "zulip"); y.code == 0 || !strings.Contains(y.err, "usage") {
		t.Errorf("%d %s", y.code, y.err)
	}
	if y := run(t, r.path, "", "zulip", "frob"); y.code == 0 {
		t.Error("an unknown subcommand")
	}
}

// Each of the two questions is about its own permission.
func TestZulipAddGuidedAsksReadAndSendSeparately(t *testing.T) {
	r := run(t, "", "team\nhttps://acme.zulipchat.com\nb@acme.zulipchat.com\nin\nInbox\nn\ny\nout\nOutbox\ny\nn\n\n", "zulip", "add")
	if r.code != 0 {
		t.Fatalf("%s\n%s", r.err, r.out)
	}
	z, _ := load(t, r.path).ZulipServer("team")
	in, _ := z.Channel("in")
	out, _ := z.Channel("out")
	if in.CanRead() || !in.CanSend() || !out.CanRead() || out.CanSend() {
		t.Errorf("%+v %+v", in, out)
	}
}

// The mode is not part of Zulip's name for the channel.
func TestZulipAddTakesTheModeOffTheChannelNameAndTheSpacesOffTheNames(t *testing.T) {
	r := run(t, "", "", "zulip", "add", "--name", "t", "--site", "https://a.zulipchat.com", "--email", "b@a.zulipchat.com",
		"--channel", " c =C Name:read", "--channel", "d=D Name:send")
	if r.code != 0 {
		t.Fatalf("%s", r.err)
	}
	z, _ := load(t, r.path).ZulipServer("t")
	c, _ := z.Channel("c")
	d, _ := z.Channel("d")
	if len(z.Channels) != 2 || c.Channel != "C Name" || d.Channel != "D Name" {
		t.Errorf("%+v", z.Channels)
	}
}

// A mistake is found before anyone is asked whether to replace a server: there is nothing to replace it with.
func TestZulipAddRefusesABadServerBeforeAskingAboutReplacingOne(t *testing.T) {
	first := run(t, "", guidedZulip, "zulip", "add")
	// the same Zulip channel under two names is wrong only when the whole server is looked at, not in any one answer
	r := run(t, first.path, "y\n", "zulip", "add", "--name", "team", "--site", "https://o.zulipchat.com", "--email", "x@o.zulipchat.com", "--channel", "z=Z", "--channel", "y=Z")
	if r.code == 0 || strings.Contains(r.out, "already exists") {
		t.Errorf("exit %d, and it must not ask:\n%s%s", r.code, r.out, r.err)
	}
}

func TestZulipRemoveTakesExactlyOneName(t *testing.T) {
	r := run(t, "", guidedZulip, "zulip", "add")
	if x := run(t, r.path, "", "zulip", "remove", "team", "extra"); x.code == 0 || !strings.Contains(x.err, "usage") {
		t.Errorf("%d %s", x.code, x.err)
	}
	if _, ok := load(t, r.path).ZulipServer("team"); !ok {
		t.Error("a refused remove removed something")
	}
}

func TestZulipListPutsReadBeforeSendUnderTheirHeadings(t *testing.T) {
	r := run(t, "", "", "zulip", "add", "--name", "team", "--site", "https://acme.zulipchat.com", "--email", "b@acme.zulipchat.com", "--channel", "news=announce:read")
	l := run(t, r.path, "", "zulip", "list")
	var head, row string
	for _, line := range strings.Split(l.out, "\n") {
		switch {
		case strings.HasPrefix(line, "SERVER"):
			head = line
		case strings.HasPrefix(line, "team"):
			row = line
		}
	}
	if !regexp.MustCompile(`READ\s+SEND$`).MatchString(head) || !regexp.MustCompile(`yes\s+no$`).MatchString(row) {
		t.Errorf("a channel that can be read and not sent to:\n%s", l.out)
	}
}
