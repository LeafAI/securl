package configcli

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

const tgToken = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"

// The guided questions, in order: the bot's name, then each chat (its name and its id) until a blank name, then for each chat whether
// the agent may read it and whether it may send to it.
const guidedBot = "ops\nalerts\n-1001234567890\n\n\n\n"

func TestTelegramAddGuidedWritesABotAndItsChats(t *testing.T) {
	r := run(t, "", guidedBot, "telegram", "add")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	if len(c.Telegram.Bots) != 1 || c.Telegram.Bots[0].Name != "ops" || len(c.Telegram.Bots[0].Chats) != 1 {
		t.Fatalf("%+v", c.Telegram)
	}
	ch := c.Telegram.Bots[0].Chats[0]
	if ch.Name != "alerts" || ch.ChatID != -1001234567890 || !ch.CanRead() || !ch.CanSend() {
		t.Errorf("%+v", ch)
	}
	raw, _ := os.ReadFile(r.path)
	for _, def := range []string{"send_limit", "read_messages", "send_window", "read: true", "send: true"} {
		if strings.Contains(string(raw), def) {
			t.Errorf("defaults are not written (%s):\n%s", def, raw)
		}
	}
	if !strings.Contains(r.out, "session_open") || !strings.Contains(r.out, "telegram://ops") {
		t.Errorf("the output says how the token is given:\n%s", r.out)
	}
}

// A bot token is typed by a person on a page and kept in the vault: nothing here asks for one, takes one as a flag, or writes one.
func TestTelegramAddNeverAsksForOrTakesOrWritesAToken(t *testing.T) {
	r := run(t, "", guidedBot, "telegram", "add")
	// A question is where the answer is typed: the prompt ends the line ("label: " or "label [default]: "), and what follows it on
	// the same line is the answer. A sentence that only mentions a token is not a question.
	for _, prompt := range regexp.MustCompile(`(?m)^[^\n]*?(?:\[[^\]]*\])?: ?$`).FindAllString(r.out, -1) {
		l := strings.ToLower(prompt)
		if strings.Contains(l, "token") || strings.Contains(l, "password") || strings.Contains(l, "secret") {
			t.Errorf("a question asks for a token: %q", prompt)
		}
	}
	if !strings.Contains(r.out, "No token is needed here") {
		t.Errorf("it says plainly that no token is asked for:\n%s", r.out)
	}
	for _, flagName := range []string{"--token", "--bot-token", "--secret", "--password"} {
		// with a valid chat too, so that the only thing wrong is the flag: a flag that exists would make this a success
		r := run(t, "", "", "telegram", "add", "--name", "ops", "--chat", "a=1", flagName, tgToken)
		if r.code == 0 {
			t.Errorf("%s was accepted", flagName)
		}
		if strings.Contains(r.out+r.err, "AAH-SECRET") || strings.Contains(r.out+r.err, tgToken) {
			t.Errorf("%s: the refusal repeats the token:\n%s%s", flagName, r.out, r.err)
		}
		if raw, _ := os.ReadFile(r.path); strings.Contains(string(raw), "telegram:") {
			t.Errorf("%s: a bot was written although the call was refused:\n%s", flagName, raw)
		}
	}
	raw, _ := os.ReadFile(r.path)
	if strings.Contains(string(raw), "token") {
		t.Errorf("the file holds a token:\n%s", raw)
	}
}

// Each way a --chat can be wrong is refused by the flag's own check, with the flag named and without repeating more than a short
// piece of what was typed. (The save step checks again with the same rules; this is the first line, which says what to fix.)
func TestEachWayAChatFlagCanBeWrongIsNamedByTheFlagItself(t *testing.T) {
	long := strings.Repeat("x", 200)
	for spec, want := range map[string]string{
		"alerts":         "name=chat_id",
		"alerts=0":       "chat id",
		"alerts=abc":     "chat id",
		"alerts=":        "chat id",
		"alerts=1:write": ":read or :send",
		long:             "name=chat_id",
	} {
		_, err := parseChatSpec(spec)
		if err == nil || !strings.Contains(err.Error(), want) {
			t.Errorf("%q: want an error about %q, got %v", spec[:min(len(spec), 20)], want, err)
			continue
		}
		if len(err.Error()) > 200 {
			t.Errorf("the error repeats what was typed in full (%d characters)", len(err.Error()))
		}
	}
	if c, err := parseChatSpec("a=-100"); err != nil || c.ChatID != -100 {
		t.Errorf("%+v %v", c, err)
	}
}

func TestTelegramAddByFlagsNeedsNoQuestionsAndTakesSeveralChats(t *testing.T) {
	r := run(t, "", "", "telegram", "add", "--name", "ops", "--chat", "alerts=-1001234567890", "--chat", "dev=-1009876543210:send",
		"--chat", "me=123456789:read")
	if r.code != 0 {
		t.Fatalf("exit %d: %s\n%s", r.code, r.err, r.out)
	}
	c := load(t, r.path)
	got := c.Telegram.Bots[0].Chats
	if len(got) != 3 {
		t.Fatalf("%+v", got)
	}
	if !got[0].CanRead() || !got[0].CanSend() {
		t.Errorf("both by default: %+v", got[0])
	}
	if got[1].CanRead() || !got[1].CanSend() {
		t.Errorf(":send is send only: %+v", got[1])
	}
	if !got[2].CanRead() || got[2].CanSend() {
		t.Errorf(":read is read only: %+v", got[2])
	}
}

func TestTelegramAddChecksEveryAnswerWithTheCheckTheConfigurationApplies(t *testing.T) {
	for name, args := range map[string][]string{
		"bad bot name":    {"--name", "a b", "--chat", "x=1"},
		"no chat":         {"--name", "ops"},
		"chat without id": {"--name", "ops", "--chat", "x"},
		"chat id zero":    {"--name", "ops", "--chat", "x=0"},
		"chat id text":    {"--name", "ops", "--chat", "x=abc"},
		"bad mode":        {"--name", "ops", "--chat", "x=1:write"},
		"same name twice": {"--name", "ops", "--chat", "x=1", "--chat", "x=2"},
		"same id twice":   {"--name", "ops", "--chat", "x=1", "--chat", "y=1"},
		"limit too high":  {"--name", "ops", "--chat", "x=1", "--send-limit", "100000"},
		"read too many":   {"--name", "ops", "--chat", "x=1", "--read-messages", "1000"},
		"unknown flag":    {"--name", "ops", "--chat", "x=1", "--bogus", "1"},
	} {
		r := run(t, "", "", append([]string{"telegram", "add"}, args...)...)
		if r.code == 0 {
			t.Errorf("%s: accepted", name)
			continue
		}
		if raw, _ := os.ReadFile(r.path); len(raw) > 0 && strings.Contains(string(raw), "telegram:") {
			t.Errorf("%s: a refused bot reached the file:\n%s", name, raw)
		}
	}
}

func TestTelegramAddReplacesABotOfTheSameNameOnlyAfterAsking(t *testing.T) {
	r := run(t, "", "", "telegram", "add", "--name", "ops", "--chat", "a=1")
	r2 := run(t, r.path, "n\n", "telegram", "add", "--name", "ops", "--chat", "b=2")
	if r2.code == 0 {
		t.Error("declining the replacement is not a success")
	}
	if c := load(t, r.path); c.Telegram.Bots[0].Chats[0].Name != "a" {
		t.Errorf("the bot was replaced after the answer was no: %+v", c.Telegram.Bots)
	}
	r3 := run(t, r.path, "y\n", "telegram", "add", "--name", "ops", "--chat", "b=2")
	if r3.code != 0 {
		t.Fatalf("%s", r3.err)
	}
	if c := load(t, r.path); len(c.Telegram.Bots) != 1 || c.Telegram.Bots[0].Chats[0].Name != "b" {
		t.Errorf("replaced: %+v", c.Telegram.Bots)
	}
}

func TestTelegramListShowsBotsAndChatsByNameWithWhatEachAllowsAndNothingSecret(t *testing.T) {
	r := run(t, "", "", "telegram", "add", "--name", "ops", "--chat", "alerts=-1001234567890", "--chat", "me=123:read")
	l := run(t, r.path, "", "telegram", "list")
	if l.code != 0 {
		t.Fatal(l.err)
	}
	for _, want := range []string{"ops", "alerts", "me", "READ", "SEND"} {
		if !strings.Contains(l.out, want) {
			t.Errorf("%q missing:\n%s", want, l.out)
		}
	}
	empty := run(t, "", "", "telegram", "list")
	if !strings.Contains(empty.out, "telegram add") {
		t.Errorf("an empty list says how to add one:\n%s", empty.out)
	}
}

func TestTelegramRemoveForgetsABotAndSaysTheTokenStaysUntilItIsClosed(t *testing.T) {
	r := run(t, "", "", "telegram", "add", "--name", "ops", "--chat", "a=1")
	if x := run(t, r.path, "", "telegram", "remove", "nope"); x.code == 0 {
		t.Error("a bot that does not exist")
	}
	x := run(t, r.path, "", "telegram", "remove", "ops")
	if x.code != 0 {
		t.Fatal(x.err)
	}
	if c := load(t, r.path); len(c.Telegram.Bots) != 0 {
		t.Errorf("%+v", c.Telegram)
	}
	if !strings.Contains(x.out, "session_close") || !strings.Contains(x.out, "telegram://ops") {
		t.Errorf("a token saved for it stays in the vault until it is closed:\n%s", x.out)
	}
}

func TestTelegramProxyIsSetLikeAnyOtherSettingAndNotEchoed(t *testing.T) {
	r := run(t, "", "", "set", "telegram.proxy", "http://user:pa55word@127.0.0.1:1080")
	if r.code != 0 {
		t.Fatal(r.err)
	}
	g := run(t, r.path, "", "get", "telegram.proxy")
	if strings.Contains(g.out, "pa55word") {
		t.Errorf("config get echoes the proxy's credential: %q", g.out)
	}
	s := run(t, r.path, "", "show")
	if strings.Contains(s.out, "pa55word") {
		t.Errorf("config show echoes it:\n%s", s.out)
	}
	if rv := run(t, r.path, "", "get", "telegram.proxy", "-reveal"); !strings.Contains(rv.out, "pa55word") {
		t.Errorf("-reveal shows it, as it does for the other secrets: %q", rv.out)
	}
}

func TestTheUsageListsTheTelegramCommands(t *testing.T) {
	r := run(t, "", "", "bogus")
	if !strings.Contains(r.err+r.out, "telegram") {
		t.Errorf("%s%s", r.err, r.out)
	}
}
