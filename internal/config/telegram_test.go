package config

import (
	"strings"
	"testing"
	"time"
)

const goodTelegram = `
telegram:
  proxy: http://127.0.0.1:1080
  bots:
    - name: ops
      chats:
        - {name: alerts, chat_id: -1001234567890}
        - {name: dev, chat_id: -1009876543210, read: false}
        - {name: me, chat_id: 123456789, send: false}
`

func parseTG(t *testing.T, y string) (*Config, error) {
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

func TestATelegramBotAndItsChatsAreReadFromTheConfiguration(t *testing.T) {
	c, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Telegram.Bots) != 1 || c.Telegram.Proxy != "http://127.0.0.1:1080" {
		t.Fatalf("%+v", c.Telegram)
	}
	b := c.Telegram.Bots[0]
	if b.Name != "ops" || len(b.Chats) != 3 {
		t.Fatalf("%+v", b)
	}
	if b.Chats[0].ChatID != -1001234567890 || b.Chats[0].Name != "alerts" {
		t.Errorf("%+v", b.Chats[0])
	}
}

// Reading is on by default (the owner asked for it) and sending too; each is switched off by saying so, per chat.
func TestAChatCanBeReadAndSentToUnlessItSaysOtherwise(t *testing.T) {
	c, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	b := c.Telegram.Bots[0]
	if !b.Chats[0].CanRead() || !b.Chats[0].CanSend() {
		t.Errorf("the default is read and send: %+v", b.Chats[0])
	}
	if b.Chats[1].CanRead() || !b.Chats[1].CanSend() {
		t.Errorf("read: false switches reading off and leaves sending: %+v", b.Chats[1])
	}
	if !b.Chats[2].CanRead() || b.Chats[2].CanSend() {
		t.Errorf("send: false switches sending off and leaves reading: %+v", b.Chats[2])
	}
}

func TestTheTelegramLimitsHaveDefaultsAndCeilings(t *testing.T) {
	c, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	b := c.Telegram.Bots[0]
	if b.SendLimit() != 20 || b.SendWindow() != time.Minute {
		t.Errorf("default: %d per %s", b.SendLimit(), b.SendWindow())
	}
	if b.ReadMessages() != 50 || b.MaxReadMessages() != 100 {
		t.Errorf("read: %d of at most %d", b.ReadMessages(), b.MaxReadMessages())
	}
	if b.MaxTextRunes() != 4000 {
		t.Errorf("a message holds at most %d characters (Telegram's limit is 4096, and the header takes some)", b.MaxTextRunes())
	}
}

func TestNoTelegramConfigurationMeansNoTelegram(t *testing.T) {
	c, err := parseTG(t, "dingtalk:\n  webhook: \"https://oapi.dingtalk.com/robot/send?access_token=x\"\n")
	if err != nil {
		t.Fatal(err)
	}
	if len(c.Telegram.Bots) != 0 || c.Telegram.Proxy != "" {
		t.Errorf("%+v", c.Telegram)
	}
	if _, ok := c.TelegramBot("ops"); ok {
		t.Error("there is no bot")
	}
}

func TestABotAndItsChatsAreFoundByExactName(t *testing.T) {
	c, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	b, ok := c.TelegramBot("ops")
	if !ok || b.Name != "ops" {
		t.Fatalf("%+v %v", b, ok)
	}
	for _, bad := range []string{"", "OPS", "ops ", "o", "ops/alerts"} {
		if _, ok := c.TelegramBot(bad); ok {
			t.Errorf("%q is not a bot", bad)
		}
	}
	ch, ok := b.Chat("alerts")
	if !ok || ch.ChatID != -1001234567890 {
		t.Errorf("%+v %v", ch, ok)
	}
	for _, bad := range []string{"", "Alerts", "-1001234567890", "alerts "} {
		if _, ok := b.Chat(bad); ok {
			t.Errorf("%q must not be a chat: the agent names a chat, it never supplies an id", bad)
		}
	}
}

func TestTelegramConfigurationErrorsSayWhatToChange(t *testing.T) {
	bot := func(rest string) string { return "telegram:\n  bots:\n    - name: ops\n" + rest }
	chat := func(c string) string { return bot("      chats:\n        - " + c + "\n") }
	for name, tc := range map[string]struct{ yaml, want string }{
		"no name":               {"telegram:\n  bots:\n    - chats: [{name: a, chat_id: 1}]\n", "name"},
		"bad bot name":          {"telegram:\n  bots:\n    - name: 'a b'\n      chats: [{name: a, chat_id: 1}]\n", "name"},
		"duplicate bot":         {"telegram:\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n    - {name: ops, chats: [{name: b, chat_id: 2}]}\n", "twice"},
		"no chats":              {bot("      chats: []\n"), "chat"},
		"chat without name":     {chat("{chat_id: 1}"), "name"},
		"chat without id":       {chat("{name: a}"), "chat_id"},
		"zero id":               {chat("{name: a, chat_id: 0}"), "chat_id"},
		"duplicate chat":        {bot("      chats:\n        - {name: a, chat_id: 1}\n        - {name: a, chat_id: 2}\n"), "twice"},
		"same id twice":         {bot("      chats:\n        - {name: a, chat_id: 1}\n        - {name: b, chat_id: 1}\n"), "same"},
		"neither read nor send": {chat("{name: a, chat_id: 1, read: false, send: false}"), "neither"},
		"send limit zero":       {bot("      send_limit: -1\n      chats: [{name: a, chat_id: 1}]\n"), "send_limit"},
		"send limit huge":       {bot("      send_limit: 100000\n      chats: [{name: a, chat_id: 1}]\n"), "send_limit"},
		"read more than max":    {bot("      read_messages: 1000\n      chats: [{name: a, chat_id: 1}]\n"), "read_messages"},
		"proxy not a url":       {"telegram:\n  proxy: 'not a url'\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n", "proxy"},
		"proxy bad scheme":      {"telegram:\n  proxy: ftp://127.0.0.1:1080\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n", "proxy"},
		"proxy with a path":     {"telegram:\n  proxy: http://127.0.0.1:1080/x\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n", "proxy"},
	} {
		t.Run(name, func(t *testing.T) {
			_, err := parseTG(t, tc.yaml)
			if err == nil {
				t.Fatalf("accepted:\n%s", tc.yaml)
			}
			if !strings.Contains(strings.ToLower(err.Error()), tc.want) {
				t.Errorf("the error does not name %q: %v", tc.want, err)
			}
		})
	}
}

// The bot token is never in the configuration: a person types it on a page and it goes to the vault. A file that has one is
// refused, and the refusal does not repeat it.
func TestAConfigurationThatHoldsABotTokenIsRefusedWithoutEchoingIt(t *testing.T) {
	const tok = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"
	for _, y := range []string{
		"telegram:\n  bots:\n    - {name: ops, token: " + tok + ", chats: [{name: a, chat_id: 1}]}\n",
		"telegram:\n  bots:\n    - {name: ops, bot_token: " + tok + ", chats: [{name: a, chat_id: 1}]}\n",
	} {
		err := ParseStrict([]byte(y))
		if err == nil {
			t.Fatalf("a token in the file was accepted:\n%s", y)
		}
		if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "AAH-SECRET") {
			t.Errorf("the error repeats the token: %v", err)
		}
	}
}

// The environment may switch the proxy (a machine that needs one in one place and not in another) but never the token.
func TestTheProxyMayComeFromTheEnvironmentAndTheTokenNeverDoes(t *testing.T) {
	t.Setenv("SECURL_TELEGRAM_PROXY", "http://10.0.0.1:3128")
	c, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	if c.Telegram.Proxy != "http://10.0.0.1:3128" {
		t.Errorf("the environment overrides the file: %q", c.Telegram.Proxy)
	}
	t.Setenv("SECURL_TELEGRAM_BOT_TOKEN", "123456789:AAH-SECRET")
	c2, err := parseTG(t, goodTelegram)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(strings.ToLower(configDump(c2)), "aah-secret") {
		t.Error("a token from the environment must not reach the configuration")
	}
}

func TestTelegramIdsAreNotSecretsButTheProxyMayCarryACredential(t *testing.T) {
	c, err := parseTG(t, "telegram:\n  proxy: http://user:pa55word@127.0.0.1:1080\n  bots:\n    - {name: ops, chats: [{name: a, chat_id: 1}]}\n")
	if err != nil {
		t.Fatal(err)
	}
	if c.Telegram.Proxy != "http://user:pa55word@127.0.0.1:1080" {
		t.Errorf("a proxy credential is allowed: %q", c.Telegram.Proxy)
	}
	if strings.Contains(c.Telegram.ProxyForDisplay(), "pa55word") {
		t.Errorf("but it is not shown: %q", c.Telegram.ProxyForDisplay())
	}
	if !strings.Contains(c.Telegram.ProxyForDisplay(), "127.0.0.1:1080") {
		t.Errorf("what is shown still says which proxy: %q", c.Telegram.ProxyForDisplay())
	}
}

func configDump(c *Config) string {
	var b strings.Builder
	for _, bot := range c.Telegram.Bots {
		b.WriteString(bot.Name)
		for _, ch := range bot.Chats {
			b.WriteString(ch.Name)
		}
	}
	b.WriteString(c.Telegram.Proxy)
	return b.String()
}
