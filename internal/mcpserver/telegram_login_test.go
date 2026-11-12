package mcpserver

import (
	"context"
	"net/url"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/telegram/telegramtest"
	"github.com/LeafAI/securl/internal/telegramsite"
)

const (
	tgToken = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"
	tgChatA = int64(-1001111111111)
	tgChatB = int64(-1002222222222)
	tgChatC = int64(-1003333333333)
)

type tgEnv struct {
	*gateEnv
	api *telegramtest.API
	rec *notes
}

// withTelegram starts an open server that has one bot with three chats, a fake Bot API, and (optionally) a session for the bot, as
// if a person had typed its token.
func withTelegram(t *testing.T, session bool, tweak func(*config.Config)) *tgEnv {
	t.Helper()
	api := telegramtest.New(telegramtest.Bot{Token: tgToken, ID: 123456789, Username: "securl_test_bot", Privacy: false,
		Chats: map[int64]bool{tgChatA: true, tgChatB: true, tgChatC: true}})
	t.Cleanup(api.Close)
	rec := &notes{}
	g := gateServer(t, "open", func(c *config.Config) {
		f := false
		c.Telegram.Bots = []config.TelegramBot{{Name: "ops", Chats: []config.TelegramChat{
			{Name: "alerts", ChatID: tgChatA},
			{Name: "dev", ChatID: tgChatB, Read: &f},
			{Name: "me", ChatID: tgChatC, Send: &f},
		}}}
		if tweak != nil {
			tweak(c)
		}
	})
	g.s.telegramAPI = api.URL
	g.s.telegramHTTP = api.Client()
	g.s.notify = rec
	e := &tgEnv{gateEnv: g, api: api, rec: rec}
	if session {
		e.login(t)
	}
	return e
}

// login stores the session a person's login would make, through the driver (so that it is the session the driver really makes).
func (e *tgEnv) login(t *testing.T) {
	t.Helper()
	sess := &site.Session{Tokens: map[string]string{telegramsite.TokenBot: tgToken, telegramsite.TokenUsername: "securl_test_bot", telegramsite.TokenReadsAll: "true"}}
	e.s.core.cache.Put(telegramsite.BaseURL("ops"), e.s.telegramDriver(), sess)
}

// Each way a key can be wrong is refused for its own reason, and only the exact form telegram://<bot> names a bot. Each case is
// checked on its own: a case that another guard also catches would hide a guard that has been lost.
func TestOnlyTheExactFormTelegramColonSlashSlashBotNamesABot(t *testing.T) {
	e := withTelegram(t, false, nil)
	for raw, want := range map[string]string{
		"telegram://ops":      "",
		"telegram://nope":     "unknown_target",
		"telegram://":         "invalid_argument",
		"telegram://ops/x":    "invalid_argument",
		"telegram://ops/":     "invalid_argument",
		"telegram://u@ops":    "invalid_argument",
		"telegram://u:p@ops":  "invalid_argument",
		"telegram://ops?x=1":  "invalid_argument",
		"telegram://ops#frag": "invalid_argument",
		"telegram:ops":        "invalid_argument",
		"telegram:/ops":       "invalid_argument",
		"db://ops":            "invalid_argument",
		"https://ops":         "invalid_argument",
		"ops":                 "invalid_argument",
		"":                    "invalid_argument",
	} {
		name, u, terr := e.s.telegramTarget(raw)
		switch {
		case want == "" && (terr != nil || name != "ops" || u == nil || u.String() != "telegram://ops"):
			t.Errorf("%q must name the bot: %v %v %v", raw, name, u, terr)
		case want != "" && (terr == nil || terr.Code != want || u != nil):
			t.Errorf("%q: want %s, got %v (url %v)", raw, want, terr, u)
		}
	}
	// the same through the tool, and Telegram is never contacted for any of it
	for _, raw := range []string{"telegram://nope", "telegram://ops/x", "telegram://u@ops"} {
		if out, isErr := e.call(t, "session_open", map[string]any{"url": raw}); !isErr {
			t.Errorf("%q: %v", raw, out)
		}
	}
	if len(e.api.Paths()) != 0 {
		t.Error("Telegram was contacted while a key was being refused")
	}
}

func TestAHTTPToolCannotReachABotByAnyURLItCanBuild(t *testing.T) {
	e := withTelegram(t, true, nil)
	for _, u := range []string{"https://api.telegram.org", "https://api.telegram.org/bot" + tgToken + "/getMe", "http://ops", "telegram://ops"} {
		out, isErr := e.call(t, "request", map[string]any{"url": u, "method": "GET", "path": "/getMe"})
		if !isErr {
			t.Errorf("%s: request went through: %v", u, out)
		}
		if strings.Contains(raw(out), "AAH-SECRET") {
			t.Errorf("%s: the answer carries the token: %s", u, raw(out))
		}
	}
	if n := len(e.api.Paths()); n != 0 {
		t.Errorf("%d requests reached the Bot API through request", n)
	}
}

func TestSessionListShowsABotButNeverItsToken(t *testing.T) {
	e := withTelegram(t, true, nil)
	out, isErr := e.call(t, "session_list", nil)
	if isErr {
		t.Fatal(out)
	}
	s := raw(out)
	if !strings.Contains(s, "telegram://ops") {
		t.Errorf("the session is listed: %s", s)
	}
	for _, secret := range []string{"AAH-SECRET", tgToken, "123456789:"} {
		if strings.Contains(s, secret) {
			t.Errorf("session_list carries %q: %s", secret, s)
		}
	}
}

func TestTheConfirmationNamesTheBotAndSaysTheTokenCannotBeRecovered(t *testing.T) {
	d := closeDetail([]string{"telegram://ops", "https://gitlab.example"})
	if !strings.Contains(d, "telegram://ops") {
		t.Errorf("%s", d)
	}
	if !strings.Contains(strings.ToLower(d), "token") {
		t.Errorf("closing a bot's session forgets a token somebody typed, and the confirmation says so: %s", d)
	}
}

func TestTheLoginMessageSaysWhatTheTokenWillBeUsedFor(t *testing.T) {
	d := (&Server{cfg: &config.Config{Telegram: config.Telegram{Bots: []config.TelegramBot{{Name: "ops", Chats: []config.TelegramChat{{Name: "alerts", ChatID: tgChatA}}}}}}}).telegramDriver()
	u := telegramsite.BaseURL("ops")
	detail := d.Detail(u)
	for _, want := range []string{"ops", "alerts", "agent"} {
		if !strings.Contains(detail, want) {
			t.Errorf("the person is told what the token lets an agent do (%q missing): %s", want, detail)
		}
	}
	if strings.Contains(detail, "-100") {
		t.Errorf("a chat is named, not its id: %s", detail)
	}
}

// A session is in the vault, not only in memory: after the vault locks and opens again (or the process restarts), it comes back
// through the driver it was filed under. If the Telegram driver is not registered then, the session silently disappears and a
// person has to type the token again for nothing.
func TestABotSessionComesBackThroughItsDriverAfterTheVaultLocksAndOpens(t *testing.T) {
	e := withTelegram(t, true, nil)
	if _, ok := e.s.core.cache.Peek(telegramsite.Key("ops")); !ok {
		t.Fatal("the session was not stored")
	}
	e.v.Lock()
	e.s.closeCore()
	if err := e.s.UnlockWith(gatePass); err != nil {
		t.Fatal(err)
	}
	out, isErr := e.call(t, "session_list", nil)
	if isErr || !strings.Contains(raw(out), "telegram://ops") {
		t.Errorf("the session did not come back: %v %v", isErr, out)
	}
	if _, err := e.s.core.cache.Lookup(context.Background(), telegramsite.BaseURL("ops"), nil, 0); err != nil {
		t.Errorf("the stored session cannot be used through its driver: %v", err)
	}
}

func telegramsiteBase(name string) *url.URL { return telegramsite.BaseURL(name) }

func sessionWith(tokens map[string]string) *site.Session { return &site.Session{Tokens: tokens} }

// A locked or uninitialised vault is answered as such, whatever the call names: a bot that is not configured must not be told apart
// from one that is, by a person or program that has not got the vault open.
func TestTheTelegramToolsAnswerForTheVaultNotForTheBotWhileItIsShut(t *testing.T) {
	for _, state := range []string{"locked", "none"} {
		g := gateServer(t, state, func(c *config.Config) {
			c.Telegram.Bots = []config.TelegramBot{{Name: "ops", Chats: []config.TelegramChat{{Name: "alerts", ChatID: -1001111111111}}}}
		})
		want := map[string]string{"locked": "vault_locked", "none": "vault_not_initialized"}[state]
		for _, bot := range []string{"ops", "does-not-exist"} {
			for _, tool := range []string{"telegram_send", "telegram_read"} {
				args := map[string]any{"bot": bot, "chat": "alerts", "text": "x"}
				if tool == "telegram_read" {
					delete(args, "text")
				}
				out, isErr := g.call(t, tool, args)
				if !isErr || out["code"] != want {
					t.Errorf("%s %s bot=%s: want %s, got %v %v", state, tool, bot, want, isErr, out)
				}
			}
		}
	}
}
