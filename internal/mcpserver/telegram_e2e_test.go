package mcpserver_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/telegram/telegramtest"
)

const (
	e2eToken = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"
	e2eChatA = int64(-1001111111111)
	e2eChatB = int64(-1002222222222)
)

func jsonOf(v any) string { b, _ := json.Marshal(v); return string(b) }

func telegramSetup(t *testing.T) (*env, *telegramtest.API) {
	t.Helper()
	api := telegramtest.New(telegramtest.Bot{Token: e2eToken, ID: 123456789, Username: "securl_test_bot",
		Chats: map[int64]bool{e2eChatA: true, e2eChatB: true}})
	t.Cleanup(api.Close)
	e := setupFull(t, nil, mcpserver.Options{TelegramAPI: api.URL, TelegramHTTP: api.Client()}, func(c *config.Config) {
		c.Telegram.Bots = []config.TelegramBot{{Name: "ops", Chats: []config.TelegramChat{
			{Name: "alerts", ChatID: e2eChatA}, {Name: "dev", ChatID: e2eChatB}}}}
	})
	return e, api
}

// typeToken drives the real page as the person: the token goes into the one secret field and is sealed in the browser.
func typeToken(t *testing.T, e *env, n int, token string) string {
	t.Helper()
	vals, _ := json.Marshal(map[string]string{"bot_token": token})
	return human(t, e.rec.wait(t, n), e.dir, "submit", string(vals), "")
}

func TestAPersonTypesTheBotTokenOnThePageAndTheSessionIsMade(t *testing.T) {
	e, api := telegramSetup(t)
	out, isErr := e.call(t, "session_open", map[string]any{"url": "telegram://ops", "reason": "tell the channel what happened", "max_block_seconds": 1})
	if isErr || out["status"] != "pending" {
		t.Fatalf("%v %v", isErr, out)
	}
	if page := typeToken(t, e, 1, e2eToken); !strings.Contains(page, "Done") {
		t.Fatalf("the page said %q", page)
	}
	done, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if isErr || done["status"] != "ok" || done["base_url"] != "telegram://ops" {
		t.Fatalf("%v %v", isErr, done)
	}
	if api.Calls["getMe"] == 0 {
		t.Error("the token was never checked against Telegram")
	}
	if s, _ := e.call(t, "session_list", nil); !strings.Contains(jsonOf(s), "telegram://ops") {
		t.Errorf("the session is listed: %v", s)
	}
}

// Nothing a person types may reach anywhere an agent, a log or a chat can read it.
func TestTheBotTokenReachesNoAnswerNoMessageAndNoAuditLine(t *testing.T) {
	e, _ := telegramSetup(t)
	out, _ := e.call(t, "session_open", map[string]any{"url": "telegram://ops", "max_block_seconds": 1})
	typeToken(t, e, 1, e2eToken)
	done, _ := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	for name, v := range map[string]string{"session_open": jsonOf(out), "session_wait": jsonOf(done)} {
		if strings.Contains(v, "AAH-SECRET") || strings.Contains(v, e2eToken) {
			t.Errorf("%s carries the token: %s", name, v)
		}
	}
	for i, m := range e.rec.all() {
		if strings.Contains(m, "AAH-SECRET") || strings.Contains(m, e2eToken) {
			t.Errorf("message %d carries the token", i+1)
		}
	}
	a, _ := os.ReadFile(e.auditFile)
	if strings.Contains(string(a), "AAH-SECRET") || strings.Contains(string(a), "123456789:") {
		t.Errorf("the audit log carries the token:\n%s", a)
	}
}

func TestTheMessageToThePersonSaysWhichChatsTheTokenOpens(t *testing.T) {
	e, _ := telegramSetup(t)
	e.call(t, "session_open", map[string]any{"url": "telegram://ops", "max_block_seconds": 1})
	msg := e.rec.wait(t, 1)
	for _, want := range []string{"ops", "alerts", "dev", "AI agent"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the person is told what they are agreeing to (%q missing):\n%s", want, msg)
		}
	}
	if strings.Contains(msg, "-100111") || strings.Contains(msg, "-100222") {
		t.Errorf("chats are named, not numbered:\n%s", msg)
	}
}

func TestAWrongTokenOnThePageIsSaidAndNothingIsKept(t *testing.T) {
	e, _ := telegramSetup(t)
	out, _ := e.call(t, "session_open", map[string]any{"url": "telegram://ops", "max_block_seconds": 1})
	typeToken(t, e, 1, "999:WRONG-TOKEN-abcdefghijklmnopqrstuvwxyz0123")
	// the driver asks again after a wrong one? it ends the login with the reason: either way nothing is stored
	e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 5})
	if s, _ := e.call(t, "session_list", nil); strings.Contains(jsonOf(s), "telegram://ops") {
		t.Errorf("a session was made from a token Telegram refused: %v", s)
	}
}

func TestRejectingTheLoginMakesNoSession(t *testing.T) {
	e, _ := telegramSetup(t)
	out, _ := e.call(t, "session_open", map[string]any{"url": "telegram://ops", "max_block_seconds": 1})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "not now")
	res, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !isErr || res["code"] != "user_rejected" {
		t.Errorf("%v %v", isErr, res)
	}
}
