package mcpserver_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk/dingtalktest"
	"github.com/LeafAI/securl/internal/mcpserver"
)

const (
	e2eHookToken = "c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	e2eHookSec   = "SECabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
	e2eHook      = "https://oapi.dingtalk.com/robot/send?access_token=" + e2eHookToken
)

func dingtalkSetup(t *testing.T, sign bool) (*env, *dingtalktest.API) {
	t.Helper()
	rb := dingtalktest.Robot{Token: e2eHookToken}
	if sign {
		rb.Secret = e2eHookSec
	}
	api := dingtalktest.New(rb)
	t.Cleanup(api.Close)
	e := setupFull(t, nil, mcpserver.Options{DingTalkAPI: api.URL, DingTalkHTTP: api.Client()}, func(c *config.Config) {
		c.DingTalk.Groups = []config.DingTalkGroup{{Name: "ops", Sign: sign}}
	})
	return e, api
}

// typeWebhook drives the real page as the person: the webhook (and the secret) go into secret fields and are sealed in the browser.
// n is which message to the person holds the link: the first login is the first message, the next one the second.
func typeWebhook(t *testing.T, e *env, n int, vals map[string]string) string {
	t.Helper()
	b, _ := json.Marshal(vals)
	return human(t, e.rec.wait(t, n), e.dir, "submit", string(b), "")
}

func openGroup(t *testing.T, e *env, vals map[string]string) (map[string]any, map[string]any) {
	t.Helper()
	return openGroupNth(t, e, 1, vals)
}

func openGroupNth(t *testing.T, e *env, n int, vals map[string]string) (map[string]any, map[string]any) {
	t.Helper()
	out, isErr := e.call(t, "session_open", map[string]any{"url": "dingtalk://ops", "reason": "tell the group what happened", "max_block_seconds": 1, "force_refresh": n > 1})
	if isErr || out["status"] != "pending" {
		t.Fatalf("%v %v", isErr, out)
	}
	if page := typeWebhook(t, e, n, vals); !strings.Contains(page, "Done") {
		t.Fatalf("the page said %q", page)
	}
	done, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if isErr || done["status"] != "ok" || done["base_url"] != "dingtalk://ops" {
		t.Fatalf("%v %v", isErr, done)
	}
	return out, done
}

func TestAPersonPastesTheWebhookOnThePageAndAMessageThenReachesTheGroup(t *testing.T) {
	e, api := dingtalkSetup(t, false)
	openGroup(t, e, map[string]string{"webhook": e2eHook})
	if n := len(api.Requests()); n != 0 {
		t.Fatalf("a login posted something: %d requests (DingTalk cannot check a robot without posting)", n)
	}
	out, isErr := e.call(t, "dingtalk_send", map[string]any{"group": "ops", "text": "the deploy finished"})
	if isErr || out["sent"] != true {
		t.Fatalf("%v %v", isErr, out)
	}
	got := api.Sent()
	if len(got) != 1 || got[0].Token != e2eHookToken || !strings.Contains(got[0].Text, "the deploy finished") || !strings.HasPrefix(got[0].Text, "[securl] AI agent message") {
		t.Errorf("%+v", got)
	}
	if s, _ := e.call(t, "session_list", nil); !strings.Contains(jsonOf(s), "dingtalk://ops") {
		t.Errorf("the session is listed: %v", s)
	}
}

func TestAGroupWhoseRobotSignsIsAskedForItsSecretToo(t *testing.T) {
	e, api := dingtalkSetup(t, true)
	openGroup(t, e, map[string]string{"webhook": e2eHook, "secret": e2eHookSec})
	if out, isErr := e.call(t, "dingtalk_send", map[string]any{"group": "ops", "text": "signed"}); isErr || out["sent"] != true {
		t.Fatalf("a signed robot accepts the message: %v %v", isErr, out)
	}
	if n := len(api.Sent()); n != 1 {
		t.Errorf("%d", n)
	}
}

// Nothing a person types may reach anywhere an agent, a log or a chat can read it.
func TestTheWebhookAndTheSecretReachNoAnswerNoMessageAndNoAuditLine(t *testing.T) {
	e, _ := dingtalkSetup(t, true)
	open, done := openGroup(t, e, map[string]string{"webhook": e2eHook, "secret": e2eHookSec})
	sent, _ := e.call(t, "dingtalk_send", map[string]any{"group": "ops", "text": "hello"})
	list, _ := e.call(t, "session_list", nil)
	targets, _ := e.call(t, "dingtalk_targets", nil)
	secrets := []string{"SECRETTOKEN", e2eHookToken, e2eHookSec, "SECabcdef", "access_token", "oapi.dingtalk.com"}
	for name, v := range map[string]string{"session_open": jsonOf(open), "session_wait": jsonOf(done), "dingtalk_send": jsonOf(sent), "session_list": jsonOf(list), "dingtalk_targets": jsonOf(targets)} {
		for _, s := range secrets {
			if strings.Contains(v, s) {
				t.Errorf("%s carries %q: %s", name, s, v)
			}
		}
	}
	for i, m := range e.rec.all() {
		for _, s := range secrets {
			if strings.Contains(m, s) {
				t.Errorf("message %d to the person carries %q", i+1, s)
			}
		}
	}
	a, _ := os.ReadFile(e.auditFile)
	for _, s := range secrets {
		if strings.Contains(string(a), s) {
			t.Errorf("the audit log carries %q:\n%s", s, a)
		}
	}
}

func TestTheMessageToThePersonSaysWhichGroupTheWebhookOpens(t *testing.T) {
	e, _ := dingtalkSetup(t, false)
	e.call(t, "session_open", map[string]any{"url": "dingtalk://ops", "max_block_seconds": 1})
	msg := e.rec.wait(t, 1)
	for _, want := range []string{"ops", "AI agent", "send messages", "Nothing is sent now"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the person is told what they are agreeing to (%q missing):\n%s", want, msg)
		}
	}
}

// An address that is not the robot's is refused at the page, before anything is kept or sent: a person can be tricked into pasting one.
func TestAnAddressThatIsNotDingTalksIsRefusedAndNothingIsKeptOrSent(t *testing.T) {
	e, api := dingtalkSetup(t, false)
	out, _ := e.call(t, "session_open", map[string]any{"url": "dingtalk://ops", "max_block_seconds": 1})
	typeWebhook(t, e, 1, map[string]string{"webhook": "https://evil.example/robot/send?access_token=" + e2eHookToken})
	e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 5})
	if s, _ := e.call(t, "session_list", nil); strings.Contains(jsonOf(s), "dingtalk://ops") {
		t.Errorf("a session was made from an address that is not DingTalk's: %v", s)
	}
	if len(api.Requests()) != 0 {
		t.Error("something was sent")
	}
}

func TestRejectingTheDingTalkLoginMakesNoSession(t *testing.T) {
	e, _ := dingtalkSetup(t, false)
	out, _ := e.call(t, "session_open", map[string]any{"url": "dingtalk://ops", "max_block_seconds": 1})
	human(t, e.rec.wait(t, 1), e.dir, "reject", "", "not now")
	res, isErr := e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 20})
	if !isErr || res["code"] != "user_rejected" {
		t.Errorf("%v %v", isErr, res)
	}
}

// A robot DingTalk does not know is found by the first send, and the person is asked again.
func TestAWrongWebhookIsFoundByTheFirstSendAndThenAskedAgain(t *testing.T) {
	e, api := dingtalkSetup(t, false)
	wrong := strings.Replace(e2eHook, "SECRETTOKEN", "WRONGTOKEN0", 1)
	openGroup(t, e, map[string]string{"webhook": wrong})
	out, isErr := e.call(t, "dingtalk_send", map[string]any{"group": "ops", "text": "x"})
	if !isErr || out["code"] != "session_expired" {
		t.Fatalf("%v %v", isErr, out)
	}
	if strings.Contains(jsonOf(out), "WRONGTOKEN0") {
		t.Errorf("the answer repeats the token: %v", out)
	}
	if len(api.Sent()) != 0 {
		t.Error("something was sent")
	}
	if s, _ := e.call(t, "session_list", nil); strings.Contains(jsonOf(s), "dingtalk://ops") {
		t.Errorf("the session of a robot that does not exist is kept: %v", s)
	}
	// and a person can type the right one
	openGroupNth(t, e, 2, map[string]string{"webhook": e2eHook})
	if out, isErr := e.call(t, "dingtalk_send", map[string]any{"group": "ops", "text": "now it works"}); isErr || out["sent"] != true {
		t.Errorf("%v %v", isErr, out)
	}
}
