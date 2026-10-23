package mcpserver_test

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/vault"
)

func viaAgent(c *config.Config) { c.Security.LinkViaAgent = true }

// linkMessage is how the test's person is handed a link: human() looks for "](link)" in a message.
func linkMessage(out map[string]any) string {
	l, _ := out["link"].(string)
	return "[open](" + l + ")"
}

func TestWithNoWebhookTheLinkComesBackToTheAgentAndNobodyIsNotified(t *testing.T) {
	e := setupWith(t, viaAgent)
	start := time.Now()
	out, isErr := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "reason": "list merge requests", "max_block_seconds": 60})
	if took := time.Since(start); took > 25*time.Second {
		t.Fatalf("the call waited %s for a person who has not been given the link yet", took)
	}
	if isErr || out["status"] != "pending" || out["waiting_for"] != "login" {
		t.Fatalf("the call must come back as soon as the link exists: %v %v", isErr, out)
	}
	link, _ := out["link"].(string)
	if !strings.Contains(link, "#") || !strings.HasPrefix(link, "file://") {
		t.Fatalf("the link of the page is part of the answer: %v", out)
	}
	if k, _ := out["key_code"].(string); len(k) != 19 {
		t.Errorf("the key code the person compares with the page: %v", out["key_code"])
	}
	if ins, _ := out["instruction"].(string); !strings.Contains(strings.ToLower(ins), "user") {
		t.Errorf("the agent is told what to do with the link: %v", out["instruction"])
	}

	// the person types into the page; the second step's link is handed over the same way
	r1 := human(t, linkMessage(out), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	if !strings.Contains(r1, "Another step is needed") {
		t.Fatalf("round 1 page: %q", r1)
	}
	out, isErr = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 30})
	if isErr || out["status"] != "pending" || out["waiting_for"] != "totp" || out["link"] == nil {
		t.Fatalf("the next step's link comes back too: %v %v", isErr, out)
	}
	human(t, linkMessage(out), e.dir, "submit", `{"code":"123456"}`, "")
	out, isErr = e.call(t, "session_wait", map[string]any{"login_id": out["login_id"], "max_block_seconds": 30})
	if isErr || out["status"] != "ok" || out["link"] != nil || out["key_code"] != nil {
		t.Fatalf("a finished login carries no link: %v %v", isErr, out)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("the notifier must not be used while the link goes to the agent: %d messages", n)
	}
}

func TestAWaitThatFindsTheSameLinkAgainBlocksInsteadOfRepeatingIt(t *testing.T) {
	e := setupWith(t, viaAgent)
	first, _ := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "max_block_seconds": 30})
	if first["link"] == nil {
		t.Fatalf("no link: %v", first)
	}
	start := time.Now()
	again, _ := e.call(t, "session_wait", map[string]any{"login_id": first["login_id"], "max_block_seconds": 3})
	if took := time.Since(start); took < 2*time.Second {
		t.Fatalf("a link the agent already has must not end the wait: it returned after %s", took)
	}
	if again["status"] != "pending" || again["link"] != first["link"] {
		t.Fatalf("a wait that times out still shows the link, so an agent that lost it can show it again: %v", again)
	}
}

func TestAConfiguredWebhookWinsOverTheSwitch(t *testing.T) {
	e := setupWith(t, func(c *config.Config) {
		c.Security.LinkViaAgent = true
		c.DingTalk.Webhook = "https://oapi.dingtalk.example/robot/send?access_token=T"
	})
	out, isErr := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "max_block_seconds": 1})
	if isErr || out["status"] != "pending" || out["link"] != nil || out["key_code"] != nil {
		t.Fatalf("with a robot configured the link goes to DingTalk only: %v %v", isErr, out)
	}
	if !strings.Contains(e.rec.wait(t, 1), "](") {
		t.Error("the message is sent as before")
	}
}

func TestWithoutTheSwitchTheLinkIsNeverReturned(t *testing.T) {
	e := setup(t)
	out, _ := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "max_block_seconds": 1})
	for _, k := range []string{"link", "key_code", "instruction"} {
		if out[k] != nil {
			t.Errorf("%s must not be in the answer: %v", k, out)
		}
	}
}

func TestThePolicyShowsWhetherLinksGoToTheAgent(t *testing.T) {
	for name, tc := range map[string]struct {
		tweak func(*config.Config)
		want  bool
	}{
		"off":            {nil, false},
		"on, no webhook": {viaAgent, true},
		"on, with a webhook": {func(c *config.Config) {
			viaAgent(c)
			c.DingTalk.Webhook = "https://x.example/robot/send?access_token=T"
		}, false},
		"a webhook alone is not it": {func(c *config.Config) { c.DingTalk.Webhook = "https://x.example/robot/send?access_token=T" }, false},
	} {
		e := setupWith(t, tc.tweak)
		raw := readPolicy(t, e)
		if got, _ := raw["link_via_agent"].(bool); got != tc.want {
			t.Errorf("%s: link_via_agent = %v, want %v (%v)", name, got, tc.want, raw)
		}
	}
}

func readPolicy(t *testing.T, e *env) map[string]any {
	t.Helper()
	res, err := e.cs.ReadResource(t.Context(), &mcp.ReadResourceParams{URI: "securl://policy"})
	if err != nil {
		t.Fatal(err)
	}
	var m map[string]any
	if err := json.Unmarshal([]byte(res.Contents[0].Text), &m); err != nil {
		t.Fatal(err)
	}
	return m
}

func TestTheLinkOfAnUnlockComesBackToTheAgentToo(t *testing.T) {
	e := unlockSetup(t, viaAgent)
	start := time.Now()
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 60})
	if took := time.Since(start); took > 25*time.Second {
		t.Fatalf("the call waited %s for a person who has not been given the link yet", took)
	}
	if isErr || out["status"] != "pending" || out["link"] == nil || out["key_code"] == nil || out["instruction"] == nil {
		t.Fatalf("%v %v", isErr, out)
	}
	start = time.Now()
	again, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 3})
	if took := time.Since(start); took < 2*time.Second || again["link"] != out["link"] {
		t.Fatalf("a link the agent already has must not end the wait: %s %v", took, again)
	}
	if n := len(e.rec.all()); n != 0 {
		t.Errorf("nobody is notified: %d", n)
	}
	vals, _ := json.Marshal(map[string]string{"passphrase": e2ePass})
	human(t, linkMessage(out), e.dir, "submit", string(vals), "")
	out, isErr = e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 30, "unlock_id": out["login_id"]})
	if isErr || out["status"] != "unlocked" || out["link"] != nil {
		t.Fatalf("%v %v", isErr, out)
	}
	if e.v.State() != vault.Unlocked {
		t.Error("the vault is open")
	}
}

func TestTheLinkIsNotWrittenToTheAuditLog(t *testing.T) {
	e := unlockSetup(t, viaAgent)
	out, _ := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 30})
	link, _ := out["link"].(string)
	if link == "" {
		t.Fatalf("no link: %v", out)
	}
	raw, err := os.ReadFile(e.audit)
	if err != nil {
		t.Fatal(err)
	}
	frag := link[strings.Index(link, "#")+1:]
	if strings.Contains(string(raw), frag[:40]) {
		t.Errorf("the audit log holds the link:\n%s", raw)
	}
	if !strings.Contains(string(raw), `"delivery":"agent"`) {
		t.Errorf("the audit log says how the link was delivered:\n%s", raw)
	}
}
