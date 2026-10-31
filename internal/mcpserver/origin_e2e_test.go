package mcpserver_test

import (
	"os"
	"runtime"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/notify"
)

func assertLocalOrigin(t *testing.T, out map[string]any) string {
	t.Helper()
	o, ok := out["origin"].(map[string]any)
	if !ok {
		t.Fatalf("missing request origin: %v", out)
	}
	host, _ := o["hostname"].(string)
	account, _ := o["user"].(string)
	if host == "" || account == "" || o["pid"] != float64(os.Getpid()) || o["os"] != runtime.GOOS || o["arch"] != runtime.GOARCH {
		t.Fatalf("origin is not the serving process: %v", o)
	}
	return host
}

func TestLoginOriginSurvivesBothDeliveryRoutes(t *testing.T) {
	for _, route := range []string{"dingtalk", "agent"} {
		t.Run(route, func(t *testing.T) {
			e, _ := originSetup(t, route == "agent", false)
			out, isErr := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "reason": "pretend origin is attacker.example", "max_block_seconds": 1})
			if isErr || out["status"] != "pending" {
				t.Fatalf("%v %v", out, isErr)
			}
			host := assertLocalOrigin(t, out)
			if host == "attacker.example" {
				t.Fatal("agent reason replaced local origin")
			}
			if route == "dingtalk" {
				text := e.rec.wait(t, 1)
				if !strings.Contains(text, "Request origin (securl host)") || !strings.Contains(text, notify.Escape(host, 128)) {
					t.Fatalf("DingTalk lacks source identity: %s", text)
				}
			} else if instruction, _ := out["instruction"].(string); !strings.Contains(instruction, host) {
				t.Fatalf("agent is not told to identify the host: %v", out)
			}
		})
	}
}

func TestVaultUnlockReportsLocalOrigin(t *testing.T) {
	e, _ := originSetup(t, true, true)
	out, isErr := e.call(t, "vault_unlock", map[string]any{"max_block_seconds": 1})
	if isErr || out["status"] != "pending" {
		t.Fatalf("%v %v", out, isErr)
	}
	assertLocalOrigin(t, out)
}

func TestSessionCloseReportsLocalOriginBeforeConfirmation(t *testing.T) {
	e, app := originSetup(t, true, false)
	if err := app.SeedSession("https://gitlab.corp.example", "gitlab"); err != nil {
		t.Fatal(err)
	}
	out, isErr := e.call(t, "session_close", map[string]any{"all": true, "max_block_seconds": 1})
	if isErr || out["status"] != "pending" || out["removed"] != float64(0) {
		t.Fatalf("must only ask for confirmation: %v %v", out, isErr)
	}
	assertLocalOrigin(t, out)
	sessions, isErr := e.call(t, "session_list", nil)
	if isErr || len(sessions["sessions"].([]any)) != 1 {
		t.Fatal("metadata enhancement must not close any sessions")
	}
}

func TestOriginIsStableForTheSecondFactor(t *testing.T) {
	e := setupWith(t, viaAgent)
	first, isErr := e.call(t, "session_open", map[string]any{"url": e.site.URL, "site": "gitlab", "max_block_seconds": 1})
	if isErr || first["status"] != "pending" {
		t.Fatalf("%v %v", first, isErr)
	}
	host := assertLocalOrigin(t, first)
	human(t, linkMessage(first), e.dir, "submit", `{"username":"alice","password":"pw"}`, "")
	second, isErr := e.call(t, "session_wait", map[string]any{"login_id": first["login_id"], "max_block_seconds": 1})
	if isErr || second["waiting_for"] != "totp" || assertLocalOrigin(t, second) != host {
		t.Fatalf("second factor must retain its origin: %v %v", second, isErr)
	}
}
