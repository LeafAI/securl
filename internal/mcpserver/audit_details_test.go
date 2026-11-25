package mcpserver

import (
	"context"
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/modelcontextprotocol/go-sdk/mcp"
)

func TestDetailedAuditRecordsSafeRequestMetadata(t *testing.T) {
	s, cfg := newTestServer(t, nil)
	in := RequestInput{URL: "https://private-user:private-pass@example.test/private-root?api_key=private-query#private-fragment", Method: "POST", Path: "/private-path", Query: map[string]multiValue{"private-query-key": {"private-query-value"}}, Headers: map[string]string{"Authorization": "private-header"}, JSON: json.RawMessage(`{"password":"private-json"}`), Form: map[string]multiValue{"private-form-key": {"private-form-value"}}, Text: "private-text", Base64: "private-base64", TimeoutSeconds: 15, FollowRedirects: true, MaxResponseBytes: 1000}
	out := RequestOutput{Status: 201, Body: "private-response", Headers: map[string][]string{"Set-Cookie": {"private-cookie"}}, TotalBytes: 42, Redactions: 2}
	s.observe("request", nil, in, out, nil, 7*time.Millisecond)
	ev := events(t, cfg.Audit.File)[0]
	if ev.Host != "example.test" || ev.Millis != 7 || ev.Arguments["origin"] != "https://example.test" || ev.Arguments["method"] != "POST" || ev.Arguments["query_count"] != float64(1) || ev.Arguments["timeout_seconds"] != float64(15) || ev.Arguments["follow_redirects"] != true || ev.Outcome["http_status"] != float64(201) || ev.Outcome["response_bytes"] != float64(42) {
		t.Fatalf("missing audit metadata: %+v", ev)
	}
	data, err := os.ReadFile(cfg.Audit.File)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") {
		t.Fatalf("raw sensitive input/output in log: %s", data)
	}
}

func TestDetailedAuditDoesNotStorePayloadsOrHandoverSecrets(t *testing.T) {
	s, cfg := newTestServer(t, nil)
	sql := "SELECT 'private-sql'"
	s.observe("db_query", nil, DBQueryInput{Target: "db", Database: "app", SQL: sql, Limit: 20}, DBQueryOutput{Rows: [][]any{{"private-row"}}}, nil, time.Millisecond)
	s.observe("redis_exec", nil, RedisExecInput{Target: "cache", Command: []string{"SET", "private-key", "private-value"}}, RedisExecOutput{Value: "private-redis"}, nil, time.Millisecond)
	s.observe("zulip_send", nil, ZulipSendInput{Server: "team", Channel: "ops", Topic: "private-topic", Text: "private-message"}, ZulipSendOutput{Sent: true, MessageID: 123}, nil, time.Millisecond)
	s.observe("session_open", nil, LoginInput{URL: "https://example.test", ManageCredentials: true}, &LoginOutput{Status: "pending", LoginID: "lg_example", WaitingFor: "credential_setup", LinkHandover: LinkHandover{Link: "https://private-link", KeyCode: "private-keycode", Instruction: "private-instruction"}}, nil, time.Millisecond)
	s.observe("session_wait", nil, LoginWaitInput{LoginID: "lg_example"}, nil, errf("site_unreachable", true, "private-error"), time.Millisecond)
	ev := events(t, cfg.Audit.File)
	n, h := audit.Fingerprint(sql)
	if ev[0].Arguments["sql_bytes"] != float64(n) || ev[0].Arguments["sql_sha256"] != h || ev[0].Outcome["row_count"] != float64(1) {
		t.Fatal(ev[0])
	}
	if ev[1].Arguments["command"] != "SET" || ev[1].Arguments["argument_count"] != float64(2) {
		t.Fatal(ev[1])
	}
	if ev[2].Arguments["channel"] != "ops" || ev[2].Outcome["message_id"] != float64(123) {
		t.Fatal(ev[2])
	}
	if ev[3].Arguments["manage_credentials"] != true || ev[3].Outcome["login_id"] != "lg_example" || ev[3].Result != "pending" {
		t.Fatal(ev[3])
	}
	if ev[4].Result != "site_unreachable" || ev[4].Retryable == nil || !*ev[4].Retryable {
		t.Fatal(ev[4])
	}
	data, err := os.ReadFile(cfg.Audit.File)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") {
		t.Fatalf("raw sensitive input/output in log: %s", data)
	}
}

func TestDetailedAuditRecordsInvalidArgumentsThroughMCP(t *testing.T) {
	srv, s := protoServer(t)
	cs := connect(t, s, srv)
	res, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "session_open", Arguments: map[string]any{"url": "https://example.test", "private-unknown": "private-value"}})
	if err != nil || !res.IsError {
		t.Fatalf("expected argument rejection: %v %v", res, err)
	}
	es := events(t, s.cfg.Audit.File)
	if len(es) != 1 || es[0].Event != "tool_call" || es[0].Tool != "session_open" || es[0].Result != "invalid_argument" || es[0].Client != "proto-test/9" || es[0].Retryable == nil || *es[0].Retryable || len(es[0].Arguments) != 0 {
		t.Fatalf("invalid call not safely audited: %+v", es)
	}
	data, err := os.ReadFile(s.cfg.Audit.File)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), "private-") {
		t.Fatalf("invalid raw arguments in log: %s", data)
	}
}
