package main

import (
	"os"
	"regexp"
	"strings"
	"testing"
)

// The documents are read by people configuring allow-lists and by agents' authors: a tool name that is wrong in them is
// a bug. These tests read the real tool list from the source and hold the documents to it.

var documents = []string{"README.md", "DESIGN.md", "MCP_TOOLS.md", "docs/OPERATING.md", "docs/ROADMAP.md", "skills/securl/SKILL.md"}

func realTools(t *testing.T) map[string]bool {
	t.Helper()
	b, err := os.ReadFile("internal/mcpserver/names.go")
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{"dingtalk_targets": true, "dingtalk_send": true, "telegram_targets": true, "telegram_send": true, "telegram_read": true, "redis_targets": true, "redis_query": true, "redis_exec": true, "rocketmq_targets": true, "rocketmq_read": true, "archery_instances": true, "archery_groups": true, "archery_query": true, "archery_run_sql": true,
		"archery_wait": true, "archery_workflow_status": true, "archery_cancel": true}
	for _, m := range regexp.MustCompile(`= "([a-z_]+)"`).FindAllStringSubmatch(string(b), -1) {
		have[m[1]] = true
	}
	return have
}

var toolish = regexp.MustCompile("`((?:session|site|vault|archery|db|telegram|dingtalk|redis|rocketmq)_[a-z_]+)`")

func TestEveryToolTheDocumentsNameExists(t *testing.T) {
	have := realTools(t)
	// Error codes, fields and configuration keys that share a prefix with the tools: they are not tools.
	notTools := map[string]bool{
		"session_expired": true, "vault_locked": true, "vault_not_initialized": true, // error codes
		"site_unreachable": true, "archery_error": true, "redis_error": true, // error codes
		"site_options": true, "archery_ddl_allowed": true, "archery_requests_allowed": true, // configuration key and policy fields
		"archery_submit_sql": true,                                                                   // named in order to say it does not exist
		"session_dropped":    true, "session_close_requested": true, "session_close_confirmed": true, // audit events
		"session_close_declined": true, "session_close_wrong_word": true, "session_close_round": true,
	}
	for _, f := range documents {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		for _, m := range toolish.FindAllStringSubmatch(string(b), -1) {
			if !have[m[1]] && !notTools[m[1]] {
				t.Errorf("%s names the tool %q, which does not exist", f, m[1])
			}
		}
	}
}

func TestNoDocumentUsesAnOldToolNameOrResource(t *testing.T) {
	// "`login` step" and "(`login`/`totp`)" name a round of the page, which is still called login: that is not a tool.
	old := regexp.MustCompile("`(login_wait|login_sites|login_sessions|logout)`|login://|`login\\(|call `login`|call `login`|login_wait|login_sites|login_sessions|`login` tool|`login` returns|`login` result|`login` output|`login` call|`login` \\(cached|`login` with")
	for _, f := range documents {
		b, _ := os.ReadFile(f)
		for i, line := range strings.Split(string(b), "\n") {
			if old.MatchString(line) {
				t.Errorf("%s:%d uses an old tool name or resource: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

func TestTheToolReferenceDocumentsEveryTool(t *testing.T) {
	b, _ := os.ReadFile("MCP_TOOLS.md")
	for name := range realTools(t) {
		if !strings.Contains(string(b), "`"+name+"`") {
			t.Errorf("MCP_TOOLS.md does not document %s", name)
		}
	}
}

func TestDocumentsCarryNoOldProgramOrConfigNames(t *testing.T) {
	bad := regexp.MustCompile(`~/\.config/login|LOGIN_DINGTALK|LOGIN_TUNNEL|leafai\.github\.io/login|LeafAI/login\b|login-data|login-page|\bgo install [^ ]*/login\b`)
	for _, f := range append(documents, "docs/static-page-review.md", "THIRD_PARTY_NOTICES.md", "Dockerfile") {
		b, err := os.ReadFile(f)
		if err != nil {
			continue
		}
		for i, line := range strings.Split(string(b), "\n") {
			if bad.MatchString(line) {
				t.Errorf("%s:%d: %s", f, i+1, strings.TrimSpace(line))
			}
		}
	}
}

// No document may say that a credential is returned to the agent: it is not.
func TestNoDocumentSaysCredentialsAreHandedToTheAgent(t *testing.T) {
	for _, f := range documents {
		b, _ := os.ReadFile(f)
		low := strings.ToLower(string(b))
		for _, phrase := range []string{"handed to the agent by design", "cookie_header", "keeps its credentials in the result", "still returns the cookie", "raw secrets (by design)", "contain only cookies/tokens"} {
			if strings.Contains(low, phrase) {
				t.Errorf("%s still says %q", f, phrase)
			}
		}
	}
}

func TestNoDocumentTalksAboutCompatibilityWithAnOlderName(t *testing.T) {
	for _, f := range documents {
		b, _ := os.ReadFile(f)
		low := strings.ToLower(string(b))
		for _, phrase := range []string{"formerly login", "was called `login`", "still used until you move", "still work next to"} {
			if strings.Contains(low, phrase) {
				t.Errorf("%s: %q", f, phrase)
			}
		}
	}
}

// A channel is not a group to Telegram, and a bot reads a channel's posts only as an administrator. A document that did not say so would
// leave a person with a bot that reads an empty channel and no error, which is exactly what happened.
func TestTheDocumentsSayThatAChannelIsReadAndThatTheBotMustBeItsAdministrator(t *testing.T) {
	for _, f := range []string{"skills/securl/SKILL.md", "MCP_TOOLS.md", "docs/OPERATING.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		low := strings.ToLower(string(b))
		for _, want := range []string{"channel", "administrator", "channel_post"} {
			if f == "docs/OPERATING.md" && want == "channel_post" {
				continue
			}
			if !strings.Contains(low, want) {
				t.Errorf("%s does not say %q about reading a channel", f, want)
			}
		}
	}
}

// The flag that makes one process serve stdio and the socket is a flag of the program, and the documents that name it must name one the
// program has: a document that sends somebody to a flag that does not exist is worse than none.
func TestTheDaemonFlagTheDocumentsNameIsOneTheProgramHas(t *testing.T) {
	src, err := os.ReadFile("main.go")
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(src), `flag.Bool("daemon"`) {
		t.Fatal("main.go has no -daemon flag, and the documents say it has")
	}
	for _, f := range []string{"skills/securl/SKILL.md", "docs/OPERATING.md", "README.md", "DESIGN.md"} {
		b, err := os.ReadFile(f)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(string(b), "`securl -daemon`") && !strings.Contains(string(b), "securl -daemon") {
			t.Errorf("%s does not say that `securl -daemon` exists", f)
		}
	}
	for _, f := range []string{"skills/securl/SKILL.md", "docs/OPERATING.md", "README.md", "DESIGN.md", "main.go", "serve_daemon_unix.go", "serve_daemon_other.go"} {
		b, _ := os.ReadFile(f)
		if strings.Contains(string(b), "--daemon") {
			t.Errorf("%s writes the flag with two dashes: the program's own flags (-config, -daemon) are written with one", f)
		}
	}
	skill, _ := os.ReadFile("skills/securl/SKILL.md")
	for _, must := range []string{"off by default", "one vault", "already listening"} {
		if !strings.Contains(string(skill), must) {
			t.Errorf("the skill does not say %q about -daemon", must)
		}
	}
}
