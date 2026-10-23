package climode

import "testing"

func TestCommandPathOfATool(t *testing.T) {
	for tool, want := range map[string][2]string{
		"session_open":            {"session", "open"},
		"session_wait":            {"session", "wait"},
		"session_close":           {"session", "close"},
		"session_list":            {"session", "list"},
		"site_list":               {"site", "list"},
		"vault_status":            {"vault", "status"},
		"vault_unlock":            {"vault", "unlock"},
		"db_targets":              {"db", "targets"},
		"db_query":                {"db", "query"},
		"db_exec":                 {"db", "exec"},
		"archery_run_sql":         {"archery", "run-sql"},
		"archery_workflow_status": {"archery", "workflow-status"},
		"archery_instances":       {"archery", "instances"},
		"request":                 {"request", ""},
	} {
		g, s := commandPath(tool)
		if g != want[0] || s != want[1] {
			t.Errorf("commandPath(%q) = %q %q, want %q %q", tool, g, s, want[0], want[1])
		}
	}
}

func TestFlagNameOfAField(t *testing.T) {
	for in, want := range map[string]string{
		"max_block_seconds": "max-block-seconds",
		"url":               "url",
		"force_refresh":     "force-refresh",
	} {
		if got := flagName(in); got != want {
			t.Errorf("flagName(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestToolNamesInTheHelpBecomeTheCommandsThatRunThem(t *testing.T) {
	names := []string{"session_open", "session_wait", "db_targets", "archery_run_sql", "archery_wait", "request", "vault_unlock"}
	for in, want := range map[string]string{
		"call session_open with url db://x first":   "call `securl session open` with url db://x first",
		"resume with archery_wait or session_wait.": "resume with `securl archery wait` or `securl session wait`.",
		"names from db_targets":                     "names from `securl db targets`",
		"call archery_run_sql, then request":        "call `securl archery run-sql`, then request",
		"a request is sent":                         "a request is sent", // the plain word is not a tool name here
		"the request tool":                          "the request tool",
		"session_open_extra is not a tool":          "session_open_extra is not a tool",
		"vault_unlock needs no vault":               "vault_unlock needs no vault", // no command: left as it is
		"Set `session_open` (backticks stay) ok":    "Set `securl session open` (backticks stay) ok",
		"in session_open's docs":                    "in `securl session open`'s docs",
		"x_session_open":                            "x_session_open",
		"session_open, session_wait; db_targets.":   "`securl session open`, `securl session wait`; `securl db targets`.",
	} {
		if got := commandNames(in, names, map[string]bool{"vault_unlock": true}); got != want {
			t.Errorf("commandNames(%q)\n  got  %q\n  want %q", in, got, want)
		}
	}
}
