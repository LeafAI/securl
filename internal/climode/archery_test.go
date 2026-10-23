package climode

import (
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/site/archery/archerytest"
	"github.com/LeafAI/securl/internal/web"
)

// The Archery tools log in on the way: with no session they answer pending, and what they are waiting for (a login) is a
// person's. The command waits for it like any other and prints the real answer, not the pending one with exit 0, which a script
// would take for success and an empty list. Three of the tools say it in a `login` object, one in `status`, and the workflow
// tools in `status` as well with `phase: login`.
func TestAnArcheryCommandWithNoSessionWaitsForTheLoginAndPrintsTheRealAnswer(t *testing.T) {
	browsertest.Require(t)
	for _, tc := range []struct {
		name string
		args func(url string) []string
		want string
	}{
		{"instances", func(u string) []string { return []string{"archery", "instances", "--url", u} }, `"instances"`},
		{"groups", func(u string) []string { return []string{"archery", "groups", "--url", u} }, `"groups"`},
		{"query", func(u string) []string {
			return []string{"archery", "query", "--url", u, "--instance", "prod", "--database", "d", "--sql", "select 1"}
		}, `"rows"`},
	} {
		t.Run(tc.name, func(t *testing.T) {
			f := &archerytest.Fake{}
			arch := httptest.NewServer(f.Handler())
			defer arch.Close()
			r := newRig(t, true)
			r.secret = func() (string, error) { return testPass, nil }
			pages := t.TempDir()
			if err := web.WriteTo(pages); err != nil {
				t.Fatal(err)
			}
			r.cfg.Web.PageURL = "file://" + pages + "/index.html"
			r.cfg.Web.TTL = time.Minute
			r.cfg.MCP.MaxBlockSeconds = 1
			rec := r.withRobot()
			r.cfg.Web.TTL = time.Minute

			done := make(chan int, 1)
			stderr := &syncBuf{}
			env := r.envFor()
			env.Err = stderr
			env.Secret = func() (string, error) { return testPass, nil }
			go func() { done <- Run(t.Context(), tc.args(arch.URL), env) }()
			link := linkIn(t, rec, 1)
			time.Sleep(2500 * time.Millisecond) // slower than max_block_seconds: the tool answers pending first
			browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"username":"alice","password":"pw"}`, "")
			select {
			case code := <-done:
				if code != 0 {
					t.Fatalf("exit %d\n%s%s", code, r.out.String(), stderr.String())
				}
			case <-time.After(60 * time.Second):
				t.Fatal("the command did not finish after the person logged in")
			}
			if strings.Contains(r.out.String(), `"pending"`) || !strings.Contains(r.out.String(), tc.want) {
				t.Errorf("the answer must be the real one, not the pending login:\n%s", r.out.String())
			}
		})
	}
}

// A tool that logs in on the way and is then called again must be called again with what it was given: the answer to the login is
// the login's ("ok", a site), and printing it as the result of run-sql would tell a script that a workflow was made. Here the fake
// Archery is told to wait for approval, so the real answer is a pending workflow, which is not the login's.
func TestRunSQLWithNoSessionLogsInAndThenSubmitsInsteadOfPrintingTheLogin(t *testing.T) {
	browsertest.Require(t)
	f := &archerytest.Fake{}
	arch := httptest.NewServer(f.Handler())
	defer arch.Close()
	r := newRig(t, true)
	r.secret = func() (string, error) { return testPass, nil }
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.MCP.MaxBlockSeconds = 1
	r.cfg.Archery.PollInterval = 20 * time.Millisecond
	rec := r.withRobot()
	r.cfg.Web.TTL = time.Minute
	done := make(chan int, 1)
	env := r.envFor()
	env.Err = &syncBuf{}
	env.Secret = func() (string, error) { return testPass, nil }
	go func() {
		done <- Run(t.Context(), []string{"archery", "run-sql", "--url", arch.URL, "--instance", "prod", "--database", "d",
			"--sql", "select 1", "--title", "t", "--resource-group", "dba", "--approval-timeout-seconds", "1"}, env)
	}()
	link := linkIn(t, rec, 1)
	// The person is slower than max_block_seconds, so the tool answers pending and the command has to carry on by itself.
	time.Sleep(2500 * time.Millisecond)
	browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"username":"alice","password":"pw"}`, "")
	select {
	case <-done:
	case <-time.After(60 * time.Second):
		t.Fatal("the command did not finish")
	}
	if f.Submitted == nil {
		t.Errorf("after the login the SQL must have been submitted; the command printed:\n%s", r.out.String())
	}
}

// Only the tools that log in on the way are called again after the login. Opening a session is the login itself, and a tool that
// waited for a person's confirmation (closing sessions) has had its answer: calling it again would ask the person a second time.
func TestOnlyTheToolsThatLogInOnTheWayAreCalledAgain(t *testing.T) {
	for tool, want := range map[string]bool{
		"archery_instances": true, "archery_groups": true, "archery_query": true, "archery_run_sql": true,
		"archery_workflow_status": true, "archery_cancel": true,
		"archery_wait": false, "session_open": false, "session_close": false, "session_wait": false, "request": false,
		"db_query": false, "db_exec": false, "vault_unlock": false,
	} {
		if got := isLoginThenCall(tool); got != want {
			t.Errorf("%s: called again after a login = %v, want %v", tool, got, want)
		}
	}
}

// A usage error says where to look once: the messages that already end in "(see --help)" are not given a second one.
func TestAUsageErrorPointsToHelpOnlyOnce(t *testing.T) {
	r := newRig(t, false)
	for _, args := range [][]string{
		{"archery", "cancel", "--url", "https://a.example"}, // a required flag is missing
		{"archery", "cancel", "--nope", "x"},                // an unknown flag
		{"archery", "cancel", "stray"},                      // a stray word
	} {
		if code := r.run(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want usage (2)", args, code)
		}
		if n := strings.Count(r.errOut.String(), "see --help"); n != 1 {
			t.Errorf("%v: points to --help %d times:\n%s", args, n, r.errOut.String())
		}
	}
}
