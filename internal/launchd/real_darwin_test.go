//go:build darwin

package launchd

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The real launchd, a label of its own and the domain of whoever runs the test: an upgrade over an agent that is RUNNING, whose
// process takes a while to exit. launchctl bootout returns before the process has gone, and a bootstrap in that moment fails with
// "Input/output error"; the install has to wait the old process out. It loads an agent into a real login session, so it is
// opt-in: SECURL_REAL_LAUNCHD=1 go test ./internal/launchd. The fake in the other tests can only say what launchctl is believed to do.
func TestRealLaunchdUpgradeOverARunningAgentThatIsSlowToExit(t *testing.T) {
	if os.Getenv("SECURL_REAL_LAUNCHD") != "1" {
		t.Skip("loads a test agent into the real login session: set SECURL_REAL_LAUNCHD=1")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	slow := filepath.Join(dir, "slowexit.sh")
	script := "#!/bin/sh\ntrap 'sleep 2; exit 0' TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(slow, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := Spec{Dir: dir, UID: os.Getuid(), Binary: slow, Label: "com.leafai.securl-upgrade-probe"}
	t.Cleanup(func() { exec.Command("/bin/launchctl", "bootout", s.target()).Run() })
	waited := 0
	s.Wait = func(d time.Duration) { waited++; time.Sleep(d) }
	for i := 1; i <= 4; i++ {
		if err := Install(s, Launchctl{}); err != nil {
			t.Fatalf("install #%d: %v", i, err)
		}
		if out, err := exec.Command("/bin/launchctl", "print", s.target()).CombinedOutput(); err != nil || !strings.Contains(string(out), "state") {
			t.Fatalf("install #%d left the agent not loaded: %v %s", i, err, out)
		}
		time.Sleep(300 * time.Millisecond) // let the new process start, so that the next install replaces a running one
	}
	if waited == 0 {
		t.Error("the old process was still exiting at some install, so a wait was expected: the test did not reach the case it is for")
	}
}

// The real launchd, a label of its own: the agent as Plist makes it, running a stand-in daemon that stops the way the real one does,
// in order and with exit 0, when it is sent SIGTERM. A killed daemon must be started again, and one that was taken out with
// bootout (what `securl daemon uninstall` does) must stay gone. The fake launchctl of the other tests can only say what launchctl
// is believed to do; this is what it does. It loads an agent into a real login session, so it is opt-in: SECURL_REAL_LAUNCHD=1.
func TestRealLaunchdStartsAKilledDaemonAgainAndLeavesOneThatWasTakenOut(t *testing.T) {
	if os.Getenv("SECURL_REAL_LAUNCHD") != "1" {
		t.Skip("loads a test agent into the real login session: set SECURL_REAL_LAUNCHD=1")
	}
	dir := t.TempDir()
	if err := os.Chmod(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	starts := filepath.Join(dir, "starts")
	daemon := filepath.Join(dir, "daemon.sh")
	script := "#!/bin/sh\necho \"start $$\" >> '" + starts + "'\ntrap 'echo \"stop $$\" >> '" + starts + "'; exit 0' TERM\nwhile :; do sleep 1; done\n"
	if err := os.WriteFile(daemon, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	s := Spec{Dir: dir, UID: os.Getuid(), Binary: daemon, Label: "com.leafai.securl-restart-probe"}
	t.Cleanup(func() { exec.Command("/bin/launchctl", "bootout", s.target()).Run() })
	if err := Install(s, Launchctl{}); err != nil {
		t.Fatal(err)
	}
	count := func(word string) int {
		b, _ := os.ReadFile(starts)
		return strings.Count(string(b), word+" ")
	}
	waitFor := func(what string, ok func() bool) {
		t.Helper()
		for end := time.Now().Add(20 * time.Second); time.Now().Before(end); time.Sleep(200 * time.Millisecond) {
			if ok() {
				return
			}
		}
		t.Fatalf("%s did not happen in 20 seconds; the file says:\n%s", what, func() string { b, _ := os.ReadFile(starts); return string(b) }())
	}
	waitFor("the first start", func() bool { return count("start") == 1 })
	pid := func() string {
		out, _ := exec.Command("/bin/launchctl", "print", s.target()).CombinedOutput()
		for _, l := range strings.Split(string(out), "\n") {
			if f := strings.Fields(l); len(f) == 3 && f[0] == "pid" && f[1] == "=" {
				return f[2]
			}
		}
		return ""
	}
	first := pid()
	if first == "" {
		t.Fatal("the agent has no pid")
	}
	if out, err := exec.Command("/bin/kill", "-TERM", first).CombinedOutput(); err != nil {
		t.Fatalf("kill: %v %s", err, out)
	}
	waitFor("the stop", func() bool { return count("stop") == 1 })
	// ThrottleInterval is the pause before launchd starts it again, which a test cannot shorten: this is the wait the real agent has.
	for end := time.Now().Add(45 * time.Second); count("start") < 2 && time.Now().Before(end); time.Sleep(500 * time.Millisecond) {
	}
	if count("start") < 2 {
		b, _ := os.ReadFile(starts)
		t.Fatalf("a daemon that was killed (exit 0) was not started again:\n%s", b)
	}
	if again := pid(); again == "" || again == first {
		t.Errorf("the agent's pid is %q after the restart, was %q", again, first)
	}
	if err := Uninstall(s, Launchctl{}); err != nil {
		t.Fatal(err)
	}
	waitFor("the stop at uninstall", func() bool { return count("stop") == 2 })
	before := count("start")
	time.Sleep(time.Duration(throttleSeconds+5) * time.Second)
	if n := count("start"); n != before {
		t.Errorf("an agent that was uninstalled was started again: %d starts, was %d", n, before)
	}
}
