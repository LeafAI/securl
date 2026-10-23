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
