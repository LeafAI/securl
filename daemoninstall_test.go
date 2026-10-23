//go:build darwin

package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
)

// `securl daemon install` writes a LaunchAgent into the home of whoever runs it and loads it into their session. These tests run
// the real binary with a throwaway HOME and a launchctl that is not the system's: the first line of defence is that no test can
// load anything into the real login session of the person who runs the tests.

func fakeLaunchctl(t *testing.T) (bin, log string) {
	t.Helper()
	dir := t.TempDir()
	log = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1\" in print) [ -f " + filepath.Join(dir, "loaded") + " ] || exit 113 ;; bootstrap) touch " + filepath.Join(dir, "loaded") + " ;; bootout) rm -f " + filepath.Join(dir, "loaded") + " ;; esac\nexit 0\n"
	bin = filepath.Join(dir, "launchctl")
	if err := os.WriteFile(bin, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return bin, log
}

// testBinary is the program built with -tags launchctltest, which alone reads SECURL_LAUNCHCTL. The binary that is shipped has no
// such path (launchctl_real_darwin.go), and TestTheShippedBinaryIgnoresTheLaunchctlVariable holds it to that.
var (
	testBinOnce sync.Once
	testBinPath string
	testBinDir  string
)

// cleanupTestBinary removes the test binary and its directory; TestMain calls it when the run is over.
func cleanupTestBinary() {
	if testBinDir != "" {
		os.RemoveAll(testBinDir)
	}
}

func testBinary(t *testing.T) string {
	t.Helper()
	testBinOnce.Do(func() {
		// not t.TempDir(): it is removed when the first test that asked for it ends, and the binary serves all of them. It is
		// removed by TestMain at the end of the run instead (cleanupTestBinary).
		dir, _ := os.MkdirTemp("", "securl-launchctltest")
		testBinDir = dir
		testBinPath = filepath.Join(dir, "securl")
		if out, err := exec.Command("go", "build", "-tags", "launchctltest", "-o", testBinPath, ".").CombinedOutput(); err != nil {
			t.Fatalf("go build -tags launchctltest: %v\n%s", err, out)
		}
	})
	return testBinPath
}

// agentDir is where the agent is written: /Library/LaunchAgents for the program that is shipped, and a directory of the test's own
// for the test binary, which alone reads SECURL_AGENT_DIR (launchctl_test_darwin.go).
func runInstall(t *testing.T, agentDir, ctl string, args ...string) (out string, code int) {
	t.Helper()
	cmd := exec.Command(testBinary(t), append([]string{"daemon"}, args...)...)
	cmd.Env = append(os.Environ(), "SECURL_LAUNCHCTL="+ctl, "SECURL_AGENT_DIR="+agentDir, "SECURL_TEST_AS_ROOT=1")
	b, err := cmd.CombinedOutput()
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	}
	return string(b), code
}

func plistIn(dir string) string { return filepath.Join(dir, "com.leafai.securl.plist") }

// `securl daemon install` makes the one agent of the machine, in /Library/LaunchAgents, which launchd loads for every user at login,
// as that user. It is run as root (the installer is root), writes no path of any user's, and loads the agent into the session of the
// user it is told is at the console, so that the daemon runs now and not only at the next login.
func TestDaemonInstallWritesTheMachinesAgentAndLoadsItForTheUserAtTheConsole(t *testing.T) {
	dir := t.TempDir()
	ctl, log := fakeLaunchctl(t)
	out, code := runInstall(t, dir, ctl, "install", "-uid", "501")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	b, err := os.ReadFile(plistIn(dir))
	if err != nil {
		t.Fatalf("no plist: %v\n%s", err, out)
	}
	p := string(b)
	self, _ := filepath.EvalSymlinks(testBinary(t))
	if !strings.Contains(p, "<string>"+self+"</string>") {
		t.Errorf("the plist runs the binary that install itself is (%s), by its real absolute path:\n%s", self, p)
	}
	for _, bad := range []string{"/Users/", "~", "-config", "StandardErrorPath"} {
		if strings.Contains(p, bad) {
			t.Errorf("the plist has %q in it, and it is loaded for every user:\n%s", bad, p)
		}
	}
	if !strings.Contains(p, "<string>-log</string>") || !strings.Contains(p, "<string>default</string>") {
		t.Errorf("the daemon is told to log to the file of the user it runs as:\n%s", p)
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "bootstrap gui/501 "+plistIn(dir)) {
		t.Errorf("loaded into the session of the user at the console: %q", calls)
	}
	if strings.Contains(string(calls), "system") {
		t.Errorf("a system domain was used: %q", calls)
	}
	if exec.Command("plutil", "-lint", plistIn(dir)).Run() != nil {
		t.Errorf("plutil rejects the plist:\n%s", p)
	}
}

func TestDaemonInstallWithNoUserOnlyPutsTheAgentInPlace(t *testing.T) {
	dir := t.TempDir()
	ctl, log := fakeLaunchctl(t)
	out, code := runInstall(t, dir, ctl, "install")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(plistIn(dir)); err != nil {
		t.Fatalf("no plist: %v", err)
	}
	if calls, _ := os.ReadFile(log); len(calls) != 0 {
		t.Errorf("nobody to load it for, yet launchctl was asked: %q", calls)
	}
	if !strings.Contains(out, "next login") {
		t.Errorf("it says that the daemon starts at each user's next login:\n%s", out)
	}
}

func TestDaemonInstallSaysThatEveryUserGetsADaemonThatStartsLockedAndHowToOpenIt(t *testing.T) {
	dir := t.TempDir()
	ctl, _ := fakeLaunchctl(t)
	out, _ := runInstall(t, dir, ctl, "install", "-uid", "501")
	for _, want := range []string{"every user", "locked", "securl unlock"} {
		if !strings.Contains(out, want) {
			t.Errorf("the message lacks %q:\n%s", want, out)
		}
	}
}

func TestDaemonUninstallRemovesTheAgentAndStopsTheDaemon(t *testing.T) {
	dir := t.TempDir()
	ctl, log := fakeLaunchctl(t)
	runInstall(t, dir, ctl, "install", "-uid", "501")
	out, code := runInstall(t, dir, ctl, "uninstall", "-uid", "501")
	if code != 0 {
		t.Fatalf("exit %d\n%s", code, out)
	}
	if _, err := os.Stat(plistIn(dir)); err == nil {
		t.Error("the plist is still there: every user would get a daemon at the next login")
	}
	calls, _ := os.ReadFile(log)
	if !strings.Contains(string(calls), "bootout gui/501/com.leafai.securl") {
		t.Errorf("not unloaded: %q", calls)
	}
	if _, code := runInstall(t, dir, ctl, "uninstall"); code != 0 {
		t.Error("uninstalling again must be fine")
	}
}

func TestDaemonStatusSaysWhetherTheAgentIsInstalled(t *testing.T) {
	dir := t.TempDir()
	ctl, _ := fakeLaunchctl(t)
	out, _ := runInstall(t, dir, ctl, "status")
	if !strings.Contains(out, "login agent: not installed") {
		t.Errorf("%s", out)
	}
	runInstall(t, dir, ctl, "install", "-uid", "501")
	out, _ = runInstall(t, dir, ctl, "status")
	if !strings.Contains(out, "login agent: installed") {
		t.Errorf("%s", out)
	}
}

// Writing /Library/LaunchAgents needs root. A person who is not root gets the reason and the command to run, and nothing is written
// or loaded: a half-made agent would be worse than none.
func TestDaemonInstallAsAnOrdinaryUserSaysItNeedsRootAndWritesNothing(t *testing.T) {
	dir := t.TempDir()
	ctl, log := fakeLaunchctl(t)
	cmd := exec.Command(testBinary(t), "daemon", "install")
	cmd.Env = append(os.Environ(), "SECURL_LAUNCHCTL="+ctl, "SECURL_AGENT_DIR="+dir) // not SECURL_TEST_AS_ROOT: as the person that runs the tests
	if os.Geteuid() == 0 {
		t.Skip("this test is for a user who is not root")
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("an ordinary user installed a machine-wide agent:\n%s", out)
	}
	for _, want := range []string{"root", "sudo"} {
		if !strings.Contains(string(out), want) {
			t.Errorf("it says it needs root, and how: lacks %q\n%s", want, out)
		}
	}
	if _, err := os.Stat(plistIn(dir)); err == nil {
		t.Error("a plist was written without root")
	}
	if calls, _ := os.ReadFile(log); len(calls) != 0 {
		t.Errorf("launchctl was asked: %q", calls)
	}
}

// root runs install for the person who ran sudo: the agent is for every user, and it is loaded into the session of that person only if
// they say which (the installer does, from the console). Without -uid root's own session is never used: the daemon would run as root.
func TestDaemonInstallNeverLoadsTheAgentIntoRootsSession(t *testing.T) {
	dir := t.TempDir()
	ctl, log := fakeLaunchctl(t)
	for _, args := range [][]string{{"install", "-uid", "0"}, {"install", "-uid", "-5"}, {"install", "-uid", "abc"}} {
		out, code := runInstall(t, dir, ctl, args...)
		if code == 0 {
			t.Errorf("%v: accepted\n%s", args, out)
		}
		if calls, _ := os.ReadFile(log); strings.Contains(string(calls), "gui/0") {
			t.Errorf("%v: the agent was loaded into root's session: %q", args, calls)
		}
	}
}

func TestDaemonInstallSaysWhichBinaryTheAgentRuns(t *testing.T) {
	dir := t.TempDir()
	ctl, _ := fakeLaunchctl(t)
	out, _ := runInstall(t, dir, ctl, "install", "-uid", "501")
	self, _ := filepath.EvalSymlinks(testBinary(t))
	if !strings.Contains(out, self) {
		t.Errorf("install says which binary the agent runs:\n%s", out)
	}
}

// The shipped binary runs as root when it installs the agent. It must not take from the environment what a root process writes to or
// runs: SECURL_AGENT_DIR (where the plist goes), SECURL_LAUNCHCTL (the program that loads it) and SECURL_TEST_AS_ROOT (whether root is
// needed at all) exist in the binary the tests build with -tags launchctltest, and nowhere else. This is checked on the binaries, by
// looking for the variables' names, and not by running them: a run would call the real launchctl.
func TestTheShippedBinaryHasNoWayToTakeFromTheEnvironmentWhatRootWritesOrRuns(t *testing.T) {
	shipped, err := os.ReadFile(binary(t))
	if err != nil {
		t.Fatal(err)
	}
	tested, err := os.ReadFile(testBinary(t))
	if err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"SECURL_LAUNCHCTL", "SECURL_AGENT_DIR", "SECURL_TEST_AS_ROOT"} {
		if bytes.Contains(shipped, []byte(name)) {
			t.Errorf("the shipped binary reads %s: that must be compiled into the test binary only (-tags launchctltest)", name)
		}
		if !bytes.Contains(tested, []byte(name)) {
			t.Errorf("the test binary does not read %s, so the tests above would run the real thing", name)
		}
	}
	if !bytes.Contains(shipped, []byte("/bin/launchctl")) {
		t.Error("the shipped binary does not name /bin/launchctl by its absolute path")
	}
	if !bytes.Contains(shipped, []byte("/Library/LaunchAgents")) {
		t.Error("the shipped binary does not name /Library/LaunchAgents by its absolute path")
	}
}
