package launchd

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// The agent is the machine's: one plist in /Library/LaunchAgents, which launchd loads for every user at graphical login, as that
// user, in that user's session. So the plist names no user, no home directory and no config of anybody's: each user's daemon finds
// its own, because launchd gives it that user's HOME. These tests hold that, and the way the agent is installed and removed.

// fakeCtl stands in for launchctl, which a test must not run: it would load a real agent into the login session of whoever runs
// the tests. It remembers what it was asked and behaves like launchctl about the one thing that matters, whether a service is
// loaded.
type fakeCtl struct {
	calls   [][]string
	loaded  bool
	failOn  string
	busyFor int // the next this-many bootstraps fail with EIO, as they do while the previous process is still exiting
}

func (f *fakeCtl) Run(args ...string) (string, error) {
	f.calls = append(f.calls, args)
	if args[0] == "bootstrap" && f.busyFor > 0 {
		// launchctl answers "Bootstrap failed: 5: Input/output error" while the process of the agent that was just taken out is still
		// exiting: the label is not free yet. It is a matter of time, not a refusal.
		f.busyFor--
		return "Bootstrap failed: 5: Input/output error", errors.New("exit status 5")
	}
	if f.failOn != "" && args[0] == f.failOn {
		return "boom", errors.New("exit 1")
	}
	switch args[0] {
	case "bootstrap":
		f.loaded = true
	case "bootout":
		if !f.loaded {
			return "Could not find service", errors.New("exit 113")
		}
		f.loaded = false
	case "print":
		if !f.loaded {
			return "", errors.New("exit 113")
		}
	}
	return "", nil
}

func (f *fakeCtl) names() string {
	var n []string
	for _, c := range f.calls {
		n = append(n, c[0])
	}
	return strings.Join(n, ",")
}

// spec is the agent as the installer makes it: one plist for the machine, in a directory that a test stands in for.
func spec(t *testing.T) Spec {
	t.Helper()
	return Spec{Dir: t.TempDir(), UID: 501, Binary: "/usr/local/bin/securl", Label: Label}
}

func agentPath(s Spec) string { return filepath.Join(s.Dir, Label+".plist") }

func TestThePlistRunsTheDaemonAtLoginAndRestartsItOnlyAfterAFailure(t *testing.T) {
	p, err := spec(t).Plist()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"<string>com.leafai.securl</string>",
		"<string>/usr/local/bin/securl</string>", "<string>daemon</string>",
		// the log is the daemon's to open, from its own HOME: the word, not a path, because launchd expands neither "~" nor $HOME
		"<string>-log</string>", "<string>default</string>",
		"<key>RunAtLoad</key>", "<key>KeepAlive</key>", "<key>SuccessfulExit</key>", "<key>ThrottleInterval</key>",
		"<key>ProcessType</key>", "<string>Background</string>",
	} {
		if !strings.Contains(p, want) {
			t.Errorf("the plist lacks %s:\n%s", want, p)
		}
	}
	// KeepAlive must be conditional. A daemon that stops cleanly (SIGTERM from `daemon uninstall`, or the exit of a second
	// start that found one running) is not started again at once; one that crashes is.
	flat := strings.Join(strings.Fields(p), "")
	if !strings.Contains(flat, "<key>SuccessfulExit</key><false/>") {
		t.Errorf("KeepAlive restarts only after a failure (SuccessfulExit false):\n%s", p)
	}
}

// Loaded for every user from one file, the plist can hold nothing that is one user's: no home directory, no user name, no config
// path, no log path under a home. launchd does not expand "~" or $HOME in it (it was tried: the log was simply not written), so the
// daemon finds its own config and writes its own log, from the HOME that launchd gives it.
func TestThePlistNamesNoUserNoHomeAndNoPathUnderOne(t *testing.T) {
	p, err := spec(t).Plist()
	if err != nil {
		t.Fatal(err)
	}
	for _, bad := range []string{"/Users/", "~", "$HOME", "${HOME", "UserName", "GroupName", "Library/Logs", "Library/Application Support",
		"-config", "StandardErrorPath", "StandardOutPath", "WorkingDirectory", "EnvironmentVariables"} {
		if strings.Contains(p, bad) {
			t.Errorf("the plist contains %q: it is loaded for every user, and a path of one user's would be wrong for the others:\n%s", bad, p)
		}
	}
}

func TestThePlistHoldsNoSecretAndNoShell(t *testing.T) {
	p, _ := spec(t).Plist()
	for _, bad := range []string{"EnvironmentVariables", "PASSPHRASE", "assphrase", "webhook", "/bin/sh", "/bin/bash", "sudo", "access_token"} {
		if strings.Contains(p, bad) {
			t.Errorf("the plist contains %q: the daemon is started directly, with no shell and no secret in its environment:\n%s", bad, p)
		}
	}
}

func TestThePlistIsWellFormedWhateverThePathOfTheBinaryHolds(t *testing.T) {
	for _, path := range []string{`/opt/a & b/securl`, `/opt/a<b>/securl`, `/opt/it's "x"/securl`, `/opt/ü/ç/securl`} {
		s := spec(t)
		s.Binary = path
		p, err := s.Plist()
		if err != nil {
			t.Fatalf("%q: %v", path, err)
		}
		if strings.Contains(p, "<b>") || strings.Contains(p, "& b") {
			t.Errorf("%q was put in the plist without escaping:\n%s", path, p)
		}
		if err := wellFormed(p); err != nil {
			t.Errorf("%q: the plist is not well-formed XML: %v\n%s", path, err, p)
		}
	}
}

func TestARelativeBinaryIsRefused(t *testing.T) {
	s := spec(t)
	s.Binary = "securl"
	if _, err := s.Plist(); err == nil {
		t.Error("launchd starts a program by an absolute path: a relative one would run whatever a PATH it does not have would find")
	}
}

func TestADirectoryThatIsNotAbsoluteIsRefused(t *testing.T) {
	s := spec(t)
	s.Dir = "LaunchAgents"
	if err := Install(s, &fakeCtl{}); err == nil {
		t.Error("a relative directory would put the plist wherever the current directory is")
	}
	if _, err := os.Stat("LaunchAgents"); err == nil {
		os.RemoveAll("LaunchAgents")
		t.Error("a directory was made relative to the working directory")
	}
}

func TestInstallWritesThePlistAndLoadsItIntoTheSessionOfTheUserItIsFor(t *testing.T) {
	s := spec(t)
	ctl := &fakeCtl{}
	if err := Install(s, ctl); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(agentPath(s))
	if err != nil {
		t.Fatalf("no plist: %v", err)
	}
	// launchd refuses a plist that others can write; for /Library/LaunchAgents it also wants root as the owner, which a test cannot
	// have, and which the installer gets by being root
	if st.Mode().Perm() != 0o644 {
		t.Errorf("mode %v: launchd refuses a plist that others can write", st.Mode().Perm())
	}
	var boot []string
	for _, c := range ctl.calls {
		if c[0] == "bootstrap" {
			boot = c
		}
	}
	if len(boot) != 3 || boot[1] != "gui/501" || boot[2] != agentPath(s) {
		t.Errorf("bootstrap into the login session of the user it is for (gui/501) with this plist; got %v", boot)
	}
	for _, c := range ctl.calls {
		if j := strings.Join(c, " "); strings.Contains(j, "system") || strings.Contains(j, "sudo") {
			t.Errorf("a system-wide domain, or sudo, is never used: %v", c)
		}
	}
}

// With no user to load it for (nobody is logged in), the plist is still put in place: launchd will load it for each user at their
// next login, which is when it is wanted.
func TestInstallWithNoUserOnlyPutsThePlistInPlace(t *testing.T) {
	s := spec(t)
	s.UID = -1
	ctl := &fakeCtl{}
	if err := Install(s, ctl); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(agentPath(s)); err != nil {
		t.Fatalf("no plist: %v", err)
	}
	if len(ctl.calls) != 0 {
		t.Errorf("launchctl was called with no user to load it for: %v", ctl.calls)
	}
}

func TestInstallTwiceReplacesTheLoadedAgentInsteadOfFailing(t *testing.T) {
	s := spec(t)
	ctl := &fakeCtl{}
	if err := Install(s, ctl); err != nil {
		t.Fatal(err)
	}
	ctl.calls = nil
	if err := Install(s, ctl); err != nil {
		t.Fatalf("a second install: %v", err)
	}
	if !strings.Contains(ctl.names(), "bootout") || !strings.HasSuffix(ctl.names(), "bootstrap") {
		t.Errorf("an agent that is loaded is taken out before the new one is loaded; calls: %s", ctl.names())
	}
}

func TestInstallFailsLoudlyAndLeavesNoPlistWhenLaunchctlRefuses(t *testing.T) {
	s := spec(t)
	err := Install(s, &fakeCtl{failOn: "bootstrap"})
	if err == nil {
		t.Fatal("a failed bootstrap was reported as installed")
	}
	if !strings.Contains(err.Error(), "boom") {
		t.Errorf("launchctl's own message is in the error: %v", err)
	}
	if _, serr := os.Stat(agentPath(s)); serr == nil {
		t.Error("a plist that was never loaded was left behind: the next login would try it")
	}
}

func TestInstallKeepsAnEarlierPlistWhenTheNewOneCannotBeLoaded(t *testing.T) {
	s := spec(t)
	os.WriteFile(agentPath(s), []byte("OLD"), 0o644)
	if err := Install(s, &fakeCtl{failOn: "bootstrap"}); err == nil {
		t.Fatal("reported as installed")
	}
	if b, _ := os.ReadFile(agentPath(s)); string(b) != "OLD" {
		t.Errorf("the earlier plist was lost: %q", b)
	}
}

func TestInstallSaysWhyWhenTheDirectoryCannotBeWritten(t *testing.T) {
	s := spec(t)
	if err := os.Chmod(s.Dir, 0o555); err != nil {
		t.Fatal(err)
	}
	defer os.Chmod(s.Dir, 0o755)
	if os.Geteuid() == 0 {
		t.Skip("root can write a directory that is not writable")
	}
	err := Install(s, &fakeCtl{})
	if err == nil {
		t.Fatal("installed into a directory that cannot be written")
	}
	for _, want := range []string{s.Dir, "permission denied"} {
		if !strings.Contains(strings.ToLower(err.Error()), strings.ToLower(want)) {
			t.Errorf("the error names the real cause: it lacks %q: %v", want, err)
		}
	}
}

func TestUninstallStopsAndRemovesAndIsNotAnErrorWhenThereIsNothing(t *testing.T) {
	s := spec(t)
	ctl := &fakeCtl{}
	if err := Install(s, ctl); err != nil {
		t.Fatal(err)
	}
	if err := Uninstall(s, ctl); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(agentPath(s)); err == nil {
		t.Error("the plist is still there")
	}
	if ctl.loaded {
		t.Error("the agent is still loaded")
	}
	if err := Uninstall(s, &fakeCtl{}); err != nil {
		t.Errorf("uninstalling what is not installed must be fine: %v", err)
	}
}

func TestUninstallRemovesOnlyItsOwnFile(t *testing.T) {
	s := spec(t)
	other := filepath.Join(s.Dir, "com.example.other.plist")
	os.WriteFile(other, []byte("x"), 0o644)
	ctl := &fakeCtl{}
	Install(s, ctl)
	Uninstall(s, ctl)
	if _, err := os.Stat(other); err != nil {
		t.Error("a plist of something else was removed")
	}
}

func TestUninstallDoesNotRemoveAPlistItDidNotMake(t *testing.T) {
	s := spec(t)
	os.WriteFile(agentPath(s), []byte("<plist>somebody else wrote this under our label</plist>"), 0o644)
	if err := Uninstall(s, &fakeCtl{}); err == nil {
		t.Error("a plist under our label that we did not write is not ours to remove without saying so")
	}
	if _, err := os.Stat(agentPath(s)); err != nil {
		t.Error("it was removed")
	}
}

func TestStatusSaysInstalledAndLoaded(t *testing.T) {
	s := spec(t)
	if st := Status(s, &fakeCtl{}); st.Installed || st.Loaded {
		t.Errorf("nothing yet: %+v", st)
	}
	ctl := &fakeCtl{}
	Install(s, ctl)
	if st := Status(s, ctl); !st.Installed || !st.Loaded {
		t.Errorf("installed and loaded: %+v", st)
	}
	ctl.loaded = false
	if st := Status(s, ctl); !st.Installed || st.Loaded {
		t.Errorf("a plist that is not loaded: %+v", st)
	}
}

// macOS's own validator is the judge of the plist, not the Go XML parser: launchd rejects a file that is well-formed XML and not a
// property list. Skipped where plutil does not exist.
func TestPlutilAcceptsThePlist(t *testing.T) {
	plutil, err := exec.LookPath("plutil")
	if err != nil {
		t.Skip("plutil exists on macOS only")
	}
	for _, bin := range []string{"/usr/local/bin/securl", `/opt/a & b/<c>/securl`} {
		s := spec(t)
		s.Binary = bin
		p, err := s.Plist()
		if err != nil {
			t.Fatal(err)
		}
		f := filepath.Join(t.TempDir(), "x.plist")
		os.WriteFile(f, []byte(p), 0o644)
		if out, err := exec.Command(plutil, "-lint", f).CombinedOutput(); err != nil {
			t.Errorf("binary %q: plutil -lint: %v\n%s\n%s", bin, err, out, p)
		}
	}
}

// stubbornCtl is launchctl that will not take a loaded agent out.
type stubbornCtl struct{ fakeCtl }

func (c *stubbornCtl) Run(args ...string) (string, error) {
	if args[0] == "bootout" {
		c.calls = append(c.calls, args)
		return "Operation not permitted", errors.New("exit 1")
	}
	return c.fakeCtl.Run(args...)
}

// An agent that cannot be stopped is not reported as removed: the plist stays, so the next try finds what is still running, and
// the person is told that it did not work and why.
func TestUninstallSaysSoAndKeepsThePlistWhenTheAgentCannotBeStopped(t *testing.T) {
	s := spec(t)
	good := &fakeCtl{}
	if err := Install(s, good); err != nil {
		t.Fatal(err)
	}
	c := &stubbornCtl{fakeCtl{loaded: true}}
	err := Uninstall(s, c)
	if err == nil {
		t.Fatal("an agent that could not be stopped was reported as removed")
	}
	if !strings.Contains(err.Error(), "Operation not permitted") {
		t.Errorf("launchctl's own message is in the error: %v", err)
	}
	if _, serr := os.Stat(agentPath(s)); serr != nil {
		t.Error("the plist was removed although the agent is still running: the next login would still start it, and nothing would say why")
	}
}

// Replacing a running agent is what an upgrade is. launchctl bootout returns before the old process has gone, and a bootstrap in
// that moment fails with "Input/output error" (5). The installer must not give up on the first answer: the daemon would then
// stay down until the next login, which is what a person who just installed a new version sees as "it did not start".
func TestInstallRetriesWhileTheLabelIsStillBusyAfterTheOldAgentWasTakenOut(t *testing.T) {
	s := spec(t)
	var waits []time.Duration
	s.Wait = func(d time.Duration) { waits = append(waits, d) }
	ctl := &fakeCtl{loaded: true, busyFor: 3}
	if err := Install(s, ctl); err != nil {
		t.Fatalf("an upgrade over a running agent: %v", err)
	}
	if len(waits) != 3 || waits[0] != bootstrapPause {
		t.Errorf("each busy answer is waited out before the next try, not hammered: %v", waits)
	}
	if !ctl.loaded {
		t.Error("the new agent must be loaded in the end")
	}
	if n := strings.Count(ctl.names(), "bootstrap"); n != 4 {
		t.Errorf("three busy answers and one that worked: %d bootstraps; calls: %s", n, ctl.names())
	}
	if _, err := os.Stat(agentPath(s)); err != nil {
		t.Errorf("the plist stays: %v", err)
	}
}

func TestInstallGivesUpWhenTheLabelStaysBusyAndSaysSo(t *testing.T) {
	s := spec(t)
	s.Wait = func(time.Duration) {}
	ctl := &fakeCtl{busyFor: 1000}
	err := Install(s, ctl)
	if err == nil || !strings.Contains(err.Error(), "Input/output error") {
		t.Fatalf("a label that never frees up is an error that says what launchctl said: %v", err)
	}
	if n := strings.Count(ctl.names(), "bootstrap"); n != maxBootstrapTries {
		t.Errorf("%d tries, want %d", n, maxBootstrapTries)
	}
	if _, err := os.Stat(agentPath(s)); !os.IsNotExist(err) {
		t.Error("a plist that could not be loaded is not left behind")
	}
}

// Only the busy answer is retried. Anything else (a malformed plist, a domain that does not exist) will not be different in a
// second, and waiting for it would only delay the message.
func TestInstallDoesNotRetryAnAnswerThatTimeWillNotChange(t *testing.T) {
	s := spec(t)
	s.Wait = func(time.Duration) {}
	ctl := &fakeCtl{failOn: "bootstrap"}
	if err := Install(s, ctl); err == nil {
		t.Fatal("expected an error")
	}
	if n := strings.Count(ctl.names(), "bootstrap"); n != 1 {
		t.Errorf("%d bootstraps, want 1", n)
	}
}
