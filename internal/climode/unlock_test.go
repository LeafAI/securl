//go:build unix

package climode

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

func (r *rig) unlock(t *testing.T) int {
	t.Helper()
	r.out.Reset()
	r.errOut.Reset()
	env := r.envFor()
	env.NoDaemon = r.noDaemon || r.cfg.Daemon.Socket == ""
	env.Err = &syncWriter{w: &r.errOut}
	env.DaemonHandshake = r.handshake
	if r.secret != nil {
		env.Secret = func() (string, error) { r.asked++; return r.secret() }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Unlock(ctx, env)
}

func TestUnlockOnAnOpenDaemonSaysSoAndAsksNobody(t *testing.T) {
	r := newRig(t, false)
	rec := r.withRobot()
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	if code := r.unlock(t); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if rec.count() != 0 {
		t.Errorf("nobody should be asked to open a vault that is open: %d messages", rec.count())
	}
	var m map[string]any
	if err := json.Unmarshal(r.out.Bytes(), &m); err != nil || m["status"] != "unlocked" || m["already_unlocked"] != true {
		t.Errorf("the answer says it was already open: %s", r.out.String())
	}
}

func TestUnlockOfALockedDaemonAsksThePersonByLinkAndNeverTakesAPassphraseHere(t *testing.T) {
	browsertest.Require(t)
	r := newRig(t, true)
	rec := r.withRobot()
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Vault.UnlockTTL = time.Minute
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	// a terminal is present: the passphrase is still not asked for here, because it would travel over the socket
	r.secret = func() (string, error) { t.Error("securl unlock read a passphrase on the terminal"); return "", nil }

	done := make(chan int, 1)
	go func() { done <- r.unlock(t) }()
	link := linkIn(t, rec, 1)
	if page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"passphrase":"`+testPass+`"}`, "").Msg; !strings.Contains(page, "Done") {
		t.Fatalf("the unlock page said %q", page)
	}
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s%s", code, r.out.String(), r.errOut.String())
	}
	if r.vault.State() != vault.Unlocked {
		t.Error("the daemon's vault is open")
	}
	if strings.Contains(r.out.String()+r.errOut.String(), testPass) {
		t.Error("the passphrase is in the output")
	}
	if r.asked != 0 {
		t.Errorf("asked for a passphrase %d times", r.asked)
	}
}

func TestUnlockWithNoDaemonIsAnErrorThatSaysHowToStartOne(t *testing.T) {
	r := newRig(t, true)
	r.cfg.Daemon.Socket = "/tmp/no-such-dir-for-securl-test/d.sock"
	code := r.unlock(t)
	if code != exitSetup {
		t.Errorf("exit %d, want %d", code, exitSetup)
	}
	if !strings.Contains(r.errOut.String(), "securl daemon") {
		t.Errorf("the message says how to start a daemon:\n%s", r.errOut.String())
	}
	if r.out.Len() != 0 {
		t.Errorf("nothing was done, so no answer: %q", r.out.String())
	}
	if r.vault.State() != vault.Locked {
		t.Error("with no daemon there is nothing to open: opening the vault of this process would help nobody")
	}
}

func TestUnlockNeverFallsBackToOpeningTheVaultInItsOwnProcess(t *testing.T) {
	r := newRig(t, true)
	r.secret = func() (string, error) {
		t.Error("a passphrase was asked for although there is no daemon to give it to")
		return testPass, nil
	}
	r.cfg.Daemon.Socket = "/tmp/no-such-dir-for-securl-test/d.sock"
	r.unlock(t)
	if r.vault.State() != vault.Locked || r.asked != 0 {
		t.Errorf("state %v, asked %d", r.vault.State(), r.asked)
	}
}

func TestUnlockWithNoDaemonFlagIsRefusedAsMeaningless(t *testing.T) {
	r := newRig(t, true)
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.noDaemon = true
	code := r.unlock(t)
	if code != exitUsage {
		t.Errorf("exit %d, want %d", code, exitUsage)
	}
	if !strings.Contains(r.errOut.String(), "daemon") {
		t.Errorf("%s", r.errOut.String())
	}
	if r.vault.State() != vault.Locked {
		t.Error("nothing may be opened")
	}
}

func TestUnlockWhenNobodyAnswersEndsPendingWithTheContinuation(t *testing.T) {
	r := newRig(t, true)
	r.withRobot()
	r.cfg.Vault.UnlockTTL = 2 * time.Second
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	code := r.unlock(t)
	if code == 0 {
		t.Fatalf("nobody typed anything, yet the vault was reported open: %s", r.out.String())
	}
	if r.vault.State() != vault.Locked {
		t.Error("still locked")
	}
	if code != exitPending && code != exitToolError {
		t.Errorf("exit %d: a person who did not answer is either pending (4) or the tool's own error (1)", code)
	}
}

func TestUnlockSaysWhatItIsWaitingForOnStderrAndKeepsStdoutForTheAnswer(t *testing.T) {
	r := newRig(t, true)
	r.withRobot()
	r.cfg.Vault.UnlockTTL = 2 * time.Second
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.unlock(t)
	if !strings.Contains(r.errOut.String(), "asking the person") || !strings.Contains(r.errOut.String(), "nothing is typed here") {
		t.Errorf("the terminal says, before it waits, what it waits for and that nothing is typed here:\n%s", r.errOut.String())
	}
	if r.out.Len() > 0 {
		var m map[string]any
		if err := json.Unmarshal(r.out.Bytes(), &m); err != nil {
			t.Errorf("stdout is the answer and only the answer: %q", r.out.String())
		}
	}
}

// The command talks to the daemon: a version mismatch is said, as for any command.
func TestUnlockSaysWhenTheDaemonIsAnotherVersion(t *testing.T) {
	r := newRig(t, false)
	r.withRobot()
	old := mcpserverVersion()
	setMCPVersion("0.0.1-daemon")
	sock, _ := r.startDaemon(t)
	setMCPVersion(old)
	r.viaDaemon(sock)
	r.unlock(t)
	if !strings.Contains(r.errOut.String(), "0.0.1-daemon") {
		t.Errorf("%s", r.errOut.String())
	}
}

// Something on the socket path that is not a daemon is not "no daemon": the person expected one, and a message that says there
// is none sends them to start a second one on top of a file that is in the way.
func TestUnlockOfSomethingThatIsNotADaemonSaysItDidNotAnswerRatherThanThatThereIsNone(t *testing.T) {
	r := newRig(t, true)
	dir, err := os.MkdirTemp("/tmp", "sd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	if err := os.WriteFile(sock, []byte("not a socket"), 0o600); err != nil {
		t.Fatal(err)
	}
	r.viaDaemon(sock)
	if code := r.unlock(t); code != exitSetup {
		t.Errorf("exit %d, want %d", code, exitSetup)
	}
	if !strings.Contains(r.errOut.String(), "did not answer") {
		t.Errorf("%s", r.errOut.String())
	}
	if strings.Contains(r.errOut.String(), "no daemon is running") {
		t.Errorf("a file that is in the way is not an absent daemon:\n%s", r.errOut.String())
	}
}

// Nobody answered: the command says so in its exit code, whichever way the tool reports it. The daemon's own error (a person
// who did not come in time) is the tool's answer, and is passed on as it is; "pending" is what a wait that was cut short
// gives. Each has its own code, and a script tells them apart.
func TestUnlockPassesOnWhatTheDaemonSaidWhenNobodyCame(t *testing.T) {
	r := newRig(t, true)
	r.withRobot()
	r.cfg.Vault.UnlockTTL = 1500 * time.Millisecond
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	code := r.unlock(t)
	var m map[string]any
	if err := json.Unmarshal(r.out.Bytes(), &m); err != nil {
		t.Fatalf("stdout is not the answer: %q", r.out.String())
	}
	switch m["code"] {
	case "human_timeout":
		if code != exitToolError {
			t.Errorf("the daemon's own error is exit %d, got %d", exitToolError, code)
		}
	default:
		if m["status"] != "pending" || code != exitPending {
			t.Errorf("neither the daemon's error nor a pending answer: %v (exit %d)", m, code)
		}
	}
}

// Ctrl-C while the person has not answered: the command stops waiting and says that the vault is still shut, with the code that
// means "a person has not answered yet". The unlock itself is not undone: the link in the person's hands is still good until
// it expires, and a later `securl unlock` joins it instead of sending another.
func TestInterruptingUnlockWhileWaitingExitsWithTheCodeForPendingAndLeavesTheVaultShut(t *testing.T) {
	r := newRig(t, true)
	r.withRobot()
	r.cfg.Vault.UnlockTTL = time.Minute
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)

	env := r.envFor()
	env.NoDaemon = false
	sw := &syncWriter{w: &r.errOut}
	env.Err = sw
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan int, 1)
	go func() { done <- Unlock(ctx, env) }()
	deadline := time.Now().Add(20 * time.Second)
	for !strings.Contains(sw.String(), "asking the person") && time.Now().Before(deadline) {
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(300 * time.Millisecond) // the link has been sent and the command is waiting
	cancel()
	select {
	case code := <-done:
		if code == 0 {
			t.Fatalf("an interrupted wait reported the vault open: %s", r.out.String())
		}
		if code != exitPending {
			t.Errorf("exit %d, want %d: a person who has not answered yet is pending, not a failure to set up\n%s", code, exitPending, sw.String())
		}
		if strings.Contains(sw.String(), "context") {
			t.Errorf("the message is about the person, not about a Go context:\n%s", sw.String())
		}
		if !strings.Contains(sw.String(), "securl unlock") {
			t.Errorf("it says how to carry on (run securl unlock again: it joins the same link):\n%s", sw.String())
		}
	case <-time.After(20 * time.Second):
		t.Fatal("the command did not stop when it was interrupted")
	}
	if r.vault.State() != vault.Locked {
		t.Error("an interrupted unlock must leave the vault shut")
	}
}
