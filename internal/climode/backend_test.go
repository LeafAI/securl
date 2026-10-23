//go:build unix

package climode

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

// startDaemon runs a daemon in this process, on its own vault and a short socket path, and returns the socket.
func (r *rig) startDaemon(t *testing.T) (sock string, app *mcpserver.Server) {
	sock, app, _ = r.startDaemonWithStop(t)
	return sock, app
}

// startDaemonWithStop is startDaemon, and also returns what ends the daemon (its connections included), as a crash would.
func (r *rig) startDaemonWithStop(t *testing.T) (sock string, app *mcpserver.Server, stop func()) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "d.sock")
	opt := r.serverOptions()
	opt.Vault = r.vault
	srv, app, err := mcpserver.New(r.cfg, opt)
	if err != nil {
		t.Fatal(err)
	}
	l, err := daemon.Listen(sock)
	if err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() { daemon.Serve(ctx, l, srv, daemon.Options{}); close(done) }()
	var once sync.Once
	stop = func() { once.Do(func() { cancel(); <-done }) }
	t.Cleanup(func() { stop(); app.Close() })
	return sock, app, stop
}

func (r *rig) viaDaemon(sock string) { r.cfg.Daemon.Socket = sock }

func TestACommandUsesARunningDaemonAndLeavesItsVaultOpen(t *testing.T) {
	r := newRig(t, false)
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.secret = func() (string, error) { t.Error("the daemon's vault is open: nothing to ask"); return "", nil }
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if r.vault.State() != vault.Unlocked {
		t.Error("a command that used a daemon must not lock the daemon's vault: the next command would find it shut")
	}
	if r.asked != 0 {
		t.Errorf("asked for the passphrase %d times", r.asked)
	}
}

// A daemon that is locked is opened the way an agent opens it: the person types the passphrase on the page that a link leads
// to. The passphrase is never sent to the daemon over its socket. The socket is open to every process of the user, an agent's
// shell included, and no tool takes a passphrase precisely so that nothing an agent can reach could be made to carry one.
func TestACommandThatFindsTheDaemonsVaultLockedAsksThePersonByLinkAndNeverSendsAPassphrase(t *testing.T) {
	r := newRig(t, true)
	rec := r.withRobot()
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.secret = func() (string, error) {
		t.Error("a passphrase typed here would have to travel over the socket")
		return "", nil
	}
	code := r.run(t, "site", "list")
	if code == 0 {
		t.Fatalf("nobody typed on the page, so the command cannot succeed")
	}
	if rec.count() == 0 {
		t.Errorf("the person must have been sent the link for the daemon's vault; stderr: %s", r.errOut.String())
	}
	if r.asked != 0 {
		t.Errorf("the terminal passphrase prompt was used with a daemon: %d", r.asked)
	}
	if r.vault.State() != vault.Locked {
		t.Error("nothing opened the vault")
	}
}

func TestOnceThePersonHasUnlockedTheDaemonTheNextCommandsJustRun(t *testing.T) {
	r := newRig(t, true)
	sock, app := r.startDaemon(t)
	r.viaDaemon(sock)
	if err := app.UnlockWith(testPass); err != nil { // what the person's page does
		t.Fatal(err)
	}
	for i := 0; i < 2; i++ {
		if code := r.run(t, "site", "list"); code != 0 {
			t.Fatalf("run %d: exit %d: %s%s", i, code, r.out.String(), r.errOut.String())
		}
	}
	if r.vault.State() != vault.Unlocked {
		t.Error("commands do not lock a daemon's vault")
	}
}

func TestWithNoDaemonACommandFallsBackToItsOwnProcessAndSaysSo(t *testing.T) {
	r := newRig(t, false)
	r.cfg.Daemon.Socket = filepath.Join("/tmp", "no-such-dir-for-securl-test", "d.sock")
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if !strings.Contains(r.errOut.String(), "no daemon") {
		t.Errorf("the person is told that this command ran by itself, and how to start a daemon:\n%s", r.errOut.String())
	}
	if !strings.Contains(r.errOut.String(), "securl daemon") {
		t.Errorf("%s", r.errOut.String())
	}
	if r.out.Len() == 0 || !strings.HasPrefix(strings.TrimSpace(r.out.String()), "{") {
		t.Errorf("the answer is still the JSON on stdout: %q", r.out.String())
	}
}

func TestTheFallbackNoteIsOnlyWrittenOnce(t *testing.T) {
	r := newRig(t, false)
	r.cfg.Daemon.Socket = filepath.Join("/tmp", "no-such-dir-for-securl-test", "d.sock")
	r.run(t, "site", "list")
	if n := strings.Count(r.errOut.String(), "no daemon"); n != 1 {
		t.Errorf("the note appears %d times:\n%s", n, r.errOut.String())
	}
}

func TestNoDaemonFlagNeverTouchesTheSocket(t *testing.T) {
	r := newRig(t, false)
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.noDaemon = true
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if strings.Contains(r.errOut.String(), "no daemon") {
		t.Errorf("--no-daemon is a choice, not a fallback; there is nothing to apologise for:\n%s", r.errOut.String())
	}
	if r.vault.State() != vault.Locked {
		t.Error("in its own process the command locks the vault again when it ends")
	}
}

func TestADaemonOfAnotherVersionIsUsedButTheCommandSaysSo(t *testing.T) {
	r := newRig(t, false)
	old := mcpserver.Version
	mcpserver.Version = "0.0.1-daemon"
	sock, _ := r.startDaemon(t)
	mcpserver.Version = old
	r.viaDaemon(sock)
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errOut.String())
	}
	if !strings.Contains(r.errOut.String(), "0.0.1-daemon") {
		t.Errorf("a daemon that is older or newer than this command may answer differently: say which one it is:\n%s", r.errOut.String())
	}
}

// The command is already talking to a daemon when it stops. Running the tool again in this process could do twice what the
// first attempt may already have done (a change on a database), so it is an error and the person decides.
func TestADaemonThatStopsInTheMiddleIsAnErrorNotAFallback(t *testing.T) {
	r := newRig(t, false)
	sock, _, stop := r.startDaemonWithStop(t)
	r.viaDaemon(sock)
	r.afterConnect = stop
	code := r.run(t, "site", "list")
	if code == 0 {
		t.Fatalf("the daemon went away before the tool was called, yet the command succeeded: %s", r.out.String())
	}
	if r.out.Len() != 0 {
		t.Errorf("no answer may be printed for a call that never completed: %q", r.out.String())
	}
	if strings.Contains(r.errOut.String(), "runs by itself") {
		t.Errorf("a command that had started on a daemon was silently re-run in its own process:\n%s", r.errOut.String())
	}
	if code != exitSetup {
		t.Errorf("exit %d, want %d", code, exitSetup)
	}
}

func TestStandardInputIsOnlyReadByTheCommandThatWasGivenIt(t *testing.T) {
	r := newRig(t, false)
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.in = "select 1\n"
	// the flag value `-` is read by the command and sent as the value; it is never sent to the daemon as a stream
	if code := r.run(t, "db", "query", "--target", "none", "--sql", "-"); code != exitToolError {
		t.Fatalf("exit %d", code)
	}
	if m := r.json(t); m["code"] != "unknown_target" {
		t.Errorf("%v", m)
	}
	_ = time.Second
}

// A command that finished with a daemon leaves the daemon exactly as it found it: nothing it does may lock the vault, close
// the daemon's tunnels, or drain its logins. (That the command's own process is locked at the end is another test.)
func TestFinishingACommandDoesNotLockTheDaemonOrAffectTheNext(t *testing.T) {
	r := newRig(t, false)
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	for i := 0; i < 3; i++ {
		if code := r.run(t, "site", "list"); code != 0 {
			t.Fatalf("run %d: exit %d: %s", i, code, r.errOut.String())
		}
		if r.vault.State() != vault.Unlocked {
			t.Fatalf("after run %d the daemon's vault is %v", i, r.vault.State())
		}
	}
}

// Something on the socket path that is not a daemon is not "no daemon": the person expected one, and running the command
// by itself would hide that from them (and lock the vault they thought was kept open).
func TestSomethingThatIsNotADaemonOnTheSocketPathIsAnErrorNotAFallback(t *testing.T) {
	r := newRig(t, false)
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
	code := r.run(t, "site", "list")
	if code != exitSetup {
		t.Errorf("exit %d, want %d\n%s", code, exitSetup, r.errOut.String())
	}
	if r.out.Len() != 0 {
		t.Errorf("nothing ran: %q", r.out.String())
	}
	if strings.Contains(r.errOut.String(), "runs by itself") {
		t.Errorf("the command went on without a daemon:\n%s", r.errOut.String())
	}
	if !strings.Contains(r.errOut.String(), "daemon did not answer") {
		t.Errorf("the error says that it is the daemon that did not answer:\n%s", r.errOut.String())
	}
}

// A listener that accepts and says nothing is a daemon that hangs: the command must not wait for ever for it.
func TestADaemonThatNeverAnswersTheHandshakeIsGivenUpOn(t *testing.T) {
	r := newRig(t, false)
	dir, err := os.MkdirTemp("/tmp", "sd")
	if err != nil {
		t.Fatal(err)
	}
	defer os.RemoveAll(dir)
	sock := filepath.Join(dir, "d.sock")
	l, err := net.Listen("unix", sock)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		for {
			c, err := l.Accept()
			if err != nil {
				return
			}
			defer c.Close() // accepted, never answered
		}
	}()
	r.viaDaemon(sock)
	r.handshake = 500 * time.Millisecond
	start := time.Now()
	code := r.run(t, "site", "list")
	if code != exitSetup {
		t.Errorf("exit %d, want %d\n%s", code, exitSetup, r.errOut.String())
	}
	if took := time.Since(start); took > 20*time.Second {
		t.Errorf("the command waited %s for a daemon that never answered", took)
	}
}
