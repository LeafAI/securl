//go:build unix

package climode

import (
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

// One daemon, three commands: the person unlocks the daemon once, logs in once, and every later command, from any shell, finds
// both done. No credential reaches any command's output at any point.
func TestOneDaemonServesALoginAndTheCommandsThatFollowIt(t *testing.T) {
	browsertest.Require(t)
	gl := fakeGitLab()
	defer gl.Close()

	r := newRig(t, true)
	rec := r.withRobot()
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Web.TTL = time.Minute
	r.cfg.Vault.UnlockTTL = time.Minute
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)

	// 1. the daemon is locked: a command asks the person to open it, by link; the person types the passphrase on the page
	done := make(chan int, 1)
	var first rig
	first.cfg, first.vault, first.server = r.cfg, r.vault, r.server
	go func() { done <- first.run(t, "session", "list") }()
	link := linkIn(t, rec, 1)
	page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"passphrase":"`+testPass+`"}`, "").Msg
	if !strings.Contains(page, "Done") {
		t.Fatalf("the unlock page said %q", page)
	}
	if code := <-done; code != 0 {
		t.Fatalf("the command that waited for the unlock: exit %d\n%s%s", code, first.out.String(), first.errOut.String())
	}
	if r.vault.State() != vault.Unlocked {
		t.Fatal("the daemon's vault is open after the person typed the passphrase")
	}

	// 2. a login, from a second command, with the person typing on the page
	var second rig
	second.cfg, second.vault, second.server = r.cfg, r.vault, r.server
	go func() { done <- second.run(t, "session", "open", "--url", gl.URL, "--site", "gitlab") }()
	link = linkIn(t, rec, 2)
	if page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"username":"alice","password":"pw-SECRET-1"}`, "").Msg; !strings.Contains(page, "Done") {
		t.Fatalf("the login page said %q", page)
	}
	if code := <-done; code != 0 {
		t.Fatalf("session open: exit %d\n%s%s", code, second.out.String(), second.errOut.String())
	}

	// 3. a third command, with nobody to ask, uses the session that the second one made
	var third rig
	third.cfg, third.vault, third.server = r.cfg, r.vault, r.server
	if code := third.run(t, "request", "--url", gl.URL, "--method", "GET", "--path", "/api/v4/user"); code != 0 {
		t.Fatalf("request: exit %d\n%s%s", code, third.out.String(), third.errOut.String())
	}
	if !strings.Contains(third.out.String(), "alice") {
		t.Errorf("the session of the second command was not used by the third: %s", third.out.String())
	}
	if rec.count() != 2 {
		t.Errorf("the person was asked %d times: once to unlock, once to log in, and not for the request", rec.count())
	}

	for name, c := range map[string]*rig{"first": &first, "second": &second, "third": &third} {
		for _, secret := range []string{"pw-SECRET-1", "COOKIE-SECRET-9", "_gitlab_session", testPass} {
			if strings.Contains(c.out.String(), secret) || strings.Contains(c.errOut.String(), secret) {
				t.Errorf("the %s command's output carries %q", name, secret)
			}
		}
	}
}

// The documents promise that an unlocked daemon locks itself again after vault.idle_lock. That promise is what bounds the
// exposure of running one, so it is held by a test: after the idle time the next command finds the vault shut and has to ask.
func TestADaemonLocksItselfAfterTheIdleTimeAndTheNextCommandHasToAsk(t *testing.T) {
	r := newRig(t, false)
	rec := r.withRobot()
	r.cfg.Vault.IdleLock = 400 * time.Millisecond
	sock, app := r.startDaemon(t)
	r.viaDaemon(sock)
	_ = app

	if code := r.run(t, "session", "list"); code != 0 {
		t.Fatalf("exit %d: %s", code, r.errOut.String())
	}
	if r.vault.State() != vault.Unlocked {
		t.Fatal("open straight after use")
	}
	time.Sleep(900 * time.Millisecond) // more than twice the idle time, with nobody using the daemon
	if st := r.vault.State(); st != vault.Locked {
		t.Fatalf("the daemon's vault is %v after the idle time; the documents say it locks", st)
	}
	code := r.run(t, "session", "list")
	if code == 0 {
		t.Fatalf("a locked daemon answered a tool that needs the vault: %s", r.out.String())
	}
	if rec.count() == 0 {
		t.Errorf("the next command must ask the person to unlock again; stderr: %s", r.errOut.String())
	}
}

// Use keeps the daemon open: the idle time runs from the last use, not from the unlock.
func TestUseKeepsADaemonOpenPastTheIdleTime(t *testing.T) {
	r := newRig(t, false)
	r.cfg.Vault.IdleLock = 700 * time.Millisecond
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	for i := 0; i < 4; i++ {
		if code := r.run(t, "session", "list"); code != 0 {
			t.Fatalf("run %d (the daemon locked while it was in use): exit %d: %s", i, code, r.errOut.String())
		}
		time.Sleep(300 * time.Millisecond)
	}
}
