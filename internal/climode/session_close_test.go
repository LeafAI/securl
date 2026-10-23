package climode

import (
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/web"
)

// `securl session close` does not close anything on its own say-so: it asks the person, like `securl unlock` does, and waits.
// The command line is a client of the server's question, not a way around it.
func TestSessionCloseFromTheCommandLineWaitsForThePersonAndThenCloses(t *testing.T) {
	browsertest.Require(t)
	gl := fakeGitLab()
	defer gl.Close()
	r := newRig(t, true)
	r.secret = func() (string, error) { return testPass, nil }
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Web.TTL = time.Minute
	rec := r.withRobot()
	r.cfg.Web.TTL = time.Minute
	// The first call gives up waiting after a second and answers pending, so the command has to continue with the id and the same
	// scope. With the default it would wait inside the first call, and the continuation would never be exercised.
	r.cfg.MCP.MaxBlockSeconds = 1

	// a saved session, as a person's login leaves it
	stderr := &syncBuf{}
	env := r.envFor()
	env.Err = stderr
	env.Secret = func() (string, error) { return testPass, nil }
	done := make(chan int, 1)
	go func() {
		done <- Run(t.Context(), []string{"session", "open", "--url", gl.URL, "--site", "gitlab"}, env)
	}()
	browsertest.Drive(t, pages, browsertest.Fragment(linkIn(t, rec, 1)), "submit", `{"username":"alice","password":"pw-SECRET-1"}`, "")
	if code := <-done; code != 0 {
		t.Fatalf("login: exit %d: %s", code, stderr.String())
	}

	// asking to close it is asked of the person; until they answer, the command waits and nothing is closed
	r.out.Reset()
	stderr2 := &syncBuf{}
	env2 := r.envFor()
	env2.Err = stderr2
	env2.Secret = func() (string, error) { return testPass, nil }
	done2 := make(chan int, 1)
	go func() {
		done2 <- Run(t.Context(), []string{"session", "close", "--url", gl.URL}, env2)
	}()
	link := linkIn(t, rec, 2)
	select {
	case code := <-done2:
		t.Fatalf("the command ended (%d) before anybody confirmed:\n%s%s", code, r.out.String(), stderr2.String())
	case <-time.After(1500 * time.Millisecond):
	}
	if msg := rec.msgs[1]; !strings.Contains(msg, strings.TrimPrefix(gl.URL, "http://")) {
		t.Errorf("the message names what is closed:\n%s", msg)
	}
	if page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"confirm":"DELETE"}`, "").Msg; !strings.Contains(page, "Done") {
		t.Fatalf("page said %q", page)
	}
	select {
	case code := <-done2:
		if code != 0 {
			t.Fatalf("exit %d\n%s%s", code, r.out.String(), stderr2.String())
		}
	case <-time.After(60 * time.Second):
		t.Fatal("the command did not finish after the person confirmed")
	}
	if m := r.json(t); m["status"] != "closed" || m["removed"] != float64(1) {
		t.Errorf("the answer: %s", r.out.String())
	}
}

func TestSessionCloseRejectedOnThePageExitsWithAnErrorAndClosesNothing(t *testing.T) {
	browsertest.Require(t)
	gl := fakeGitLab()
	defer gl.Close()
	r := newRig(t, true)
	r.secret = func() (string, error) { return testPass, nil }
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Web.TTL = time.Minute
	rec := r.withRobot()
	r.cfg.Web.TTL = time.Minute
	login := func() {
		stderr := &syncBuf{}
		env := r.envFor()
		env.Err = stderr
		env.Secret = func() (string, error) { return testPass, nil }
		done := make(chan int, 1)
		go func() {
			done <- Run(t.Context(), []string{"session", "open", "--url", gl.URL, "--site", "gitlab"}, env)
		}()
		browsertest.Drive(t, pages, browsertest.Fragment(linkIn(t, rec, 1)), "submit", `{"username":"alice","password":"pw-SECRET-1"}`, "")
		if code := <-done; code != 0 {
			t.Fatalf("login: exit %d: %s", code, stderr.String())
		}
	}
	login()
	r.out.Reset()
	env := r.envFor()
	env.Secret = func() (string, error) { return testPass, nil }
	done := make(chan int, 1)
	go func() { done <- Run(t.Context(), []string{"session", "close", "--all"}, env) }()
	browsertest.Drive(t, pages, browsertest.Fragment(linkIn(t, rec, 2)), "reject", "", "keep it")
	if code := <-done; code != exitToolError {
		t.Fatalf("a rejection is a tool error (1), got %d: %s", code, r.out.String())
	}
	if m := r.json(t); m["code"] != "user_rejected" {
		t.Errorf("%s", r.out.String())
	}
	r.out.Reset()
	if code := r.run(t, "session", "list"); code != 0 || !strings.Contains(r.out.String(), strings.TrimPrefix(gl.URL, "http://")) {
		t.Errorf("the session must still be there (exit %d): %s", code, r.out.String())
	}
}

// `site list` says which websites securl knows; it holds nothing secret and the server answers it with the vault shut, so the
// command must not make a person unlock the vault for it.
func TestSiteListNeedsNoVaultAndAsksNobody(t *testing.T) {
	r := newRig(t, true)
	rec := r.withRobot()
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if !strings.Contains(r.out.String(), `"sites"`) {
		t.Errorf("%s", r.out.String())
	}
	if n := len(rec.msgs); n != 0 {
		t.Errorf("a person was asked to unlock the vault for a list of site names: %d messages", n)
	}
	if r.vault.State().String() != "locked" {
		t.Error("the vault was opened")
	}
}

// A command that finds the vault already open must not say that it is asking anybody: nobody is asked, and a line that says so
// sends a person looking for a message that was never sent.
func TestACommandOnAnOpenDaemonDoesNotSayItIsAskingForTheVault(t *testing.T) {
	r := newRig(t, false)
	rec := r.withRobot()
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	if code := r.run(t, "session", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if strings.Contains(r.errOut.String(), "asking the person") {
		t.Errorf("the vault was open, nobody was asked:\n%s", r.errOut.String())
	}
	if rec.count() != 0 {
		t.Errorf("%d messages", rec.count())
	}
}

func TestACommandOnALockedDaemonStillSaysItIsAskingBeforeItWaits(t *testing.T) {
	r := newRig(t, true)
	rec := r.withRobot()
	r.cfg.Vault.UnlockTTL = time.Second
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)
	r.run(t, "session", "list")
	if !strings.Contains(r.errOut.String(), "asking the person to open the vault") {
		t.Errorf("while the person has the link the terminal must say what it waits for:\n%s", r.errOut.String())
	}
	if rec.count() == 0 {
		t.Error("a locked vault is asked for")
	}
}
