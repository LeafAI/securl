//go:build unix

package climode

import (
	"regexp"
	"strings"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/browsertest"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

var stderrLinkRE = regexp.MustCompile(`(file://\S+#\S+)`)

// With no robot and security.link_via_agent, the link of an unlock goes to the terminal of `securl unlock`, and only there: it
// is printed on stderr, never on stdout, and nothing is sent anywhere else. The person opens it and types the passphrase.
// Neither feature can show this alone: one makes the link available, the other is the command that prints it.
func TestUnlockWithNoRobotPrintsTheLinkOnStderrAndTheVaultOpens(t *testing.T) {
	browsertest.Require(t)
	r := newRig(t, true)
	pages := t.TempDir()
	if err := web.WriteTo(pages); err != nil {
		t.Fatal(err)
	}
	r.cfg.Web.PageURL = "file://" + pages + "/index.html"
	r.cfg.Vault.UnlockTTL = time.Minute
	r.cfg.Security.LinkViaAgent = true
	r.server.Tunnels = localTunnels{}
	sock, _ := r.startDaemon(t)
	r.viaDaemon(sock)

	env := r.envFor()
	env.NoDaemon = false
	sw := &syncWriter{w: &r.errOut}
	env.Err = sw
	done := make(chan int, 1)
	go func() { done <- Unlock(t.Context(), env) }()

	var link string
	deadline := time.Now().Add(30 * time.Second)
	for link == "" && time.Now().Before(deadline) {
		link = stderrLinkRE.FindString(sw.String())
		time.Sleep(50 * time.Millisecond)
	}
	if link == "" {
		t.Fatalf("no link on stderr:\n%s", sw.String())
	}
	if !strings.Contains(sw.String(), "key code") {
		t.Errorf("the key code is printed with the link:\n%s", sw.String())
	}
	if page := browsertest.Drive(t, pages, browsertest.Fragment(link), "submit", `{"passphrase":"`+testPass+`"}`, "").Msg; !strings.Contains(page, "Done") {
		t.Fatalf("the unlock page said %q", page)
	}
	if code := <-done; code != 0 {
		t.Fatalf("exit %d\n%s", code, sw.String())
	}
	if r.vault.State() != vault.Unlocked {
		t.Error("the vault is open")
	}
	if strings.Contains(r.out.String(), "file://") || strings.Contains(r.out.String(), "key_code") {
		t.Errorf("a link is for the person at the terminal: it must not be in the answer on stdout\n%s", r.out.String())
	}
	if strings.Contains(r.out.String()+sw.String(), testPass) {
		t.Error("the passphrase is in the output")
	}
}
