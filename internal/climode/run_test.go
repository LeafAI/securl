package climode

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/mcpserver"
	"github.com/LeafAI/securl/internal/vault"
)

const testPass = "correct horse battery staple"

type rig struct {
	server mcpserver.Options
	cfg    *config.Config
	vault  *vault.Vault
	out    bytes.Buffer
	errOut bytes.Buffer
	in     string
	secret func() (string, error) // nil: not a terminal
	asked  int                    // how many times the passphrase was asked for

	noDaemon     bool          // --no-daemon
	handshake    time.Duration // how long to wait for a daemon's answer to the handshake (0: the default)
	afterConnect func()        // called once a command has connected to its backend, before it calls the tool
}

func newRig(t *testing.T, locked bool) *rig {
	t.Helper()
	dir := t.TempDir()
	cfg, _ := config.Load(dir + "/none.yaml")
	cfg.Security.AllowLocalAddresses = true
	r := &rig{cfg: cfg, vault: vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)}
	if err := r.vault.Init(testPass); err != nil {
		t.Fatal(err)
	}
	if locked {
		r.vault.Lock()
	}
	return r
}

func (r *rig) run(t *testing.T, args ...string) int {
	t.Helper()
	r.out.Reset()
	r.errOut.Reset()
	env := Env{Config: r.cfg, Vault: r.vault, In: strings.NewReader(r.in), Out: &r.out, Err: &syncWriter{w: &r.errOut},
		Server: r.serverOptions(), NoDaemon: r.noDaemon, AfterConnect: r.afterConnect, DaemonHandshake: r.handshake}
	if r.cfg.Daemon.Socket == "" {
		// Not one of the daemon tests: no daemon may be reached by accident, whatever is running on the machine that tests.
		env.NoDaemon = true
	}
	if r.secret != nil {
		env.Secret = func() (string, error) { r.asked++; return r.secret() }
	}
	ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
	defer cancel()
	return Run(ctx, args, env)
}

func (r *rig) envFor() Env {
	return Env{Config: r.cfg, Vault: r.vault, In: strings.NewReader(""), Out: &r.out, Err: &r.errOut, Server: r.serverOptions(), NoDaemon: true}
}

// toolNames asks the server what tools it has, as a client does.
func (r *rig) toolNames(t *testing.T) []string {
	t.Helper()
	cs, closeFn, _, err := connectApp(context.Background(), r.envFor(), false)
	if err != nil {
		t.Fatal(err)
	}
	defer closeFn()
	res, err := cs.ListTools(context.Background(), &mcp.ListToolsParams{})
	if err != nil {
		t.Fatal(err)
	}
	var names []string
	for _, tl := range res.Tools {
		names = append(names, tl.Name)
	}
	return names
}

func (r *rig) serverOptions() mcpserver.Options { return r.server }

func (r *rig) json(t *testing.T) map[string]any {
	t.Helper()
	var m map[string]any
	if err := json.Unmarshal(r.out.Bytes(), &m); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, r.out.String())
	}
	return m
}

func TestAToolRunsFromTheCommandLineAndPrintsItsAnswerAsJSON(t *testing.T) {
	r := newRig(t, false)
	if code := r.run(t, "site", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	sites, _ := r.json(t)["sites"].([]any)
	if len(sites) == 0 {
		t.Errorf("site_list answered no sites: %s", r.out.String())
	}
	if r.errOut.Len() != 0 {
		t.Errorf("a plain answer writes nothing to stderr: %q", r.errOut.String())
	}
}

func TestAToolErrorIsPrintedAsJSONAndExitsNonZero(t *testing.T) {
	r := newRig(t, false)
	code := r.run(t, "db", "query", "--target", "nope", "--sql", "select 1")
	if code != exitToolError {
		t.Errorf("exit %d, want %d", code, exitToolError)
	}
	if m := r.json(t); m["code"] != "unknown_target" {
		t.Errorf("the error is the tool's own: %v", m)
	}
}

func TestAFlagProblemIsAUsageErrorAndNothingRuns(t *testing.T) {
	r := newRig(t, false)
	for _, args := range [][]string{
		{"db", "query", "--target", "x"}, // --sql missing
		{"db", "query", "--bogus", "1"},  // unknown flag
		{"session", "wait", "--max-block-seconds", "soon", "--login-id", "x"},
	} {
		if code := r.run(t, args...); code != exitUsage {
			t.Errorf("%v: exit %d, want %d", args, code, exitUsage)
		}
		if r.out.Len() != 0 {
			t.Errorf("%v: nothing may reach stdout: %q", args, r.out.String())
		}
		if !strings.Contains(r.errOut.String(), "--help") {
			t.Errorf("%v: the message points at --help: %q", args, r.errOut.String())
		}
	}
}

func TestHelpNeedsNoVaultAndNoConfig(t *testing.T) {
	r := newRig(t, true)
	if code := r.run(t, "db", "query", "--help"); code != 0 {
		t.Fatalf("exit %d", code)
	}
	if !strings.Contains(r.out.String(), "--sql") || r.asked != 0 {
		t.Errorf("%q asked=%d", r.out.String(), r.asked)
	}
}

func TestAnUnknownCommandIsAUsageErrorThatListsTheRealOnes(t *testing.T) {
	r := newRig(t, false)
	if code := r.run(t, "frobnicate"); code != exitUsage {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(r.errOut.String(), "session") || !strings.Contains(r.errOut.String(), "request") {
		t.Errorf("%q", r.errOut.String())
	}
}

// ---- the vault ----

func TestOnATerminalTheVaultIsOpenedWithThePassphraseTypedThereAndLockedAgain(t *testing.T) {
	r := newRig(t, true)
	r.secret = func() (string, error) { return testPass, nil }
	if code := r.run(t, "session", "list"); code != 0 {
		t.Fatalf("exit %d: %s%s", code, r.out.String(), r.errOut.String())
	}
	if r.asked != 1 {
		t.Errorf("the passphrase is asked for once, was %d", r.asked)
	}
	if r.vault.State() != vault.Locked {
		t.Error("the vault must be locked again when the command is over: it is open only while this process runs")
	}
	if strings.Contains(r.out.String()+r.errOut.String(), testPass) {
		t.Error("the passphrase is in the output")
	}
}

func TestAWrongPassphraseIsAskedForAgainThenGivenUp(t *testing.T) {
	r := newRig(t, true)
	tries := []string{"not it", "also not it", testPass}
	r.secret = func() (string, error) { p := tries[0]; tries = tries[1:]; return p, nil }
	if code := r.run(t, "session", "list"); code != 0 {
		t.Fatalf("the third try is right: exit %d: %s", code, r.errOut.String())
	}
	if r.asked != 3 {
		t.Errorf("asked %d times", r.asked)
	}

	r2 := newRig(t, true)
	r2.secret = func() (string, error) { return "never right", nil }
	if code := r2.run(t, "session", "list"); code != exitSetup {
		t.Errorf("exit %d, want %d", code, exitSetup)
	}
	if r2.asked != 3 {
		t.Errorf("it gives up after three: asked %d", r2.asked)
	}
	if r2.out.Len() != 0 {
		t.Errorf("nothing ran: %q", r2.out.String())
	}
}

// recorder stands in for the DingTalk robot: it keeps the messages, so a test can see that the person was asked.
type recorder struct {
	mu   sync.Mutex
	msgs []string
}

func (r *recorder) Markdown(_ context.Context, _, text string) error {
	r.mu.Lock()
	r.msgs = append(r.msgs, text)
	r.mu.Unlock()
	return nil
}

func (r *recorder) count() int {
	r.mu.Lock()
	defer r.mu.Unlock()
	return len(r.msgs)
}

type localTunnel struct{ url string }

func (l localTunnel) PublicURL() string   { return l.url }
func (localTunnel) Done() <-chan struct{} { return nil }
func (localTunnel) Close()                {}

type localTunnels struct{}

func (localTunnels) Start(_ context.Context, port int) (flow.Tunnel, error) {
	return localTunnel{fmt.Sprintf("http://127.0.0.1:%d", port)}, nil
}

// withRobot gives the rig a robot and a tunnel that need nothing outside this process, and a short wait for the person.
func (r *rig) withRobot() *recorder {
	rec := &recorder{}
	r.server.Notifier, r.server.Tunnels = rec, localTunnels{}
	r.cfg.Web.TTL = 3 * time.Second
	r.cfg.Vault.UnlockTTL = 3 * time.Second
	return rec
}

// A passphrase on standard input is what a script would pipe in. Reading it would make the passphrase a thing that
// sits in shell history and process listings, which is what the vault is built to avoid: the vault is opened remotely
// instead, and nobody has typed on the page, so the command ends without it being open.
func TestWithNoTerminalThePassphraseIsNeverReadFromStandardInput(t *testing.T) {
	r := newRig(t, true)
	rec := r.withRobot()
	r.in = testPass + "\n"
	code := r.run(t, "session", "list")
	if r.vault.State() != vault.Locked {
		t.Fatal("a passphrase on stdin opened the vault")
	}
	if code == 0 {
		t.Errorf("nobody typed the passphrase on the page, so the command cannot succeed (exit %d)", code)
	}
	if rec.count() == 0 {
		t.Errorf("the person must have been asked in the usual way (the remote unlock); stderr: %s", r.errOut.String())
	}
	if r.out.Len() != 0 {
		t.Errorf("no tool ran: %q", r.out.String())
	}
}

func TestThePassphraseIsNotTakenFromTheEnvironmentEither(t *testing.T) {
	t.Setenv("SECURL_PASSPHRASE", testPass)
	t.Setenv("SECURL_VAULT_PASSPHRASE", testPass)
	r := newRig(t, true)
	rec := r.withRobot()
	r.run(t, "session", "list")
	if r.vault.State() != vault.Locked {
		t.Fatal("an environment variable opened the vault")
	}
	if rec.count() == 0 {
		t.Errorf("the person must have been asked: %s", r.errOut.String())
	}
}

func TestWithoutAVaultTheCommandSaysSoAndRunsNothing(t *testing.T) {
	dir := t.TempDir()
	cfg, _ := config.Load(dir + "/none.yaml")
	r := &rig{cfg: cfg, vault: vault.NewWithCost(cfg.Vault.Dir, 1, 8, 1)}
	if code := r.run(t, "session", "list"); code != exitSetup {
		t.Errorf("exit %d", code)
	}
	if !strings.Contains(r.errOut.String(), "securl vault init") {
		t.Errorf("%q", r.errOut.String())
	}
}

func TestAnOpenVaultIsLeftAsItWasFoundByNothingButTheRunItself(t *testing.T) {
	r := newRig(t, false)
	if code := r.run(t, "session", "list"); code != 0 {
		t.Fatal(code)
	}
	// The vault object was handed in open. Locking it at the end is the right thing for a process that is about to exit.
	if r.vault.State() != vault.Locked {
		t.Error("the command locks the vault it used")
	}
}

// ---- a person who has not answered yet ----

func TestACommandThatIsStillWaitingForAPersonExitsWithTheCodeForThat(t *testing.T) {
	r := newRig(t, false)
	r.withRobot()
	r.cfg.Web.TTL = time.Minute
	// no driver is needed: any site that wants a login sends the link and waits; the answer is cut short by the context
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	env := r.envFor()
	env.Server.Notifier, env.Server.Tunnels = r.server.Notifier, r.server.Tunnels
	gl := fakeGitLab()
	defer gl.Close()
	code := Run(ctx, []string{"session", "open", "--url", gl.URL, "--site", "gitlab", "--max-block-seconds", "1", "--wait=false"}, env)
	if code != exitPending {
		t.Fatalf("exit %d, want %d (pending)\nstdout: %s\nstderr: %s", code, exitPending, r.out.String(), r.errOut.String())
	}
	if m := r.json(t); m["status"] != "pending" || m["login_id"] == nil {
		t.Errorf("a pending answer names what to continue with: %s", r.out.String())
	}
}

// With the link going to the agent, the link is for the person at this terminal: it is printed on stderr and never in the
// answer on stdout, which a script may pipe into anything.
func TestAHandedOverLinkIsPrintedOnStderrAndNeverOnStdout(t *testing.T) {
	out := map[string]any{"status": "pending", "waiting_for": "login", "link": "https://page.example/#SECRETFRAGMENT", "key_code": "AAAA BBBB CCCC DDDD"}
	var o, e bytes.Buffer
	announce(Env{Out: &o, Err: &e}, out)
	if !strings.Contains(e.String(), "https://page.example/#SECRETFRAGMENT") || !strings.Contains(e.String(), "AAAA BBBB CCCC DDDD") {
		t.Errorf("the person must see the link and the key code on stderr: %q", e.String())
	}
	if o.Len() != 0 {
		t.Errorf("stdout is the answer and nothing else: %q", o.String())
	}
}

func TestTheFinalAnswerNeverCarriesTheLink(t *testing.T) {
	var o, e bytes.Buffer
	code := finish(Env{Out: &o, Err: &e}, map[string]any{"status": "pending", "login_id": "lg_1", "next_tool": "session_wait"}, false)
	if code != exitPending {
		t.Errorf("exit %d, want %d", code, exitPending)
	}
	if strings.Contains(o.String(), "link") {
		t.Errorf("%s", o.String())
	}
	var o2, e2 bytes.Buffer
	if code := finish(Env{Out: &o2, Err: &e2}, map[string]any{"status": "ok"}, false); code != 0 {
		t.Errorf("an ok answer exits 0: %d", code)
	}
	if code := finish(Env{Out: &o2, Err: &e2}, map[string]any{"code": "x"}, true); code != exitToolError {
		t.Errorf("an error answer exits %d: %d", exitToolError, code)
	}
}

func TestDecliningToWaitIsOnlyForAnExplicitFalse(t *testing.T) {
	for in, want := range map[string]bool{
		"unset":      false,
		"wait=true":  false,
		"wait=false": true,
	} {
		input := map[string]any{}
		switch in {
		case "wait=true":
			input["wait"] = true
		case "wait=false":
			input["wait"] = false
		}
		if got := declinesToWait(input); got != want {
			t.Errorf("%s: declinesToWait = %v, want %v", in, got, want)
		}
	}
}

// vault_status is not a command (`securl vault status` is the program's own, older command), so nothing here can take the
// word: the group `vault` has no command of the tools in it.
func TestNoToolTakesAWordOfAnExistingCommand(t *testing.T) {
	r := newRig(t, false)
	cat, err := catalog(r.envFor())
	if err != nil {
		t.Fatal(err)
	}
	existing := map[string][]string{
		"vault":  {"init", "status", "passwd", "migrate", "unlock", "lock"},
		"config": {},
	}
	for key, cmd := range cat.cmds {
		if cmd.group == "config" {
			t.Errorf("the tool %s would take `securl config ...`, which is the program's own", cmd.tool)
		}
		for _, sub := range existing[cmd.group] {
			if cmd.sub == sub {
				t.Errorf("`securl %s` is both a tool and an existing command", key)
			}
		}
	}
	for _, own := range []string{"config", "doctor", "page", "version", "serve", "help"} {
		if _, ok := cat.cmds[own]; ok {
			t.Errorf("the tool %s takes the word %q, which the program uses", cat.cmds[own].tool, own)
		}
	}
}

// syncWriter serialises writes: a command writes progress from the server's goroutines while the test reads.
type syncWriter struct {
	mu sync.Mutex
	w  io.Writer
}

func (s *syncWriter) Write(p []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.w.Write(p)
}

// String is what has been written so far, read under the same lock as the writes.
func (s *syncWriter) String() string {
	s.mu.Lock()
	defer s.mu.Unlock()
	if st, ok := s.w.(interface{ String() string }); ok {
		return st.String()
	}
	return ""
}
