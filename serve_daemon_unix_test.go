//go:build unix

package main

import (
	"bufio"
	"context"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/daemon"
)

// bothProc is `securl <args>` running as a real process with stdio held open by the test, a short socket and a locked vault.
type bothProc struct {
	cmd    *exec.Cmd
	in     io.WriteCloser
	out    *bufio.Reader
	stderr *safeBuf
	cfg    string
	sock   string
	dir    string
}

func startBoth(t *testing.T, args ...string) *bothProc {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sbd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	p := &bothProc{dir: dir, sock: filepath.Join(dir, "d.sock"), cfg: filepath.Join(dir, "config.yaml"), stderr: &safeBuf{}}
	if err := os.WriteFile(p.cfg, []byte("vault:\n  dir: "+filepath.Join(dir, "vault")+"\ndaemon:\n  socket: "+p.sock+"\n"+
		"dingtalk:\n  webhook: https://127.0.0.1:1/robot/send?access_token=x\ntunnel:\n  order: [none]\n  providers:\n    - {name: none, command: \"false\", url: \"http://127.0.0.1:1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := makeVault(filepath.Join(dir, "vault"), "a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	p.cmd = exec.Command(binary(t), append(args, "-config", p.cfg)...)
	p.cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
	p.cmd.Stderr = p.stderr
	p.in, _ = p.cmd.StdinPipe()
	o, _ := p.cmd.StdoutPipe()
	p.out = bufio.NewReader(o)
	if err := p.cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { p.in.Close(); p.cmd.Process.Kill(); p.cmd.Wait() })
	return p
}

func (p *bothProc) waitSocket(t *testing.T) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(p.sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the socket did not appear:\n%s", p.stderr.String())
}

// stdioAnswers sends an MCP initialize on the process's stdin and reports whether securl answers on its stdout.
func (p *bothProc) stdioAnswers(t *testing.T) bool {
	t.Helper()
	io.WriteString(p.in, initialize)
	line := make(chan string, 1)
	go func() { s, _ := p.out.ReadString('\n'); line <- s }()
	select {
	case s := <-line:
		var m struct {
			Result struct {
				ServerInfo struct{ Name string } `json:"serverInfo"`
			} `json:"result"`
		}
		return json.Unmarshal([]byte(s), &m) == nil && m.Result.ServerInfo.Name == "securl"
	case <-time.After(15 * time.Second):
		return false
	}
}

// socketClient opens an MCP session over the daemon socket, as a command of the command line does.
func socketClient(t *testing.T, sock string) *mcp.ClientSession {
	t.Helper()
	c, err := daemon.Dial(context.Background(), sock)
	if err != nil {
		t.Fatal(err)
	}
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "c", Version: "0"}, nil).Connect(context.Background(), &mcp.IOTransport{Reader: c, Writer: c}, nil)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cs.Close() })
	return cs
}

func vaultStateOverSocket(t *testing.T, sock string) string {
	t.Helper()
	res, err := socketClient(t, sock).CallTool(context.Background(), &mcp.CallToolParams{Name: "vault_status", Arguments: map[string]any{}})
	if err != nil || res.IsError {
		t.Fatalf("%v %+v", err, res)
	}
	b, _ := json.Marshal(res.StructuredContent)
	var out struct{ State string }
	json.Unmarshal(b, &out)
	return out.State
}

// Without -daemon a securl serves stdio and nothing else: no socket is made, so nothing about the default changes.
func TestWithoutTheDaemonFlagNoSocketIsMade(t *testing.T) {
	p := startBoth(t)
	if !p.stdioAnswers(t) {
		t.Fatalf("stdio does not answer:\n%s", p.stderr.String())
	}
	if _, err := os.Stat(p.sock); err == nil {
		t.Error("a socket was made without -daemon")
	}
}

func TestSecurlDashDashDaemonServesStdioAndTheSocketFromOneProcess(t *testing.T) {
	for name, args := range map[string][]string{"no word": {"-daemon"}, "serve": {"serve", "-daemon"}} {
		t.Run(name, func(t *testing.T) {
			p := startBoth(t, args...)
			p.waitSocket(t)
			if !p.stdioAnswers(t) {
				t.Fatalf("stdio does not answer:\n%s", p.stderr.String())
			}
			if got := vaultStateOverSocket(t, p.sock); got != "locked" {
				t.Errorf("the socket answers for the same server, whose vault is locked: %q", got)
			}
			if !strings.Contains(p.stderr.String(), "also listening on "+p.sock) {
				t.Errorf("it says the path it listens on, so that it can be compared with what a command looks for:\n%s", p.stderr.String())
			}
		})
	}
}

func TestADaemonAlreadyOnTheSocketStopsTheServerBeforeItServesStdio(t *testing.T) {
	cfg, _, _, _ := startDaemonProcess(t)
	cmd := exec.Command(binary(t), "-daemon", "-config", cfg)
	cmd.Env = append(os.Environ(), "HOME="+filepath.Dir(cfg), "XDG_CONFIG_HOME="+filepath.Join(filepath.Dir(cfg), "cfg"))
	cmd.Stdin = strings.NewReader(initialize)
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("it served although the socket is taken")
	}
	if !strings.Contains(string(out), "already running") {
		t.Errorf("it says why:\n%s", out)
	}
	if strings.Contains(string(out), `"jsonrpc"`) {
		t.Errorf("it answered on stdio although it could not make the socket:\n%s", out)
	}
}

func TestWhenStdioEndsTheSocketIsRemovedAndTheProcessExits(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	if !p.stdioAnswers(t) {
		t.Fatal("stdio does not answer")
	}
	p.in.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("the end of stdio is an orderly stop: %v\n%s", err, p.stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("it kept running after its stdio ended")
	}
	if _, err := os.Stat(p.sock); err == nil {
		t.Error("the socket is left behind")
	}
}

func TestATerminationSignalStopsBothAndRemovesTheSocket(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	if !p.stdioAnswers(t) {
		t.Fatal("stdio does not answer")
	}
	if err := p.cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a termination signal is an orderly stop: %v\n%s", err, p.stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("it ignored SIGTERM")
	}
	if _, err := os.Stat(p.sock); err == nil {
		t.Error("the socket is left behind")
	}
}

// What the socket gives is the same as the daemon's: another user's connection is not served (the check is the daemon package's own).
func TestTheSocketOfTheServerIsPrivateToItsUser(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	st, err := os.Stat(p.sock)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the socket is reachable by others: %v", st.Mode())
	}
}

func tmpShort(t *testing.T) (string, error) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sbs")
	if err == nil {
		t.Cleanup(func() { os.RemoveAll(dir) })
	}
	return dir, err
}

// A command that is in the middle of a session when stdio ends is closed by the socket's own shutdown, and the process waits for that
// to finish before it leaves: it does not exit with a session half served, and it does not leave the socket behind.
func TestAnOpenCommandSessionIsClosedWhenStdioEndsAndTheProcessWaitsForIt(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	if !p.stdioAnswers(t) {
		t.Fatal("stdio does not answer")
	}
	cs := socketClient(t, p.sock) // a command holding its session open
	p.in.Close()
	done := make(chan error, 1)
	go func() { done <- p.cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("an orderly stop: %v\n%s", err, p.stderr.String())
		}
	case <-time.After(15 * time.Second):
		t.Fatal("it kept running with a command session open after stdio ended")
	}
	if _, err := os.Stat(p.sock); err == nil {
		t.Error("the socket is left behind")
	}
	if _, err := cs.CallTool(context.Background(), &mcp.CallToolParams{Name: "vault_status", Arguments: map[string]any{}}); err == nil {
		t.Error("the command's session is still answered after the process left")
	}
}

func TestTheLogSaysThatStdioEndedAndNothingElseWasLeftRunning(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	p.stdioAnswers(t)
	p.in.Close()
	p.cmd.Wait()
	if strings.Contains(p.stderr.String(), "panic") || strings.Contains(p.stderr.String(), "accept:") {
		t.Errorf("a clean stop is quiet about errors:\n%s", p.stderr.String())
	}
}

// The same for the server that also serves the socket: a stop straight after the socket appears is an orderly stop every time.
func TestAStopRightAfterTheSocketAppearsStopsTheDualServerOrderlyEveryTime(t *testing.T) {
	for i := 0; i < 30; i++ {
		p := startBoth(t, "-daemon")
		for end := time.Now().Add(15 * time.Second); time.Now().Before(end); {
			if st, err := os.Stat(p.sock); err == nil && st.Mode()&os.ModeSocket != 0 {
				break
			}
			time.Sleep(time.Millisecond)
		}
		p.cmd.Process.Signal(syscall.SIGTERM)
		err := p.cmd.Wait()
		_, statErr := os.Stat(p.sock)
		if err != nil {
			t.Fatalf("run %d: a stop right after the socket appeared was not orderly: %v\n%s", i, err, p.stderr.String())
		}
		if statErr == nil {
			t.Fatalf("run %d: the socket file was left behind", i)
		}
	}
}

// A command finds the socket of the dual server by the same rule that made it: the same configuration file gives the same path, and
// `securl daemon status` with it reaches the process and reads its vault.
func TestACommandWithTheSameConfigurationFindsTheDualServersSocketByItself(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	if !p.stdioAnswers(t) {
		t.Fatal("stdio does not answer")
	}
	out, errOut, code := runBinary(t, p.cfg, "daemon", "status", "-config", p.cfg)
	if code != 0 || !strings.Contains(out, "running") || !strings.Contains(out, p.sock) || !strings.Contains(out, "locked") {
		t.Errorf("a command with the same configuration does not find the server: %q %q %d", out, errOut, code)
	}
}

func TestACommandWithAnotherSocketSettingDoesNotFindItAndSaysWhereItLooked(t *testing.T) {
	p := startBoth(t, "-daemon")
	p.waitSocket(t)
	other := filepath.Join(p.dir, "other.yaml")
	if err := os.WriteFile(other, []byte("vault:\n  dir: "+filepath.Join(p.dir, "vault")+"\ndaemon:\n  socket: "+filepath.Join(p.dir, "elsewhere.sock")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	out, _, code := runBinary(t, p.cfg, "daemon", "status", "-config", other)
	if code == 0 || !strings.Contains(out, "not running") || !strings.Contains(out, "elsewhere.sock") {
		t.Errorf("a command that reads another configuration says it did not find a daemon, and where it looked: %q %d", out, code)
	}
}

// The program's own flags are written with one dash (-config, -daemon), as the documents write them. Go's flag package takes two as well, so
// a person who types --daemon is served too; both spellings and the explicit values reach the same switch.
func TestTheDaemonFlagIsWrittenWithOneDashAndTwoWorkToo(t *testing.T) {
	for name, arg := range map[string]string{"one dash": "-daemon", "two dashes": "--daemon", "explicit true": "-daemon=true"} {
		t.Run(name, func(t *testing.T) {
			p := startBoth(t, arg)
			p.waitSocket(t)
			if !p.stdioAnswers(t) {
				t.Fatalf("stdio does not answer:\n%s", p.stderr.String())
			}
		})
	}
	p := startBoth(t, "-daemon=false")
	if !p.stdioAnswers(t) {
		t.Fatalf("stdio does not answer:\n%s", p.stderr.String())
	}
	if _, err := os.Stat(p.sock); err == nil {
		t.Error("-daemon=false made a socket")
	}
}
