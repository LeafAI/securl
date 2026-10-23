//go:build unix

package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"syscall"
	"testing"
	"time"
)

// startDaemonProcess runs `securl daemon` as a real process on a short socket, with a locked vault, and returns it.
func startDaemonProcess(t *testing.T) (cfg, sock string, cmd *exec.Cmd, stderr *safeBuf) {
	t.Helper()
	dir, err := os.MkdirTemp("/tmp", "sdm")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	sock = filepath.Join(dir, "d.sock")
	cfg = filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("vault:\n  dir: "+filepath.Join(dir, "vault")+"\ndaemon:\n  socket: "+sock+"\n"+
		// no test may reach the network: the tunnel is a command that fails at once
		"dingtalk:\n  webhook: https://127.0.0.1:1/robot/send?access_token=x\ntunnel:\n  order: [none]\n  providers:\n    - {name: none, command: \"false\", url: \"http://127.0.0.1:1\"}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := makeVault(filepath.Join(dir, "vault"), "a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command(binary(t), "daemon", "-config", cfg)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
	stderr = &safeBuf{}
	cmd.Stderr = stderr
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { cmd.Process.Kill(); cmd.Wait() })
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if st, err := os.Stat(sock); err == nil && st.Mode()&os.ModeSocket != 0 {
			return cfg, sock, cmd, stderr
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatalf("the daemon did not start:\n%s", stderr.String())
	return
}

func TestSecurlDaemonListensAndStopsOnATerminationSignal(t *testing.T) {
	_, sock, cmd, stderr := startDaemonProcess(t)
	if !strings.Contains(stderr.String(), "listening") {
		t.Errorf("the daemon says where it listens:\n%s", stderr.String())
	}
	if err := cmd.Process.Signal(syscall.SIGTERM); err != nil {
		t.Fatal(err)
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()
	select {
	case err := <-done:
		if err != nil {
			t.Errorf("a termination signal is an orderly stop, not a failure: %v", err)
		}
	case <-time.After(15 * time.Second):
		t.Fatal("the daemon ignored SIGTERM")
	}
	if _, err := os.Stat(sock); err == nil {
		t.Error("the socket file is left behind after an orderly stop")
	}
}

func TestACommandReachesTheDaemonProcessAndTheVaultStaysLockedForAnAgentShell(t *testing.T) {
	cfg, _, _, _ := startDaemonProcess(t)
	dir := filepath.Dir(cfg)
	run := func(args ...string) (string, string, int) {
		cmd := exec.Command(binary(t), append(args, "-config", cfg)...)
		cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
		var out, errb safeBuf
		cmd.Stdout, cmd.Stderr = &out, &errb
		err := cmd.Run()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return out.String(), errb.String(), code
	}
	out, errOut, code := run("vault", "status")
	if code != 0 || !strings.Contains(out, "locked") {
		t.Errorf("vault status reads the files, not the daemon, and the vault is locked: %q %q %d", out, errOut, code)
	}
	// a tool that needs the vault: with the daemon locked and no way to reach a person, the command ends with an error rather
	// than opening anything, and says that it is the daemon it spoke to
	out, errOut, code = run("site", "list")
	if code == 0 || strings.Contains(out, `"sites"`) {
		t.Errorf("a locked daemon answered a tool that needs the vault: %q %q %d", out, errOut, code)
	}
	if strings.Contains(errOut, "no daemon") {
		t.Errorf("the command did not find the daemon that is running:\n%s", errOut)
	}
}

func TestASecondDaemonOnTheSameSocketExitsAndTheFirstKeepsServing(t *testing.T) {
	cfg, sock, _, _ := startDaemonProcess(t)
	dir := filepath.Dir(cfg)
	cmd := exec.Command(binary(t), "daemon", "-config", cfg)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatal("a second daemon started")
	}
	if !strings.Contains(string(out), "already running") {
		t.Errorf("%s", out)
	}
	if st, err := os.Stat(sock); err != nil || st.Mode()&os.ModeSocket == 0 {
		t.Error("the first daemon's socket was disturbed")
	}
}

func TestDaemonStatusSaysWhetherADaemonIsRunning(t *testing.T) {
	cfg, _, cmd, _ := startDaemonProcess(t)
	dir := filepath.Dir(cfg)
	status := func() (string, int) {
		c := exec.Command(binary(t), "daemon", "status", "-config", cfg)
		c.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
		out, err := c.CombinedOutput()
		code := 0
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		}
		return string(out), code
	}
	out, code := status()
	if code != 0 || !strings.Contains(out, "running") || !strings.Contains(out, "locked") {
		t.Errorf("a running, locked daemon: %q (exit %d)", out, code)
	}
	cmd.Process.Signal(syscall.SIGTERM)
	cmd.Wait()
	out, code = status()
	if code == 0 || !strings.Contains(out, "not running") {
		t.Errorf("no daemon: %q (exit %d)", out, code)
	}
}

type safeBuf struct {
	mu sync.Mutex
	b  strings.Builder
}

func (s *safeBuf) Write(p []byte) (int, error) { s.mu.Lock(); defer s.mu.Unlock(); return s.b.Write(p) }
func (s *safeBuf) String() string              { s.mu.Lock(); defer s.mu.Unlock(); return s.b.String() }

func runBinary(t *testing.T, cfg string, args ...string) (stdout, stderr string, code int) {
	t.Helper()
	dir := filepath.Dir(cfg)
	cmd := exec.Command(binary(t), args...)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
	var out, errb safeBuf
	cmd.Stdout, cmd.Stderr = &out, &errb
	if err := cmd.Run(); err != nil {
		if ee, ok := err.(*exec.ExitError); ok {
			code = ee.ExitCode()
		} else {
			t.Fatal(err)
		}
	}
	return out.String(), errb.String(), code
}

func TestSecurlUnlockWithNoDaemonSaysHowToStartOneAndExits3(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, []byte("daemon:\n  socket: /tmp/securl-no-such-dir-xyz/d.sock\n"), 0o600)
	out, errOut, code := runBinary(t, cfg, "unlock", "-config", cfg)
	if code != 3 {
		t.Errorf("exit %d, want 3\n%s", code, errOut)
	}
	if !strings.Contains(errOut, "securl daemon") || out != "" {
		t.Errorf("stdout %q stderr %q", out, errOut)
	}
}

func TestSecurlUnlockReachesTheRunningDaemonAndNeverReadsAPassphrase(t *testing.T) {
	cfg, _, _, _ := startDaemonProcess(t)
	// no terminal here; and the daemon's robot cannot be reached, so the ask ends with the tool's own error. What matters:
	// it was the daemon that was asked, and nothing was read from standard input.
	cmd := exec.Command(binary(t), "unlock", "-config", cfg)
	dir := filepath.Dir(cfg)
	cmd.Env = append(os.Environ(), "HOME="+dir, "XDG_CONFIG_HOME="+filepath.Join(dir, "cfg"))
	cmd.Stdin = strings.NewReader("a passphrase long enough to use\n")
	var out, errb safeBuf
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	if err == nil {
		t.Fatalf("a passphrase on stdin opened the daemon's vault:\n%s", out.String())
	}
	if !strings.Contains(errb.String(), "asking the person") {
		t.Errorf("the command did not ask the daemon to unlock:\n%s", errb.String())
	}
	if strings.Contains(errb.String(), "no daemon") {
		t.Errorf("it did not find the daemon that is running:\n%s", errb.String())
	}
	o, _, code := runBinary(t, cfg, "daemon", "status", "-config", cfg)
	if code != 0 || !strings.Contains(o, "locked") {
		t.Errorf("the daemon must still be locked: %q (exit %d)", o, code)
	}
}

func TestSecurlUnlockHelpAndStrayArguments(t *testing.T) {
	dir := t.TempDir()
	cfg := filepath.Join(dir, "config.yaml")
	os.WriteFile(cfg, nil, 0o600)
	out, _, code := runBinary(t, cfg, "unlock", "--help")
	if code != 0 || !strings.Contains(out, "usage: securl unlock") || !strings.Contains(out, "never here") {
		t.Errorf("help: %q (exit %d)", out, code)
	}
	_, errOut, code := runBinary(t, cfg, "unlock", "now", "-config", cfg)
	if code != 2 || !strings.Contains(errOut, "unexpected argument") {
		t.Errorf("a stray word is a usage error: exit %d: %s", code, errOut)
	}
	_, errOut, code = runBinary(t, cfg, "unlock", "--no-daemon", "-config", cfg)
	if code != 2 || !strings.Contains(errOut, "--no-daemon") {
		t.Errorf("--no-daemon is refused as meaningless: exit %d: %s", code, errOut)
	}
}
