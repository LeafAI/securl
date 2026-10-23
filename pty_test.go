package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// On a real terminal a command asks for the passphrase itself and reads it without echo. The other tests stand in for the
// terminal; this one runs the real binary under `expect`, which gives it a pseudo-terminal, so that term.IsTerminal and
// term.ReadPassword are the real ones. It needs expect (it is skipped without it).
func TestOnARealTerminalTheCommandAsksForThePassphraseWithoutEchoingIt(t *testing.T) {
	expect, err := exec.LookPath("expect")
	if err != nil {
		t.Skip("expect is not installed")
	}
	home := t.TempDir()
	cfgDir := filepath.Join(home, "cfg", "securl")
	if err := os.MkdirAll(cfgDir, 0o700); err != nil {
		t.Fatal(err)
	}
	cfg := filepath.Join(cfgDir, "config.yaml")
	if err := os.WriteFile(cfg, []byte("vault:\n  dir: "+filepath.Join(home, "vault")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	const pass = "a passphrase long enough to use"
	bin := binary(t)
	run := func(script string, args ...string) (string, error) {
		file := filepath.Join(t.TempDir(), "drive.exp")
		if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
			t.Fatal(err)
		}
		cmd := exec.Command(expect, append(append([]string{file, bin}, args...), "-config", cfg)...)
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t), "PASS="+pass)
		out, err := cmd.CombinedOutput()
		return string(out), err
	}

	if out, err := run(`
set timeout 30
log_user 1
spawn {*}$argv
expect "New vault passphrase"
send "$env(PASS)\r"
expect "Repeat it"
send "$env(PASS)\r"
expect eof
catch wait r
exit [lindex $r 3]`, "vault", "init"); err != nil {
		t.Fatalf("vault init on a terminal: %v\n%s", err, out)
	}

	out, err := run(`
set timeout 60
log_user 1
spawn {*}$argv
expect "Vault passphrase"
send "$env(PASS)\r"
expect eof
catch wait r
exit [lindex $r 3]`, "session", "list")
	if err != nil {
		t.Fatalf("session list on a terminal: %v\n%s", err, out)
	}
	if strings.Contains(strings.Replace(out, "send \""+pass, "", 1), pass) && strings.Count(out, pass) > 0 {
		// expect itself does not print what it sends with log_user on, so any occurrence is an echo by the program or the tty
		t.Errorf("the passphrase appears on the terminal:\n%s", out)
	}
	if !strings.Contains(out, `"sessions"`) {
		t.Errorf("the command did not run after the passphrase:\n%s", out)
	}
}

// With no terminal (a pipe, a script, an agent's shell) the program must not try to read a passphrase from the terminal
// functions: they would fail on a pipe, or worse, wait. It takes the other way, the remote unlock, and says so.
func TestWithoutATerminalTheCommandDoesNotAskForAPassphraseAtAll(t *testing.T) {
	home := t.TempDir()
	cfgDir := filepath.Join(home, "cfg", "securl")
	os.MkdirAll(cfgDir, 0o700)
	cfg := filepath.Join(cfgDir, "config.yaml")
	os.WriteFile(cfg, []byte("web:\n  ttl: 3s\nvault:\n  dir: "+filepath.Join(home, "vault")+"\n  unlock_ttl: 3s\n"+
		// the tunnel is a command that fails at once, so no test reaches the network; the remote unlock then ends with an error
		"dingtalk:\n  webhook: https://127.0.0.1:1/robot/send?access_token=x\ntunnel:\n  order: [none]\n  providers:\n    - {name: none, command: \"false\", url: \"http://127.0.0.1:1\"}\n"), 0o600)
	// make a vault directly: a pipe cannot be used for `vault init`'s own prompts
	const pass = "a passphrase long enough to use"
	if err := makeVault(filepath.Join(home, "vault"), pass); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(binary(t), "session", "list", "-config", cfg)
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t))
	cmd.Stdin = strings.NewReader(pass + "\n")
	out, err := cmd.CombinedOutput()
	if err == nil {
		t.Fatalf("a command with no terminal and nobody to unlock the vault cannot succeed:\n%s", out)
	}
	if strings.Contains(string(out), "Vault passphrase:") {
		t.Errorf("it asked for the passphrase with no terminal:\n%s", out)
	}
	if strings.Contains(string(out), `"sessions"`) {
		t.Errorf("a passphrase piped to stdin opened the vault:\n%s", out)
	}
}

// With standard error sent to a file the person cannot see the prompt, so the program must not wait on the terminal for a
// passphrase nobody knows is being asked for: it behaves as it does with no terminal. (stdin is a terminal here, stderr is not.)
func TestWithStandardErrorRedirectedThePassphraseIsNotAskedForOnTheTerminal(t *testing.T) {
	expect, err := exec.LookPath("expect")
	if err != nil {
		t.Skip("expect is not installed")
	}
	home := t.TempDir()
	cfgDir := filepath.Join(home, "cfg", "securl")
	os.MkdirAll(cfgDir, 0o700)
	cfg := filepath.Join(cfgDir, "config.yaml")
	os.WriteFile(cfg, []byte("web:\n  ttl: 3s\nvault:\n  dir: "+filepath.Join(home, "vault")+"\n  unlock_ttl: 3s\n"+
		"dingtalk:\n  webhook: https://127.0.0.1:1/robot/send?access_token=x\ntunnel:\n  order: [none]\n  providers:\n    - {name: none, command: \"false\", url: \"http://127.0.0.1:1\"}\n"), 0o600)
	if err := makeVault(filepath.Join(home, "vault"), "a passphrase long enough to use"); err != nil {
		t.Fatal(err)
	}
	logFile := filepath.Join(home, "stderr.log")
	file := filepath.Join(t.TempDir(), "drive.exp")
	script := `
set timeout 20
log_user 1
spawn sh -c "$env(argv) 2> $env(LOGFILE)"
expect {
  "Vault passphrase" { puts "\n[PROMPT-ON-TERMINAL]"; send "x\r"; exp_continue }
  eof
}
`
	if err := os.WriteFile(file, []byte(script), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd := exec.Command(expect, file)
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t), "LOGFILE="+logFile,
		"argv="+binary(t)+" session list -config "+cfg)
	out, _ := cmd.CombinedOutput()
	if strings.Contains(string(out), "PROMPT-ON-TERMINAL") {
		t.Errorf("it waited on the terminal for a passphrase with standard error redirected:\n%s", out)
	}
	if b, _ := os.ReadFile(logFile); strings.Contains(string(b), "Vault passphrase:") {
		t.Errorf("the prompt went into the redirected file, where nobody sees it:\n%s", b)
	}
}
