package main

import (
	"bufio"
	"encoding/json"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

var (
	builtOnce sync.Once
	builtPath string
	builtErr  error
)

// binary builds the program once for the tests that must run the real thing: what `securl` does with its arguments is
// decided in main, which a test cannot call without exiting.
func binary(t *testing.T) string {
	t.Helper()
	builtOnce.Do(func() {
		dir, err := os.MkdirTemp("", "securl-bin")
		if err != nil {
			builtErr = err
			return
		}
		builtPath = filepath.Join(dir, "securl")
		if out, err := exec.Command("go", "build", "-o", builtPath, ".").CombinedOutput(); err != nil {
			builtErr = &buildError{string(out), err}
		}
	})
	if builtErr != nil {
		t.Fatal(builtErr)
	}
	return builtPath
}

type buildError struct {
	out string
	err error
}

func (e *buildError) Error() string { return e.err.Error() + "\n" + e.out }

const initialize = `{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"protocolVersion":"2025-06-18","capabilities":{},"clientInfo":{"name":"probe","version":"0"}}}` + "\n"

// serves reports whether the program, started with these arguments, answers an MCP initialize on stdin/stdout.
func serves(t *testing.T, args ...string) bool {
	t.Helper()
	home := t.TempDir()
	cmd := exec.Command(binary(t), args...)
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t))
	in, _ := cmd.StdinPipe()
	out, _ := cmd.StdoutPipe()
	if err := cmd.Start(); err != nil {
		t.Fatal(err)
	}
	defer func() { in.Close(); cmd.Process.Kill(); cmd.Wait() }()
	io.WriteString(in, initialize)
	line := make(chan string, 1)
	go func() {
		s, _ := bufio.NewReader(out).ReadString('\n')
		line <- s
	}()
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

// No arguments is what every MCP client config starts: it must stay the MCP server on stdio.
func TestNoArgumentsIsStillTheMCPServer(t *testing.T) {
	if !serves(t) {
		t.Fatal("securl with no arguments does not answer an MCP initialize")
	}
}

func TestOnlyFlagsIsStillTheMCPServer(t *testing.T) {
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if !serves(t, "-config", cfg) {
		t.Fatal("securl -config <file> does not answer an MCP initialize")
	}
}

func TestServeIsTheSameServerByName(t *testing.T) {
	if !serves(t, "serve") {
		t.Fatal("securl serve does not answer an MCP initialize")
	}
	cfg := filepath.Join(t.TempDir(), "c.yaml")
	if !serves(t, "serve", "-config", cfg) {
		t.Fatal("securl serve -config <file> does not answer an MCP initialize")
	}
}

// A command is not the server: it must run, print and exit, never wait on stdin as the server does.
func TestACommandRunsAndExitsInsteadOfServing(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(binary(t), "site", "list")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t))
	cmd.Stdin = strings.NewReader("")
	done := make(chan error, 1)
	var out []byte
	go func() { var err error; out, err = cmd.CombinedOutput(); done <- err }()
	select {
	case <-done:
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("a command did not exit: it started the server")
	}
	if strings.Contains(string(out), `"jsonrpc"`) {
		t.Errorf("a command printed MCP protocol: %s", out)
	}
}

func TestAnUnknownWordIsAnErrorNotASilentServer(t *testing.T) {
	home := t.TempDir()
	cmd := exec.Command(binary(t), "frobnicate")
	cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t))
	cmd.Stdin = strings.NewReader("")
	done := make(chan error, 1)
	var out []byte
	go func() { var err error; out, err = cmd.CombinedOutput(); done <- err }()
	select {
	case err := <-done:
		if err == nil {
			t.Error("exit 0 for a word that is no command")
		}
	case <-time.After(30 * time.Second):
		cmd.Process.Kill()
		t.Fatal("an unknown word started the server and waited on stdin (this was `securl site list` before: it hung)")
	}
	if !strings.Contains(string(out), "no such command") {
		t.Errorf("%s", out)
	}
}

// `serve -config X` must read X. flag stops at the first word that is not a flag, so if "serve" were left in the arguments
// the flag after it would be ignored and the server would run on the default configuration: another set of secrets than
// the one that was asked for. A file that does not parse proves the file was read.
func TestServeReadsTheConfigFileGivenAfterIt(t *testing.T) {
	for _, args := range [][]string{{"-config"}, {"serve", "-config"}} {
		bad := filepath.Join(t.TempDir(), "bad.yaml")
		if err := os.WriteFile(bad, []byte("bogus_key_that_does_not_exist: 1\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		home := t.TempDir()
		cmd := exec.Command(binary(t), append(append([]string{}, args...), bad)...)
		cmd.Env = append(os.Environ(), "HOME="+home, "XDG_CONFIG_HOME="+filepath.Join(home, "cfg"), "XDG_RUNTIME_DIR="+shortRuntimeDir(t))
		cmd.Stdin = strings.NewReader("")
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%v: a configuration that does not parse was accepted", args)
		}
		if !strings.Contains(string(out), "bogus_key_that_does_not_exist") {
			t.Errorf("%v: the file given after the word was not the one read: %s", args, out)
		}
	}
}

// shortRuntimeDir is an empty runtime directory for a program the tests run, so that its default daemon socket is one that
// nobody listens on. Without it a test that runs a command talks to the daemon of whoever runs the tests (the default socket is
// per user, not per HOME), and what it does there is done on their vault. It is short: socket paths are limited.
func shortRuntimeDir(t *testing.T) string {
	t.Helper()
	dir, err := os.MkdirTemp("", "sr")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(dir) })
	return dir
}
