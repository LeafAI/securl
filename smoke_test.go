package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"
)

// scripts/smoke-readonly.sh is run against the daemon a person is using, so it must be incapable of changing anything there. The
// test reads every command the script can run and accepts only the ones that read; a command that writes, asks a person, or
// reaches a site has to be added here on purpose, with a reason, and not by accident in the script.
var readOnlyCommands = map[string]bool{
	"vault status": true, // reads the vault's header
	"site list":    true, // names of drivers
	"session list": true, // names, expiry; never a credential
	"db targets":   true, // names and modes; never a host or an account
	"version":      true,
}

// Anything that must never be in a script that runs unattended on a live daemon.
var mustNotAppear = []string{
	"session close", "session open", "session wait", "unlock", "db exec", "db query", "archery", "request", "config", "daemon install",
	"daemon uninstall", "launchctl", "kill", "rm ", "--all", "--force", "vault init", "vault rotate", "sudo", "serve",
}

var smokeCall = regexp.MustCompile(`(?m)^check\s+"[^"]*"\s+(?:"[^"]*"|'[^']*')\s+(?:run|"\$BIN")\s+([a-z][a-z -]*?)\s*$`)

func TestTheSmokeScriptRunsOnlyCommandsThatRead(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("scripts", "smoke-readonly.sh"))
	if err != nil {
		t.Fatal(err)
	}
	calls := smokeCall.FindAllStringSubmatch(string(b), -1)
	if len(calls) < len(readOnlyCommands) {
		t.Fatalf("the script runs %d commands, the test knows %d: the pattern no longer reads the script", len(calls), len(readOnlyCommands))
	}
	seen := map[string]bool{}
	for _, c := range calls {
		cmd := strings.Join(strings.Fields(c[1]), " ")
		seen[cmd] = true
		if !readOnlyCommands[cmd] {
			t.Errorf("the smoke script runs %q, which is not on the list of commands that only read", cmd)
		}
	}
	for cmd := range readOnlyCommands {
		if !seen[cmd] {
			t.Errorf("%q is on the list but the script does not run it", cmd)
		}
	}
}

func TestTheSmokeScriptNamesNoCommandThatChangesAnything(t *testing.T) {
	b, err := os.ReadFile(filepath.Join("scripts", "smoke-readonly.sh"))
	if err != nil {
		t.Fatal(err)
	}
	// What the script runs is what follows `run` (or `"$BIN"`); the comments say what is left out and the messages tell a person
	// what to do, so neither is looked at.
	ran := regexp.MustCompile(`(?m)^[^#\n]*(?:\brun\s+|"\$BIN"\s+)([a-z][^\n]*)$`)
	for _, m := range ran.FindAllStringSubmatch(string(b), -1) {
		for _, bad := range mustNotAppear {
			if strings.Contains(m[1], bad) {
				t.Errorf("the smoke script runs %q, which contains %q", strings.TrimSpace(m[1]), bad)
			}
		}
	}
}

func TestTheSmokeScriptStopsWhenThereIsNoDaemonOrTheVaultIsLocked(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "securl")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1 $2\" in\n\"daemon status\") echo \"$FAKE_STATUS\";;\n*) echo '{\"sites\":[]}';;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	for name, status := range map[string]string{
		"no daemon":     "securl: no daemon is running",
		"locked daemon": "daemon: running (version x, vault locked) on /tmp/s",
	} {
		os.Remove(log)
		cmd := exec.Command("sh", filepath.Join("scripts", "smoke-readonly.sh"), fake)
		cmd.Env = append(os.Environ(), "FAKE_STATUS="+status)
		out, err := cmd.CombinedOutput()
		if err == nil {
			t.Errorf("%s: the script must not succeed:\n%s", name, out)
		}
		calls, _ := os.ReadFile(log)
		if got := strings.TrimSpace(string(calls)); got != "daemon status" {
			t.Errorf("%s: only the status may be read, the script ran:\n%s", name, got)
		}
	}
}

func TestTheSmokeScriptRunsExactlyTheReadCommandsOnAnOpenDaemon(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "securl")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1 $2\" in\n\"daemon status\") echo 'daemon: running (version x, vault unlocked) on /tmp/s';;\n\"vault status\") echo 'vault: unlocked';;\n\"site list\") echo '{\"sites\":[]}';;\n\"session list\") echo '{\"sessions\":[]}';;\n\"db targets\") echo '{\"targets\":[]}';;\n\"version \") echo securl 1;;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", filepath.Join("scripts", "smoke-readonly.sh"), fake).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	calls, _ := os.ReadFile(log)
	want := []string{"daemon status", "vault status", "site list", "session list", "db targets", "version"}
	got := strings.Split(strings.TrimSpace(string(calls)), "\n")
	// the first status is the check that a daemon is there, and it is the only status the script reads
	if len(got) != len(want) {
		t.Fatalf("ran %d commands %q, wanted %q", len(got), got, want)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("command %d: %q, wanted %q", i, got[i], want[i])
		}
	}
	if !strings.Contains(string(out), "5 passed, 0 failed") {
		t.Errorf("%s", out)
	}
}

func TestTheSmokeScriptPassesTheConfigFileToEveryCommand(t *testing.T) {
	dir := t.TempDir()
	log := filepath.Join(dir, "calls")
	fake := filepath.Join(dir, "securl")
	script := "#!/bin/sh\necho \"$@\" >> " + log + "\ncase \"$1 $2\" in\n\"daemon status\") echo 'daemon: running (version x, vault unlocked) on /tmp/s';;\n\"vault status\") echo 'vault:';;\n\"site list\") echo '\"sites\"';;\n\"session list\") echo '\"sessions\"';;\n\"db targets\") echo '\"targets\"';;\n*) echo securl;;\nesac\n"
	if err := os.WriteFile(fake, []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("sh", filepath.Join("scripts", "smoke-readonly.sh"), "-config", "/x/config.yaml", fake).CombinedOutput()
	if err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	calls, _ := os.ReadFile(log)
	for _, l := range strings.Split(strings.TrimSpace(string(calls)), "\n") {
		if l != "version" && !strings.HasSuffix(l, "-config /x/config.yaml") {
			t.Errorf("%q was run without the config file the caller named", l)
		}
	}
}
