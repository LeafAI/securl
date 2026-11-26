package main

import (
	"bytes"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// generate.go is run with `go run generate.go`, so it is tested the way it is used: as a program, in a copy of a tiny module.

// The program lives in securl's own tree, because it imports securl's internal package, so it runs there. What it builds is whatever
// directory it is run in, which a test makes a tiny module of its own: the program is copied in as the file it would be run from.
func runGenerate(t *testing.T, dir string, env []string, args ...string) (string, string, error) {
	t.Helper()
	root, _ := os.Getwd()
	cmd := exec.Command("go", append([]string{"run", filepath.Join(root, "generate.go")}, args...)...)
	cmd.Dir = root
	cmd.Env = append(os.Environ(), append([]string{"SECURL_SOURCE_DIR=" + dir}, env...)...)
	var out, errb bytes.Buffer
	cmd.Stdout, cmd.Stderr = &out, &errb
	err := cmd.Run()
	return out.String(), errb.String(), err
}

func tinyModule(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/mini\n\ngo 1.26.9\n"), 0o644)
	os.WriteFile(filepath.Join(dir, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644)
	return dir
}

func TestNoDriverRunsTheCommandAsItIs(t *testing.T) {
	dir := tinyModule(t)
	out, _, err := runGenerate(t, dir, []string{"SECURL_DRIVERS="}, "--", "sh", "-c", "echo ran-here:$SECURL_DRIVERS_BUILT:")
	if err != nil || !strings.Contains(out, "ran-here::") {
		t.Fatalf("%v\n%s", err, out)
	}
}

func TestADriverThatIsNotPinnedIsRefusedBeforeAnythingIsRun(t *testing.T) {
	dir := tinyModule(t)
	marker := filepath.Join(t.TempDir(), "ran")
	_, errb, err := runGenerate(t, dir, nil, "--driver", "gitlab.example.com/g/r@main", "--", "sh", "-c", "touch "+marker)
	if err == nil || !strings.Contains(errb, "pinned") {
		t.Errorf("%v\n%s", err, errb)
	}
	if _, e := os.Stat(marker); e == nil {
		t.Error("the command ran")
	}
}

func TestTheDriversOfTheEnvironmentAndOfTheFlagsAreBothUsed(t *testing.T) {
	dir := tinyModule(t)
	_, errb, err := runGenerate(t, dir, []string{"SECURL_DRIVERS=gitlab.example.com/a/b@main"}, "--", "true")
	if err == nil || !strings.Contains(errb, "pinned") {
		t.Errorf("SECURL_DRIVERS is read: %v\n%s", err, errb)
	}
	_, errb, err = runGenerate(t, dir, []string{"SECURL_DRIVERS="}, "--driver", "a b", "--", "true")
	if err == nil {
		t.Errorf("--driver is read: %s", errb)
	}
}

func TestNothingIsRunWithoutACommand(t *testing.T) {
	if _, _, err := runGenerate(t, tinyModule(t), nil); err == nil {
		t.Error("a command is needed")
	}
	if _, _, err := runGenerate(t, tinyModule(t), nil, "--driver", "gitlab.example.com/a/b@v1.0.0"); err == nil {
		t.Error("a command is needed, also with a driver")
	}
}

// `go run` reports any failure of the program it ran as "exit status 1" and prints the program's own status in its place, so what is
// read here is that line: the status of the build command is the status generate ends with.
func TestTheExitStatusOfTheCommandIsTheExitStatusOfTheBuild(t *testing.T) {
	for _, code := range []string{"3", "5", "42"} {
		_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS="}, "--", "sh", "-c", "exit "+code)
		if err == nil || !strings.Contains(errb, "\nexit status "+code+"\n") {
			t.Errorf("exit %s: generate must end with that status: %v\n%s", code, err, errb)
		}
	}
	_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS="}, "--", "true")
	if err != nil || strings.Contains(errb, "exit status") {
		t.Errorf("a build that works ends with 0: %v\n%s", err, errb)
	}
}

func TestBeforeAnythingIsRunTheMistakeEndsWithStatusTwo(t *testing.T) {
	for name, args := range map[string][]string{
		"no command": nil, "a bad flag": {"--nosuchflag", "--", "true"}, "a bad driver": {"--driver", "nonsense", "--", "true"},
		"a bad key": {"--ssh-key", "relative", "--", "true"},
	} {
		_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS="}, args...)
		if err == nil || !strings.Contains(errb, "exit status 2") {
			t.Errorf("%s: %v\n%s", name, err, errb)
		}
	}
}

func TestAnExistingKeyPathThatIsNotPlainIsRefused(t *testing.T) {
	_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS="}, "--ssh-key", "/tmp/my key", "--", "true")
	if err == nil || !strings.Contains(errb, "ssh key path") {
		t.Errorf("%v\n%s", err, errb)
	}
}

func TestTheSshKeyOfTheEnvironmentIsRead(t *testing.T) {
	_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS=", "SECURL_DRIVERS_SSH_KEY=relative/key"}, "--", "true")
	if err == nil || !strings.Contains(errb, "ssh key path") {
		t.Errorf("%v\n%s", err, errb)
	}
}

func TestTheCommandRunsInTheSourceDirectoryItWasGiven(t *testing.T) {
	dir := tinyModule(t)
	out, _, err := runGenerate(t, dir, []string{"SECURL_DRIVERS="}, "--", "sh", "-c", "pwd -P")
	if err != nil {
		t.Fatal(err)
	}
	want, _ := filepath.EvalSymlinks(dir)
	if strings.TrimSpace(out) != want {
		t.Errorf("the command ran in %q, want %q", strings.TrimSpace(out), want)
	}
	other := t.TempDir()
	os.WriteFile(filepath.Join(other, "go.mod"), []byte("module example.test/other\n\ngo 1.26.9\n"), 0o644)
	if out2, _, _ := runGenerate(t, other, []string{"SECURL_DRIVERS="}, "--", "sh", "-c", "pwd -P"); strings.TrimSpace(out2) == strings.TrimSpace(out) {
		t.Error("another source directory gave the same answer")
	}
}

func TestAnOrdinaryBuildPrintsNothingAboutDrivers(t *testing.T) {
	_, errb, err := runGenerate(t, tinyModule(t), []string{"SECURL_DRIVERS="}, "--", "true")
	if err != nil || strings.Contains(errb, "built in") {
		t.Errorf("%v\n%s", err, errb)
	}
}
