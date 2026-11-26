package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

const goodDriver = "gitlab.example.com/g/r@v1.2.3"

// makeN runs make without running any recipe and returns what it would run. The environment is the test's own, minus anything that
// would change the answer: a developer's own SECURL_DRIVERS must not decide what a test sees.
func makeN(t *testing.T, env []string, target string, args ...string) string {
	t.Helper()
	cmd := exec.Command("make", append([]string{"-n", target}, args...)...)
	cmd.Env = append(cleanEnv(), env...)
	out, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("make -n %s: %v\n%s", target, err, out)
	}
	return string(out)
}

func cleanEnv() []string {
	var out []string
	for _, e := range os.Environ() {
		if !strings.HasPrefix(e, "SECURL_DRIVERS") && !strings.HasPrefix(e, "DRIVERS") && !strings.HasPrefix(e, "MAKEFLAGS") && !strings.HasPrefix(e, "MFLAGS") {
			out = append(out, e)
		}
	}
	return out
}

var packaged = map[string]string{
	"deb": `bash scripts/deb.sh "dist" "1.2.3" "amd64"`,
	"rpm": `bash scripts/rpm.sh "dist" "1.2.3" "amd64" "1"`,
}

func TestWithNoDriversMakeRunsTheScriptsAsBefore(t *testing.T) {
	for target, want := range packaged {
		out := makeN(t, nil, target, "VERSION=1.2.3", "DEB_ARCH=amd64", "RPM_ARCH=amd64")
		if strings.TrimSpace(out) != want {
			t.Errorf("%s: want exactly %q, got %q", target, want, out)
		}
	}
	for _, empty := range []string{"DRIVERS=", "DRIVERS=   "} {
		out := makeN(t, nil, "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64", empty)
		if strings.Contains(out, "generate.go") {
			t.Errorf("%q: nothing is generated when no driver is asked for: %s", empty, out)
		}
	}
	if out := makeN(t, []string{"SECURL_DRIVERS="}, "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64"); strings.Contains(out, "generate.go") {
		t.Errorf("an empty SECURL_DRIVERS asks for nothing: %s", out)
	}
}

// A list of nothing but spaces and commas is no driver at all, and a value that would run a command if make read it is a driver
// (a mistaken one, which the generator refuses), not an empty list and not something to run.
func TestWhatCountsAsNoDriverAndWhatDoesNot(t *testing.T) {
	for value, wantGenerator := range map[string]bool{
		"": false, " ": false, "   ": false, "\t": false,
		"a/b@v1.0.0": true, " a/b@v1.0.0 ": true, "x": true, ",": true, "$(shell true)": true, "$$": true,
	} {
		out := makeN(t, nil, "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64", "DRIVERS="+value)
		if got := strings.Contains(out, "generate.go"); got != wantGenerator {
			t.Errorf("DRIVERS=%q: generator run %v, want %v:\n%s", value, got, wantGenerator, out)
		}
	}
}

func TestWithDriversMakeRunsTheWholeScriptInsideTheGenerator(t *testing.T) {
	for target, want := range packaged {
		out := makeN(t, nil, target, "VERSION=1.2.3", "DEB_ARCH=amd64", "RPM_ARCH=amd64", "DRIVERS="+goodDriver)
		if strings.TrimSpace(out) != "go run generate.go -- "+want {
			t.Errorf("%s: the script is the command the generator runs, after --: %q", target, out)
		}
	}
}

// The key path is text too: a $(shell ...) in it must not be run by make.
func TestAnSshKeyPathWithMakeSyntaxIsNotExpandedByMake(t *testing.T) {
	root, _ := os.Getwd()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Makefile"), mustRead(t, filepath.Join(root, "Makefile")), 0o644)
	os.WriteFile(filepath.Join(dir, "generate.go"), []byte("//go:build ignore\n\npackage main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() { fmt.Printf(\"[%s]\", os.Getenv(\"SECURL_DRIVERS_SSH_KEY\")) }\n"), 0o644)
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, how := range []string{"arg", "env"} {
		key := "/k$(shell touch " + marker + ")"
		cmd := exec.Command("make", "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64", "DRIVERS="+goodDriver)
		cmd.Dir, cmd.Env = dir, cleanEnv()
		if how == "arg" {
			cmd.Args = append(cmd.Args, "DRIVERS_SSH_KEY="+key)
		} else {
			cmd.Env = append(cmd.Env, "SECURL_DRIVERS_SSH_KEY="+key)
		}
		out, err := cmd.CombinedOutput()
		if err != nil || !strings.Contains(string(out), "["+key+"]") {
			t.Errorf("%s: the generator received %s (%v)", how, out, err)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("make ran a command that was in a key path")
	}
}

func TestTheDriversOfTheEnvironmentAreUsedToo(t *testing.T) {
	out := makeN(t, []string{"SECURL_DRIVERS=" + goodDriver}, "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64")
	if !strings.Contains(out, "go run generate.go --") {
		t.Errorf("%s", out)
	}
}

func TestMacosWithDriversRunsBothBuildsInsideTheGenerator(t *testing.T) {
	out := makeN(t, nil, "macos", "MACOS_VERSION=nightly-20261012-1a2b3c4d5e6f", "DRIVERS="+goodDriver)
	want := `go run generate.go -- bash scripts/macos-build.sh "nightly-20261012-1a2b3c4d5e6f" "dist"`
	if strings.TrimSpace(out) != want {
		t.Errorf("want %q, got %q", want, out)
	}
	if strings.Contains(out, "go build") {
		t.Errorf("the generator runs a script that builds both architectures: %s", out)
	}
}

// What a person wrote is text. Make must not expand a $ in it, and a shell must never read it: it travels in the environment, and
// the generator, which reads it as a list of specs, refuses what is not one. Run for real, so that what make and the shell do is
// what is tested, with a stand-in for the generator that prints what it received.
func TestAValueWithShellOrMakeSyntaxReachesTheGeneratorAsItWasWritten(t *testing.T) {
	root, _ := os.Getwd()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Makefile"), mustRead(t, filepath.Join(root, "Makefile")), 0o644)
	os.Mkdir(filepath.Join(dir, "scripts"), 0o755)
	os.WriteFile(filepath.Join(dir, "generate.go"), []byte("//go:build ignore\n\npackage main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() { fmt.Printf(\"[%s]\", os.Getenv(\"SECURL_DRIVERS\")) }\n"), 0o644)
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, value := range []string{"x;touch " + marker, "a$(id)b", "a$(shell touch " + marker + ")b", "a`id`b", "a'b", "a\"b", "a&b|c>d", "a$$b", "a b,c"} {
		cmd := exec.Command("make", "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64", "DRIVERS="+value)
		cmd.Dir = dir
		cmd.Env = cleanEnv()
		out, err := cmd.CombinedOutput()
		if err != nil {
			t.Errorf("%q: %v\n%s", value, err, out)
			continue
		}
		if !strings.Contains(string(out), "["+value+"]") {
			t.Errorf("%q: the generator received %s", value, out)
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("something in a driver value was run")
	}
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func TestTheOfficialReleaseAndNightlyBuildsRefuseDrivers(t *testing.T) {
	for script, args := range map[string][]string{
		"scripts/release.sh":         {t.TempDir(), "nightly-20261012-1a2b3c4"},
		"scripts/publish-nightly.sh": {t.TempDir(), strings.Repeat("a", 40), "nightly-20261012-1a2b3c4", "owner/repo"},
	} {
		cmd := exec.Command("bash", append([]string{script}, args...)...)
		cmd.Env = append(cleanEnv(), "SECURL_DRIVERS="+goodDriver)
		out, err := cmd.CombinedOutput()
		if err == nil || !strings.Contains(string(out), "SECURL_DRIVERS is set") {
			t.Errorf("%s must refuse a build with external drivers, and say why: %v\n%s", script, err, out)
		}
		clean := exec.Command("bash", append([]string{script}, args...)...)
		clean.Env = append(cleanEnv(), "SECURL_DRIVERS=")
		if out2, _ := clean.CombinedOutput(); strings.Contains(string(out2), "SECURL_DRIVERS is set") {
			t.Errorf("%s refuses an ordinary build: %s", script, out2)
		}
	}
}

// Through the environment a value of nothing but white space is kept as it is: it is no driver, and the build is the plain one.
func TestAnEnvironmentValueOfOnlyWhiteSpaceAsksForNothing(t *testing.T) {
	for _, value := range []string{" ", "   ", "\t", " \t "} {
		out := makeN(t, []string{"SECURL_DRIVERS=" + value}, "rpm", "VERSION=1.2.3", "RPM_ARCH=amd64")
		if strings.Contains(out, "generate.go") {
			t.Errorf("SECURL_DRIVERS=%q is no driver: %s", value, out)
		}
	}
}

// Make decides whether a driver was asked for without reading the text as make: a $(shell ...) that came in through the
// environment is the one place where it would be run, because a variable from the environment is expanded each time it is read.
func TestAnEnvironmentValueWithMakeSyntaxIsNeverRunByMake(t *testing.T) {
	root, _ := os.Getwd()
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "Makefile"), mustRead(t, filepath.Join(root, "Makefile")), 0o644)
	os.WriteFile(filepath.Join(dir, "generate.go"), []byte("//go:build ignore\n\npackage main\n\nimport (\n\t\"fmt\"\n\t\"os\"\n)\n\nfunc main() { fmt.Printf(\"[%s]\", os.Getenv(\"SECURL_DRIVERS\")) }\n"), 0o644)
	marker := filepath.Join(t.TempDir(), "pwned")
	for _, value := range []string{"a$(shell touch " + marker + ")b", "$(shell touch " + marker + ")", "x$(info " + marker + ")"} {
		for _, target := range []string{"rpm", "deb", "macos"} {
			cmd := exec.Command("make", "-n", target, "VERSION=1.2.3", "RPM_ARCH=amd64", "DEB_ARCH=amd64")
			cmd.Dir, cmd.Env = dir, append(cleanEnv(), "SECURL_DRIVERS="+value)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Errorf("%s %q: %v\n%s", target, value, err, out)
			}
			if strings.Contains(string(out), marker) && !strings.Contains(string(out), "["+value+"]") && strings.Contains(string(out), "touch") {
				_ = out
			}
		}
	}
	if _, err := os.Stat(marker); err == nil {
		t.Error("make ran a command that came in through SECURL_DRIVERS")
	}
}
