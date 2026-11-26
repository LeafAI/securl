package driverbuild

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// mini is a stand-in for securl: a Go module of its own with a main package that a generated file can add imports to, and a
// go.mod and go.sum that must come out of the build byte for byte as they went in.
func mini(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	must := func(name, body string) {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	must("go.mod", "module example.test/mini\n\ngo 1.26.9\n")
	must("go.sum", "")
	must("main.go", "package main\n\nimport \"fmt\"\n\nvar loaded []string\n\nfunc main() { fmt.Println(loaded) }\n")
	return dir
}

// withDriver is a driver repository whose init adds its name to the main package's list through a hook it can reach: a package-level
// variable of a tiny shared module would need a second repository, so the driver just prints at init.
func driverRepo(t *testing.T, module, say string) *repo {
	t.Helper()
	r := newRepo(t, module)
	os.WriteFile(filepath.Join(r.dir, "driver.go"), []byte("package drv\n\nimport \"fmt\"\n\nfunc init() { fmt.Println(\"driver-loaded:"+say+"\") }\n"), 0o644)
	gitIn(t, r.dir, "add", ".")
	gitIn(t, r.dir, "commit", "-q", "-m", "prints")
	r.last = gitIn(t, r.dir, "rev-parse", "HEAD")
	gitIn(t, r.dir, "tag", "-a", "v2.0.0", "-m", "prints")
	return r
}

func goBin(t *testing.T) string {
	t.Helper()
	p, err := exec.LookPath("go")
	if err != nil {
		t.Skip("go is not on the path")
	}
	return p
}

func TestABuildWithADriverRunsTheCommandWithTheDriverLinkedInAndCleansUp(t *testing.T) {
	goBin(t)
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	goModBefore, _ := os.ReadFile(filepath.Join(src, "go.mod"))
	goSumBefore, _ := os.ReadFile(filepath.Join(src, "go.sum"))
	out := filepath.Join(t.TempDir(), "mini")
	spec := Spec{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}
	res, err := Build(Options{
		Dir: src, Specs: []Spec{spec}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"go", "build", "-o", out, "."}, Stdout: os.Stderr, Stderr: os.Stderr,
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(res.Drivers) != 1 || res.Drivers[0].Commit != r.last {
		t.Errorf("the commit the tag names is reported: %+v want %s", res.Drivers, r.last)
	}
	got, err := exec.Command(out).CombinedOutput()
	if err != nil || !strings.Contains(string(got), "driver-loaded:one") {
		t.Errorf("the driver was not linked in: %v\n%s", err, got)
	}
	if _, err := os.Stat(filepath.Join(src, ExtraFile)); err == nil {
		t.Error("the generated file is removed after the build")
	}
	goModAfter, _ := os.ReadFile(filepath.Join(src, "go.mod"))
	goSumAfter, _ := os.ReadFile(filepath.Join(src, "go.sum"))
	if string(goModAfter) != string(goModBefore) || string(goSumAfter) != string(goSumBefore) {
		t.Errorf("go.mod and go.sum are untouched:\n%s\n%s", goModAfter, goSumAfter)
	}
	if entries, _ := os.ReadDir(src); len(entries) != 3 {
		t.Errorf("nothing else is left in the source tree: %v", entries)
	}
}

func TestTheCommandIsToldWhichModfileToUseAndNothingElseIsChanged(t *testing.T) {
	goBin(t)
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	probe := filepath.Join(t.TempDir(), "env.txt")
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"sh", "-c", "echo \"$GOFLAGS\" > " + probe},
	})
	if err != nil {
		t.Fatal(err)
	}
	b, _ := os.ReadFile(probe)
	if !strings.Contains(string(b), "-modfile=") || !strings.Contains(string(b), "-mod=mod") {
		t.Errorf("go is told to use the build's own go.mod: %s", b)
	}
}

// The binary says which drivers it holds, by what the generated file itself puts in it: a build script that forgot to pass a flag on
// cannot make a binary with an unnamed driver in it.
func TestTheBinaryKnowsWhichCommitsOfWhichDriversItHolds(t *testing.T) {
	goBin(t)
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	os.MkdirAll(filepath.Join(src, "internal", "mcpserver"), 0o755)
	os.WriteFile(filepath.Join(src, "go.mod"), []byte("module github.com/LeafAI/securl\n\ngo 1.26.9\n"), 0o644)
	os.WriteFile(filepath.Join(src, "internal", "mcpserver", "v.go"), []byte("package mcpserver\n\nvar ExternalDrivers []string\n"), 0o644)
	os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\n\nimport (\n\t\"fmt\"\n\n\t\"github.com/LeafAI/securl/internal/mcpserver\"\n)\n\nfunc main() { fmt.Println(\"drivers:\", mcpserver.ExternalDrivers) }\n"), 0o644)
	out := filepath.Join(t.TempDir(), "mini")
	res, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"go", "build", "-o", out, "."},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, err := exec.Command(out).CombinedOutput()
	want := "drivers: [example.test/g/drv@" + r.last + "]"
	if err != nil || !strings.Contains(string(got), want) {
		t.Errorf("want %q: %v\n%s", want, err, got)
	}
	if res.Summary() != "example.test/g/drv@"+r.last {
		t.Errorf("%q", res.Summary())
	}
}

func TestWithNoDriversTheCommandRunsAsItIsAndNothingIsGenerated(t *testing.T) {
	src := mini(t)
	probe := filepath.Join(t.TempDir(), "env.txt")
	res, err := Build(Options{Dir: src, Command: []string{"sh", "-c", "echo \"[$GOFLAGS][$SECURL_DRIVERS_BUILT]\" > " + probe}})
	if err != nil || len(res.Drivers) != 0 {
		t.Fatalf("%v %+v", err, res)
	}
	if b, _ := os.ReadFile(probe); strings.TrimSpace(string(b)) != "["+os.Getenv("GOFLAGS")+"][]" || strings.Contains(string(b), "modfile") {
		t.Errorf("an ordinary build is an ordinary build: %s", b)
	}
	if _, err := os.Stat(filepath.Join(src, ExtraFile)); err == nil {
		t.Error("no file")
	}
}

func TestAFailedBuildStillCleansUpAndSaysSo(t *testing.T) {
	goBin(t)
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"sh", "-c", "exit 3"},
	})
	if err == nil || !strings.Contains(err.Error(), "build command") {
		t.Errorf("%v", err)
	}
	if _, e := os.Stat(filepath.Join(src, ExtraFile)); e == nil {
		t.Error("the generated file is left behind after a failure")
	}
}

func TestADriverThatCannotBeFetchedStopsTheBuildBeforeTheCommandRuns(t *testing.T) {
	src := mini(t)
	ran := filepath.Join(t.TempDir(), "ran")
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}}, CloneURL: func(Spec) string { return "file:///nonexistent-xyz" },
		Command: []string{"sh", "-c", "touch " + ran},
	})
	if err == nil {
		t.Fatal("a missing repository was not an error")
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("the build command ran although a driver could not be fetched")
	}
	if _, e := os.Stat(filepath.Join(src, ExtraFile)); e == nil {
		t.Error("nothing is generated")
	}
}

func TestADriverThatIsNotTheModuleItClaimsStopsTheBuild(t *testing.T) {
	r := newRepo(t, "github.com/somebody/else")
	src := mini(t)
	ran := filepath.Join(t.TempDir(), "ran")
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"sh", "-c", "touch " + ran},
	})
	if err == nil || !strings.Contains(err.Error(), "declares") {
		t.Errorf("%v", err)
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("the build command ran")
	}
}

func TestAGeneratedFileThatIsAlreadyThereIsNotOverwritten(t *testing.T) {
	src := mini(t)
	os.WriteFile(filepath.Join(src, ExtraFile), []byte("package main\n// mine\n"), 0o644)
	r := newRepo(t, "example.test/g/drv")
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"true"},
	})
	if err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("%v", err)
	}
	if b, _ := os.ReadFile(filepath.Join(src, ExtraFile)); !strings.Contains(string(b), "mine") {
		t.Error("a file that was there before the build is left as it was")
	}
}

func TestTheBuildNeedsACommandAndASourceDirectoryAndRunsNothingWithout(t *testing.T) {
	if _, err := Build(Options{Dir: mini(t)}); err == nil {
		t.Error("no command")
	}
	ran := filepath.Join(t.TempDir(), "ran")
	touch := []string{"sh", "-c", "touch " + ran}
	if _, err := Build(Options{Command: touch}); err == nil || !strings.Contains(err.Error(), "no source directory given") {
		t.Errorf("no directory: %v", err)
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("with no source directory the command ran in whatever directory the caller happened to be in")
	}
	if _, err := Build(Options{Dir: filepath.Join(t.TempDir(), "nope"), Command: touch}); err == nil || !strings.Contains(err.Error(), "not there") {
		t.Errorf("a directory that is not there: %v", err)
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("the command ran")
	}
	file := filepath.Join(t.TempDir(), "afile")
	os.WriteFile(file, []byte("x"), 0o644)
	if _, err := Build(Options{Dir: file, Command: touch}); err == nil || !strings.Contains(err.Error(), "not there") {
		t.Errorf("a file is not a source directory: %v", err)
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("the command ran")
	}
}

func TestTwoDriversAreBothFetchedAndBothLinkedIn(t *testing.T) {
	goBin(t)
	a := driverRepo(t, "example.test/g/one", "one")
	b := driverRepo(t, "example.test/g/two", "two")
	src := mini(t)
	out := filepath.Join(t.TempDir(), "mini")
	repos := map[string]string{"example.test/g/one": a.dir, "example.test/g/two": b.dir}
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/one", Rev: "v2.0.0"}, {Host: "example.test", Path: "g/two", Rev: "v2.0.0"}},
		CloneURL: func(s Spec) string { return "file://" + repos[s.Module()] }, Command: []string{"go", "build", "-o", out, "."},
	})
	if err != nil {
		t.Fatal(err)
	}
	got, _ := exec.Command(out).CombinedOutput()
	if !strings.Contains(string(got), "driver-loaded:one") || !strings.Contains(string(got), "driver-loaded:two") {
		t.Errorf("%s", got)
	}
}

func TestTheTemporaryDirectoryOfABuildIsRemoved(t *testing.T) {
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	tmp := t.TempDir()
	t.Setenv("TMPDIR", tmp)
	_, err := Build(Options{
		Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"true"},
	})
	if err != nil {
		t.Fatal(err)
	}
	if left, _ := os.ReadDir(tmp); len(left) != 0 {
		t.Errorf("the fetched sources and the module file are not left lying around: %v", left)
	}
}

func TestADriverIsFetchedFromItsSshAddressWhenNoOtherIsGiven(t *testing.T) {
	src := mini(t)
	spec := Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}
	fake := t.TempDir()
	log := filepath.Join(fake, "asked")
	// a git that records the address it is asked to add as the remote, and then fails: what matters is the address
	os.WriteFile(filepath.Join(fake, "git"), []byte("#!/bin/sh\necho \"$@\" >> "+log+"\nif [ \"$1\" = remote ]; then exit 0; fi\nif [ \"$1\" = init ]; then exit 0; fi\nexit 1\n"), 0o755)
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := Build(Options{Dir: src, Specs: []Spec{spec}, Command: []string{"true"}})
	if err == nil {
		t.Fatal("the fake git fails")
	}
	if b, _ := os.ReadFile(log); !strings.Contains(string(b), "remote add origin "+spec.CloneURL()+"\n") {
		t.Errorf("git was never told to clone from %q:\n%s", spec.CloneURL(), b)
	}
}

func TestTheGitEnvironmentOfTheBuildReachesGitAndTheCommandsDoesNot(t *testing.T) {
	src := mini(t)
	fake := t.TempDir()
	log := filepath.Join(fake, "env")
	os.WriteFile(filepath.Join(fake, "git"), []byte("#!/bin/sh\nenv > "+log+"\nexit 1\n"), 0o755)
	t.Setenv("PATH", fake+string(os.PathListSeparator)+os.Getenv("PATH"))
	_, err := Build(Options{Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}}, CloneURL: func(Spec) string { return "x" },
		Command: []string{"true"}, GitEnv: []string{"GIT_SSH_COMMAND=ssh -i /dev/null"}, Env: []string{"ONLY_FOR_THE_COMMAND=1"}})
	if err == nil {
		t.Fatal("the fake git fails")
	}
	b, _ := os.ReadFile(log)
	if !strings.Contains(string(b), "GIT_SSH_COMMAND=ssh -i /dev/null") {
		t.Errorf("git is given the ssh command:\n%s", b)
	}
	if strings.Contains(string(b), "ONLY_FOR_THE_COMMAND") {
		t.Errorf("what is for the build command is not for git:\n%s", b)
	}
}

func TestTheEnvironmentOfTheCommandIsTheCallersPlusWhatWasAdded(t *testing.T) {
	src := mini(t)
	probe := filepath.Join(t.TempDir(), "env.txt")
	t.Setenv("FROM_THE_CALLER", "yes")
	_, err := Build(Options{Dir: src, Command: []string{"sh", "-c", "echo \"$FROM_THE_CALLER $ADDED\" > " + probe}, Env: []string{"ADDED=also"}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(probe); strings.TrimSpace(string(b)) != "yes also" {
		t.Errorf("%q", b)
	}
}

func TestAFailureSaysWhichExitStatus(t *testing.T) {
	_, err := Build(Options{Dir: mini(t), Command: []string{"sh", "-c", "exit 7"}})
	if err == nil || !strings.Contains(err.Error(), "exit status 7") {
		t.Errorf("%v", err)
	}
	_, err = Build(Options{Dir: mini(t), Command: []string{"/nonexistent/command-xyz"}})
	if err == nil || !strings.Contains(err.Error(), "could not be started") {
		t.Errorf("%v", err)
	}
}

func TestTheOutputOfTheCommandGoesWhereTheCallerSaid(t *testing.T) {
	var out, errb strings.Builder
	_, err := Build(Options{Dir: mini(t), Command: []string{"sh", "-c", "echo to-out; echo to-err >&2"}, Stdout: &out, Stderr: &errb})
	if err != nil {
		t.Fatal(err)
	}
	if strings.TrimSpace(out.String()) != "to-out" || strings.TrimSpace(errb.String()) != "to-err" {
		t.Errorf("%q %q", out.String(), errb.String())
	}
}

func TestASourceDirectoryWithoutAGoModIsRefusedBeforeAnythingIsWritten(t *testing.T) {
	r := driverRepo(t, "example.test/g/drv", "one")
	src := t.TempDir()
	os.WriteFile(filepath.Join(src, "main.go"), []byte("package main\nfunc main(){}\n"), 0o644)
	ran := filepath.Join(t.TempDir(), "ran")
	_, err := Build(Options{Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"sh", "-c", "touch " + ran}})
	if err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("%v", err)
	}
	if _, e := os.Stat(ran); e == nil {
		t.Error("the command ran")
	}
	if _, e := os.Stat(filepath.Join(src, ExtraFile)); e == nil {
		t.Error("a file was written")
	}
}

func TestTheChecksumsOfTheBaseModuleAreAvailableToTheBuild(t *testing.T) {
	r := driverRepo(t, "example.test/g/drv", "one")
	src := mini(t)
	os.WriteFile(filepath.Join(src, "go.sum"), []byte("example.invalid/x v1.0.0 h1:AAAA=\n"), 0o644)
	probe := filepath.Join(t.TempDir(), "sum.txt")
	_, err := Build(Options{Dir: src, Specs: []Spec{{Host: "example.test", Path: "g/drv", Rev: "v2.0.0"}}, CloneURL: func(Spec) string { return "file://" + r.dir },
		Command: []string{"sh", "-c", "m=${GOFLAGS##*-modfile=}; m=${m%% *}; cat \"${m%.mod}.sum\" > " + probe}})
	if err != nil {
		t.Fatal(err)
	}
	if b, _ := os.ReadFile(probe); !strings.Contains(string(b), "example.invalid/x v1.0.0 h1:AAAA=") {
		t.Errorf("the build's own go.sum starts from the repository's, so what is already trusted stays trusted: %q", b)
	}
}

func TestTheSummaryNamesEachDriverAndTheCommitItIs(t *testing.T) {
	r := &Result{Drivers: []Fetched{
		{Spec: Spec{Host: "example.test", Path: "g/one", Rev: "v1.0.0"}, Commit: strings.Repeat("a", 40)},
		{Spec: Spec{Host: "example.test", Path: "g/two", Rev: "v2.0.0"}, Commit: strings.Repeat("b", 40)},
	}}
	want := "example.test/g/one@" + strings.Repeat("a", 40) + " example.test/g/two@" + strings.Repeat("b", 40)
	if r.Summary() != want {
		t.Errorf("%q", r.Summary())
	}
	if (&Result{}).Summary() != "" {
		t.Error("no driver, nothing to say")
	}
}
