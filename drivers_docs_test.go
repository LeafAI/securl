package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/driverbuild"
	"github.com/LeafAI/securl/internal/mcpserver"
)

// docs/DRIVERS.md tells people how to build a driver in and how to write one. What it promises is held to the code: the example
// compiles against the package it names, every spec it shows is one the build accepts, and the numbers are the ones in the code.

func driversDoc(t *testing.T) string {
	t.Helper()
	b, err := os.ReadFile("docs/DRIVERS.md")
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func codeBlocks(doc, lang string) []string {
	re := regexp.MustCompile("(?s)```" + lang + "\n(.*?)```")
	var out []string
	for _, m := range re.FindAllStringSubmatch(doc, -1) {
		out = append(out, m[1])
	}
	return out
}

// The driver a reader copies must compile: it is built here against this tree, as an outside module would build it.
func TestTheExampleDriverInTheDocumentCompilesAgainstThePackageItNames(t *testing.T) {
	blocks := codeBlocks(driversDoc(t), "go")
	if len(blocks) != 1 {
		t.Fatalf("the document has %d go examples, want the one driver", len(blocks))
	}
	root, _ := os.Getwd()
	dir := t.TempDir()
	os.MkdirAll(filepath.Join(dir, "admin"), 0o755)
	os.WriteFile(filepath.Join(dir, "admin", "admin.go"), []byte(blocks[0]), 0o644)
	os.WriteFile(filepath.Join(dir, "go.mod"), []byte("module example.test/admin\n\ngo 1.26.9\n\nrequire github.com/LeafAI/securl v0.0.0\n\nreplace github.com/LeafAI/securl => "+root+"\n"), 0o644)
	b, _ := os.ReadFile(filepath.Join(root, "go.sum"))
	os.WriteFile(filepath.Join(dir, "go.sum"), b, 0o644)
	// an outside module cannot import internal/: building it proves the example uses only what is exported
	cmd := exec.Command("go", "vet", "./admin/")
	cmd.Dir = dir
	cmd.Env = append(os.Environ(), "GOFLAGS=-mod=mod", "GOPROXY=off")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("the example in docs/DRIVERS.md does not build:\n%s", out)
	}
}

func TestTheExampleRegistersADriverThatTakesPartInRememberedCredentials(t *testing.T) {
	ex := codeBlocks(driversDoc(t), "go")[0]
	for _, want := range []string{"driver.Register(", "RememberScope()", "driver.LoginFields()", "ask.Ask(ctx, \"login\"", "driver.Session{"} {
		if !strings.Contains(ex, want) {
			t.Errorf("the example does not show %q", want)
		}
	}
	if strings.Contains(ex, "internal/") {
		t.Error("the example imports an internal package, which an outside module cannot")
	}
}

// Every command line the document shows names drivers that the build would accept.
func TestEverySpecTheDocumentShowsIsOneTheBuildAccepts(t *testing.T) {
	// what `securl version` prints (in a block with no language) shows commits shortened; it is output, not something to type
	doc := withoutOutputBlocks(driversDoc(t))
	re := regexp.MustCompile(`[a-z0-9.-]+\.[a-z]+(?::\d+)?/[A-Za-z0-9_./-]+@[A-Za-z0-9._-]+`)
	seen := 0
	for _, m := range re.FindAllString(doc, -1) {
		if strings.HasPrefix(m, "github.com/LeafAI/securl") {
			continue
		}
		seen++
		if _, err := driverbuild.ParseSpec(m); err != nil {
			t.Errorf("the document shows %q, which the build refuses: %v", m, err)
		}
	}
	if seen < 6 {
		t.Errorf("only %d specs were found in the document", seen)
	}
}

// withoutOutputBlocks drops the blocks that have no language after their opening fence: they show what a program prints.
func withoutOutputBlocks(doc string) string {
	var out []string
	in, skip := false, false
	for _, line := range strings.Split(doc, "\n") {
		switch {
		case strings.HasPrefix(line, "```") && !in:
			in, skip = true, line == "```"
		case strings.HasPrefix(line, "```") && in:
			in, skip = false, false
			continue
		}
		if !skip {
			out = append(out, line)
		}
	}
	return strings.Join(out, "\n")
}

func TestTheNumbersAndNamesTheDocumentGivesAreTheCodes(t *testing.T) {
	doc := driversDoc(t)
	if !strings.Contains(doc, "At most 16.") || driverbuild.MaxSpecs != 16 {
		t.Errorf("the limit on drivers is %d", driverbuild.MaxSpecs)
	}
	for _, want := range []string{driverbuild.ExtraFile, "SECURL_DRIVERS", "SECURL_DRIVERS_SSH_KEY", "--ssh-key", "go build -modfile", "scripts/release.sh", "scripts/publish-nightly.sh", "github.com/LeafAI/securl/driver", "securl version", "+drivers["} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document does not mention %q", want)
		}
	}
	for _, f := range []string{"generate.go", "scripts/release.sh", "scripts/publish-nightly.sh", "driver/driver.go", "internal/driverbuild/build.go"} {
		if _, err := os.Stat(f); err != nil {
			t.Errorf("the document names %s, which is not there", f)
		}
	}
}

// The version line the document shows is the one the program prints.
func TestTheVersionLineInTheDocumentIsTheShapeTheProgramPrints(t *testing.T) {
	old := mcpserver.ExternalDrivers
	defer func() { mcpserver.ExternalDrivers = old }()
	mcpserver.ExternalDrivers = []string{"gitlab.example.com/group/repo@4b5a6fc17bbd68ba7390b6b944aa1cf43140271e"}
	got := versionLine()
	if !strings.Contains(got, " +drivers[gitlab.example.com/group/repo@4b5a6fc17bbd] ") {
		t.Errorf("%q", got)
	}
	doc := driversDoc(t)
	if !strings.Contains(doc, "+drivers[gitlab.example.com/group/repo@4b5a6fc17bbd]") {
		t.Error("the document shows another shape")
	}
}

func TestTheDocumentSaysWhatAnOperatorMustKnowAboutTrust(t *testing.T) {
	doc := strings.ToLower(strings.Join(strings.Fields(driversDoc(t)), " "))
	for _, want := range []string{
		"write access to a driver's repository is therefore write access to securl",
		"protected branches", "pinned", "never touched", "experimental", "never published", "known_hosts", "never learns a host",
		"never repeats what git or ssh printed", "only for the two rounds securl knows how to remember",
		"refuse to run when `securl_drivers` is set", "a binary with a driver from another repository in it is for whoever built it",
	} {
		if !strings.Contains(doc, want) {
			t.Errorf("the document does not say %q", want)
		}
	}
}

func TestTheReadmePointsAtTheDriversGuideAndSaysTheOfficialBuildRefusesThem(t *testing.T) {
	b, _ := os.ReadFile("README.md")
	s := strings.Join(strings.Fields(string(b)), " ")
	for _, want := range []string{"docs/DRIVERS.md", "DRIVERS=", "pinned", "write access to its repository is write access to securl", "refuses to be made with one"} {
		if !strings.Contains(s, want) {
			t.Errorf("the README does not say %q", want)
		}
	}
}

// What the build adds to the tree is never committed by mistake: it is removed after the build, and if a build is killed it is
// still not something git would pick up.
func TestTheGeneratedFileIsIgnoredByGit(t *testing.T) {
	cmd := exec.Command("git", "check-ignore", "-q", driverbuild.ExtraFile)
	if err := cmd.Run(); err != nil {
		t.Errorf("%s is not in .gitignore: %v", driverbuild.ExtraFile, err)
	}
}
