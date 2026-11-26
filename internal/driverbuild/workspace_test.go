package driverbuild

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheModulePathIsWhatTheDriversGoModDeclares(t *testing.T) {
	for name, tc := range map[string]struct{ mod, want string }{
		"plain":           {"module example.test/g/drv\n\ngo 1.26.9\n", "example.test/g/drv"},
		"quoted":          {"module \"example.test/g/drv\"\n", "example.test/g/drv"},
		"a comment first": {"// a driver\nmodule example.test/g/drv\n", "example.test/g/drv"},
		"tabs":            {"module\texample.test/g/drv\n", "example.test/g/drv"},
		"indented":        {"  module example.test/g/drv\n", "example.test/g/drv"},
		"a major version": {"module example.test/g/drv/v2\n", "example.test/g/drv/v2"},
	} {
		dir := t.TempDir()
		os.WriteFile(filepath.Join(dir, "go.mod"), []byte(tc.mod), 0o644)
		got, err := ModulePath(dir)
		if err != nil || got != tc.want {
			t.Errorf("%s: got %q, %v", name, got, err)
		}
	}
	empty := t.TempDir()
	if _, err := ModulePath(empty); err == nil {
		t.Error("no go.mod")
	}
	os.WriteFile(filepath.Join(empty, "go.mod"), []byte("go 1.26.9\n"), 0o644)
	if _, err := ModulePath(empty); err == nil {
		t.Error("a go.mod with no module line")
	}
	os.WriteFile(filepath.Join(empty, "go.mod"), []byte("modulex example.test/x\n"), 0o644)
	if _, err := ModulePath(empty); err == nil {
		t.Error("modulex is not module")
	}
}

func TestADriverWhoseModuleIsNotWhereItWasFetchedFromIsRefused(t *testing.T) {
	good := Fetched{Spec: Spec{Host: "example.test", Path: "g/drv", Rev: "v1.0.0"}, Commit: strings.Repeat("a", 40), Dir: t.TempDir()}
	os.WriteFile(filepath.Join(good.Dir, "go.mod"), []byte("module example.test/g/drv\n"), 0o644)
	if err := good.CheckModule(); err != nil {
		t.Errorf("%v", err)
	}
	bad := good
	bad.Dir = t.TempDir()
	os.WriteFile(filepath.Join(bad.Dir, "go.mod"), []byte("module github.com/somebody/else\n"), 0o644)
	err := bad.CheckModule()
	if err == nil || !strings.Contains(err.Error(), "declares") {
		t.Errorf("a repository that calls itself another module would be built in under a name nobody reviewed: %v", err)
	}
	if err != nil && strings.Contains(err.Error(), "somebody") {
		t.Errorf("what it declares is not repeated: %v", err)
	}
	none := good
	none.Dir = t.TempDir()
	if err := none.CheckModule(); err == nil || !strings.Contains(err.Error(), "go.mod") {
		t.Errorf("a driver with no go.mod: %v", err)
	}
	major := good
	major.Dir = t.TempDir()
	os.WriteFile(filepath.Join(major.Dir, "go.mod"), []byte("module example.test/g/drv/v2\n"), 0o644)
	if err := major.CheckModule(); err == nil {
		t.Error("a /v2 module is a different path from the one fetched")
	}
}

func fetched(t *testing.T, path, rev string) Fetched {
	t.Helper()
	d := t.TempDir()
	os.WriteFile(filepath.Join(d, "go.mod"), []byte("module example.test/"+path+"\n"), 0o644)
	return Fetched{Spec: Spec{Host: "example.test", Path: path, Rev: rev}, Commit: strings.Repeat("c", 40), Dir: d}
}

const base = "module github.com/LeafAI/securl\n\ngo 1.26.9\n\nrequire gopkg.in/yaml.v3 v3.0.1\n"

func TestTheModfileGetsOneRequireAndOneReplacePerDriverAndKeepsTheRest(t *testing.T) {
	a, b := fetched(t, "g/one", "v1.0.0"), fetched(t, "g/two", "v1.0.0")
	out, err := Modfile(base, []Fetched{a, b})
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		"module github.com/LeafAI/securl", "require gopkg.in/yaml.v3 v3.0.1",
		"require example.test/g/one v0.0.0", "replace example.test/g/one => " + a.Dir,
		"require example.test/g/two v0.0.0", "replace example.test/g/two => " + b.Dir,
	} {
		if !strings.Contains(out, want) {
			t.Errorf("%q is missing:\n%s", want, out)
		}
	}
	if strings.Count(out, "\nreplace ") != 2 || strings.Count(out, "require example.test") != 2 {
		t.Errorf("%s", out)
	}
	if out2, err := Modfile(base, nil); err != nil || out2 != base {
		t.Errorf("no driver, no change: %v\n%s", err, out2)
	}
}

// A path that holds a space, a newline or a quote would end the replace line and begin a directive of its own.
func TestADirectoryThatCouldEndTheReplaceLineIsRefused(t *testing.T) {
	for name, dir := range map[string]string{
		"a newline": "/tmp/x\nreplace github.com/LeafAI/securl => /tmp/evil", "a space": "/tmp/a b", "a quote": "/tmp/a\"b",
		"a tab": "/tmp/a\tb", "relative": "tmp/x", "a comment": "/tmp/a//b c",
	} {
		f := fetched(t, "g/one", "v1.0.0")
		f.Dir = dir
		if _, err := Modfile(base, []Fetched{f}); err == nil {
			t.Errorf("%s: %q was accepted", name, dir)
		}
	}
	f := fetched(t, "g/one", "v1.0.0")
	f.Spec.Path = "g/one\nreplace x => y"
	if _, err := Modfile(base, []Fetched{f}); err == nil {
		t.Error("a module path that is not a plain path")
	}
}

func TestADriverThatReplacesSecurlOrAnotherDriverIsRefused(t *testing.T) {
	f := fetched(t, "g/one", "v1.0.0")
	if _, err := Modfile(base+"\nreplace example.test/g/one => /elsewhere\n", []Fetched{f}); err == nil || !strings.Contains(err.Error(), "already") {
		t.Errorf("the module is already in the base go.mod: %v", err)
	}
}

func TestTheGeneratedSourceLinksTheDriversInAndSaysWhichCommitsWereBuilt(t *testing.T) {
	a, b := fetched(t, "g/one", "v1.0.0"), fetched(t, "g/two/sub", "v1.0.0")
	src := Source([]Fetched{a, b}, "github.com/LeafAI/securl/internal/mcpserver")
	want := "// Code generated by generate.go; DO NOT EDIT.\n\npackage main\n\nimport (\n" +
		"\t\"github.com/LeafAI/securl/internal/mcpserver\"\n\n" +
		"\t_ \"example.test/g/one\"\n\t_ \"example.test/g/two/sub\"\n)\n\n" +
		"func init() {\n\tmcpserver.ExternalDrivers = []string{\n" +
		"\t\t\"example.test/g/one@" + a.Commit + "\",\n\t\t\"example.test/g/two/sub@" + b.Commit + "\",\n\t}\n}\n"
	if src != want {
		t.Errorf("got:\n%s\nwant:\n%s", src, want)
	}
	if Source(nil, "github.com/LeafAI/securl/internal/mcpserver") != "" {
		t.Error("no driver, no file")
	}
}

func TestWithNoPackageToRecordThemInTheDriversAreOnlyLinkedIn(t *testing.T) {
	a := fetched(t, "g/one", "v1.0.0")
	want := "// Code generated by generate.go; DO NOT EDIT.\n\npackage main\n\nimport (\n\t_ \"example.test/g/one\"\n)\n"
	if got := Source([]Fetched{a}, ""); got != want {
		t.Errorf("got:\n%s\nwant:\n%s", got, want)
	}
}

func TestTheDriversAreImportedInTheOrderTheyWereAskedFor(t *testing.T) {
	a, b, c := fetched(t, "g/zzz", "v1.0.0"), fetched(t, "g/aaa", "v1.0.0"), fetched(t, "g/mmm", "v1.0.0")
	src := Source([]Fetched{a, b, c}, "")
	if !(strings.Index(src, "zzz") < strings.Index(src, "aaa") && strings.Index(src, "aaa") < strings.Index(src, "mmm")) {
		t.Errorf("the order is the one given, so that the build is the same each time:\n%s", src)
	}
}

func TestEachCharacterThatCouldEndOrChangeAReplaceLineIsRefusedOnItsOwn(t *testing.T) {
	for name, dir := range map[string]string{
		"a space": "/tmp/a b", "a tab": "/tmp/a\tb", "a newline": "/tmp/a\nb", "a carriage return": "/tmp/a\rb", "a quote": "/tmp/a\"b",
		"a backtick": "/tmp/a`b", "a backslash": "/tmp/a\\b", "a delete character": "/tmp/a\x7fb", "a null": "/tmp/a\x00b", "a double slash": "/tmp//b",
		"not absolute": "tmp/b", "empty": "",
	} {
		f := fetched(t, "g/one", "v1.0.0")
		f.Dir = dir
		if _, err := Modfile(base, []Fetched{f}); err == nil {
			t.Errorf("%s: %q was accepted", name, dir)
		}
	}
	for _, dir := range []string{"/tmp/securl-drivers-123/d0", "/var/folders/ab/c_d-e.f/T/x"} {
		f := fetched(t, "g/one", "v1.0.0")
		f.Dir = dir
		if _, err := Modfile(base, []Fetched{f}); err != nil {
			t.Errorf("%q: %v", dir, err)
		}
	}
}

func TestADirectoryThatIsOnlyAbsoluteAndPlainIsFine(t *testing.T) {
	if !plainDir("/a/b/c") || plainDir("a/b") || plainDir("/a//b") || plainDir("/a b") {
		t.Error("plainDir")
	}
}

func TestADriverIsRefusedWhenTheModuleFileOfSecurlIsNotReadable(t *testing.T) {
	f := fetched(t, "g/one", "v1.0.0")
	f.Dir = t.TempDir()
	if err := f.CheckModule(); err == nil || !strings.Contains(err.Error(), "no go.mod") {
		t.Errorf("%v", err)
	}
}

// With no driver the module file is the repository's own, byte for byte, whatever its ending: nothing is trimmed or added.
func TestWithNoDriverTheModuleFileIsReturnedExactly(t *testing.T) {
	for _, in := range []string{"module x\n", "module x", "module x\n\n\n", ""} {
		got, err := Modfile(in, nil)
		if err != nil || got != in {
			t.Errorf("%q -> %q, %v", in, got, err)
		}
	}
}
