package main

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

const addSumsScript = "scripts/add-to-sums.sh"

func addSkip(t *testing.T) {
	t.Helper()
	if runtime.GOOS == "windows" {
		t.Skip("bash script")
	}
	if _, err := exec.LookPath("bash"); err != nil {
		t.Skip("bash")
	}
}

// sumsDir is a release directory as release.sh leaves it: two archives and their sums.
func sumsDir(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	for _, n := range []string{"securl_linux_amd64.tar.gz", "securl_windows_amd64.zip"} {
		os.WriteFile(filepath.Join(dir, n), []byte("content of "+n), 0o644)
	}
	for sum, args := range map[string][]string{"SHA1SUMS": {"-a", "1"}, "SHA256SUMS": {"-a", "256"}} {
		c := exec.Command("shasum", append(args, "securl_linux_amd64.tar.gz", "securl_windows_amd64.zip")...)
		c.Dir = dir
		out, err := c.Output()
		if err != nil {
			t.Skipf("shasum: %v", err)
		}
		os.WriteFile(filepath.Join(dir, sum), out, 0o644)
	}
	return dir
}

func addSums(dir string, files ...string) ([]byte, error) {
	return exec.Command("bash", append([]string{addSumsScript, dir}, files...)...).CombinedOutput()
}

func TestAddedFilesAreListedInBothSumFilesAndTheOldLinesAreKept(t *testing.T) {
	addSkip(t)
	dir := sumsDir(t)
	before, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	os.WriteFile(filepath.Join(dir, "securl_nightly-20261012-1a2b3c4_macos.pkg"), []byte("a package"), 0o644)
	os.WriteFile(filepath.Join(dir, "securl_macos.pkg"), []byte("a package"), 0o644)
	if out, err := addSums(dir, "securl_nightly-20261012-1a2b3c4_macos.pkg", "securl_macos.pkg"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for _, sum := range []string{"SHA1SUMS", "SHA256SUMS"} {
		b, _ := os.ReadFile(filepath.Join(dir, sum))
		for _, want := range []string{"securl_nightly-20261012-1a2b3c4_macos.pkg", "securl_macos.pkg", "securl_linux_amd64.tar.gz", "securl_windows_amd64.zip"} {
			if !strings.Contains(string(b), "  "+want+"\n") {
				t.Errorf("%s lacks %s:\n%s", sum, want, b)
			}
		}
	}
	after, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	for _, line := range strings.Split(strings.TrimSpace(string(before)), "\n") {
		if !strings.Contains(string(after), line+"\n") {
			t.Errorf("the line of an archive changed or was lost: %s", line)
		}
	}
}

func TestTheCheckAUserMakesPassesAfterTheFilesWereAdded(t *testing.T) {
	addSkip(t)
	dir := sumsDir(t)
	os.WriteFile(filepath.Join(dir, "securl_macos.pkg"), []byte("a package"), 0o644)
	if out, err := addSums(dir, "securl_macos.pkg"); err != nil {
		t.Fatalf("%v\n%s", err, out)
	}
	for sum, args := range map[string][]string{"SHA1SUMS": {"-a", "1"}, "SHA256SUMS": {"-a", "256"}} {
		c := exec.Command("shasum", append(args, "--check", "--strict", sum)...)
		c.Dir = dir
		if out, err := c.CombinedOutput(); err != nil {
			t.Errorf("%s: %v\n%s", sum, err, out)
		}
	}
}

func TestAddedLinesAreInTheSameOrderAsIfTheyHadBeenThereFromTheStart(t *testing.T) {
	addSkip(t)
	dir := sumsDir(t)
	os.WriteFile(filepath.Join(dir, "securl_macos.pkg"), []byte("p"), 0o644)
	addSums(dir, "securl_macos.pkg")
	b, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
	var names []string
	for _, l := range strings.Split(strings.TrimSpace(string(b)), "\n") {
		names = append(names, strings.Fields(l)[1])
	}
	want := []string{"securl_linux_amd64.tar.gz", "securl_macos.pkg", "securl_windows_amd64.zip"}
	if strings.Join(names, ",") != strings.Join(want, ",") {
		t.Errorf("order %v, want %v", names, want)
	}
}

func TestAddingRefusesWhatWouldMakeTheSumsLieOrBeAmbiguous(t *testing.T) {
	addSkip(t)
	for name, tc := range map[string]struct {
		prep  func(dir string)
		files []string
	}{
		"already listed": {func(d string) {}, []string{"securl_linux_amd64.tar.gz"}},
		"not a file":     {func(d string) {}, []string{"securl_missing.pkg"}},
		"a path, not a name": {func(d string) {
			os.MkdirAll(filepath.Join(d, "sub"), 0o755)
			os.WriteFile(filepath.Join(d, "sub", "x"), []byte("x"), 0o644)
		}, []string{"sub/x"}},
		"the signature itself": {func(d string) { os.WriteFile(filepath.Join(d, "SHA256SUMS.sig"), []byte("s"), 0o644) }, []string{"SHA256SUMS.sig"}},
		"a sums file":          {func(d string) {}, []string{"SHA256SUMS"}},
		"an empty name":        {func(d string) {}, []string{""}},
		"no files at all":      {func(d string) {}, nil},
		"one good, one bad":    {func(d string) { os.WriteFile(filepath.Join(d, "good.pkg"), []byte("g"), 0o644) }, []string{"good.pkg", "bad.pkg"}},
	} {
		dir := sumsDir(t)
		tc.prep(dir)
		b1, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		out, err := addSums(dir, tc.files...)
		if err == nil {
			t.Errorf("%s: accepted\n%s", name, out)
		}
		b2, _ := os.ReadFile(filepath.Join(dir, "SHA256SUMS"))
		if string(b1) != string(b2) {
			t.Errorf("%s: SHA256SUMS was changed although the call was refused:\n%s", name, b2)
		}
	}
}

func TestAddingToSumsThatDoNotExistIsAnError(t *testing.T) {
	addSkip(t)
	dir := t.TempDir()
	os.WriteFile(filepath.Join(dir, "x.pkg"), []byte("x"), 0o644)
	if out, err := addSums(dir, "x.pkg"); err == nil {
		t.Errorf("accepted: there are no sums to add to\n%s", out)
	}
}
