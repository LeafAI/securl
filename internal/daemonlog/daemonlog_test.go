package daemonlog

import (
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

func TestDefaultIsInTheLogsDirectoryOfTheHomeOfWhoRunsIt(t *testing.T) {
	got, err := Resolve("default", "/Users/alice")
	if err != nil {
		t.Fatal(err)
	}
	if got != "/Users/alice/Library/Logs/securl-daemon.log" {
		t.Errorf("got %q", got)
	}
	got, _ = Resolve("default", "/Users/bob")
	if got != "/Users/bob/Library/Logs/securl-daemon.log" {
		t.Errorf("one plist serves every user: the same word is each user's own file; got %q", got)
	}
}

func TestAPathIsUsedAsItIsWhenItIsAbsolute(t *testing.T) {
	got, err := Resolve("/var/log/x.log", "/Users/alice")
	if err != nil || got != "/var/log/x.log" {
		t.Errorf("%q %v", got, err)
	}
}

func TestNothingMeansStandardError(t *testing.T) {
	got, err := Resolve("", "/Users/alice")
	if err != nil || got != "" {
		t.Errorf("no -log is the terminal, as when a person runs the daemon by hand: %q %v", got, err)
	}
}

func TestResolveRefusesWhatWouldWriteInTheWrongPlace(t *testing.T) {
	for name, tc := range map[string]struct{ spec, home string }{
		"a relative path":                {"securl.log", "/Users/alice"},
		"~ is not expanded":              {"~/x.log", "/Users/alice"},
		"$HOME is not":                   {"$HOME/x.log", "/Users/alice"},
		"default, no home":               {"default", ""},
		"default, relative home":         {"default", "alice"},
		"a path with a NUL":              {"/tmp/a\x00b", "/Users/alice"},
		"a path that climbs":             {"/Users/alice/../bob/x.log", "/Users/alice"},
		"a variable in an absolute path": {"/Users/$USER/x.log", "/Users/alice"},
	} {
		if got, err := Resolve(tc.spec, tc.home); err == nil {
			t.Errorf("%s: accepted, as %q", name, got)
		}
	}
}

func TestOpenCreatesAPrivateFileAndAppends(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "Library", "Logs", "securl-daemon.log")
	w, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w.Write([]byte("one\n"))
	w.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Errorf("mode %v: the log names what the daemon did, for one user's eyes", st.Mode().Perm())
	}
	if dst, _ := os.Stat(filepath.Dir(path)); dst.Mode().Perm()&0o022 != 0 {
		t.Errorf("the directory the log was made in can be written by others: %v", dst.Mode().Perm())
	}
	w2, err := Open(path)
	if err != nil {
		t.Fatal(err)
	}
	w2.Write([]byte("two\n"))
	w2.Close()
	if b, _ := os.ReadFile(path); string(b) != "one\ntwo\n" {
		t.Errorf("a second start appends, it does not erase the history: %q", b)
	}
}

func TestOpenDoesNotFollowALinkAndDoesNotKeepAFileOthersCanUse(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	dir := t.TempDir()
	target := filepath.Join(dir, "target")
	os.WriteFile(target, []byte("keep"), 0o600)
	link := filepath.Join(dir, "log")
	if err := os.Symlink(target, link); err != nil {
		t.Fatal(err)
	}
	if w, err := Open(link); err == nil {
		w.Write([]byte("x"))
		w.Close()
		t.Error("a link was followed: a log path that somebody else can swap for a link would write wherever they like")
	}
	if b, _ := os.ReadFile(target); string(b) != "keep" {
		t.Errorf("the link's target was written: %q", b)
	}
	open := filepath.Join(dir, "open.log")
	os.WriteFile(open, []byte("old\n"), 0o666)
	os.Chmod(open, 0o666)
	w, err := Open(open)
	if err != nil {
		t.Fatal(err)
	}
	w.Close()
	if st, _ := os.Stat(open); st.Mode().Perm()&0o077 != 0 {
		t.Errorf("a file that others could read or write was kept that way: %v", st.Mode().Perm())
	}
}

func TestOpenSaysWhichFileItCouldNotOpen(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "afile")
	os.WriteFile(blocker, []byte("x"), 0o600)
	path := filepath.Join(blocker, "sub", "x.log") // a directory cannot be made inside a file
	_, err := Open(path)
	if err == nil {
		t.Fatal("opened a log inside a file")
	}
	if !strings.Contains(err.Error(), blocker) {
		t.Errorf("the error names the path that failed: %v", err)
	}
}

// A "~" that is not at the start is just a character of a file name: nothing expands it, so it is not refused.
func TestATildeInTheMiddleOfAnAbsolutePathIsAFileName(t *testing.T) {
	got, err := Resolve("/Users/~alice/x.log", "/Users/alice")
	if err != nil || got != "/Users/~alice/x.log" {
		t.Errorf("%q %v", got, err)
	}
}
