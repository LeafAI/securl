//go:build unix

package daemon

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestTheDefaultSocketIsInTheRuntimeDirectoryWhenThereIsOne(t *testing.T) {
	dir := shortDir(t)
	got := DefaultSocket(func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return dir
		}
		return ""
	}, 501)
	if got != filepath.Join(dir, "securl", "d.sock") {
		t.Errorf("got %q", got)
	}
}

func TestWithoutARuntimeDirectoryTheSocketIsInAPrivateDirectoryNamedForTheUser(t *testing.T) {
	got := DefaultSocket(func(string) string { return "" }, 501)
	if !strings.Contains(got, "securl-501") {
		t.Errorf("the directory carries the uid, so two users on one machine do not share or fight over it: %q", got)
	}
	if !strings.HasPrefix(got, "/tmp/") {
		t.Errorf("a short, predictable root, not $TMPDIR (which is long on macOS and would pass the 104-byte limit): %q", got)
	}
}

func TestTheDefaultSocketPathAlwaysFits(t *testing.T) {
	long := "/var/folders/84/lgy_kh5s60d9lfvx67yr65hc0000gn/T/" + strings.Repeat("x", 80)
	for _, env := range []map[string]string{{}, {"TMPDIR": long}, {"XDG_RUNTIME_DIR": "/run/user/1000"}} {
		got := DefaultSocket(func(k string) string { return env[k] }, 4294967295)
		if len(got) > maxSocketPath {
			t.Errorf("%v: %q is %d bytes, over the %d the kernel allows", env, got, len(got), maxSocketPath)
		}
	}
}

func TestAnUnusableRuntimeDirectoryIsNotUsed(t *testing.T) {
	// a value that is not an absolute path is ignored rather than turned into a socket in the current directory
	got := DefaultSocket(func(k string) string {
		if k == "XDG_RUNTIME_DIR" {
			return "relative/dir"
		}
		return ""
	}, 501)
	if !filepath.IsAbs(got) {
		t.Errorf("%q", got)
	}
	_ = os.Getuid
}
