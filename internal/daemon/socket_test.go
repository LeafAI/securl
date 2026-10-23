//go:build unix

package daemon

import (
	"context"
	"net"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

func shortDir(t *testing.T) string {
	t.Helper()
	// a unix socket path is limited to about 104 bytes, and t.TempDir() is long on macOS
	d, err := os.MkdirTemp("/tmp", "sd")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.RemoveAll(d) })
	return d
}

func TestListenMakesASocketOnlyTheOwnerCanUse(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm()&0o077 != 0 {
		t.Errorf("the socket is reachable by others: %v", st.Mode())
	}
	if st.Mode()&os.ModeSocket == 0 {
		t.Errorf("not a socket: %v", st.Mode())
	}
	dst, _ := os.Stat(filepath.Dir(path))
	if dst.Mode().Perm()&0o022 != 0 {
		t.Errorf("the directory of the socket can be written by others: %v", dst.Mode())
	}
}

func TestTheSocketIsNeverBrieflyOpenToOthers(t *testing.T) {
	// the umask is set around bind, so there is no moment between creating the socket and chmod in which another user can connect
	old := setUmask(0)
	defer setUmask(old)
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	st, _ := os.Stat(path)
	if st.Mode().Perm() != 0o600 {
		t.Errorf("with a permissive umask the socket is %v, want 0600", st.Mode().Perm())
	}
	if got := setUmask(0); got != 0 {
		t.Errorf("the umask was left changed: %o", got)
	}
}

// Between the socket being made and the chmod there is a moment. The socket must not be open to others in it, whatever the
// umask of the process was.
func TestTheSocketIsNotOpenToOthersEvenBeforeTheChmod(t *testing.T) {
	old := setUmask(0)
	defer setUmask(old)
	var inWindow os.FileMode
	afterBind = func(path string) {
		if st, err := os.Stat(path); err == nil {
			inWindow = st.Mode().Perm()
		}
	}
	defer func() { afterBind = nil }()
	l, err := Listen(filepath.Join(shortDir(t), "d.sock"))
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if inWindow == 0 {
		t.Fatal("the hook did not run")
	}
	if inWindow&0o077 != 0 {
		t.Errorf("in the moment before the chmod the socket is %v: another user could connect in it", inWindow)
	}
}

func TestASecondDaemonRefusesToStartWhileTheFirstIsAlive(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	if l2, err := Listen(path); err == nil {
		l2.Close()
		t.Fatal("two daemons on one socket")
	} else if !strings.Contains(err.Error(), "already running") {
		t.Errorf("the error says what is wrong: %v", err)
	}
	if _, err := net.Dial("unix", path); err != nil {
		t.Errorf("the first daemon must be untouched by the refused second: %v", err)
	}
}

func TestAStaleSocketFromACrashedDaemonIsReplaced(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := net.Listen("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	l.(*net.UnixListener).SetUnlinkOnClose(false) // a crash leaves the file behind
	l.Close()
	if _, err := os.Stat(path); err != nil {
		t.Fatal("the stale socket file must exist for this test")
	}
	l2, err := Listen(path)
	if err != nil {
		t.Fatalf("a dead socket must not keep the daemon from starting: %v", err)
	}
	l2.Close()
}

func TestAFileThatIsNotASocketIsNeverRemoved(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	if err := os.WriteFile(path, []byte("precious"), 0o600); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(path); err == nil {
		l.Close()
		t.Fatal("a regular file was replaced by a socket")
	}
	if b, _ := os.ReadFile(path); string(b) != "precious" {
		t.Error("the file was changed")
	}
}

func TestASymlinkInPlaceOfTheSocketIsNotFollowed(t *testing.T) {
	dir := shortDir(t)
	target := filepath.Join(dir, "elsewhere")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(dir, "d.sock")
	if err := os.Symlink(target, path); err != nil {
		t.Fatal(err)
	}
	if l, err := Listen(path); err == nil {
		l.Close()
		t.Fatal("a symlink was replaced or followed")
	}
	if b, _ := os.ReadFile(target); string(b) != "x" {
		t.Error("the link's target was changed")
	}
}

func TestADirectoryOthersCanWriteIsRefused(t *testing.T) {
	dir := shortDir(t)
	os.Chmod(dir, 0o777)
	if l, err := Listen(filepath.Join(dir, "d.sock")); err == nil {
		l.Close()
		t.Fatal("a socket in a directory that anyone can write to: another user could replace it")
	}
}

func TestAPathTooLongForASocketIsAnErrorThatSaysSo(t *testing.T) {
	long := filepath.Join(shortDir(t), strings.Repeat("x", 120), "d.sock")
	_, err := Listen(long)
	if err == nil {
		t.Fatal("accepted")
	}
	if !strings.Contains(err.Error(), "too long") {
		t.Errorf("the error must say the path is too long: %v", err)
	}
}

func TestDialFindsADaemonAndNamesTheOneThatIsNotThere(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	if _, err := Dial(context.Background(), path); !IsNotRunning(err) {
		t.Errorf("no daemon: %v", err)
	}
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	go func() {
		c, _ := l.Accept()
		if c != nil {
			c.Close()
		}
	}()
	c, err := Dial(context.Background(), path)
	if err != nil {
		t.Fatal(err)
	}
	c.Close()
}

func TestAStaleSocketIsNotRunning(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	l, _ := net.Listen("unix", path)
	l.(*net.UnixListener).SetUnlinkOnClose(false)
	l.Close()
	if _, err := Dial(context.Background(), path); !IsNotRunning(err) {
		t.Errorf("a socket nobody listens on is a daemon that is not running: %v", err)
	}
}

func TestPeerIsTheCurrentUser(t *testing.T) {
	path := filepath.Join(shortDir(t), "d.sock")
	l, err := Listen(path)
	if err != nil {
		t.Fatal(err)
	}
	defer l.Close()
	got := make(chan error, 1)
	go func() {
		c, err := l.Accept()
		if err != nil {
			got <- err
			return
		}
		defer c.Close()
		got <- CheckPeer(c)
	}()
	c, err := net.Dial("unix", path)
	if err != nil {
		t.Fatal(err)
	}
	defer c.Close()
	select {
	case err := <-got:
		if err != nil {
			t.Errorf("a connection from the same user was refused: %v", err)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("no verdict")
	}
}

func TestPeerOfAnotherUserIsRefused(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip()
	}
	if err := checkUID(uint32(os.Getuid())+1, uint32(os.Getuid())); err == nil {
		t.Error("another uid was accepted")
	}
	if err := checkUID(uint32(os.Getuid()), uint32(os.Getuid())); err != nil {
		t.Errorf("the same uid was refused: %v", err)
	}
}
