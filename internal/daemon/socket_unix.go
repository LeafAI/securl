//go:build unix

// Package daemon is the long-running process that CLI commands talk to: it keeps one server, with its vault, in memory, and
// serves the MCP protocol on a Unix domain socket that only the user who started it can open.
//
// Only a Unix socket is used. A TCP port on the loopback would be reachable by every user of the machine and by any web page
// in a browser; a socket file is guarded by file permissions and by the kernel's report of who is on the other end.
package daemon

import (
	"context"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"syscall"
	"time"
)

// maxSocketPath is the longest path a Unix socket can have: sun_path is 104 bytes on macOS and 108 on Linux, one of them the
// terminating zero.
const maxSocketPath = 103

// afterBind is a test hook: it runs between the socket being made and the chmod that follows, the one moment at which the mode
// of the file is whatever the umask left.
var afterBind func(path string)

var errNotRunning = errors.New("no daemon is running")

// IsNotRunning reports whether err means that nothing is listening on the socket (no file, or a file nobody listens on).
func IsNotRunning(err error) bool { return errors.Is(err, errNotRunning) }

// Listen makes the socket and returns its listener. It refuses if a daemon is already listening on it, replaces a socket left
// by a daemon that died, and refuses to touch anything that is not a socket or to put one where other users could replace it.
func Listen(path string) (net.Listener, error) {
	if len(path) > maxSocketPath {
		return nil, fmt.Errorf("the socket path is too long (%d bytes, at most %d): set daemon.socket to a shorter one", len(path), maxSocketPath)
	}
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if err := checkDir(dir); err != nil {
		return nil, err
	}
	if err := clearStale(path); err != nil {
		return nil, err
	}
	// The socket is created with the umask closed, so there is no moment between its creation and a chmod in which another
	// user could connect to it.
	old := setUmask(0o177)
	l, err := net.Listen("unix", path)
	setUmask(old)
	if err != nil {
		return nil, fmt.Errorf("daemon: %w", err)
	}
	if afterBind != nil {
		afterBind(path)
	}
	if err := os.Chmod(path, 0o600); err != nil {
		l.Close()
		return nil, fmt.Errorf("daemon: %w", err)
	}
	return l, nil
}

// checkDir refuses a directory that someone else owns or can write to: they could delete the socket and put their own in its
// place, which every later command would then talk to.
func checkDir(dir string) error {
	st, err := os.Lstat(dir)
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if !st.IsDir() {
		return fmt.Errorf("daemon: %s is not a directory", dir)
	}
	if st.Mode().Perm()&0o022 != 0 {
		return fmt.Errorf("daemon: %s can be written by other users (mode %v); another user could replace the socket in it", dir, st.Mode().Perm())
	}
	if sys, ok := st.Sys().(*syscall.Stat_t); ok && int(sys.Uid) != os.Getuid() {
		return fmt.Errorf("daemon: %s belongs to another user", dir)
	}
	return nil
}

// clearStale removes the socket file of a daemon that is no longer there. A daemon that is there is an error; a file that is
// not a socket is left alone and is an error too.
func clearStale(path string) error {
	st, err := os.Lstat(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return fmt.Errorf("daemon: %w", err)
	}
	if st.Mode()&os.ModeSocket == 0 {
		return fmt.Errorf("daemon: %s exists and is not a socket; it is not removed", path)
	}
	c, err := net.DialTimeout("unix", path, 2*time.Second)
	if err == nil {
		c.Close()
		return fmt.Errorf("daemon: already running on %s", path)
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("daemon: removing the stale socket: %w", err)
	}
	return nil
}

// Dial connects to the daemon. A socket with nobody behind it is reported as not running, as is a missing one.
func Dial(ctx context.Context, path string) (net.Conn, error) {
	var d net.Dialer
	c, err := d.DialContext(ctx, "unix", path)
	if err == nil {
		return c, nil
	}
	if errors.Is(err, os.ErrNotExist) || errors.Is(err, syscall.ENOENT) {
		return nil, fmt.Errorf("%w (%s)", errNotRunning, path)
	}
	if errors.Is(err, syscall.ECONNREFUSED) {
		// "Connection refused" is what a socket that nobody listens on says, and also what Linux says for a regular file, a
		// directory and a link to one of them (macOS says "not a socket" for those). So the errno does not tell a daemon that is
		// not running from something that is in the way: what is on the path does.
		if what := inTheWay(path); what != "" {
			return nil, fmt.Errorf("%s is %s, not a socket: something else is in the place of the daemon's socket", path, what)
		}
		return nil, fmt.Errorf("%w (%s)", errNotRunning, path)
	}
	return nil, err
}

// inTheWay says what is at path when it is not a socket (and not a link to one), or "" when it is one. A path that cannot be
// examined is not said to be in the way: the dial's own error decides.
func inTheWay(path string) string {
	st, err := os.Stat(path) // follows a link: a link to a socket is the daemon's socket, a link to a file is not
	if err != nil {
		return ""
	}
	switch {
	case st.Mode()&os.ModeSocket != 0:
		return ""
	case st.IsDir():
		return "a directory"
	case st.Mode().IsRegular():
		return "a regular file"
	}
	return "not a socket"
}

// setUmask sets the process umask and returns the old one.
func setUmask(m int) int { return syscall.Umask(m) }
