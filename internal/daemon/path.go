//go:build unix

package daemon

import (
	"fmt"
	"path/filepath"
)

// DefaultSocket is where the daemon listens when daemon.socket is not set: "securl/d.sock" in the runtime directory
// ($XDG_RUNTIME_DIR, which the system makes private to the user and clears at logout), and otherwise in /tmp/securl-<uid>.
// /tmp, not $TMPDIR: on macOS $TMPDIR is a long path under /var/folders, and a socket path is limited to about 104 bytes.
// Listen makes the directory private (0700) and refuses one that other users can write to, so a shared /tmp is safe.
func DefaultSocket(getenv func(string) string, uid int) string {
	if d := getenv("XDG_RUNTIME_DIR"); d != "" && filepath.IsAbs(d) {
		if p := filepath.Join(d, "securl", "d.sock"); len(p) <= maxSocketPath {
			return p
		}
	}
	return filepath.Join("/tmp", fmt.Sprintf("securl-%d", uid), "d.sock")
}
