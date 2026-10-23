//go:build unix

package daemon

import "fmt"

// checkUID is the verdict: the peer must be the user who runs the daemon.
func checkUID(peer, self uint32) error {
	if peer != self {
		return fmt.Errorf("daemon: refusing a connection from user %d: only user %d may use this daemon", peer, self)
	}
	return nil
}

// Supported reports whether this system can run a daemon: one that can tell who is on the other end of its socket.
const Supported = supported
