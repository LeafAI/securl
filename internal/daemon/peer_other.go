//go:build unix && !linux && !darwin

package daemon

import (
	"fmt"
	"net"
)

// CheckPeer on a system where the peer's user cannot be read refuses every connection: a daemon that cannot tell who is
// calling is not started (see Supported).
func CheckPeer(net.Conn) error {
	return fmt.Errorf("daemon: this system cannot report who is on the other end of a socket")
}
