//go:build linux

package daemon

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/sys/unix"
)

// CheckPeer refuses a connection that is not from the user who runs the daemon. The kernel says who is on the other end of a
// Unix socket, so this does not depend on anything the peer sends.
func CheckPeer(c net.Conn) error {
	uc, ok := c.(*net.UnixConn)
	if !ok {
		return fmt.Errorf("daemon: not a unix connection")
	}
	raw, err := uc.SyscallConn()
	if err != nil {
		return err
	}
	var cred *unix.Ucred
	var cerr error
	if err := raw.Control(func(fd uintptr) { cred, cerr = unix.GetsockoptUcred(int(fd), unix.SOL_SOCKET, unix.SO_PEERCRED) }); err != nil {
		return err
	}
	if cerr != nil {
		return fmt.Errorf("daemon: who is on the other end: %w", cerr)
	}
	return checkUID(cred.Uid, uint32(os.Getuid()))
}
