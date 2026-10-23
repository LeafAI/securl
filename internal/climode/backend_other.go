//go:build !unix

package climode

import (
	"context"
	"errors"
)

// SocketPath: there is no daemon on this system.
func SocketPath(Env) string { return "" }

func isNotRunning(error) bool { return true }

// dialDaemon: a daemon needs a Unix socket and the system's report of who is on the other end of it, which this system does
// not give. A command runs in its own process.
func dialDaemon(_ context.Context, _ Env) (*backend, error) {
	return nil, errors.New("no daemon on this system")
}
