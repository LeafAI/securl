//go:build unix

package climode

import (
	"context"
	"fmt"
	"os"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/daemon"
	"github.com/LeafAI/securl/internal/mcpserver"
)

// SocketPath is the daemon's socket for a configuration: daemon.socket, or the default.
func SocketPath(env Env) string {
	if s := env.Config.Daemon.Socket; s != "" {
		return s
	}
	return daemon.DefaultSocket(os.Getenv, os.Getuid())
}

func isNotRunning(err error) bool { return daemon.IsNotRunning(err) }

// dialDaemon connects to a running daemon. It fails with a "not running" error when there is none, and with another error
// when something is there and does not behave like a daemon.
func dialDaemon(ctx context.Context, env Env) (*backend, error) {
	conn, err := daemon.Dial(ctx, SocketPath(env))
	if err != nil {
		return nil, err
	}
	limit := env.DaemonHandshake
	if limit <= 0 {
		limit = 10 * time.Second
	}
	hctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cs, err := mcp.NewClient(&mcp.Implementation{Name: "securl-cli", Version: mcpserver.Version}, nil).
		Connect(hctx, &mcp.IOTransport{Reader: conn, Writer: conn}, nil)
	if err != nil {
		conn.Close()
		return nil, fmt.Errorf("talking to the daemon: %w", err)
	}
	b := &backend{cs: cs, close: func() { cs.Close() }}
	if ir := cs.InitializeResult(); ir != nil && ir.ServerInfo != nil {
		b.daemon = ir.ServerInfo.Version
	}
	if b.daemon != "" && b.daemon != mcpserver.Version {
		fmt.Fprintf(env.Err, "securl: the daemon is version %s and this command is %s; they may answer differently\n", b.daemon, mcpserver.Version)
	}
	return b, nil
}
