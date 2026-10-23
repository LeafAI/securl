package climode

import (
	"context"
	"fmt"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// A backend is the server a command talks to: a daemon that keeps running, or one this command started for itself. Both
// are an MCP server; what differs is who owns the vault, and so what the command may do with it.
type backend struct {
	cs *mcp.ClientSession
	// local is the server in this process, nil for a daemon. Only a process that owns a vault may open it with a passphrase
	// typed here; a daemon's vault is never opened by sending it one.
	local localServer
	close func()
	// daemon is the version of the daemon, "" when the backend is in this process.
	daemon string
}

// localServer is what a command needs of the server it started itself.
type localServer interface {
	UnlockWith(passphrase string) error
}

// connect picks the backend: a running daemon when there is one, else a server in this process. The note about the second
// is written once, to standard error, so that a person who expected a daemon notices that there was none.
func connect(ctx context.Context, env Env, lockOnClose bool) (*backend, error) {
	if !env.NoDaemon {
		b, err := dialDaemon(ctx, env)
		if err == nil {
			return b, nil
		}
		if !isNotRunning(err) {
			return nil, fmt.Errorf("the daemon did not answer: %w", err)
		}
		if lockOnClose {
			fmt.Fprintf(env.Err, "securl: no daemon is running, so this command runs by itself and locks the vault when it ends (start one with `securl daemon`)\n")
		}
	}
	cs, closeFn, app, err := connectApp(ctx, env, lockOnClose)
	if err != nil {
		return nil, err
	}
	return &backend{cs: cs, local: app, close: closeFn}, nil
}

// IsNotRunning reports whether err says that no daemon is there.
func IsNotRunning(err error) bool { return isNotRunning(err) }

// DaemonState connects to the daemon and reports the state of its vault and its version, without asking it for anything else.
func DaemonState(ctx context.Context, env Env) (state, version string, err error) {
	b, err := dialDaemon(ctx, env)
	if err != nil {
		return "", "", err
	}
	defer b.close()
	out, isErr, err := callTool(ctx, b.cs, "vault_status", map[string]any{})
	if err != nil {
		return "", "", err
	}
	if isErr {
		return "", "", fmt.Errorf("the daemon answered with an error: %v", out["message"])
	}
	s, _ := out["state"].(string)
	return s, b.daemon, nil
}
