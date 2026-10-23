package climode

import (
	"context"
	"fmt"
)

// Unlock is `securl unlock`: it asks the person to open the vault of the running daemon, and waits.
//
// It is the one thing a command can do for a locked daemon, and it is done the way an agent does it: the daemon sends the
// link (to DingTalk, or back here with security.link_via_agent) and the person types the passphrase on the page. The
// passphrase is not typed into this command, even on a terminal. The daemon's socket is open to every process of the user,
// an agent's shell among them, and a passphrase that could be given to the daemon over it could be asked for by anything that
// reaches the socket; no tool takes one, so that nothing an agent can reach could be made to carry one.
//
// Without a daemon there is nothing for it to do: a vault opened in this process would be locked again when the command
// ends. That is an error, and says how to start one, not a quiet fallback.
func Unlock(ctx context.Context, env Env) int {
	if env.NoDaemon {
		fmt.Fprintln(env.Err, "securl unlock: --no-daemon makes no sense here: unlock opens the vault of a running daemon, and without one there is nothing that would stay open")
		return exitUsage
	}
	b, err := dialDaemon(ctx, env)
	if err != nil {
		if isNotRunning(err) {
			fmt.Fprintf(env.Err, "securl unlock: no daemon is running, so there is no vault to open that would stay open (start one with `securl daemon`)\n")
		} else {
			fmt.Fprintf(env.Err, "securl unlock: the daemon did not answer: %v\n", err)
		}
		return exitSetup
	}
	defer b.close()
	return unlockThroughServer(ctx, env, b.cs, true)
}
