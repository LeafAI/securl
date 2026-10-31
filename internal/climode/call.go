package climode

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/vault"
)

// needsNoVault is the tools that work while the vault is locked: the two about the vault itself, and the list of websites,
// which holds nothing secret. The server decides this (it answers the others vault_locked); the list here only spares a person
// from being asked to unlock for a command that does not need it.
var needsNoVault = map[string]bool{"vault_status": true, "vault_unlock": true, "site_list": true}

// call runs the tool: it opens the vault if the tool needs it, calls the tool, and while the answer says a person has to
// do something it shows what and waits, so the command comes back with the final answer.
func (c *catalog_) call(ctx context.Context, env Env, cmd *command, input map[string]any) int {
	b, err := connect(ctx, env, true)
	if err != nil {
		fmt.Fprintf(env.Err, "securl: %v\n", err)
		return exitSetup
	}
	defer b.close()
	if env.AfterConnect != nil {
		env.AfterConnect()
	}
	cs := b.cs
	if !needsNoVault[cmd.tool] {
		if code := openVault(ctx, env, b); code != 0 {
			return code
		}
	}
	out, isErr, err := callTool(ctx, cs, cmd.tool, input)
	if err != nil {
		fmt.Fprintf(env.Err, "securl: %v\n", err)
		return exitSetup
	}
	for !isErr && isPending(out) && !declinesToWait(input) {
		wait := pendingPart(out)
		next, ok := continuation(cmd.tool, wait)
		if !ok {
			return finish(env, out, false)
		}
		next.input = withScope(cmd.tool, input, next.input)
		announce(env, wait)
		if ctx.Err() != nil {
			return finish(env, out, false)
		}
		if out, isErr, err = callTool(ctx, cs, next.tool, next.input); err != nil {
			fmt.Fprintf(env.Err, "securl: %v\n", err)
			return exitSetup
		}
		if !isErr && next.tool == "session_wait" && out["status"] == "ok" && isLoginThenCall(cmd.tool) {
			// What the command waited for was a login it needs on the way (the Archery tools): done, so the call it was made for
			// is made again. Its own answer is what the person asked for; the login's is not.
			if out, isErr, err = callTool(ctx, cs, cmd.tool, input); err != nil {
				fmt.Fprintf(env.Err, "securl: %v\n", err)
				return exitSetup
			}
		}
	}
	return finish(env, out, isErr)
}

// isLoginThenCall is the tools that log in on the way and answer pending with the login they wait for: once it is done they have
// to be called again, because the answer to the wait is the login's and not their own. Opening a session is itself the login.
func isLoginThenCall(tool string) bool {
	return strings.HasPrefix(tool, "archery_") && tool != "archery_wait"
}

// isPending reports whether the answer says that a person has not answered yet. Most tools say it in `status`; the Archery tools
// that list or query (instances, groups, query) carry the login they are waiting for in a `login` object beside what they would
// have listed, and have no `status` of their own.
func isPending(out map[string]any) bool {
	if out["status"] == "pending" {
		return true
	}
	login, _ := out["login"].(map[string]any)
	return login != nil && login["status"] == "pending"
}

// pendingPart is the part of a pending answer that names what is waited for: the answer itself, or its `login`.
func pendingPart(out map[string]any) map[string]any {
	if login, _ := out["login"].(map[string]any); login != nil && out["status"] != "pending" {
		return login
	}
	return out
}

// declinesToWait is a call that said it does not want to wait: `--wait=false` asks for the pending answer at once, so the
// command prints it and exits (4) instead of waiting on the caller's behalf. The caller continues with `session wait`.
func declinesToWait(input map[string]any) bool {
	w, given := input["wait"].(bool)
	return given && !w
}

type nextCall struct {
	tool  string
	input map[string]any
}

// continuation is the call that keeps waiting for what a pending answer is waiting for. The answer names the tool
// (next_tool) and carries the id to give it.
func continuation(tool string, out map[string]any) (nextCall, bool) {
	next, _ := out["next_tool"].(string)
	id, _ := out["login_id"].(string)
	switch next {
	case "session_wait":
		if id != "" {
			return nextCall{next, map[string]any{"login_id": id}}, true
		}
	case "vault_unlock":
		if id != "" {
			return nextCall{next, map[string]any{"unlock_id": id}}, true
		}
	case "session_close":
		// The call that asked is the call that waits: the same scope, and the id it was given. The scope is not in the answer
		// (the answer names no session), so the caller's own input is added by the loop.
		if id != "" {
			return nextCall{next, map[string]any{"close_id": id}}, true
		}
	case "archery_wait":
		return nextCall{}, false // needs the workflow and the Archery URL the caller already has: the answer is returned as it is
	}
	return nextCall{}, false
}

// withScope adds to a continuation what the waiting call must repeat. Closing sessions names its scope again with the id: the
// server refuses an id for another scope, so an answer to one question can never close the sessions of another.
func withScope(tool string, input, next map[string]any) map[string]any {
	if tool != "session_close" {
		return next
	}
	out := map[string]any{}
	for _, k := range []string{"url", "all"} {
		if v, ok := input[k]; ok {
			out[k] = v
		}
	}
	for k, v := range next {
		out[k] = v
	}
	return out
}

// announce tells the person at the terminal what is being waited for. The link of a handover is on stderr, never stdout:
// stdout is the answer and nothing else.
func announce(env Env, out map[string]any) {
	announceOrigin(env, out)
	if link, _ := out["link"].(string); link != "" {
		fmt.Fprintf(env.Err, "\nOpen this link, compare the key code and type what the page asks for:\n\n  %s\n\n  key code: %v\n\n", link, out["key_code"])
		return
	}
	if w, _ := out["waiting_for"].(string); w != "" {
		fmt.Fprintf(env.Err, "waiting for the person to complete the %q step (a message was sent)...\n", w)
	}
}

// finish prints the answer and returns the exit code that goes with it.
func finish(env Env, out map[string]any, isErr bool) int {
	b, err := json.MarshalIndent(out, "", "  ")
	if err != nil {
		fmt.Fprintf(env.Err, "securl: encoding the answer: %v\n", err)
		return exitSetup
	}
	fmt.Fprintln(env.Out, string(b))
	switch {
	case isErr:
		return exitToolError
	case isPending(out):
		return exitPending
	}
	return 0
}

// openVault opens the vault when the tool needs it.
//
// In a process of its own, on a terminal, it asks for the passphrase there. With a daemon, or with no terminal, it never
// reads or sends a passphrase: the vault is opened the way an agent opens it, with a link for the person (DingTalk, or on
// standard error with security.link_via_agent). A daemon's socket is open to every process of the user, an agent's shell
// among them, and no tool takes a passphrase, so that nothing an agent can reach could be made to carry one; a passphrase
// typed here and sent over the socket would be exactly that. The link is the way in, from a terminal or not.
func openVault(ctx context.Context, env Env, b *backend) int {
	if b.local == nil {
		return unlockThroughServer(ctx, env, b.cs)
	}
	switch env.Vault.State() {
	case vault.NotInitialized:
		fmt.Fprintln(env.Err, "securl: the vault has not been set up yet: run `securl vault init`")
		return exitSetup
	case vault.Unlocked:
		return 0
	}
	if env.Secret == nil {
		return remoteUnlock(ctx, env, b.cs)
	}
	return typePassphrase(env, b.local)
}

// typePassphrase asks for the passphrase on the terminal, up to three times, and opens the vault of this process with it.
func typePassphrase(env Env, local localServer) int {
	for attempt := 1; attempt <= maxPassphraseTries; attempt++ {
		fmt.Fprint(env.Err, "Vault passphrase: ")
		pass, err := env.Secret()
		fmt.Fprintln(env.Err)
		if err != nil {
			fmt.Fprintf(env.Err, "securl: reading the passphrase: %v\n", err)
			return exitSetup
		}
		err = local.UnlockWith(pass)
		switch {
		case err == nil:
			return 0
		case !errors.Is(err, vault.ErrWrongPassphrase):
			fmt.Fprintf(env.Err, "securl: %v\n", err)
			return exitSetup
		case attempt < maxPassphraseTries:
			fmt.Fprintln(env.Err, "securl: wrong passphrase")
		}
	}
	fmt.Fprintf(env.Err, "securl: giving up after %d wrong passphrases\n", maxPassphraseTries)
	return exitSetup
}

const maxPassphraseTries = 3

// unlockThroughServer is for a daemon: the vault is the daemon's, so whether it is open is the daemon's to say, and when it
// is shut the person is asked by link. vault_unlock answers at once with "already unlocked" when it is open, so a command
// that finds an open vault pays nothing for asking. With print, the answer is printed (securl unlock); without, it is not
// (a tool command that needed the vault open goes on to its own answer).
func unlockThroughServer(ctx context.Context, env Env, cs *mcp.ClientSession, print ...bool) int {
	if len(print) > 0 && print[0] {
		return unlockAndReport(ctx, env, cs)
	}
	return remoteUnlock(ctx, env, cs)
}

// remoteUnlock asks the person to open the vault the way an agent does it: the vault_unlock tool sends the link (to
// DingTalk, or back here with security.link_via_agent) and the person types the passphrase on its page. This process never
// sees the passphrase: only the server inside it reads it from the page.
func remoteUnlock(ctx context.Context, env Env, cs *mcp.ClientSession) int {
	code, _ := unlockOnce(ctx, env, cs)
	return code
}

// vaultIsShut asks the server for the state of its vault. When it cannot tell, it answers true: saying that somebody is being
// asked is the safe mistake, a silent wait is not.
func vaultIsShut(ctx context.Context, cs *mcp.ClientSession) bool {
	out, isErr, err := callTool(ctx, cs, "vault_status", map[string]any{})
	if err != nil || isErr {
		return true
	}
	return out["state"] != "unlocked"
}

// unlockAndReport is `securl unlock`: the same unlock, and its answer printed.
func unlockAndReport(ctx context.Context, env Env, cs *mcp.ClientSession) int {
	code, out := unlockOnce(ctx, env, cs)
	if out != nil {
		if fin := finish(env, out, code == exitToolError); fin != 0 && code == 0 {
			return fin
		}
	}
	return code
}

// unlockOnce asks for the vault to be opened and waits for the person. It returns the exit code and the last answer.
func unlockOnce(ctx context.Context, env Env, cs *mcp.ClientSession) (int, map[string]any) {
	// What is being waited for is said before the wait, not after: while the person has the link, the terminal would otherwise
	// show nothing at all (vault_unlock blocks until they answer). It is said only when the vault is shut: an open one asks
	// nobody, and a line that says it does sends the person looking for a message that was never sent. vault_status neither
	// blocks nor asks anybody.
	if vaultIsShut(ctx, cs) {
		fmt.Fprintln(env.Err, "securl: asking the person to open the vault: they are sent a link and type the passphrase on its page (nothing is typed here)...")
	}
	out, isErr, err := callTool(ctx, cs, "vault_unlock", map[string]any{"reason": "securl command line"})
	for err == nil && !isErr && out["status"] == "pending" {
		announce(env, out)
		next, ok := continuation("vault_unlock", out)
		if !ok || ctx.Err() != nil {
			break
		}
		out, isErr, err = callTool(ctx, cs, next.tool, next.input)
	}
	switch {
	case err != nil && ctx.Err() != nil:
		// The command was interrupted, or ran out of the time it was given, while the person had the link. That is not a
		// failure of the setup and not an error of the daemon: the person has not answered yet, and the link they hold is
		// still good until it expires, so running this again joins it instead of sending another.
		fmt.Fprintln(env.Err, "securl: stopped waiting: the vault is still locked; the link that was sent works until it expires, and `securl unlock` again waits for it")
		return exitPending, nil
	case err != nil:
		fmt.Fprintf(env.Err, "securl: %v\n", err)
		return exitSetup, nil
	case isErr:
		fmt.Fprintf(env.Err, "securl: the vault was not opened: %v\n", out["message"])
		return exitToolError, out
	case out["status"] != "unlocked":
		fmt.Fprintln(env.Err, "securl: the vault was not opened in time")
		return exitPending, out
	}
	return 0, out
}
