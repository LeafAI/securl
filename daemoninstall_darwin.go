//go:build darwin

package main

import (
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strconv"

	"github.com/LeafAI/securl/internal/launchd"
)

// daemonAgent runs `securl daemon install` and `uninstall`. It reports whether it handled the word.
//
// The agent is the machine's: one plist in /Library/LaunchAgents, which launchd loads for every user at graphical login, as that user.
// Writing that directory needs root, so this is run with sudo, or by the installer, which is root. With -uid it also loads the agent
// into the login session of that user now, so that their daemon is running when the command returns and not only after their next
// login; the installer gives the user at the console. Root's own session is never used.
func daemonAgent(word string, args []string) (handled bool, code int) {
	switch word {
	case "install", "uninstall":
	default:
		return false, 0
	}
	fs := flag.NewFlagSet("daemon "+word, flag.ContinueOnError)
	fs.SetOutput(io.Discard)
	uidArg := fs.String("uid", "", "load the agent into the login session of this user now (the user at the console); without it launchd loads it at each user's next login")
	if err := fs.Parse(args); err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon %s: %v\n", word, err)
		return true, 2
	}
	if fs.NArg() > 0 {
		fmt.Fprintf(os.Stderr, "securl daemon %s: unexpected argument %q\n", word, fs.Arg(0))
		return true, 2
	}
	uid, err := parseUID(*uidArg)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon %s: %v\n", word, err)
		return true, 2
	}
	if msg := needRoot(word, os.Geteuid()); msg != "" {
		fmt.Fprintln(os.Stderr, msg)
		return true, 3
	}
	spec, err := agentSpec(uid)
	if err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon %s: %v\n", word, err)
		return true, 3
	}
	if word == "uninstall" {
		if err := launchd.Uninstall(spec, launchctl()); err != nil {
			fmt.Fprintf(os.Stderr, "securl daemon uninstall: %v\n", err)
			return true, 3
		}
		fmt.Println("the login agent is removed: no user gets a daemon at login any more, and the daemon of the user it was loaded for is stopped")
		fmt.Println("daemons that other users are running are stopped when they log out, or with `securl daemon uninstall -uid <their uid>` run for them")
		return true, 0
	}
	if err := launchd.Install(spec, launchctl()); err != nil {
		fmt.Fprintf(os.Stderr, "securl daemon install: %v\n", err)
		return true, 3
	}
	fmt.Printf("login agent installed: %s\n", filepath.Join(spec.Dir, launchd.Label+".plist"))
	fmt.Printf("launchd runs `%s daemon` for every user, as that user, when they log in.\n", spec.Binary)
	if spec.UID >= 0 {
		fmt.Printf("It is running now for the user with uid %d.\n", spec.UID)
	} else {
		fmt.Println("It starts at each user's next login.")
	}
	fmt.Println("Each daemon starts locked and holds no secret: `securl unlock` sends you a link, and you type the passphrase on its page.")
	return true, 0
}

// parseUID reads -uid: empty is no user (-1); anything else must be a positive number, and 0 is refused, because root's session is
// the one place where the daemon must never run.
func parseUID(s string) (int, error) {
	if s == "" {
		return -1, nil
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return 0, fmt.Errorf("-uid %q is not a number", s)
	}
	if n <= 0 {
		return 0, fmt.Errorf("-uid %d: the agent is never loaded into root's session (the daemon would run as root), nor into a negative one", n)
	}
	return n, nil
}

// needRoot is the message for a person who is not root, and "" for root. /Library/LaunchAgents is written by root: an ordinary user
// gets the reason and the command, and nothing is written or loaded.
func needRoot(word string, euid int) string {
	if isRoot(euid) {
		return ""
	}
	return "securl daemon " + word + " writes /Library/LaunchAgents, which only root can, because the agent it makes is for every user of this Mac.\n" +
		"Run it with sudo:   sudo securl daemon " + word
}

// agentSpec describes the agent: the binary that is running now, in the machine's directory, for the user to load it for (or none).
func agentSpec(uid int) (launchd.Spec, error) {
	exe, err := os.Executable()
	if err != nil {
		return launchd.Spec{}, fmt.Errorf("which binary is this? %w", err)
	}
	if exe, err = filepath.EvalSymlinks(exe); err != nil {
		return launchd.Spec{}, err
	}
	return launchd.Spec{Dir: agentDir(), UID: uid, Binary: exe, Label: launchd.Label}, nil
}

// agentStatusLine is the line `securl daemon status` adds on a Mac: whether the machine's agent is there, and for this user whether
// launchd has loaded it.
func agentStatusLine(string) string {
	spec, err := agentSpec(os.Getuid())
	if err != nil {
		return ""
	}
	st := launchd.Status(spec, launchctl())
	switch {
	case st.Installed && st.Loaded:
		return "login agent: installed and loaded (launchd runs the daemon for you when you log in)"
	case st.Installed:
		return "login agent: installed, not loaded for you yet (launchd loads it at your next login)"
	}
	return "login agent: not installed (`sudo securl daemon install` makes launchd run a daemon for every user at login)"
}
