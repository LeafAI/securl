// Package launchd installs and removes the login agent that starts `securl daemon` for each user who logs in on macOS.
//
// The agent is one plist in /Library/LaunchAgents, which launchd loads for every user at graphical login, as that user and in that
// user's session. It is never a LaunchDaemon of the system: the daemon serves one account's vault and checks the user on the other end
// of its socket, and run as root it would serve root's files. Loaded per user, each user's daemon is that user's own process, with
// that user's configuration, vault and socket. The plist therefore names no user and no path under anybody's home: launchd does not
// expand "~" or $HOME in it, and the daemon finds its own config and writes its own log from the HOME that launchd gives it.
//
// /Library/LaunchAgents is written by root, so this is run by the installer (which is root) and by `securl daemon install` run as
// root; a user without root cannot make or remove it.
package launchd

import (
	"encoding/xml"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// Label is the name of the agent: the reverse-DNS name of the package, and the file name of its plist.
const Label = "com.leafai.securl"

// Dir is where launchd looks for agents that an administrator provides, for every user.
const Dir = "/Library/LaunchAgents"

// marker is written into the plist, so that uninstall can tell a file that this program made from one that merely has the same
// name: somebody's own agent under our label is not removed without being told of.
const marker = "made by the securl installer or `securl daemon install`; remove it with `securl daemon uninstall`"

// Spec says what to install, and for which user's session to load it now.
type Spec struct {
	Dir    string // the directory of the plist: Dir for the agent that is shipped
	UID    int    // the user whose login session the agent is loaded into now, or -1 for nobody: launchd loads it at the next login
	Binary string // absolute path of the securl binary that the agent runs
	Label  string
	// Wait is how a retry waits (time.Sleep when nil); a test gives it one that does not.
	Wait func(time.Duration)
}

// maxBootstrapTries bounds how often a busy label is tried again, and bootstrapPause is the wait between two tries.
const (
	maxBootstrapTries = 20
	bootstrapPause    = 500 * time.Millisecond
)

// Ctl is launchctl. It is an interface so that a test never loads anything into a real login session.
type Ctl interface {
	Run(args ...string) (output string, err error)
}

// Launchctl is the real one.
type Launchctl struct{}

// Run runs /bin/launchctl and returns what it printed, standard error included.
func (Launchctl) Run(args ...string) (string, error) {
	out, err := exec.Command("/bin/launchctl", args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func (s Spec) domain() string { return fmt.Sprintf("gui/%d", s.UID) }
func (s Spec) target() string { return s.domain() + "/" + s.label() }
func (s Spec) path() string   { return filepath.Join(s.Dir, s.label()+".plist") }

func (s Spec) label() string {
	if s.Label != "" {
		return s.Label
	}
	return Label
}

// Plist is the text of the agent. Every value is escaped: a path may hold anything.
func (s Spec) Plist() (string, error) {
	if !filepath.IsAbs(s.Binary) {
		return "", fmt.Errorf("the binary %q is not an absolute path: launchd has no PATH to look it up in", s.Binary)
	}
	var b strings.Builder
	b.WriteString("<?xml version=\"1.0\" encoding=\"UTF-8\"?>\n")
	b.WriteString("<!DOCTYPE plist PUBLIC \"-//Apple//DTD PLIST 1.0//EN\" \"http://www.apple.com/DTDs/PropertyList-1.0.dtd\">\n")
	b.WriteString("<!-- " + marker + " -->\n<plist version=\"1.0\">\n<dict>\n")
	b.WriteString("\t<key>Label</key>\n\t<string>" + esc(s.label()) + "</string>\n")
	b.WriteString("\t<key>ProgramArguments</key>\n\t<array>\n")
	// -log default: the daemon opens ~/Library/Logs/securl-daemon.log of the user it runs as, from the HOME launchd gives it. The plist
	// cannot name that file: launchd expands neither "~" nor $HOME, and the plist is one file for every user.
	b.WriteString("\t\t<string>" + esc(s.Binary) + "</string>\n\t\t<string>daemon</string>\n\t\t<string>-log</string>\n\t\t<string>default</string>\n\t</array>\n")
	b.WriteString("\t<key>RunAtLoad</key>\n\t<true/>\n")
	// Started again after a crash, not after a clean stop: `daemon uninstall` stops it with SIGTERM, which is a clean exit, and
	// a second daemon that finds the first one running exits with an error that must not turn into a loop (the throttle below
	// is the limit if it ever does).
	b.WriteString("\t<key>KeepAlive</key>\n\t<dict>\n\t\t<key>SuccessfulExit</key>\n\t\t<false/>\n\t</dict>\n")
	b.WriteString("\t<key>ThrottleInterval</key>\n\t<integer>30</integer>\n")
	b.WriteString("\t<key>ProcessType</key>\n\t<string>Background</string>\n")
	b.WriteString("</dict>\n</plist>\n")
	return b.String(), nil
}

func esc(s string) string {
	var b strings.Builder
	_ = xml.EscapeText(&b, []byte(s))
	return b.String()
}

// wellFormed checks that text is XML a parser accepts.
func wellFormed(text string) error {
	d := xml.NewDecoder(strings.NewReader(text))
	d.Strict = true
	d.Entity = xml.HTMLEntity
	for {
		if _, err := d.Token(); err != nil {
			if errors.Is(err, io.EOF) {
				return nil
			}
			return err
		}
	}
}

// Install puts the plist in place and, for a user, loads the agent into that user's login session now. An agent of ours that is
// already loaded for that user is taken out first, so that a second install replaces it. The plist is put in place before launchctl
// is asked to load it (launchd remembers the path, and reads it again at the next login), and if launchctl refuses it, the earlier
// plist is put back, or with none the new one is taken away: nothing is left that would be tried at the next login without ever
// having worked. With no user (UID < 0) the plist is only put in place, and launchd loads it for each user at their next login.
func Install(s Spec, ctl Ctl) error {
	if !filepath.IsAbs(s.Dir) {
		return fmt.Errorf("the directory %q is not an absolute path", s.Dir)
	}
	text, err := s.Plist()
	if err != nil {
		return err
	}
	_, statErr := os.Stat(s.Dir)
	if err := os.MkdirAll(s.Dir, 0o755); err != nil {
		return fmt.Errorf("making %s: %w", s.Dir, err)
	}
	if errors.Is(statErr, os.ErrNotExist) {
		// Made by this call, so its mode is ours to set, whatever umask the installer runs with: launchd does not trust a directory that
		// others can write. A directory that was already there is not touched: it is the system's or somebody's, and not ours to change.
		if err := os.Chmod(s.Dir, 0o755); err != nil {
			return fmt.Errorf("setting the mode of %s: %w", s.Dir, err)
		}
	}
	if s.UID >= 0 {
		if _, err := ctl.Run("print", s.target()); err == nil {
			if out, err := ctl.Run("bootout", s.target()); err != nil {
				return fmt.Errorf("taking the loaded agent out first: %v: %s", err, out)
			}
		}
	}
	var old []byte
	hadOld := false
	if b, err := os.ReadFile(s.path()); err == nil {
		old, hadOld = b, true
	}
	restore := func() {
		if hadOld {
			os.WriteFile(s.path(), old, 0o644)
		} else {
			os.Remove(s.path())
		}
	}
	tmp, err := os.CreateTemp(s.Dir, "."+s.label()+".*.new")
	if err != nil {
		return fmt.Errorf("writing the plist in %s: %w", s.Dir, err)
	}
	tmpPath := tmp.Name()
	defer os.Remove(tmpPath)
	if _, err := tmp.WriteString(text); err != nil {
		tmp.Close()
		return fmt.Errorf("writing the plist in %s: %w", s.Dir, err)
	}
	if err := tmp.Close(); err != nil {
		return fmt.Errorf("writing the plist in %s: %w", s.Dir, err)
	}
	if err := os.Chmod(tmpPath, 0o644); err != nil {
		return fmt.Errorf("writing the plist in %s: %w", s.Dir, err)
	}
	if err := os.Rename(tmpPath, s.path()); err != nil {
		return fmt.Errorf("putting the plist in place in %s: %w", s.Dir, err)
	}
	if s.UID < 0 {
		return nil
	}
	if out, err := s.bootstrap(ctl); err != nil {
		restore()
		return fmt.Errorf("launchctl refused the agent: %v: %s", err, out)
	}
	return nil
}

// bootstrap loads the agent. An upgrade takes the running agent out first, and launchctl returns from that before the old process
// has exited: a bootstrap in that moment fails with "Input/output error" (exit status 5) because the label is not free yet, and
// succeeds a moment later. That one answer is tried again, a few times; every other is final, since time does not change it.
func (s Spec) bootstrap(ctl Ctl) (string, error) {
	wait := s.Wait
	if wait == nil {
		wait = time.Sleep
	}
	var out string
	var err error
	for try := 1; try <= maxBootstrapTries; try++ {
		if out, err = ctl.Run("bootstrap", s.domain(), s.path()); err == nil {
			return out, nil
		}
		if !labelBusy(out, err) || try == maxBootstrapTries {
			break
		}
		wait(bootstrapPause)
	}
	return out, err
}

// labelBusy reports whether launchctl said that the label is still held by the process that was just taken out.
func labelBusy(out string, err error) bool {
	return strings.Contains(out, "Input/output error") || strings.Contains(err.Error(), "exit status 5")
}

// Uninstall stops the agent for the user (if there is one) and removes the plist, so that it is loaded for nobody at the next login.
// Nothing to remove is not an error. A plist under our label that this program did not write is not removed: it is reported.
func Uninstall(s Spec, ctl Ctl) error {
	bootout := func() {
		if s.UID < 0 {
			return
		}
		if _, err := ctl.Run("print", s.target()); err == nil {
			ctl.Run("bootout", s.target())
		}
	}
	b, err := os.ReadFile(s.path())
	switch {
	case errors.Is(err, os.ErrNotExist):
		bootout() // loaded without a file (removed by hand): still taken out
		return nil
	case err != nil:
		return fmt.Errorf("reading %s: %w", s.path(), err)
	}
	if !strings.Contains(string(b), marker) {
		return fmt.Errorf("%s was not made by securl, so it is not removed; remove it yourself if it is yours", s.path())
	}
	if s.UID >= 0 {
		if _, err := ctl.Run("print", s.target()); err == nil {
			if out, err := ctl.Run("bootout", s.target()); err != nil {
				return fmt.Errorf("stopping the agent: %v: %s", err, out)
			}
		}
	}
	if err := os.Remove(s.path()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return fmt.Errorf("removing %s: %w", s.path(), err)
	}
	return nil
}

// State is what Status finds.
type State struct {
	Installed bool   // the plist is there and ours
	Loaded    bool   // launchd has the agent in this user's session
	Path      string // where the plist is
}

// Status reads the state without changing anything.
func Status(s Spec, ctl Ctl) State {
	st := State{Path: s.path()}
	if b, err := os.ReadFile(s.path()); err == nil && strings.Contains(string(b), marker) {
		st.Installed = true
	}
	if s.UID >= 0 {
		if _, err := ctl.Run("print", s.target()); err == nil {
			st.Loaded = true
		}
	}
	return st
}
