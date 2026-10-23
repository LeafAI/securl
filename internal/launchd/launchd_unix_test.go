//go:build unix

package launchd

import (
	"os"
	"path/filepath"
	"syscall"
	"testing"
)

// /Library/LaunchAgents is there on a Mac that has had any agent installed, and is not on one that has not: the installer makes it
// rather than failing for want of it, with the mode launchd needs (not writable by others).
func TestInstallMakesTheDirectoryWhenItIsNotThereYet(t *testing.T) {
	// Two umasks that a root might have: one that lets everything through, and a strict one that takes more than 0755 allows. The
	// mode of the directory is the code's to set, not the umask's: with 0077 a directory that launchd (which runs as other users) cannot
	// enter would hold an agent that is then never loaded for them.
	for name, mask := range map[string]int{"open umask 000": 0o000, "strict umask 077": 0o077} {
		old := syscall.Umask(mask)
		s := spec(t)
		s.Dir = filepath.Join(s.Dir, "Library", "LaunchAgents")
		err := Install(s, &fakeCtl{})
		st, serr := os.Stat(s.Dir)
		syscall.Umask(old)
		if err != nil {
			t.Fatalf("%s: the directory does not exist yet: %v", name, err)
		}
		if _, err := os.Stat(agentPath(s)); err != nil {
			t.Fatalf("%s: no plist: %v", name, err)
		}
		if serr != nil || st.Mode().Perm() != 0o755 {
			t.Errorf("%s: the directory is %v, want 0755: launchd would not trust a directory that others can write, nor one that other users cannot enter", name, st.Mode().Perm())
		}
		if pst, _ := os.Stat(agentPath(s)); pst.Mode().Perm() != 0o644 {
			t.Errorf("%s: the plist is %v, want 0644", name, pst.Mode().Perm())
		}
	}
}

// A directory that was already there is not ours to change.
func TestInstallLeavesTheModeOfADirectoryThatWasAlreadyThere(t *testing.T) {
	s := spec(t)
	os.Chmod(s.Dir, 0o700)
	if err := Install(s, &fakeCtl{}); err != nil {
		t.Fatal(err)
	}
	if st, _ := os.Stat(s.Dir); st.Mode().Perm() != 0o700 {
		t.Errorf("the mode of a directory that was there was changed to %v", st.Mode().Perm())
	}
}
