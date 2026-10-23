// Package daemonlog is where `securl daemon` writes its log when it is started by launchd, which gives a job no terminal and, unless
// the plist names a file, throws its standard error away.
//
// The plist cannot name a file: it is one file for every user (/Library/LaunchAgents), and launchd expands neither "~" nor $HOME in
// it. So the plist gives the daemon the word "default", and the daemon makes the path from the HOME that launchd gave it.
package daemonlog

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
)

// Default is the word that stands for the log of whoever runs the daemon.
const Default = "default"

// Resolve turns the value of -log into a path: "" is no file (standard error), "default" is Library/Logs/securl-daemon.log in home,
// and anything else must be an absolute path. A relative path, "~" and "$HOME" are refused rather than guessed at: a log written in
// the wrong place is a log nobody reads, or a file in a directory that somebody else chose.
func Resolve(spec, home string) (string, error) {
	switch {
	case spec == "":
		return "", nil
	case spec == Default:
		if home == "" || !filepath.IsAbs(home) {
			return "", fmt.Errorf("-log %s needs the home directory of the user, and it is %q", Default, home)
		}
		return filepath.Join(home, "Library", "Logs", "securl-daemon.log"), nil
	case strings.ContainsRune(spec, 0):
		return "", fmt.Errorf("-log: the path holds a NUL byte")
	case strings.HasPrefix(spec, "~") || strings.Contains(spec, "$"):
		return "", fmt.Errorf("-log %q: \"~\" and variables are not expanded; give an absolute path or %q", spec, Default)
	case !filepath.IsAbs(spec):
		return "", fmt.Errorf("-log %q is not an absolute path", spec)
	case strings.Contains(spec, ".."):
		return "", fmt.Errorf("-log %q has a \"..\" in it", spec)
	}
	return spec, nil
}

// Open opens the log for appending, making its directory (0700) and the file (0600). It never follows a link in the place of the
// file, and it takes away from an existing file the rights that others had to it: the log says what the daemon did, for one user.
func Open(path string) (*os.File, error) {
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("making the directory of the log %s: %w", path, err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_APPEND|os.O_WRONLY|noFollow, 0o600)
	if err != nil {
		return nil, fmt.Errorf("opening the log %s: %w", path, err)
	}
	if err := f.Chmod(0o600); err != nil {
		f.Close()
		return nil, fmt.Errorf("securing the log %s: %w", path, err)
	}
	return f, nil
}
