//go:build darwin && launchctltest

package main

import (
	"os"
	"os/exec"
	"strings"

	"github.com/LeafAI/securl/internal/launchd"
)

// This file is compiled only into the binary that the tests build with -tags launchctltest. It lets them put a stand-in where
// launchctl is, a directory of their own where /Library/LaunchAgents is, and pretend to be root, so that no test loads anything into
// the login session of the person who runs it or writes to a directory of the machine. The shipped binary has none of these: see
// launchctl_real_darwin.go.
type envLaunchctl struct{ path string }

func (e envLaunchctl) Run(args ...string) (string, error) {
	out, err := exec.Command(e.path, args...).CombinedOutput()
	return strings.TrimSpace(string(out)), err
}

func launchctl() launchd.Ctl {
	if p := os.Getenv("SECURL_LAUNCHCTL"); p != "" {
		return envLaunchctl{p}
	}
	return launchd.Launchctl{}
}

func agentDir() string {
	if d := os.Getenv("SECURL_AGENT_DIR"); d != "" {
		return d
	}
	return launchd.Dir
}

func isRoot(euid int) bool { return euid == 0 || os.Getenv("SECURL_TEST_AS_ROOT") != "" }
