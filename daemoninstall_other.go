//go:build !darwin

package main

import "fmt"

// There is no login agent off macOS: a Linux user has systemd's user units, which is not what this builds.
func daemonAgent(word string, _ []string) (bool, int) {
	switch word {
	case "install", "uninstall":
		fmt.Println("securl daemon " + word + ": a login agent is made for macOS only; start `securl daemon` from your own session manager")
		return true, 3
	}
	return false, 0
}

func agentStatusLine(string) string { return "" }
