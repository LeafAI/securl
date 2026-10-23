//go:build darwin && !launchctltest

package main

import "github.com/LeafAI/securl/internal/launchd"

// What a process that runs as root writes and runs is fixed here, by absolute paths, and nothing in the environment can change it:
// an agent's shell or a poisoned profile must not be able to make `securl daemon install`, run with sudo, write a file of its choosing
// or run a program of its choosing.
func launchctl() launchd.Ctl { return launchd.Launchctl{} }

func agentDir() string { return launchd.Dir }

// isRoot is whether this process may write the machine's agent.
func isRoot(euid int) bool { return euid == 0 }
