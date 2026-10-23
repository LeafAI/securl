//go:build !unix

package main

import (
	"fmt"
	"os"
)

// runDaemon: there is no daemon on this system (it needs a Unix socket and the system's report of who is on the other end).
func runDaemon([]string) int {
	fmt.Fprintln(os.Stderr, "securl daemon: not available on this system; the commands run in their own process")
	return 3
}
