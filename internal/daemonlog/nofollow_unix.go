//go:build unix

package daemonlog

import "syscall"

// noFollow makes open fail on a link in the place of the file instead of following it.
const noFollow = syscall.O_NOFOLLOW
