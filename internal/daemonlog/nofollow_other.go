//go:build !unix

package daemonlog

// noFollow: there is no daemon off Unix, so nothing opens this log there; the flag does not exist.
const noFollow = 0
