package main

import (
	"fmt"
	"runtime"
	"runtime/debug"
	"strings"

	"github.com/LeafAI/securl/internal/mcpserver"
)

// versionLine describes this build: the release version (set with -ldflags, see mcpserver.Version),
// the commit it was built from when known, and the Go toolchain.
func versionLine() string {
	rev := ""
	if bi, ok := debug.ReadBuildInfo(); ok {
		for _, s := range bi.Settings {
			switch {
			case s.Key == "vcs.revision" && len(s.Value) >= 7:
				rev = " (" + s.Value[:7] + ")"
			case s.Key == "vcs.modified" && s.Value == "true" && rev != "":
				rev = rev[:len(rev)-1] + ", modified)"
			}
		}
	}
	return fmt.Sprintf("securl %s%s%s %s %s/%s", mcpserver.Version, driversNote(), rev, runtime.Version(), runtime.GOOS, runtime.GOARCH)
}

// driversNote says which drivers from other repositories were built in, each as module@first-12-digits-of-the-commit. A binary that
// holds one is never taken for an ordinary build. What is written here came from a build, but it is held to one line all the same.
func driversNote() string {
	if len(mcpserver.ExternalDrivers) == 0 {
		return ""
	}
	parts := make([]string, 0, len(mcpserver.ExternalDrivers))
	for _, d := range mcpserver.ExternalDrivers {
		name, commit, _ := strings.Cut(d, "@")
		if len(commit) > 12 {
			commit = commit[:12]
		}
		parts = append(parts, oneLine(name)+"@"+oneLine(commit))
	}
	return " +drivers[" + strings.Join(parts, " ") + "]"
}

func oneLine(s string) string {
	return strings.Map(func(r rune) rune {
		if r < ' ' || r == 0x7f {
			return '?'
		}
		return r
	}, s)
}
