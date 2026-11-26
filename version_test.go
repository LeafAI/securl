package main

import (
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/mcpserver"
)

func TestVersionLine(t *testing.T) {
	got := versionLine()
	for _, want := range []string{"securl ", mcpserver.Version, "go1", "/"} {
		if !strings.Contains(got, want) {
			t.Errorf("version line %q lacks %q", got, want)
		}
	}
	if strings.HasPrefix(got, "login ") {
		t.Errorf("the program is called securl: %q", got)
	}
	if strings.Contains(got, "\n") {
		t.Errorf("must be a single line: %q", got)
	}
}

func TestAnOrdinaryBuildSaysNothingOfDrivers(t *testing.T) {
	old := mcpserver.ExternalDrivers
	defer func() { mcpserver.ExternalDrivers = old }()
	mcpserver.ExternalDrivers = nil
	if got := versionLine(); strings.Contains(got, "driver") {
		t.Errorf("%q", got)
	}
}

// A binary with a driver from another repository in it says so, and says which commit: it cannot be taken for the one that was
// published, and a driver that was not the one reviewed shows.
func TestABuildWithExternalDriversSaysWhichCommits(t *testing.T) {
	old := mcpserver.ExternalDrivers
	defer func() { mcpserver.ExternalDrivers = old }()
	mcpserver.ExternalDrivers = []string{"gitlab.example.com/g/one@" + strings.Repeat("a", 40), "gitlab.example.com/g/two@" + strings.Repeat("b", 40)}
	got := versionLine()
	if strings.Contains(got, "\n") {
		t.Errorf("one line: %q", got)
	}
	for _, want := range []string{"+drivers", "gitlab.example.com/g/one@" + strings.Repeat("a", 12), "gitlab.example.com/g/two@" + strings.Repeat("b", 12)} {
		if !strings.Contains(got, want) {
			t.Errorf("%q lacks %q", got, want)
		}
	}
	if strings.Contains(got, strings.Repeat("a", 13)) {
		t.Errorf("a commit is shown by its first 12 digits: %q", got)
	}
}

func TestADriverNameWithAControlCharacterCannotBreakTheVersionLine(t *testing.T) {
	old := mcpserver.ExternalDrivers
	defer func() { mcpserver.ExternalDrivers = old }()
	mcpserver.ExternalDrivers = []string{"x\nsecurl 9.9.9@abc"}
	if got := versionLine(); strings.Contains(got, "\n") {
		t.Errorf("%q", got)
	}
}
