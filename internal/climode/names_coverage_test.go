package climode

import (
	"sort"
	"strings"
	"testing"
)

func TestEveryToolIsACommandOrIsListedAsNot(t *testing.T) {
	r := newRig(t, false)
	cat, err := catalog(r.envFor())
	if err != nil {
		t.Fatal(err)
	}
	var missing []string
	for _, tool := range r.toolNames(t) {
		g, s := commandPath(tool)
		key := g
		if s != "" {
			key = g + " " + s
		}
		_, isCmd := cat.cmds[key]
		_, excluded := notCommands[tool]
		switch {
		case isCmd && excluded:
			t.Errorf("%s is a command and is also listed as not one", tool)
		case !isCmd && !excluded:
			missing = append(missing, tool)
		}
	}
	if len(missing) > 0 {
		t.Errorf("tools with no command: %v (add them or list them in notCommands with the reason)", missing)
	}
	for tool, why := range notCommands {
		if strings.TrimSpace(why) == "" {
			t.Errorf("%s: a tool left out needs a reason", tool)
		}
	}
}

func TestEveryCommandIsATool(t *testing.T) {
	r := newRig(t, false)
	cat, err := catalog(r.envFor())
	if err != nil {
		t.Fatal(err)
	}
	have := map[string]bool{}
	for _, tool := range r.toolNames(t) {
		have[tool] = true
	}
	var keys []string
	for k, c := range cat.cmds {
		keys = append(keys, k)
		if !have[c.tool] {
			t.Errorf("command %q runs the tool %q, which does not exist", k, c.tool)
		}
	}
	sort.Strings(keys)
	if len(keys) != len(have)-len(notCommands) {
		t.Errorf("%d commands for %d tools (%d left out): %v", len(keys), len(have), len(notCommands), keys)
	}
}

func TestNoTwoToolsShareACommand(t *testing.T) {
	r := newRig(t, false)
	seen := map[string]string{}
	for _, tool := range r.toolNames(t) {
		g, s := commandPath(tool)
		key := g + " " + s
		if other, dup := seen[key]; dup {
			t.Errorf("%s and %s are both `securl %s`", tool, other, strings.TrimSpace(key))
		}
		seen[key] = tool
	}
}

// A group name and a tool name must not be the same word, or `securl x` would be both a command and a group.
func TestNoGroupIsAlsoACommandOnItsOwn(t *testing.T) {
	r := newRig(t, false)
	groups := map[string]bool{}
	alone := map[string]bool{}
	for _, tool := range r.toolNames(t) {
		g, s := commandPath(tool)
		if s == "" {
			alone[g] = true
		} else {
			groups[g] = true
		}
	}
	for g := range alone {
		if groups[g] {
			t.Errorf("%q is both a command and a group of commands", g)
		}
	}
}
