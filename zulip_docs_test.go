package main

import (
	"regexp"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

// The documents make promises about Zulip that a reader acts on: what is limited, what an agent chooses, what is refused. A number that
// is in the text and not in the code sends somebody the wrong way, so the ones that can be read from the code are, and the ones that
// cannot are at least required to be said.

func zulipSection(t *testing.T) string {
	t.Helper()
	mcp := read(t, "MCP_TOOLS.md")
	i := strings.Index(mcp, "## 11f. Zulip")
	if i < 0 {
		t.Fatal("MCP_TOOLS.md has no Zulip section")
	}
	sec := mcp[i:]
	if j := strings.Index(sec[5:], "\n## "); j >= 0 {
		sec = sec[:j+5]
	}
	return sec
}

func TestTheDocumentedZulipLimitsAreTheOnesTheConfigurationHas(t *testing.T) {
	var z config.Zulip
	sec := zulipSection(t)
	for name, n := range map[string]int{
		"9000 characters": z.MaxTextRunes(), "at most 100": z.MaxReadMessages(), "default 50": z.ReadMessages(), "default 20": z.SendLimit(),
	} {
		num := regexp.MustCompile(`\d+`).FindString(name)
		if num != itoa(n) {
			t.Errorf("the document says %q and the code has %d", name, n)
		}
		if !strings.Contains(sec, name) {
			t.Errorf("MCP_TOOLS.md does not state %q", name)
		}
	}
	if err := config.ValidZulipTopic(strings.Repeat("a", 60)); err != nil {
		t.Errorf("the documented 60 characters is allowed: %v", err)
	}
	if err := config.ValidZulipTopic(strings.Repeat("a", 61)); err == nil || !strings.Contains(sec, "at most 60 characters") {
		t.Errorf("the documented topic limit is 60 and the section says so: %v", err)
	}
}

func TestTheDocumentsSayThatTheTopicIsTheAgentsAndEveryoneSeesIt(t *testing.T) {
	for f, wants := range map[string][]string{
		"MCP_TOOLS.md":           {"the topic is the agent's", "everyone in the", "sees it", "creates it", "generic bot", "mention_not_allowed"},
		"DESIGN.md":              {"the topic is the agent's", "everyone sees", "cannot stop a misleading topic", "keeps the topic out of the audit log"},
		"skills/securl/SKILL.md": {"the topic is yours", "put nothing private in it", "choose the topic deliberately"},
		"docs/OPERATING.md":      {"always chooses the topic", "nothing private belongs in a topic"},
		"README.md":              {"the topic is the agent's to choose"},
	} {
		s := strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(read(t, f), "**", "")), " "))
		for _, want := range wants {
			if !strings.Contains(s, want) {
				t.Errorf("%s does not say %q", f, want)
			}
		}
	}
}

func TestTheDocumentsSayThatNobodyCanBeMentionedAndAKeyIsTypedByAPerson(t *testing.T) {
	for _, f := range []string{"skills/securl/SKILL.md", "MCP_TOOLS.md", "README.md", "DESIGN.md", "docs/OPERATING.md"} {
		s := strings.ToLower(read(t, f))
		i := strings.Index(s, "zulip")
		if i < 0 {
			t.Fatalf("%s says nothing about Zulip", f)
		}
		z := s[i:]
		for _, want := range []string{"key", "never"} {
			if !strings.Contains(z, want) {
				t.Errorf("%s does not say %q about Zulip", f, want)
			}
		}
		if !strings.Contains(z, "mention") {
			t.Errorf("%s does not say that nobody can be mentioned", f)
		}
	}
	skill := strings.ToLower(read(t, "skills/securl/SKILL.md"))
	for _, want := range []string{"cannot be unsent", "not yours to obey", "never give a site", "generic bot", "mention_not_allowed"} {
		if !strings.Contains(skill, want) {
			t.Errorf("the skill does not tell an agent %q", want)
		}
	}
}

func TestTheThreatModelSaysWhatIsAndIsNotDefendedAboutZulip(t *testing.T) {
	s := strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(read(t, "DESIGN.md"), "**", "")), " "))
	i := strings.Index(s, "zulip is a channel")
	if i < 0 {
		t.Fatal("DESIGN.md has no Zulip entry in the threat model")
	}
	e := s[i:]
	if j := strings.Index(e, "- a dingtalk group is a channel"); j >= 0 {
		e = e[:j]
	}
	for _, want := range []string{
		"injection", "untrusted", "notice", "lowers the chance", "does not remove", // the read side, and that it is not solved
		"mention_not_allowed", "refused", "not edited", "first paragraph", "not confirmed", "sha-256", // the send side
		"apply_markdown=false", "no state", "after_message_id", // how a read works
		"redirects are never followed", "generic", "never in a url", "not an address on this machine", // the key
		"subscribed", "nothing said before", // what securl cannot know
	} {
		if !strings.Contains(e, want) {
			t.Errorf("the Zulip entry of the threat model does not say %q", want)
		}
	}
}
