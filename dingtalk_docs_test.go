package main

import (
	"fmt"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

// The documents make promises about DingTalk groups that a reader acts on: how fast a robot may send, what is never shown, that there
// is nothing to read. A number or a claim that is in the text and not in the code sends somebody the wrong way, so the ones that can be
// read from the code are, and the ones that cannot are required to be said.

// flat reads Markdown as sentences: line breaks, bold marks and code ticks are not part of what is said.
func dtFlat(t *testing.T, f string) string {
	t.Helper()
	s := strings.ReplaceAll(strings.ReplaceAll(read(t, f), "**", ""), "`", "")
	return strings.ToLower(strings.Join(strings.Fields(s), " "))
}

func dtSection(t *testing.T, f, from, until string) string {
	t.Helper()
	s := dtFlat(t, f)
	i := strings.Index(s, strings.ToLower(from))
	if i < 0 {
		t.Fatalf("%s has no %q", f, from)
	}
	e := s[i:]
	if j := strings.Index(e[len(from):], strings.ToLower(until)); j >= 0 {
		e = e[:j+len(from)]
	}
	return e
}

func TestTheDocumentedDingTalkLimitsAreTheOnesTheConfigurationHas(t *testing.T) {
	var g config.DingTalkGroup
	sec := dtSection(t, "MCP_TOOLS.md", "## 11c. dingtalk groups", "\n## 12.")
	for what, want := range map[string]string{
		"the most a robot may send a minute": fmt.Sprintf("%d messages a minute", g.MaxSendLimit()),
		"the default a minute":               fmt.Sprintf("defaults to %d a minute", g.SendLimit()),
		"the text limit":                     fmt.Sprintf("at most %d characters", g.MaxTextRunes()),
		"the throttle":                       "throttles it for ten minutes",
		"the ceiling on a setting":           fmt.Sprintf("no setting may amount to more than %d a minute", g.MaxSendLimit()),
		"that a throttle is waited out":      "nobody asks it again for ten minutes",
	} {
		if !strings.Contains(sec, want) {
			t.Errorf("MCP_TOOLS.md does not say %s (%q)", what, want)
		}
	}
	if g.MaxSendLimit() != 20 || g.SendLimit() != 10 {
		t.Errorf("DingTalk's documented limit is 20 a minute and the default stays at half of it: %d, %d", g.MaxSendLimit(), g.SendLimit())
	}
	for _, f := range []string{"README.md", "docs/OPERATING.md", "DESIGN.md"} {
		s := dtFlat(t, f)
		if !strings.Contains(s, "20 messages a minute") && !strings.Contains(s, "more than 20") && !strings.Contains(s, "over 20") {
			t.Errorf("%s does not say what DingTalk's limit is", f)
		}
	}
}

func TestEveryDocumentSaysThereIsNoWayToReadADingTalkGroup(t *testing.T) {
	// MCP_TOOLS.md says it in its own section, in the tool table and at the end of the section, and each is checked on its own: a
	// document that says it three times must not hide the loss of one.
	m := dtSection(t, "MCP_TOOLS.md", "## 11c. dingtalk groups", "\n## 12.")
	for what, want := range map[string]string{
		"at the top of the section": "send only: a custom robot cannot read a group",
		"in the tool table":         "send only: a custom robot cannot read",
		"in what securl cannot do":  "cannot read or moderate a group",
	} {
		if what == "in the tool table" {
			// the row of the table itself: the section below says the same words, so the whole file would hide the loss of the row
			var row string
			for _, l := range strings.Split(read(t, "MCP_TOOLS.md"), "\n") {
				if strings.HasPrefix(l, "| `dingtalk_send` |") {
					row = strings.ToLower(l)
				}
			}
			if !strings.Contains(row, want) {
				t.Errorf("the row of dingtalk_send in the tool table does not say that a group cannot be read: %q", row)
			}
			continue
		}
		if !strings.Contains(m, want) {
			t.Errorf("MCP_TOOLS.md does not say %s that a group cannot be read (%q)", what, want)
		}
	}
	for _, f := range []string{"README.md", "MCP_TOOLS.md", "DESIGN.md", "docs/OPERATING.md", "skills/securl/SKILL.md"} {
		s := dtFlat(t, f)
		i := strings.Index(s, "dingtalk groups")
		if i < 0 {
			i = strings.Index(s, "dingtalk group")
		}
		if i < 0 {
			t.Fatalf("%s says nothing about DingTalk groups", f)
		}
		if !strings.Contains(s[i:], "no way to read") && !strings.Contains(s[i:], "no tool to read") && !strings.Contains(s[i:], "cannot read") && !strings.Contains(s[i:], "no tool that does") {
			t.Errorf("%s does not say that a DingTalk group cannot be read", f)
		}
	}
}

func TestTheThreatModelSaysWhatIsAndIsNotDefendedAboutDingTalkGroups(t *testing.T) {
	e := dtSection(t, "DESIGN.md", "a dingtalk group is a channel", "\n## 9.")
	for _, want := range []string{
		"cannot read", "access_token", "only https://oapi.dingtalk.com/robot/send", "tricked", // what is accepted, and why
		"url.error", "redirect", "never markdown", "mention list is always empty", // how it leaks and what is refused
		"a login sends nothing", "first send", "not confirmed", "sha-256", // the one thing worse than Telegram, and the owner's choices
		"20 messages a minute", "ten minutes", "own cautious choice", "not end-to-end", // limits and honesty about what is not DingTalk's number
	} {
		if !strings.Contains(e, want) {
			t.Errorf("the DingTalk entry of the threat model does not say %q", want)
		}
	}
}

func TestTheSkillTellsAnAgentWhatADingTalkSendCanAndCannotDo(t *testing.T) {
	s := dtFlat(t, "skills/securl/SKILL.md")
	i := strings.Index(s, "### dingtalk groups")
	if i < 0 {
		t.Fatal("the skill has no section on DingTalk groups")
	}
	e := s[i:]
	if j := strings.Index(e[5:], "## 5."); j >= 0 {
		e = e[:j+5]
	}
	for _, want := range []string{
		"never give a webhook", "no tool to read a group", "nobody can be mentioned", "cannot be unsent", "plain text",
		"nothing is sent to the group by logging in", "the first send is what finds out", "refused_by_robot", "ten minutes",
	} {
		if !strings.Contains(e, want) {
			t.Errorf("the skill does not tell an agent %q", want)
		}
	}
}

func TestTheSetupGuideSaysAWebhookIsPastedByAPersonAndNeverGivenToAnAgentOrAFile(t *testing.T) {
	for _, f := range []string{"skills/securl/SKILL.md", "README.md", "docs/OPERATING.md"} {
		s := dtFlat(t, f)
		i := strings.Index(s, "dingtalk")
		if i < 0 {
			t.Fatalf("%s says nothing about DingTalk", f)
		}
		for _, want := range []string{"never", "webhook", "pastes"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s does not say %q", f, want)
			}
		}
	}
	op := dtSection(t, "docs/OPERATING.md", "### dingtalk: letting an agent send to a group", "\n## 8.")
	for _, want := range []string{"dingtalk group add", "never asks for the webhook", "session_open", "dingtalk://ops", "session_close", "found at the first send", "doctor -dingtalk-groups"} {
		if !strings.Contains(op, want) {
			t.Errorf("the setup guide does not say %q", want)
		}
	}
}

// The commands the documents tell somebody to type exist, and the flags they name are the ones the command has.
func TestTheDingTalkSetupCommandsInTheGuideTakeTheFlagsItNames(t *testing.T) {
	op := dtSection(t, "docs/OPERATING.md", "### dingtalk: letting an agent send to a group", "\n## 8.")
	for _, flag := range []string{"--name", "--sign", "--keyword", "--send-limit", "--send-window"} {
		if !strings.Contains(op, flag) {
			t.Errorf("the guide does not name %s", flag)
		}
	}
	src := read(t, "internal/configcli/dingtalk.go")
	for _, flag := range []string{"name", "sign", "keyword", "send-limit", "send-window"} {
		if !strings.Contains(src, `"`+flag+`"`) {
			t.Errorf("the command has no flag --%s, which the guide names", flag)
		}
	}
	for _, bad := range []string{"--webhook", "--token", "--secret"} {
		if strings.Contains(op, bad) {
			t.Errorf("the guide names %s: a credential is never a flag", bad)
		}
	}
}
