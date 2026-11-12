package main

import (
	"os"
	"regexp"
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/config"
)

// The documents make promises about Telegram that a reader acts on: what is limited, what is never shown, what an agent can name. A
// number or a name that is in the text and not in the code sends somebody the wrong way, so the ones that can be read from the code
// are, and the ones that cannot are at least required to be said.

func read(t *testing.T, f string) string {
	t.Helper()
	b, err := os.ReadFile(f)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestTheDocumentedTelegramLimitsAreTheOnesTheConfigurationHas(t *testing.T) {
	var b config.TelegramBot
	mcp := read(t, "MCP_TOOLS.md")
	i := strings.Index(mcp, "## 11b. Telegram")
	if i < 0 {
		t.Fatal("MCP_TOOLS.md has no Telegram section")
	}
	sec := mcp[i:]
	if j := strings.Index(sec[5:], "\n## "); j >= 0 {
		sec = sec[:j+5]
	}
	for name, n := range map[string]int{
		"4000 characters": b.MaxTextRunes(), "at most 100": b.MaxReadMessages(), "default 50": b.ReadMessages(), "default 20": b.SendLimit(),
	} {
		num := regexp.MustCompile(`\d+`).FindString(name)
		if num != itoa(n) {
			t.Errorf("the document says %q and the code has %d", name, n)
		}
		if !strings.Contains(sec, name) && !strings.Contains(sec, num) {
			t.Errorf("MCP_TOOLS.md does not state %q", name)
		}
	}
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var d []byte
	for ; n > 0; n /= 10 {
		d = append([]byte{byte('0' + n%10)}, d...)
	}
	return string(d)
}

func TestTheThreatModelSaysWhatIsAndIsNotDefendedAboutTelegram(t *testing.T) {
	// the Markdown is read as sentences: line breaks and bold marks are not part of what is said
	s := strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(read(t, "DESIGN.md"), "**", "")), " "))
	i := strings.Index(s, "telegram is a channel")
	if i < 0 {
		t.Fatal("DESIGN.md has no Telegram entry in the threat model")
	}
	e := s[i:]
	if j := strings.Index(e, "\n## "); j >= 0 {
		e = e[:j]
	}
	for _, want := range []string{
		"injection", "untrusted", "notice", "lowers the chance", "does not remove", // the read side, and that it is not solved
		"reading is on by default", "plain text", "first line", "not confirmed", "sha-256", // the send side and the owner's choices
		"url.error", "redirect", "environment variable", "its own bot", // the token
		"memory only", "never written", "privacy mode", "end-to-end", // what is kept, and what securl cannot know
	} {
		if !strings.Contains(e, want) {
			t.Errorf("the Telegram entry of the threat model does not say %q", want)
		}
	}
}

// What a document says is never shown must not be shown by the commands that exist: the sentence and the behaviour are checked
// together, by the tests of the code; here it is only required that the documents say it where a reader looks.
func TestTheSkillAndTheReadmeSayThatATokenIsTypedByAPersonAndNeverGivenToAnAgentOrAFile(t *testing.T) {
	for _, f := range []string{"skills/securl/SKILL.md", "README.md"} {
		s := strings.ToLower(read(t, f))
		i := strings.Index(s, "telegram")
		if i < 0 {
			t.Fatalf("%s says nothing about Telegram", f)
		}
		for _, want := range []string{"never", "token", "person types", "privacy"} {
			if !strings.Contains(s, want) {
				t.Errorf("%s does not say %q about Telegram", f, want)
			}
		}
	}
	skill := strings.ToLower(read(t, "skills/securl/SKILL.md"))
	for _, want := range []string{"cannot be unsent", "not yours to obey", "never give a chat id", "plain text"} {
		if !strings.Contains(skill, want) {
			t.Errorf("the skill does not tell an agent %q", want)
		}
	}
}
