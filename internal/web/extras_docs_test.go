package web_test

import (
	"os"
	"strings"
	"testing"
)

func TestTheDocumentsSayHowAFieldBesideThePasswordIsAskedSavedAndNeverShown(t *testing.T) {
	// paragraph returns the paragraph of a document that contains marker, as one line of lower-case words.
	paragraph := func(p, marker string) string {
		b, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		for _, para := range strings.Split(string(b), "\n\n") {
			one := strings.ToLower(strings.Join(strings.Fields(strings.ReplaceAll(para, "**", "")), " "))
			if strings.Contains(one, marker) {
				return one
			}
		}
		t.Fatalf("%s has no paragraph about %q", p, marker)
		return ""
	}
	for _, c := range []struct {
		file, marker string
		wants        []string
	}{
		{"../../DESIGN.md", "site.loginextras", []string{"credential_setup_x", "credential_replace_x", "(always secret, autocomplete off, sealed in the same envelope)",
			"a plain name, never one the page or the server uses, always secret, no image", "refuses a field list in the link",
			"binding includes the names of the extras", "left out or sent empty", "never written to an answer, an error, the audit log or a message", "autocomplete off"}},
		{"../../docs/OPERATING.md", "asks for a field beside the username", []string{"only when you select remember credentials", "asked again", "shown as a secret"}},
		{"../../docs/OPERATING.md", "page version 3", []string{"credential_setup_x", "credential_replace_x", "page version 3", "publish the page"}},
		{"../../MCP_TOOLS.md", "credential_setup_x", []string{"credential_setup_x", "credential_replace_x"}},
	} {
		doc := paragraph(c.file, c.marker)
		for _, want := range c.wants {
			if !strings.Contains(doc, want) {
				t.Errorf("the paragraph of %s about %q does not say %q", c.file, c.marker, want)
			}
		}
	}
}
