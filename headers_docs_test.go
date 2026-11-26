package main

import (
	"os"
	"strings"
	"testing"
)

// The headers an agent may not set are named in the reference and in what the tool tells a model. A header that is refused in the
// code and not named there sends an agent into a refusal it was never warned about; one that is named and not refused would make
// the words a promise the code does not keep. The refusal of the second-factor header is the one this holds.
func TestTheReferenceAndTheToolDescriptionNameTheSecondFactorHeaderAsRefused(t *testing.T) {
	ref, err := os.ReadFile("MCP_TOOLS.md")
	if err != nil {
		t.Fatal(err)
	}
	types, err := os.ReadFile("internal/mcpserver/types.go")
	if err != nil {
		t.Fatal(err)
	}
	for name, text := range map[string]string{"MCP_TOOLS.md": string(ref), "internal/mcpserver/types.go": string(types)} {
		if !strings.Contains(strings.ToLower(text), "x-ga-code") {
			t.Errorf("%s does not say that X-Ga-Code is refused", name)
		}
	}
	// in the reference it stands in the list of refused headers, with the others, not somewhere else in the text
	if !strings.Contains(string(ref), "Cookie, Authorization, X-Ga-Code, Host, Content-Length") {
		t.Error("MCP_TOOLS.md does not list X-Ga-Code among the headers an agent may not set")
	}
	if !strings.Contains(string(types), "Cookie, Authorization, Host, X-Ga-Code and the session's own headers are set by the gateway and refused here") {
		t.Error("the tool's own description of its headers argument does not say X-Ga-Code is refused")
	}
}
