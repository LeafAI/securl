package mcpserver

import (
	"strings"
	"testing"

	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/notify"
)

func TestPendingHandoverIdentifiesOriginOnBothDeliveryRoutes(t *testing.T) {
	o := notify.Origin{Hostname: "worker-2", User: "bob", PID: 73, OS: "linux", Arch: "amd64"}
	for _, link := range []string{"", "https://page.example/#secret"} {
		sn := flow.Snapshot{Link: link, KeyCode: "AAAA BBBB CCCC DDDD"}
		h := handover(sn, "the login page", o)
		if h.Origin == nil || *h.Origin != o {
			t.Fatalf("pending request must identify the serving host: %+v", h)
		}
		if link == "" {
			if h.Link != "" || h.Instruction != "" || h.KeyCode != "" {
				t.Fatal("DingTalk delivery must not expose its login link")
			}
			continue
		}
		if h.Link != link || !strings.Contains(h.Instruction, "worker-2") || !strings.Contains(h.Instruction, "origin") {
			t.Fatalf("agent must be instructed to present the source: %+v", h)
		}
	}
}
