package climode

import (
	"bytes"
	"strings"
	"testing"
)

func TestAnnounceShowsOriginBeforeTheHumanLink(t *testing.T) {
	var stdout, stderr bytes.Buffer
	out := map[string]any{
		"link": "https://page.example/#fragment", "key_code": "AAAA BBBB CCCC DDDD",
		"origin": map[string]any{"hostname": "worker-3", "user": "alice", "pid": 91, "os": "linux", "arch": "amd64"},
	}
	announce(Env{Out: &stdout, Err: &stderr}, out)
	text := stderr.String()
	if stdout.Len() != 0 || !strings.Contains(text, "Request origin (securl host): host worker-3; account alice; PID 91; linux/amd64") {
		t.Fatalf("origin belongs on stderr next to the link: %q / %q", stdout.String(), text)
	}
	if strings.Index(text, "worker-3") > strings.Index(text, "https://page.example") {
		t.Fatal("the person must see the origin before the link")
	}
}
