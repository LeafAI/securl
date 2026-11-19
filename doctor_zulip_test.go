package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDoctorSaysNothingAboutZulipWhenNoServerIsConfigured(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("dingtalk:\n  webhook: https://oapi.dingtalk.com/robot/send?access_token=abc\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	if strings.Contains(out, "zulip") {
		t.Errorf("a setup with no Zulip server has nothing to say about it:\n%s", out)
	}
}

func TestDoctorReportsEachZulipServerByNameWithItsChannelsAndLimitsAndNeverAnEmailOrASite(t *testing.T) {
	dir := t.TempDir()
	cfgPath := filepath.Join(dir, "c.yaml")
	os.WriteFile(cfgPath, []byte("dingtalk:\n  webhook: https://oapi.dingtalk.com/robot/send?access_token=abc\nzulip:\n"+
		"  - name: team\n    site: https://acme.example.invalid\n    email: robot-bot@acme.example.invalid\n    channels:\n      - {name: dev, channel: Dev Team}\n      - {name: news, channel: announce, send: false}\n"+
		"  - name: other\n    site: https://other.example.invalid\n    email: b@other.example.invalid\n    send_limit: 5\n    send_window: 2m\n    channels: [{name: a, channel: a, read: false}]\n"), 0o600)
	out, _ := capture(t, func() int { return runDoctor([]string{"-config", cfgPath}) })
	for _, want := range []string{"zulip team", "zulip other", "at most 20 messages per 1m0s", "at most 5 messages per 2m0s", "2 channels", "1 channel", "a person types"} {
		if !strings.Contains(out, want) {
			t.Errorf("doctor lacks %q:\n%s", want, out)
		}
	}
	for _, l := range strings.Split(out, "\n") {
		if strings.Contains(l, "zulip team") && strings.HasPrefix(l, "[FAIL]") {
			t.Errorf("a configured server is not a problem: %s", l)
		}
	}
	for _, secret := range []string{"robot-bot@", "acme.example.invalid", "other.example.invalid", "Dev Team", "announce"} {
		if strings.Contains(out, secret) {
			t.Errorf("doctor prints %q:\n%s", secret, out)
		}
	}
}
