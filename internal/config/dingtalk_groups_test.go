package config

import (
	"strings"
	"testing"
	"time"
)

const goodGroups = `
dingtalk:
  groups:
    - name: ops
    - name: alerts
      sign: true
      keyword: securl
      send_limit: 5
      send_window: 2m
`

func TestGroupsAreReadFromTheConfigurationWithTheirOwnLimits(t *testing.T) {
	c, err := parseTG(t, goodGroups)
	if err != nil {
		t.Fatal(err)
	}
	if len(c.DingTalk.Groups) != 2 {
		t.Fatalf("%+v", c.DingTalk)
	}
	g, ok := c.DingTalkGroup("alerts")
	if !ok || !g.Sign || g.Keyword != "securl" || g.SendLimit() != 5 || g.SendWindow() != 2*time.Minute {
		t.Errorf("%+v %v", g, ok)
	}
	o, _ := c.DingTalkGroup("ops")
	if o.Sign || o.Keyword != "" {
		t.Errorf("a group asks for no signing secret and wants no keyword unless it says so: %+v", o)
	}
}

// DingTalk throttles a robot for ten minutes after 20 messages in a minute. The default stays well under, and no setting reaches it.
func TestTheDefaultSendLimitIsHalfWhatDingTalkAllowsAndNoSettingExceedsIt(t *testing.T) {
	var g DingTalkGroup
	if g.SendLimit() != 10 || g.SendWindow() != time.Minute {
		t.Errorf("default %d per %s", g.SendLimit(), g.SendWindow())
	}
	if g.MaxSendLimit() != 20 {
		t.Errorf("DingTalk's own limit is 20 a minute: %d", g.MaxSendLimit())
	}
}

// The limit DingTalk throttles at is a rate, so it is the rate that is checked: 10 in 30 seconds is 20 a minute and is allowed, 20
// in 30 seconds is 40 and is not, and a long window with a small number is slow and is fine.
func TestTheRateIsWhatIsCheckedNotTheWindow(t *testing.T) {
	for y, ok := range map[string]bool{
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 10, send_window: 30s}\n":  true,
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 20, send_window: 1m}\n":   true,
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 21, send_window: 1m}\n":   false,
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 5, send_window: 10s}\n":   false, // 30 a minute
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 100, send_window: 10m}\n": true,  // 10 a minute
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 1, send_window: 3s}\n":    true,  // 20 a minute
		"dingtalk:\n  groups:\n    - {name: a, send_limit: 1, send_window: 2s}\n":    false, // 30 a minute
	} {
		if _, err := parseTG(t, y); (err == nil) != ok {
			t.Errorf("%s: accepted=%v, want %v (%v)", strings.TrimSpace(y), err == nil, ok, err)
		}
	}
}

func TestAGroupThatCouldBeThrottledOrIsMalformedIsRefused(t *testing.T) {
	for name, y := range map[string]string{
		"no name":             "dingtalk:\n  groups:\n    - {sign: true}\n",
		"bad name":            "dingtalk:\n  groups:\n    - {name: 'a b'}\n",
		"name too long":       "dingtalk:\n  groups:\n    - {name: " + strings.Repeat("a", 65) + "}\n",
		"duplicate":           "dingtalk:\n  groups:\n    - {name: a}\n    - {name: a}\n",
		"limit over 20":       "dingtalk:\n  groups:\n    - {name: a, send_limit: 21}\n",
		"limit negative":      "dingtalk:\n  groups:\n    - {name: a, send_limit: -1}\n",
		"rate over 20 a min":  "dingtalk:\n  groups:\n    - {name: a, send_limit: 20, send_window: 30s}\n",
		"default over rate":   "dingtalk:\n  groups:\n    - {name: a, send_window: 10s}\n",
		"window over 24h":     "dingtalk:\n  groups:\n    - {name: a, send_window: 25h}\n",
		"window negative":     "dingtalk:\n  groups:\n    - {name: a, send_window: -1m}\n",
		"keyword with a line": "dingtalk:\n  groups:\n    - {name: a, keyword: \"x\\ny\"}\n",
		"keyword with DEL":    "dingtalk:\n  groups:\n    - {name: a, keyword: \"x\\x7fy\"}\n",
		"keyword too long":    "dingtalk:\n  groups:\n    - {name: a, keyword: " + strings.Repeat("k", 65) + "}\n",
	} {
		if _, err := parseTG(t, y); err == nil {
			t.Errorf("%s must be refused", name)
		}
	}
}

// What a group is allowed to do is written down; the webhook and the secret that let anybody speak in it are not. A file that holds
// either is refused, and the refusal does not repeat it.
func TestAGroupWithAWebhookOrASecretInTheFileIsRefusedWithoutEchoingIt(t *testing.T) {
	const tok = "c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	for _, y := range []string{
		"dingtalk:\n  groups:\n    - {name: a, webhook: 'https://oapi.dingtalk.com/robot/send?access_token=" + tok + "'}\n",
		"dingtalk:\n  groups:\n    - {name: a, access_token: " + tok + "}\n",
		"dingtalk:\n  groups:\n    - {name: a, secret: SECabcdefabcdefabcdefabcdef}\n",
		"dingtalk:\n  groups:\n    - {name: a, token: " + tok + "}\n",
	} {
		err := ParseStrict([]byte(y))
		if err == nil {
			t.Fatalf("a credential in the file was accepted:\n%s", y)
		}
		if strings.Contains(err.Error(), "SECRETTOKEN") || strings.Contains(err.Error(), "SECabcdef") || strings.Contains(err.Error(), "oapi.dingtalk.com") {
			t.Errorf("the error repeats it: %v", err)
		}
	}
}

func TestOnlyAnExactNameFindsAGroup(t *testing.T) {
	c, _ := parseTG(t, goodGroups)
	for _, n := range []string{"", "OPS", "ops ", " ops", "op", "ops2", "../ops"} {
		if _, ok := c.DingTalkGroup(n); ok {
			t.Errorf("%q found a group", n)
		}
	}
	if _, ok := c.DingTalkGroup("ops"); !ok {
		t.Error("ops")
	}
}

// The robot that carries login links is a separate thing from the groups an agent may speak in.
func TestTheLoginRobotAndTheGroupsAreIndependent(t *testing.T) {
	c, err := parseTG(t, "dingtalk:\n  webhook: https://oapi.dingtalk.com/robot/send?access_token=x\n  keyword: login\n"+strings.TrimPrefix(goodGroups, "\ndingtalk:\n"))
	if err != nil {
		t.Fatal(err)
	}
	if c.DingTalk.Webhook == "" || c.DingTalk.Keyword != "login" || len(c.DingTalk.Groups) != 2 {
		t.Errorf("%+v", c.DingTalk)
	}
	if g, _ := c.DingTalkGroup("ops"); g.Keyword != "" {
		t.Errorf("a group does not inherit the login robot's keyword: %+v", g)
	}
}
