package config

import (
	"fmt"
	"regexp"
	"time"
)

// DingTalkGroup is one group an agent may speak in, through a custom robot of that group. The robot's webhook (and its signing
// secret, if it has one) is what lets anybody speak in the group, so it is never a field here: a person types it on a page and it stays
// in the vault, and a file that has one is refused. What the owner writes down is only that the group exists, by what name an agent
// calls it, and what limits apply.
type DingTalkGroup struct {
	Name string `yaml:"name"`
	// Sign says the robot's security setting is "sign" (加签): the person is then asked for the signing secret too.
	Sign bool `yaml:"sign"`
	// Keyword is the robot's keyword security setting, if it has one. securl puts it in the line it writes at the top of every
	// message, which is what DingTalk checks; the agent cannot change it.
	Keyword string `yaml:"keyword"`
	// SendMax and SendPeriod bound how many messages the robot sends: default 10 a minute. DingTalk throttles a robot that sends more
	// than 20 a minute for ten minutes, so no setting may reach a faster rate than that.
	SendMax    int           `yaml:"send_limit"`
	SendPeriod time.Duration `yaml:"send_window"`
}

// What DingTalk documents, and the defaults kept under it.
const (
	dingtalkRobotPerMinute = 20 // the robot is throttled for ten minutes above this
	dingtalkDefaultSend    = 10
)

var dingtalkNamePattern = regexp.MustCompile(`^[A-Za-z0-9._-]{1,64}$`)

// SendLimit is how many messages the group's robot sends in a window.
func (g DingTalkGroup) SendLimit() int {
	if g.SendMax > 0 {
		return g.SendMax
	}
	return dingtalkDefaultSend
}

// SendWindow is the length of the window the limit counts in.
func (g DingTalkGroup) SendWindow() time.Duration {
	if g.SendPeriod > 0 {
		return g.SendPeriod
	}
	return time.Minute
}

// dingtalkMaxText is how much of a message the agent may write. DingTalk's limit on the size of a text message is not in the part of
// its documentation that could be read, and it was not measured (the endpoint checks the token first, and a bogus token never reaches
// the size check), so this is a cautious choice, not DingTalk's number: well under what any chat message holds, and it leaves room for
// the line securl writes first.
const dingtalkMaxText = 4000

// MaxTextRunes is the most characters of text the agent may send in one message.
func (DingTalkGroup) MaxTextRunes() int { return dingtalkMaxText }

// MaxSendLimit is the most messages a minute DingTalk lets a robot send.
func (DingTalkGroup) MaxSendLimit() int { return dingtalkRobotPerMinute }

// perMinute is the rate the limit amounts to.
func (g DingTalkGroup) perMinute() float64 {
	return float64(g.SendLimit()) * float64(time.Minute) / float64(g.SendWindow())
}

// DingTalkGroup finds a group by its exact name.
func (c *Config) DingTalkGroup(name string) (DingTalkGroup, bool) {
	if name == "" {
		return DingTalkGroup{}, false
	}
	for _, g := range c.DingTalk.Groups {
		if g.Name == name {
			return g, true
		}
	}
	return DingTalkGroup{}, false
}

func (g DingTalkGroup) validate() error {
	if !dingtalkNamePattern.MatchString(g.Name) {
		return fmt.Errorf("name %q: use 1-64 letters, digits, '.', '_' or '-'", g.Name)
	}
	if g.SendMax < 0 || g.SendPeriod < 0 || g.SendPeriod > 24*time.Hour {
		return fmt.Errorf("send_limit/send_window: use a positive limit and a window of up to 24h")
	}
	if g.perMinute() > dingtalkRobotPerMinute {
		return fmt.Errorf("send_limit %d per %s is %.0f a minute: DingTalk throttles a robot for ten minutes above %d a minute",
			g.SendLimit(), g.SendWindow(), g.perMinute(), dingtalkRobotPerMinute)
	}
	if len([]rune(g.Keyword)) > 64 {
		return fmt.Errorf("keyword: at most 64 characters")
	}
	for _, r := range g.Keyword {
		if r < ' ' || r == 0x7f {
			return fmt.Errorf("keyword: one line, with no control characters")
		}
	}
	return nil
}

func validateDingTalkGroups(groups []DingTalkGroup) error {
	seen := map[string]bool{}
	for i, g := range groups {
		if err := g.validate(); err != nil {
			return fmt.Errorf("dingtalk.groups[%d] (%s): %w", i, g.Name, err)
		}
		if seen[g.Name] {
			return fmt.Errorf("dingtalk.groups: the name %q is used twice", g.Name)
		}
		seen[g.Name] = true
	}
	return nil
}
