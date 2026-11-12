package main

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk"
)

// doctorDingTalkGroups says what is configured, by name. It never prints a webhook, a token or a secret, and it says nothing at all
// when no group is configured.
func doctorDingTalkGroups(cfg *config.Config, report func(bool, string, string)) {
	for _, g := range cfg.DingTalk.Groups {
		how := "a person pastes its webhook at the first session_open"
		if g.Sign {
			how = "its robot signs its messages (a signing secret is pasted too); " + how
		}
		report(true, "dingtalk group "+g.Name, fmt.Sprintf("at most %d messages per %s; %s", g.SendLimit(), g.SendWindow(), how))
	}
}

// doctorDingTalkReach asks oapi.dingtalk.com something it can answer with no token and nothing to post (see dingtalk.Client.Ping). Any
// answer from DingTalk's side proves the host is reachable. A webhook is not checked: DingTalk has no call for that which does not
// post a message, and doctor does not open the vault.
func doctorDingTalkReach(ctx context.Context, cfg *config.Config, report func(bool, string, string)) {
	if len(cfg.DingTalk.Groups) == 0 {
		report(false, "dingtalk api", "no group is configured: add one with `securl config dingtalk group add`")
		return
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c := dingtalk.New("", "", dingtalk.Options{BaseURL: doctorDingTalkBase, HTTP: doctorDingTalkHTTP, Timeout: 20 * time.Second})
	if err := c.Ping(ctx); err != nil {
		if errors.Is(err, dingtalk.ErrUnreachable) {
			report(false, "dingtalk api", "oapi.dingtalk.com could not be reached: check the network (securl uses the system's proxy settings for it)")
			return
		}
		report(false, "dingtalk api", "oapi.dingtalk.com answered, but not as the robot API does: something on the way may be rewriting the answer")
		return
	}
	report(true, "dingtalk api", "oapi.dingtalk.com answered; a group's webhook cannot be checked without posting a message, so it is found out by the first send (doctor does not open the vault)")
}

// doctorDingTalkBase and doctorDingTalkHTTP are where the reachability check goes; a test points them at a fake. The product leaves
// them empty: the real endpoint, and the client's own transport.
var (
	doctorDingTalkBase string
	doctorDingTalkHTTP *http.Client
)
