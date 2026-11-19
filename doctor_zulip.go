package main

import (
	"fmt"

	"github.com/LeafAI/securl/internal/config"
)

// doctorZulip says what is configured, by name. It never prints a site, an email or a channel's name in Zulip, and it says nothing at
// all when no server is configured. It makes no request: a key cannot be checked without opening the vault, and doctor does not.
func doctorZulip(cfg *config.Config, report func(bool, string, string)) {
	for _, z := range cfg.Zulip {
		n := "channels"
		if len(z.Channels) == 1 {
			n = "channel"
		}
		report(true, "zulip "+z.Name, fmt.Sprintf("%d %s; at most %d messages per %s; a person types the bot's key at the first session_open", len(z.Channels), n, z.SendLimit(), z.SendWindow()))
	}
}
