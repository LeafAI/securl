package main

import (
	"context"
	"errors"
	"fmt"
	"net/url"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/telegram"
)

// doctorTelegram says what is configured, by name. It never prints a chat id, a token or the proxy's credential, and it says nothing at
// all when no bot is configured.
func doctorTelegram(cfg *config.Config, report func(bool, string, string)) {
	for _, b := range cfg.Telegram.Bots {
		var read, send int
		for _, c := range b.Chats {
			if c.CanRead() {
				read++
			}
			if c.CanSend() {
				send++
			}
		}
		report(true, "telegram bot "+b.Name, fmt.Sprintf("%d chats, %d can be read, %d can be sent to (at most %d messages per %s); the token is typed by a person at the first session_open",
			len(b.Chats), read, send, b.SendLimit(), b.SendWindow()))
	}
	if len(cfg.Telegram.Bots) > 0 && cfg.Telegram.Proxy != "" {
		fmt.Printf("[note] telegram goes through the proxy %s\n", cfg.Telegram.ProxyForDisplay())
	}
}

// doctorTelegramReach asks api.telegram.org something it can answer without a token (a path it does not know) the way securl will:
// through the proxy when there is one, and by no other route. Any answer from Telegram's side proves the host is reachable. The token
// is not checked: it is in the vault, doctor never asks for the passphrase, and a person's login checks it.
func doctorTelegramReach(ctx context.Context, cfg *config.Config, report func(bool, string, string)) {
	if len(cfg.Telegram.Bots) == 0 {
		report(false, "telegram api", "no bot is configured: add one with `securl config telegram add`")
		return
	}
	var proxy *url.URL
	if p := cfg.Telegram.Proxy; p != "" {
		proxy, _ = url.Parse(p)
	}
	ctx, cancel := context.WithTimeout(ctx, 20*time.Second)
	defer cancel()
	c := telegram.New("0:doctor-probe", telegram.Options{Proxy: proxy, Timeout: 20 * time.Second, BaseURL: doctorTelegramBase})
	_, err := c.Me(ctx)
	via := "directly"
	if proxy != nil {
		via = "through " + cfg.Telegram.ProxyForDisplay()
	}
	if errors.Is(err, telegram.ErrUnreachable) {
		report(false, "telegram api", "api.telegram.org could not be reached "+via+": set telegram.proxy (`securl config set telegram.proxy http://host:port`) or check the network")
		return
	}
	// Anything else is an answer from the other side: a 401 for the probe token, a 404, a refusal. Whatever it said, the host is
	// reachable, and what doctor cannot say is whether the real token works.
	report(true, "telegram api", "api.telegram.org answered "+via+"; the bot token itself is checked when a person logs in (doctor does not open the vault): `securl unlock`, then session_open telegram://<bot>")
}

// doctorTelegramBase is where the reachability check goes; a test points it at a fake by configuring a proxy that answers for any host.
const doctorTelegramBase = "http://api.telegram.org"
