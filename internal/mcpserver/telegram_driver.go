package mcpserver

import (
	"net/url"

	"github.com/LeafAI/securl/internal/telegramsite"
)

// telegramDriver is the login driver of every Telegram bot. The proxy is the owner's setting; no tool or argument chooses it.
func (s *Server) telegramDriver() *telegramsite.Driver {
	var proxy *url.URL
	if p := s.cfg.Telegram.Proxy; p != "" {
		proxy, _ = url.Parse(p) // checked when the configuration was validated
	}
	return telegramsite.New(s.cfg.TelegramBot, telegramsite.Options{BaseURL: s.telegramAPI, HTTP: s.telegramHTTP, Proxy: proxy})
}

// telegramTarget resolves the key a person or an agent named (telegram://<bot>) to a configured bot and its session key. A bot
// that is not configured is refused before anyone is asked for a token.
func (s *Server) telegramTarget(raw string) (string, *url.URL, *ToolError) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != telegramsite.Scheme || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", nil, errf("invalid_argument", false, "a Telegram bot is named telegram://<bot>, with a bot from %s", toolTelegramTargets)
	}
	b, ok := s.cfg.TelegramBot(u.Host)
	if !ok {
		e := errf("unknown_target", false, "there is no Telegram bot named %q", clipName(u.Host))
		e.Hint = "Call " + toolTelegramTargets + " to see the bots the owner has configured."
		return "", nil, e
	}
	return b.Name, telegramsite.BaseURL(b.Name), nil
}
