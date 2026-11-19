package mcpserver

import (
	"net/url"

	"github.com/LeafAI/securl/internal/zulipsite"
)

// zulipDriver is the login driver of every Zulip server. The site and the bot's email are the owner's configuration; no tool or
// argument chooses them, and the site is always https and never this machine. A test gives it an HTTP client that carries the
// requests to a fake, so that what is tested is the same code and the same rules.
func (s *Server) zulipDriver() *zulipsite.Driver {
	return zulipsite.New(s.cfg.ZulipServer, zulipsite.Options{HTTP: s.zulipHTTP})
}

// zulipTarget resolves the key a person or an agent named (zulip://<server>) to a configured server and its session key. A server
// that is not configured is refused before anyone is asked for a key.
func (s *Server) zulipTarget(raw string) (string, *url.URL, *ToolError) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != zulipsite.Scheme || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", nil, errf("invalid_argument", false, "a Zulip server is named zulip://<server>, with a server from %s", toolZulipTargets)
	}
	z, ok := s.cfg.ZulipServer(u.Host)
	if !ok {
		e := errf("unknown_target", false, "there is no Zulip server named %q", clipName(u.Host))
		e.Hint = "Call " + toolZulipTargets + " to see the servers the owner has configured."
		return "", nil, e
	}
	return z.Name, zulipsite.BaseURL(z.Name), nil
}
