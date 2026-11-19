// Package zulipsite makes a configured Zulip server look like a site to the login machinery: a person types the bot's API key on the
// usual page, it is checked by asking the server who the bot is, and it is kept in the vault like any other session.
//
// A Zulip server is never a web site to securl's HTTP tools. Its key is zulip://<name>, a scheme that they refuse, and its driver is
// never matched from a URL, so request and session_open cannot reach one by accident or by an agent's choice; only the Zulip tools,
// which take a configured name, can. The agent never holds the key: it names a server and a channel, and securl does the rest. The
// bot's email and the site are in the configuration and are not typed: what a person could be tricked into pasting somewhere else is
// the key alone, and it goes to the one site the owner wrote down.
package zulipsite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/zulip"
)

// Scheme is the URL scheme of a server's session key.
const Scheme = "zulip"

// The names under which a session keeps what it holds.
const (
	TokenKey  = "zulip_key"      // the bot's API key: the secret
	TokenName = "zulip_bot_name" // who the bot is: not a secret
)

// maxKeyRunes bounds what a person can paste. A Zulip API key is 32 characters; a longer paste is something else.
const (
	minKeyRunes = 20
	maxKeyRunes = 128
)

// BaseURL is the URL a server is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a server.
func Key(name string) string { return site.Key(BaseURL(name)) }

// Lookup finds a configured server by name.
type Lookup func(name string) (config.Zulip, bool)

// Options tunes the driver; a test points it at a fake server.
type Options struct {
	HTTP *http.Client
	// AllowInsecure lets a test use the fake's http:// address on this machine. The product never sets it.
	AllowInsecure bool
}

// Driver is the login driver of every Zulip server.
type Driver struct {
	lookup Lookup
	opt    Options
}

// New returns the driver.
func New(lookup Lookup, o Options) *Driver { return &Driver{lookup: lookup, opt: o} }

// Name is what the session is filed under.
func (*Driver) Name() string { return "zulip" }

// Match never matches: a server is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the key is the whole point.
func (*Driver) NeedsLogin() bool { return true }

func (d *Driver) server(base *url.URL) (config.Zulip, error) {
	if base == nil || base.Scheme != Scheme {
		return config.Zulip{}, fmt.Errorf("%w: not a zulip key", site.ErrLoginRejected)
	}
	z, ok := d.lookup(base.Host)
	if !ok {
		return config.Zulip{}, fmt.Errorf("%w: no Zulip server %q is configured", site.ErrLoginRejected, base.Host)
	}
	return z, nil
}

// Detail is what the message to the person says, in securl's own words and not the agent's: what the key will let an agent do. A
// channel is named by what the owner called it, never by the name Zulip gives it.
func (d *Driver) Detail(base *url.URL) string {
	z, err := d.server(base)
	if err != nil {
		return ""
	}
	var send, read []string
	for _, c := range z.Channels {
		if c.CanSend() {
			send = append(send, c.Name)
		}
		if c.CanRead() {
			read = append(read, c.Name)
		}
	}
	text := "the API key of the Zulip bot for " + z.Name + " is kept in the vault, and an AI agent can then use it through securl (it never sees the key)"
	if len(send) > 0 {
		text += ": it can send messages to " + strings.Join(send, ", ")
	}
	if len(read) > 0 {
		sep := " and it can read "
		if len(send) == 0 {
			sep = ": it can read "
		}
		text += sep + "what is said in " + strings.Join(read, ", ")
	}
	return text + ". Anyone in those channels can read what it sends."
}

// Client makes a Zulip client from a session, for the configured server. The site and the email are the configuration's, so a tool
// does not choose them.
func (d *Driver) Client(base *url.URL, s *site.Session) (*zulip.Client, config.Zulip, error) {
	z, err := d.server(base)
	if err != nil {
		return nil, z, err
	}
	if s == nil || s.Tokens[TokenKey] == "" {
		return nil, z, fmt.Errorf("%w: the session holds no key", site.ErrBadCredentials)
	}
	c, err := zulip.New(z.Site, z.Email, s.Tokens[TokenKey], zulip.Options{HTTP: d.opt.HTTP, AllowInsecure: d.opt.AllowInsecure})
	if err != nil {
		return nil, z, fmt.Errorf("%w: the configured site is not usable", site.ErrLoginRejected)
	}
	return c, z, nil
}

// label is the field's label with the server's name in it. The page cuts a label at 60 characters, so the name is cut and what is
// asked for always fits.
func label(name string) string {
	const what = "Zulip bot key for "
	room := 60 - len([]rune(what))
	n := []rune(name)
	if len(n) > room {
		n = append(n[:room-3], '.', '.', '.')
	}
	return what + string(n)
}

// keyShape accepts what an API key can be: one run of visible ASCII characters (which leaves out every space and control character), long
// enough that a pasted word is not taken for one and short enough that a pasted page is not. A slash or a colon is not part of a key and
// would break the Basic header the key is sent in (a colon ends the user name there), so each is refused.
func keyShape(k string) bool {
	n := len([]rune(k))
	if n < minKeyRunes || n > maxKeyRunes {
		return false
	}
	for _, r := range k {
		if r > '~' || r <= ' ' || r == '/' || r == ':' {
			return false
		}
	}
	return true
}

// Login asks for the key and checks it by asking the server who the bot is.
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	z, err := d.server(base)
	if err != nil {
		return nil, err
	}
	creds, err := ask.Ask(ctx, "custom", []site.Field{{Name: TokenKey, Label: label(z.Name), Secret: true}})
	if err != nil {
		return nil, err
	}
	key := strings.TrimSpace(creds[TokenKey])
	creds[TokenKey] = ""
	if !keyShape(key) {
		return nil, fmt.Errorf("%w: that is not a bot's key (Zulip shows one for the bot, as one run of letters and digits with no spaces)", site.ErrBadCredentials)
	}
	return d.check(ctx, base, key)
}

// check asks the server who the bot is, and says what went wrong in the vocabulary of the login flow. Whatever the client said is left
// out: it is made from a request that holds the key.
func (d *Driver) check(ctx context.Context, base *url.URL, key string) (*site.Session, error) {
	c, _, err := d.Client(base, &site.Session{Tokens: map[string]string{TokenKey: key}})
	if err != nil {
		return nil, err
	}
	me, err := c.Me(ctx)
	switch {
	case err == nil:
	case errors.Is(err, zulip.ErrBadKey):
		return nil, fmt.Errorf("%w: the Zulip server refused that key (it was regenerated, or is mistyped, or is for another bot)", site.ErrBadCredentials)
	case errors.Is(err, zulip.ErrUnreachable):
		return nil, fmt.Errorf("%w: the Zulip server could not be reached", site.ErrUnreachable)
	default:
		return nil, fmt.Errorf("%w: the Zulip server would not say who the bot is", site.ErrLoginRejected)
	}
	return &site.Session{Tokens: map[string]string{TokenKey: key, TokenName: me.Name}}, nil
}

// Probe checks that the kept key is still accepted. A key the owner regenerated ends the session, as a cookie the site no longer knows
// would; a network that is down says nothing about it, and the session is kept.
func (d *Driver) Probe(ctx context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	if _, err := d.server(base); err != nil {
		return err
	}
	if s == nil || s.Tokens[TokenKey] == "" {
		return fmt.Errorf("%w: the session holds no key", site.ErrBadCredentials)
	}
	_, err := d.check(ctx, base, s.Tokens[TokenKey])
	return err
}
