// Package telegramsite makes a configured Telegram bot look like a site to the login machinery: a person types the bot's token
// on the usual page, it is checked by asking Telegram who the bot is, and it is kept in the vault like any other session.
//
// A bot is never a web site. Its key is telegram://<name>, a scheme that the HTTP tools refuse, and its driver is never matched
// from a URL, so request and session_open cannot reach one by accident or by an agent's choice; only the Telegram tools, which
// take a configured name, can. The agent never holds the token: it names a bot and a chat, and securl does the rest.
package telegramsite

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"regexp"
	"strings"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/telegram"
)

// Scheme is the URL scheme of a bot's session key.
const Scheme = "telegram"

// The names under which a session keeps what it holds.
const (
	TokenBot      = "bot_token"
	TokenUsername = "bot_username" // who the bot is: not a secret
	TokenReadsAll = "reads_all"    // "true" when the bot's privacy mode is off
)

// BaseURL is the URL a bot is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a bot.
func Key(name string) string { return site.Key(BaseURL(name)) }

// A token is "<bot id>:<35 characters of letters, digits, '_' and '-'>". The shape is checked before Telegram is asked, so that
// a paste of the wrong thing (a URL, a sentence) is told so at once and nothing is sent anywhere.
var tokenShape = regexp.MustCompile(`^[0-9]{5,20}:[A-Za-z0-9_-]{30,64}$`)

// Lookup finds a configured bot by name.
type Lookup func(name string) (config.TelegramBot, bool)

// Options tunes the driver; a test points it at a fake Bot API.
type Options struct {
	BaseURL string
	HTTP    *http.Client
	Proxy   *url.URL
}

// Driver is the login driver of every Telegram bot.
type Driver struct {
	lookup Lookup
	opt    Options
}

// New returns the driver.
func New(lookup Lookup, o Options) *Driver { return &Driver{lookup: lookup, opt: o} }

// Name is what the session is filed under.
func (*Driver) Name() string { return "telegram" }

// Match never matches: a bot is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the token is the whole point.
func (*Driver) NeedsLogin() bool { return true }

func (d *Driver) bot(base *url.URL) (config.TelegramBot, error) {
	if base == nil || base.Scheme != Scheme {
		return config.TelegramBot{}, fmt.Errorf("%w: not a telegram key", site.ErrLoginRejected)
	}
	b, ok := d.lookup(base.Host)
	if !ok {
		return config.TelegramBot{}, fmt.Errorf("%w: no telegram bot %q is configured", site.ErrLoginRejected, base.Host)
	}
	return b, nil
}

// Detail is what the message to the person says, in securl's own words and not the agent's: what the token will let an agent do.
// A chat is named, never numbered: the number means nothing to the person and the name is what they wrote.
func (d *Driver) Detail(base *url.URL) string {
	b, err := d.bot(base)
	if err != nil {
		return ""
	}
	var send, read []string
	for _, c := range b.Chats {
		if c.CanSend() {
			send = append(send, c.Name)
		}
		if c.CanRead() {
			read = append(read, c.Name)
		}
	}
	text := "the bot token for " + b.Name + " is kept in the vault, and an AI agent can then use it through securl (it never sees the token)"
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
	return text + ". Anyone in those chats can read what it sends."
}

// Client makes a Bot API client from a session. The proxy and the Bot API's address are the driver's, so a tool does not choose them.
func (d *Driver) Client(s *site.Session) (*telegram.Client, error) {
	if s == nil || s.Tokens[TokenBot] == "" {
		return nil, fmt.Errorf("%w: the session holds no bot token", site.ErrBadCredentials)
	}
	return telegram.New(s.Tokens[TokenBot], telegram.Options{BaseURL: d.opt.BaseURL, HTTP: d.opt.HTTP, Proxy: d.opt.Proxy}), nil
}

// Login asks for the token and checks it by asking Telegram who the bot is.
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	b, err := d.bot(base)
	if err != nil {
		return nil, err
	}
	// The page cuts a label at 60 characters, so the name of the bot comes first and what is asked for fits.
	label := "Bot token for " + b.Name
	if len([]rune(label)) > 60 {
		label = string([]rune(label)[:57]) + "..."
	}
	creds, err := ask.Ask(ctx, "custom", []site.Field{{Name: TokenBot, Label: label, Secret: true}})
	if err != nil {
		return nil, err
	}
	token := strings.TrimSpace(creds[TokenBot])
	creds[TokenBot] = ""
	if !tokenShape.MatchString(token) {
		return nil, fmt.Errorf("%w: that is not a bot token (BotFather gives one: digits, a colon, then letters and digits, with no spaces)", site.ErrBadCredentials)
	}
	return d.check(ctx, token)
}

// check asks Telegram who the bot is, and says what went wrong in the vocabulary of the login flow. Whatever the library said is
// left out: it is made from the token's own request.
func (d *Driver) check(ctx context.Context, token string) (*site.Session, error) {
	c := telegram.New(token, telegram.Options{BaseURL: d.opt.BaseURL, HTTP: d.opt.HTTP, Proxy: d.opt.Proxy})
	me, err := c.Me(ctx)
	switch {
	case err == nil:
	case errors.Is(err, telegram.ErrBadToken):
		return nil, fmt.Errorf("%w: Telegram refused that bot token (it was revoked, or is mistyped)", site.ErrBadCredentials)
	case errors.Is(err, telegram.ErrUnreachable):
		return nil, fmt.Errorf("%w: api.telegram.org could not be reached (a proxy may be needed: telegram.proxy)", site.ErrUnreachable)
	default:
		return nil, fmt.Errorf("%w: Telegram would not say who the bot is", site.ErrLoginRejected)
	}
	reads := "false"
	if me.SeesAllGroupMessages {
		reads = "true"
	}
	return &site.Session{Tokens: map[string]string{TokenBot: token, TokenUsername: me.Username, TokenReadsAll: reads}}, nil
}

// Probe checks that the kept token is still accepted. A token the owner revoked ends the session, as a cookie the site no longer
// knows would; a network that is down says nothing about it, and the session is kept.
func (d *Driver) Probe(ctx context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	if _, err := d.bot(base); err != nil {
		return err
	}
	if s == nil || s.Tokens[TokenBot] == "" {
		return fmt.Errorf("%w: the session holds no bot token", site.ErrBadCredentials)
	}
	_, err := d.check(ctx, s.Tokens[TokenBot])
	return err
}
