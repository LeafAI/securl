// Package dingtalksite makes a configured DingTalk group look like a site to the login machinery: a person types the webhook of the
// group's custom robot (and its signing secret, when it has one) on the usual page, and it is kept in the vault like any other session.
//
// A group is never a web site. Its key is dingtalk://<name>, a scheme that the HTTP tools refuse, and its driver is never matched from
// a URL, so request and session_open cannot reach one by accident or by an agent's choice; only the DingTalk tools, which take a
// configured name, can. The agent never holds the webhook: it names a group, and securl does the rest.
//
// DingTalk has no call that checks a robot without posting a message, and a person who pastes an address must not make the group see
// a message they did not write. So a login checks only the shape and the host of what was typed (ParseWebhook), and the first send is
// what finds out whether the robot exists; a robot that is refused ends the session then, like a cookie the site no longer knows.
package dingtalksite

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk"
	"github.com/LeafAI/securl/internal/site"
)

// Scheme is the URL scheme of a group's session key.
const Scheme = "dingtalk"

// The names under which a session keeps what it holds. The webhook's host and path are the same for every robot and are not kept:
// the address is rebuilt from the access_token, so a session cannot be made to point anywhere else.
const (
	TokenWebhook = "access_token"
	TokenSecret  = "sign_secret"
)

// BaseURL is the URL a group is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a group.
func Key(name string) string { return site.Key(BaseURL(name)) }

// Lookup finds a configured group by name.
type Lookup func(name string) (config.DingTalkGroup, bool)

// Options tunes the driver; a test points it at a fake endpoint.
type Options struct {
	BaseURL string
	HTTP    *http.Client
}

// Driver is the login driver of every DingTalk group.
type Driver struct {
	lookup Lookup
	opt    Options
}

// New returns the driver.
func New(lookup Lookup, o Options) *Driver { return &Driver{lookup: lookup, opt: o} }

// Name is what the session is filed under.
func (*Driver) Name() string { return "dingtalk" }

// Match never matches: a group is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the webhook is the whole point.
func (*Driver) NeedsLogin() bool { return true }

func (d *Driver) group(base *url.URL) (config.DingTalkGroup, error) {
	if base == nil || base.Scheme != Scheme {
		return config.DingTalkGroup{}, fmt.Errorf("%w: not a dingtalk key", site.ErrLoginRejected)
	}
	g, ok := d.lookup(base.Host)
	if !ok {
		return config.DingTalkGroup{}, fmt.Errorf("%w: no DingTalk group %q is configured", site.ErrLoginRejected, base.Host)
	}
	return g, nil
}

// Detail is what the message to the person says, in securl's own words and not the agent's: what the address will let an agent do.
func (d *Driver) Detail(base *url.URL) string {
	g, err := d.group(base)
	if err != nil {
		return ""
	}
	text := "the robot webhook for the DingTalk group " + g.Name + " is kept in the vault, and an AI agent can then send messages to that group through securl (it never sees the address)"
	if g.Sign {
		text += "; the robot's signing secret is asked for too and kept the same way"
	}
	return text + ". Everyone in the group can read what it sends. Nothing is sent now: the address is only kept."
}

// Client makes a client from a session. The endpoint is the driver's, so a tool does not choose it.
func (d *Driver) Client(s *site.Session) (*dingtalk.Client, error) {
	if s == nil || s.Tokens[TokenWebhook] == "" {
		return nil, fmt.Errorf("%w: the session holds no webhook", site.ErrBadCredentials)
	}
	return dingtalk.New(s.Tokens[TokenWebhook], s.Tokens[TokenSecret], dingtalk.Options{BaseURL: d.opt.BaseURL, HTTP: d.opt.HTTP}), nil
}

// label is a field's label with the group's name in it. The page cuts a label at 60 characters, so the name is cut and what is asked
// for always fits.
func label(what, name string) string {
	room := 60 - len([]rune(what)) - len(" for ")
	n := []rune(name)
	if len(n) > room {
		n = append(n[:room-3], '.', '.', '.')
	}
	return what + " for " + string(n)
}

// Login asks for the webhook, and for the signing secret when the group has one, and keeps the access_token (and the secret).
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	g, err := d.group(base)
	if err != nil {
		return nil, err
	}
	fields := []site.Field{{Name: "webhook", Label: label("Robot webhook", g.Name), Secret: true}}
	if g.Sign {
		fields = append(fields, site.Field{Name: "secret", Label: label("Signing secret", g.Name), Secret: true})
	}
	creds, err := ask.Ask(ctx, "custom", fields)
	if err != nil {
		return nil, err
	}
	hook, sec := creds["webhook"], creds["secret"]
	creds["webhook"], creds["secret"] = "", ""
	token, err := dingtalk.ParseWebhook(hook)
	if err != nil {
		return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, firstSentence(err))
	}
	tokens := map[string]string{TokenWebhook: token}
	if g.Sign {
		if sec, err = dingtalk.ParseSecret(sec); err != nil {
			return nil, fmt.Errorf("%w: %s", site.ErrBadCredentials, firstSentence(err))
		}
		tokens[TokenSecret] = sec
	}
	return &site.Session{Tokens: tokens}, nil
}

// firstSentence is an error that this package wrote, whole: they never repeat what was typed.
func firstSentence(err error) string { return strings.TrimSpace(err.Error()) }

// Probe checks only what can be checked without posting: that the session belongs to a configured group and holds what it needs. A
// robot that DingTalk no longer knows is found by the next send, which ends the session.
func (d *Driver) Probe(_ context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	g, err := d.group(base)
	if err != nil {
		return err
	}
	if s == nil || s.Tokens[TokenWebhook] == "" {
		return fmt.Errorf("%w: the session holds no webhook", site.ErrBadCredentials)
	}
	if g.Sign && s.Tokens[TokenSecret] == "" {
		return fmt.Errorf("%w: the group's robot signs its messages and the session holds no signing secret", site.ErrBadCredentials)
	}
	return nil
}
