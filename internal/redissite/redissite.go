// Package redissite makes a configured Redis server look like a site to the login machinery: a person types the password on the usual
// page, it is checked by authenticating once, and it is kept in the vault like any other session.
//
// A Redis server is never a web site. Its key is redis://<name>, a scheme that the HTTP tools refuse, and its driver is never matched
// from a URL, so request and session_open cannot reach one by accident or by an agent's choice; only the Redis tools, which take a
// configured name, can. The agent never holds the password: it names a target and a command, and securl does the rest.
package redissite

import (
	"context"
	"crypto/tls"
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/redisx"
	"github.com/LeafAI/securl/internal/site"
)

// Scheme is the URL scheme of a target's session key.
const Scheme = "redis"

// The names under which a session keeps what it holds. The user name is not a secret; it is kept so that the session says who it is.
const (
	TokenPassword = "redis_password"
	TokenUsername = "redis_username"
)

// maxPasswordBytes bounds what a person can paste: Redis's own limit on a password is far above any real one.
const maxPasswordBytes = 512

// BaseURL is the URL a target is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a target.
func Key(name string) string { return site.Key(BaseURL(name)) }

// Lookup finds a configured target by name.
type Lookup func(name string) (config.Redis, bool)

// Options tune the driver; a test points it at a fake server on this machine.
type Options struct {
	AllowLocal bool
	Timeout    time.Duration
}

// Driver is the login driver of every Redis target.
type Driver struct {
	lookup Lookup
	opt    Options
}

// New returns the driver.
func New(lookup Lookup, o Options) *Driver { return &Driver{lookup: lookup, opt: o} }

// Name is what the session is filed under.
func (*Driver) Name() string { return "redis" }

// Match never matches: a server is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the password is the whole point.
func (*Driver) NeedsLogin() bool { return true }

func (d *Driver) target(base *url.URL) (config.Redis, error) {
	if base == nil || base.Scheme != Scheme {
		return config.Redis{}, fmt.Errorf("%w: not a redis key", site.ErrLoginRejected)
	}
	r, ok := d.lookup(base.Host)
	if !ok {
		return config.Redis{}, fmt.Errorf("%w: no Redis target %q is configured", site.ErrLoginRejected, base.Host)
	}
	return r, nil
}

// Detail is what the message to the person says, in securl's own words and not the agent's: what the password will let an agent do.
func (d *Driver) Detail(base *url.URL) string {
	r, err := d.target(base)
	if err != nil {
		return ""
	}
	text := "the Redis password for " + r.Name + " is kept in the vault, and an AI agent can then use it through securl (it never sees the password): it can read"
	if r.Writable() {
		text += " and change data with a short list of ordinary commands (never FLUSHALL, CONFIG, EVAL or KEYS)"
	}
	text += " on that server"
	if r.Username != "" {
		text += ", as the user " + r.Username
	}
	return text + ". Give the password only the rights an agent should have there."
}

// label is the field's label with the target's name (and the user, if any) in it. The page cuts a label at 60 characters, so the name
// is cut and what is asked for always fits.
func label(name, user string) string {
	what := "Redis password for "
	room := 60 - len([]rune(what))
	who := name
	if user != "" {
		who += " as " + user
	}
	r := []rune(who)
	if len(r) > room {
		r = append(r[:room-3], '.', '.', '.')
	}
	return what + string(r)
}

func (d *Driver) options(r config.Redis) redisx.Options {
	o := redisx.Options{AllowLocal: d.opt.AllowLocal, Timeout: d.opt.Timeout, MaxReply: r.ReplyLimit()}
	if o.Timeout <= 0 {
		o.Timeout = r.CommandTimeoutOrDefault()
	}
	switch r.TLSMode() {
	case config.TLSVerify:
		o.TLS = func(c net.Conn, host string) (net.Conn, error) {
			return tlsClient(c, &tls.Config{ServerName: host, MinVersion: tls.VersionTLS12})
		}
	case config.TLSSkipVerify:
		o.TLS = func(c net.Conn, host string) (net.Conn, error) {
			return tlsClient(c, &tls.Config{InsecureSkipVerify: true, MinVersion: tls.VersionTLS12}) // #nosec G402 -- the owner chose tls: skip-verify
		}
	}
	return o
}

func tlsClient(c net.Conn, cfg *tls.Config) (net.Conn, error) {
	tc := tls.Client(c, cfg)
	if err := tc.Handshake(); err != nil {
		return nil, err
	}
	return tc, nil
}

// Open connects to the target the key names and authenticates with what the session holds.
func (d *Driver) Open(ctx context.Context, base *url.URL, s *site.Session) (*redisx.Conn, error) {
	r, err := d.target(base)
	if err != nil {
		return nil, err
	}
	if s == nil || s.Tokens == nil {
		return nil, fmt.Errorf("%w: the session holds no credentials", site.ErrBadCredentials)
	}
	return redisx.Open(ctx, r.Addr(), redisx.Credentials{Username: s.Tokens[TokenUsername], Password: s.Tokens[TokenPassword]}, d.options(r))
}

// Login asks for the password and checks it by authenticating. A server that has no password is logged in to with the empty one: the
// page does not take an empty field, so the person types a single space, which is read as none.
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	r, err := d.target(base)
	if err != nil {
		return nil, err
	}
	creds, err := ask.Ask(ctx, "custom", []site.Field{{Name: "password", Label: label(r.Name, r.Username), Secret: true}})
	if err != nil {
		return nil, err
	}
	pw := creds["password"]
	creds["password"] = ""
	if pw = normalizePassword(pw); !validPassword(pw) {
		return nil, fmt.Errorf("%w: that cannot be a Redis password (one line, no control characters, at most %d bytes)", site.ErrBadCredentials, maxPasswordBytes)
	}
	tokens := map[string]string{TokenPassword: pw}
	if r.Username != "" {
		tokens[TokenUsername] = r.Username
	}
	sess := &site.Session{Tokens: tokens}
	conn, err := d.Open(ctx, base, sess)
	if err != nil {
		return nil, d.classify(err, r)
	}
	conn.Close()
	return sess, nil
}

// normalizePassword turns the single space a person types for "no password" into none, and otherwise leaves what was typed alone.
func normalizePassword(pw string) string {
	if strings.TrimSpace(pw) == "" {
		return ""
	}
	return pw
}

func validPassword(pw string) bool {
	if len(pw) > maxPasswordBytes {
		return false
	}
	for _, c := range pw {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// classify says what went wrong in the vocabulary of the login flow, in this package's own words: what the library said is left out.
func (d *Driver) classify(err error, r config.Redis) error {
	switch {
	case errors.Is(err, redisx.ErrBadCredentials):
		return fmt.Errorf("%w: the server refused that password", site.ErrBadCredentials)
	case errors.Is(err, redisx.ErrUnreachable):
		return fmt.Errorf("%w: %s could not be reached (the host, the port, the network or TLS: check them)", site.ErrUnreachable, r.Name)
	case errors.Is(err, redisx.ErrTimeout):
		return fmt.Errorf("%w: %s did not answer in time", site.ErrUnreachable, r.Name)
	case errors.Is(err, redisx.ErrLocalAddress):
		return fmt.Errorf("%w: %v", site.ErrLoginRejected, redisx.ErrLocalAddress)
	}
	return fmt.Errorf("%w: the server did not answer as Redis does", site.ErrLoginRejected)
}

// Probe checks that the kept password is still accepted. A password that was changed ends the session, as a cookie the site no longer
// knows would; a network that is down says nothing about it, and the session is kept.
func (d *Driver) Probe(ctx context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	r, err := d.target(base)
	if err != nil {
		return err
	}
	if s == nil || s.Tokens == nil {
		return fmt.Errorf("%w: the session holds no credentials", site.ErrBadCredentials)
	}
	if _, ok := s.Tokens[TokenPassword]; !ok {
		return fmt.Errorf("%w: the session holds no credentials", site.ErrBadCredentials)
	}
	conn, err := d.Open(ctx, base, s)
	if err != nil {
		return d.classify(err, r)
	}
	conn.Close()
	return nil
}
