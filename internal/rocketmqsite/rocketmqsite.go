// Package rocketmqsite makes a configured RocketMQ cluster look like a site to the login machinery: a person types the AccessKey and
// the SecretKey on the usual page, they are checked against the cluster, and they are kept in the vault like any other session.
//
// A cluster is never a web site. Its key is rocketmq://<name>, a scheme the HTTP tools refuse, and its driver is never matched from a
// URL, so request and session_open cannot reach one by accident; only the RocketMQ tools, which take a configured name, can. The agent
// never holds the keys: it names a target and a topic, and securl does the rest.
package rocketmqsite

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
	"github.com/LeafAI/securl/internal/rmq"
	"github.com/LeafAI/securl/internal/site"
)

// Scheme is the URL scheme of a target's session key.
const Scheme = "rocketmq"

// The names under which a session keeps what it holds.
const (
	TokenAccessKey = "rocketmq_access_key"
	TokenSecretKey = "rocketmq_secret_key"
)

// maxKeyBytes bounds what a person can paste: a real AccessKey or SecretKey is a few dozen characters.
const maxKeyBytes = 256

// BaseURL is the URL a target is known by inside securl.
func BaseURL(name string) *url.URL { return &url.URL{Scheme: Scheme, Host: name} }

// Key is the session key of a target.
func Key(name string) string { return site.Key(BaseURL(name)) }

// Lookup finds a configured target by name.
type Lookup func(name string) (config.RocketMQ, bool)

// Options tune the driver; a test points it at a fake broker on this machine.
type Options struct {
	AllowLocal bool
	Timeout    time.Duration
}

// Driver is the login driver of every RocketMQ target.
type Driver struct {
	lookup Lookup
	opt    Options
}

// New returns the driver.
func New(lookup Lookup, o Options) *Driver { return &Driver{lookup: lookup, opt: o} }

// Name is what the session is filed under.
func (*Driver) Name() string { return "rocketmq" }

// Match never matches: a cluster is chosen by name, never recognised from a URL.
func (*Driver) Match(*url.URL) bool { return false }

// NeedsLogin is true: the keys are the whole point.
func (*Driver) NeedsLogin() bool { return true }

func (d *Driver) target(base *url.URL) (config.RocketMQ, error) {
	if base == nil || base.Scheme != Scheme {
		return config.RocketMQ{}, fmt.Errorf("%w: not a rocketmq key", site.ErrLoginRejected)
	}
	r, ok := d.lookup(base.Host)
	if !ok {
		return config.RocketMQ{}, fmt.Errorf("%w: no RocketMQ target %q is configured", site.ErrLoginRejected, base.Host)
	}
	return r, nil
}

// Detail is what the message to the person says, in securl's own words and not the agent's: what the keys will let an agent do.
func (d *Driver) Detail(base *url.URL) string {
	r, err := d.target(base)
	if err != nil {
		return ""
	}
	return "the RocketMQ AccessKey and SecretKey for " + r.Name + " are kept in the vault, and an AI agent can then use them through securl (it never sees them) to READ messages from " +
		strings.Join(r.Topics, ", ") + " and nothing else: it cannot send a message or change anything. A message can hold business data. Give the key only a subscribe permission on those topics."
}

func (d *Driver) options(r config.RocketMQ) rmq.Options {
	o := rmq.Options{AllowLocal: d.opt.AllowLocal, Timeout: d.opt.Timeout, Group: r.Group()}
	if o.Timeout <= 0 {
		o.Timeout = r.TimeoutOrDefault()
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

// Client is a client for the cluster a key names, with the keys the session holds.
func (d *Driver) Client(base *url.URL, s *site.Session) (*rmq.Client, config.RocketMQ, error) {
	r, err := d.target(base)
	if err != nil {
		return nil, r, err
	}
	if s == nil || s.Tokens == nil || s.Tokens[TokenAccessKey] == "" || s.Tokens[TokenSecretKey] == "" {
		return nil, r, fmt.Errorf("%w: the session holds no credentials", site.ErrBadCredentials)
	}
	o := d.options(r)
	o.MaxBody = bodyCeiling(r)
	return rmq.New(r.NameServerAddrs(), rmq.Credentials{AccessKey: s.Tokens[TokenAccessKey], SecretKey: s.Tokens[TokenSecretKey]}, o), r, nil
}

// bodyCeiling is how large a body the client will hold in memory for one message: what the owner allows to be returned, and no
// less than a small amount so that a body of a few bytes is still read whole before it is cut.
func bodyCeiling(r config.RocketMQ) int {
	n := r.BodyLimit()
	if n < 1024 {
		n = 1024
	}
	return n
}

// Login asks for the keys and checks them against the cluster: the first listed topic's route, a queue's length and one pull at its
// end, which is what a read does, so a key that cannot read says so now and not when an agent first tries.
func (d *Driver) Login(ctx context.Context, base *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	r, err := d.target(base)
	if err != nil {
		return nil, err
	}
	creds, err := ask.Ask(ctx, "custom", []site.Field{
		{Name: "access_key", Label: label("AccessKey", r.Name)},
		{Name: "secret_key", Label: label("SecretKey", r.Name), Secret: true},
	})
	if err != nil {
		return nil, err
	}
	ak, sk := strings.TrimSpace(creds["access_key"]), creds["secret_key"]
	creds["access_key"], creds["secret_key"] = "", ""
	if !validKey(ak) || !validKey(sk) {
		return nil, fmt.Errorf("%w: those cannot be a RocketMQ AccessKey and SecretKey (one line, no control characters, at most %d bytes)", site.ErrBadCredentials, maxKeyBytes)
	}
	sess := &site.Session{Tokens: map[string]string{TokenAccessKey: ak, TokenSecretKey: sk}}
	if err := d.check(ctx, base, sess); err != nil {
		return nil, err
	}
	return sess, nil
}

func label(what, name string) string {
	room := 60 - len([]rune("RocketMQ  for ")) - len([]rune(what))
	r := []rune(name)
	if len(r) > room {
		r = append(r[:room-3], '.', '.', '.')
	}
	return "RocketMQ " + what + " for " + string(r)
}

func validKey(k string) bool {
	if k == "" || len(k) > maxKeyBytes {
		return false
	}
	for _, c := range k {
		if c < 0x20 || c == 0x7f {
			return false
		}
	}
	return true
}

// check asks the cluster something only a key that may read can have answered.
func (d *Driver) check(ctx context.Context, base *url.URL, s *site.Session) error {
	c, r, err := d.Client(base, s)
	if err != nil {
		return err
	}
	route, err := c.Route(ctx, r.Topics[0])
	if err != nil {
		return d.classify(err, r)
	}
	if len(route.Queues) == 0 {
		return fmt.Errorf("%w: %s has no queue for the topic %s", site.ErrLoginRejected, r.Name, r.Topics[0])
	}
	q := route.Queues[0]
	max, err := c.MaxOffset(ctx, q)
	if err != nil {
		return d.classify(err, r)
	}
	if _, err := c.Pull(ctx, q, max, 1); err != nil && !errors.Is(err, rmq.ErrOffsetOutOfRange) {
		return d.classify(err, r)
	}
	return nil
}

// classify says what went wrong in the vocabulary of the login flow, in this package's own words: what the broker said is left out.
func (d *Driver) classify(err error, r config.RocketMQ) error {
	switch {
	case errors.Is(err, rmq.ErrBadCredentials):
		return fmt.Errorf("%w: the cluster refused that AccessKey and SecretKey", site.ErrBadCredentials)
	case errors.Is(err, rmq.ErrNoPermission):
		return fmt.Errorf("%w: those keys are valid but are not allowed to read the topic %s or to use the consumer group %s: ask for a subscribe permission on both", site.ErrLoginRejected, r.Topics[0], r.Group())
	case errors.Is(err, rmq.ErrGroupNotFound):
		return fmt.Errorf("%w: the consumer group %s does not exist on the cluster: create it there, or set consumer_group to one that does", site.ErrLoginRejected, r.Group())
	case errors.Is(err, rmq.ErrTopicNotFound):
		return fmt.Errorf("%w: the topic %s does not exist on the cluster", site.ErrLoginRejected, r.Topics[0])
	case errors.Is(err, rmq.ErrUnreachable):
		return fmt.Errorf("%w: %s could not be reached (the NameServer, the broker address it gives out, the network or TLS: check them)", site.ErrUnreachable, r.Name)
	case errors.Is(err, rmq.ErrTimeout):
		return fmt.Errorf("%w: %s did not answer in time", site.ErrUnreachable, r.Name)
	case errors.Is(err, rmq.ErrLocalAddress):
		return fmt.Errorf("%w: %v", site.ErrLoginRejected, rmq.ErrLocalAddress)
	}
	return fmt.Errorf("%w: the cluster did not answer as RocketMQ does", site.ErrLoginRejected)
}

// Probe checks that the kept keys are still accepted. Keys that were changed end the session, as a cookie the site no longer knows
// would; a network that is down says nothing about them, and the session is kept.
func (d *Driver) Probe(ctx context.Context, base *url.URL, s *site.Session, _ *http.Client) error {
	return d.check(ctx, base, s)
}
