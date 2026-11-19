// Package zulip is the part of Zulip's REST API that securl needs: who a bot is, the newest messages of a channel, and a message sent
// to a channel. The server is fixed by the owner and every request goes to it and nowhere else: the bot's key is sent in the
// Authorization header, so a redirect is never followed and no error is made from what a server or a transport said.
package zulip

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

// Errors the callers act on.
var (
	ErrBadKey      = errors.New("zulip refused the bot's key")
	ErrUnreachable = errors.New("zulip could not be reached")
	ErrChannel     = errors.New("the bot cannot use that channel (it does not exist, or the bot is not subscribed to it)")
	ErrTooLong     = errors.New("the message is too long for this Zulip")
	ErrRefused     = errors.New("zulip refused the request")
)

// RateLimitedError is Zulip asking the client to slow down.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("zulip asked the bot to slow down; retry in %s", e.RetryAfter.Round(time.Second))
}

// maxBody bounds what is read of any answer: a server that sends more is not believed.
const maxBody = 16 << 20

// Options tunes a Client.
type Options struct {
	// HTTP is the client to use (a test hands in the fake server's own); when nil one is made.
	HTTP *http.Client
	// Timeout bounds one request (default 30 seconds).
	Timeout time.Duration
	// Proxy, when set, is used for every request, and the environment's proxy settings are not.
	Proxy *url.URL
	// AllowInsecure accepts an http:// site and a site on this machine. Only a test sets it: the key is sent in a header, and over
	// http it would cross the network in the clear.
	AllowInsecure bool
}

// Client talks to one Zulip server as one bot.
type Client struct {
	base  string
	email string
	key   string
	hc    *http.Client
}

// ParseSite takes the address of a Zulip server and returns it as scheme://host[:port], or an error that says what is wrong. Only an
// https address with a host and nothing else in it is accepted: the key goes to this address in a header, so it must be the server and
// not a path, a user name or a query that leads somewhere else.
func ParseSite(raw string, allowInsecure bool) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return "", errors.New("site: give the address of the Zulip server, like https://yourorg.zulipchat.com")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil || u.Host == "":
		return "", errors.New("site: that is not an address (use https://yourorg.zulipchat.com)")
	case u.Scheme != "https" && !(allowInsecure && u.Scheme == "http"):
		return "", errors.New("site: it must start with https://")
	case u.User != nil:
		return "", errors.New("site: it must not have a user name in it")
	case (u.Path != "" && u.Path != "/") || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "":
		return "", errors.New("site: give the server only, with no path, query or fragment")
	}
	if p := u.Port(); p != "" {
		if n, err := strconv.Atoi(p); err != nil || n < 1 || n > 65535 {
			return "", errors.New("site: the port is 1-65535")
		}
	}
	host := u.Hostname()
	if !allowInsecure && (host == "localhost" || net.ParseIP(host) != nil && (net.ParseIP(host).IsLoopback() || net.ParseIP(host).IsPrivate() || net.ParseIP(host).IsLinkLocalUnicast() || net.ParseIP(host).IsUnspecified())) {
		return "", errors.New("site: that is an address on this machine or its network, which is not a Zulip server to send a key to")
	}
	return u.Scheme + "://" + u.Host, nil
}

// New makes a client for a server, as the bot with this email and key.
func New(site, email, key string, o Options) (*Client, error) {
	base, err := ParseSite(site, o.AllowInsecure)
	if err != nil {
		return nil, err
	}
	hc := o.HTTP
	if hc == nil {
		timeout := o.Timeout
		if timeout <= 0 {
			timeout = 30 * time.Second
		}
		tr := &http.Transport{
			Proxy:                 func(*http.Request) (*url.URL, error) { return o.Proxy, nil },
			DialContext:           (&net.Dialer{Timeout: 15 * time.Second}).DialContext,
			TLSHandshakeTimeout:   15 * time.Second,
			ResponseHeaderTimeout: timeout,
		}
		hc = &http.Client{Transport: tr, Timeout: timeout}
	} else if o.Timeout > 0 {
		cp := *hc
		cp.Timeout = o.Timeout
		hc = &cp
	}
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{base: base, email: email, key: key, hc: &cp}, nil
}

// Me is the bot, as the server describes it.
type Me struct {
	ID    int64
	Email string
	Name  string
}

type reply struct {
	Result     string          `json:"result"`
	Msg        string          `json:"msg"`
	Code       string          `json:"code"`
	RetryAfter float64         `json:"retry-after"`
	Raw        json.RawMessage `json:"-"`
}

// do makes one request and returns the body of an answer that says success. It never returns an error made from the request's URL, the
// transport's error text or the server's own words: those can hold the key.
func (c *Client) do(ctx context.Context, method, path string, query url.Values, form url.Values) ([]byte, error) {
	u := c.base + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	var body io.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	req, err := http.NewRequestWithContext(ctx, method, u, body)
	if err != nil {
		return nil, errors.New("zulip: the request could not be made")
	}
	req.Header.Set("Authorization", "Basic "+base64.StdEncoding.EncodeToString([]byte(c.email+":"+c.key)))
	req.Header.Set("Accept", "application/json")
	if form != nil {
		req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	}
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, ErrUnreachable
	}
	defer resp.Body.Close()
	b, err := io.ReadAll(io.LimitReader(resp.Body, maxBody+1))
	if err != nil || len(b) > maxBody {
		return nil, ErrUnreachable
	}
	var r reply
	if json.Unmarshal(b, &r) != nil || (r.Result != "success" && r.Result != "error") {
		if resp.StatusCode == http.StatusUnauthorized {
			return nil, ErrBadKey
		}
		return nil, fmt.Errorf("%w (status %d)", ErrRefused, resp.StatusCode)
	}
	if r.Result == "success" && resp.StatusCode < 300 {
		return b, nil
	}
	return nil, classify(resp.StatusCode, r)
}

// classify turns an error answer into one of this package's errors. The server's own text is matched, never repeated.
func classify(status int, r reply) error {
	msg := strings.ToLower(r.Msg)
	switch {
	case status == http.StatusTooManyRequests || r.Code == "RATE_LIMIT_HIT":
		wait := time.Duration(r.RetryAfter * float64(time.Second))
		if wait <= 0 {
			wait = time.Minute
		}
		return &RateLimitedError{RetryAfter: wait}
	case status == http.StatusUnauthorized || r.Code == "UNAUTHORIZED" || strings.Contains(msg, "invalid api key"):
		return ErrBadKey
	case strings.Contains(msg, "message length") || strings.Contains(msg, "too long") || strings.Contains(msg, "exceed"):
		return ErrTooLong
	case strings.Contains(msg, "channel") || strings.Contains(msg, "stream"):
		return ErrChannel
	}
	return fmt.Errorf("%w (status %d)", ErrRefused, status)
}

// Me asks the server who the bot is. It is what a login checks the key with.
func (c *Client) Me(ctx context.Context) (Me, error) {
	b, err := c.do(ctx, http.MethodGet, "/api/v1/users/me", nil, nil)
	if err != nil {
		return Me{}, err
	}
	var v struct {
		ID    int64  `json:"user_id"`
		Email string `json:"email"`
		Name  string `json:"full_name"`
	}
	if json.Unmarshal(b, &v) != nil || v.ID == 0 {
		return Me{}, fmt.Errorf("%w: it did not say who the bot is", ErrRefused)
	}
	return Me{ID: v.ID, Email: v.Email, Name: v.Name}, nil
}

// Message is one thing somebody said in a channel.
type Message struct {
	ID         int64
	Channel    string
	Topic      string
	SenderName string // what the sender calls themselves: it can be anything, so it proves nothing
	SenderID   int64
	Content    string // the text as the sender wrote it, not rendered
	At         time.Time
}

// ReadQuery says which messages to read.
type ReadQuery struct {
	Channel string
	Topic   string // empty: every topic of the channel
	Limit   int    // the newest this many
	AfterID int64  // when set, only messages newer than this one
}

// ReadResult is what a read found, oldest first.
type ReadResult struct {
	Messages []Message
	// More is true when there are messages older than the ones returned (or, with AfterID, newer ones that did not fit).
	More bool
}

// Read returns the newest messages of a channel (or of one topic of it), oldest first. It reads and changes nothing: no message is
// marked read and none is consumed, so the same call made again returns the same messages and any new ones.
func (c *Client) Read(ctx context.Context, q ReadQuery) (ReadResult, error) {
	if q.Limit < 1 {
		q.Limit = 1
	}
	narrow := []map[string]string{{"operator": "channel", "operand": q.Channel}}
	if q.Topic != "" {
		narrow = append(narrow, map[string]string{"operator": "topic", "operand": q.Topic})
	}
	nb, err := json.Marshal(narrow)
	if err != nil {
		return ReadResult{}, errors.New("zulip: the narrow could not be encoded")
	}
	v := url.Values{"apply_markdown": {"false"}, "narrow": {string(nb)}}
	// One more than asked for is taken, to know whether there is more.
	if q.AfterID > 0 {
		v.Set("anchor", strconv.FormatInt(q.AfterID, 10))
		v.Set("include_anchor", "false")
		v.Set("num_before", "0")
		v.Set("num_after", strconv.Itoa(q.Limit+1))
	} else {
		v.Set("anchor", "newest")
		v.Set("num_before", strconv.Itoa(q.Limit+1))
		v.Set("num_after", "0")
	}
	b, err := c.do(ctx, http.MethodGet, "/api/v1/messages", v, nil)
	if err != nil {
		return ReadResult{}, err
	}
	var out struct {
		Messages []struct {
			ID      int64           `json:"id"`
			Name    string          `json:"sender_full_name"`
			Sender  int64           `json:"sender_id"`
			Content string          `json:"content"`
			Time    int64           `json:"timestamp"`
			Channel json.RawMessage `json:"display_recipient"`
			Subject string          `json:"subject"`
		} `json:"messages"`
	}
	if json.Unmarshal(b, &out) != nil {
		return ReadResult{}, fmt.Errorf("%w: the answer is not a list of messages", ErrRefused)
	}
	res := ReadResult{Messages: make([]Message, 0, len(out.Messages))}
	for _, m := range out.Messages {
		ch := q.Channel
		var s string
		if json.Unmarshal(m.Channel, &s) == nil && s != "" {
			ch = s
		}
		res.Messages = append(res.Messages, Message{ID: m.ID, Channel: ch, Topic: m.Subject, SenderName: m.Name, SenderID: m.Sender, Content: m.Content, At: time.Unix(m.Time, 0).UTC()})
	}
	if len(res.Messages) > q.Limit {
		res.More = true
		if q.AfterID > 0 {
			res.Messages = res.Messages[:q.Limit] // the oldest of what is newer: the caller reads on from the last one
		} else {
			res.Messages = res.Messages[len(res.Messages)-q.Limit:] // the newest
		}
	}
	return res, nil
}

// Send posts a message to a channel, under a topic, and returns its id.
func (c *Client) Send(ctx context.Context, channel, topic, content string) (int64, error) {
	b, err := c.do(ctx, http.MethodPost, "/api/v1/messages", nil, url.Values{"type": {"channel"}, "to": {channel}, "topic": {topic}, "content": {content}})
	if err != nil {
		return 0, err
	}
	var v struct {
		ID int64 `json:"id"`
	}
	if json.Unmarshal(b, &v) != nil {
		return 0, fmt.Errorf("%w: it did not say the message's id", ErrRefused)
	}
	return v.ID, nil
}

// String is for logs: a client never prints its key.
func (c *Client) String() string { return "zulip.Client{key: <redacted>}" }

// GoString is the same for %#v.
func (c *Client) GoString() string { return c.String() }
