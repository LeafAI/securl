// Package dingtalk is the part of the DingTalk custom-robot API an agent may use: saying something in the one group a robot is in.
//
// A custom robot is one webhook, https://oapi.dingtalk.com/robot/send?access_token=..., and the access_token in it is the robot's
// whole credential: whoever holds it can speak in the group. It is in the query of every request, so it is also in every *url.Error
// that net/http builds and in whatever a proxy or a server says back. None of that may reach an error this package returns. Every
// error here is made from what this package knows, never from what a library or a server said.
package dingtalk

import (
	"bytes"
	"context"
	"crypto/rand"
	"encoding/hex"
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

	"github.com/LeafAI/securl/internal/notify"
)

// The one host, scheme and path a webhook may have. The address is given by a person and the host is the part that would turn a
// typo, or a trick, into a request to somewhere else carrying the token: it is checked, not trusted.
const (
	Host     = "oapi.dingtalk.com"
	sendPath = "/robot/send"
)

// Errors the callers act on.
var (
	ErrBadToken    = errors.New("dingtalk does not know this robot (the token is wrong, or the robot was removed or switched off)")
	ErrGroupGone   = errors.New("the group of this robot no longer exists")
	ErrRefused     = errors.New("the robot's security settings refused the message (keyword, signature or address list)")
	ErrContent     = errors.New("dingtalk refused the content of the message")
	ErrUnreachable = errors.New("dingtalk could not be reached")
	// ErrRequest is DingTalk answering, in its own format, that it will not do what was asked and not saying why in a way this package
	// maps: the endpoint is there and speaks the robot API, and the request is what it refused.
	ErrRequest = errors.New("dingtalk refused the request")
)

// ThrottledError is DingTalk throttling the robot. The documentation says a robot that sends more than 20 messages in a minute is
// throttled for ten minutes, so that is how long nobody asks again.
type ThrottledError struct{ RetryAfter time.Duration }

func (e *ThrottledError) Error() string {
	return fmt.Sprintf("dingtalk throttled the robot; retry in %s", e.RetryAfter.Round(time.Second))
}

// throttle is how long DingTalk says a throttled robot is left alone.
const throttle = 10 * time.Minute

// Options tunes a Client. The zero value talks to oapi.dingtalk.com directly.
type Options struct {
	// BaseURL is the API's address; a test points it at a fake. Default https://oapi.dingtalk.com.
	BaseURL string
	// HTTP is the client to use (a test hands in the fake server's own); when nil one is made.
	HTTP *http.Client
	// Timeout bounds one request; default 15 seconds.
	Timeout time.Duration
	// Now is the clock the signature's timestamp is taken from.
	Now func() time.Time
}

// Client speaks as one robot.
type Client struct {
	token  string
	secret string
	base   string
	hc     *http.Client
	now    func() time.Time
}

// New makes a client for the robot with this access_token and, when its security setting is "sign", this secret.
func New(token, secret string, o Options) *Client {
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		base = "https://" + Host
	}
	hc := o.HTTP
	timeout := o.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}
	if hc == nil {
		hc = &http.Client{Timeout: timeout, Transport: &http.Transport{
			Proxy:               http.ProxyFromEnvironment,
			DialContext:         (&net.Dialer{Timeout: 10 * time.Second}).DialContext,
			TLSHandshakeTimeout: 10 * time.Second,
		}}
	}
	// A redirect is never followed: the token is in the query, and a redirect would send it to wherever it points.
	cp := *hc
	cp.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	now := o.Now
	if now == nil {
		now = time.Now
	}
	return &Client{token: token, secret: secret, base: base, hc: &cp, now: now}
}

type reply struct {
	Code int    `json:"errcode"`
	Msg  string `json:"errmsg"`
}

// Send says text in the group, as plain text and mentioning nobody. A timeout leaves it unknown whether the message was posted, so it
// is retried once with the same msgUuid, which DingTalk documents for exactly that: the group sees the message once either way.
func (c *Client) Send(ctx context.Context, text string) error {
	if strings.TrimSpace(text) == "" {
		return errors.New("dingtalk: the message is empty")
	}
	id, err := newUUID()
	if err != nil {
		return errors.New("dingtalk: could not make a message key")
	}
	body, err := json.Marshal(map[string]any{
		"msgtype": "text",
		"text":    map[string]string{"content": text},
		// Nobody is mentioned and not everybody either: an agent must not be able to call people or the whole group.
		"at":      map[string]any{"atMobiles": []string{}, "atUserIds": []string{}, "isAtAll": false},
		"msgUuid": id,
	})
	if err != nil {
		return errors.New("dingtalk: the message could not be encoded")
	}
	err = c.post(ctx, body)
	if errors.Is(err, errTimeout) {
		err = c.post(ctx, body)
	}
	if errors.Is(err, errTimeout) {
		return fmt.Errorf("%w: the robot did not answer in time", ErrUnreachable)
	}
	return err
}

// Ping asks whether the endpoint can be reached and speaks the robot API, with no token and nothing to post, so it cannot send
// anything: DingTalk answers a request that names no robot with an error of its own, and any such answer (a refusal, a throttle) is the
// proof. Only a failure to get an answer, or an answer that is not DingTalk's, is an error.
func (c *Client) Ping(ctx context.Context) error {
	err := c.post(ctx, []byte(`{}`))
	switch {
	case err == nil, errors.Is(err, ErrBadToken), errors.Is(err, ErrRefused), errors.Is(err, ErrGroupGone), errors.Is(err, ErrContent), errors.Is(err, ErrRequest):
		return nil
	}
	var th *ThrottledError
	if errors.As(err, &th) {
		return nil
	}
	if errors.Is(err, errTimeout) {
		return fmt.Errorf("%w: no answer in time", ErrUnreachable)
	}
	return err
}

var errTimeout = errors.New("timeout")

func (c *Client) post(ctx context.Context, body []byte) error {
	u := c.base + sendPath + "?" + c.query()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, u, bytes.NewReader(body))
	if err != nil {
		return errors.New("dingtalk: the request could not be made")
	}
	req.Header.Set("Content-Type", "application/json;charset=utf-8")
	resp, err := c.hc.Do(req)
	if err != nil {
		return transportError(ctx, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	return answer(resp.StatusCode, raw)
}

func (c *Client) query() string {
	q := url.Values{}
	q.Set("access_token", c.token)
	if c.secret != "" {
		ts := c.now().UnixMilli()
		q.Set("timestamp", strconv.FormatInt(ts, 10))
		q.Set("sign", notify.Sign(c.secret, ts))
	}
	return q.Encode()
}

// transportError turns a failure to get an answer into an error with none of the request in it.
func transportError(ctx context.Context, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return errors.New("dingtalk: cancelled")
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: no answer in time", ErrUnreachable)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return errTimeout
	}
	return fmt.Errorf("%w", ErrUnreachable)
}

// answer maps what DingTalk said to the vocabulary of this package. The description is DingTalk's own words and is matched, never
// repeated: whatever answers can put anything in it, including the request it was sent.
func answer(status int, raw []byte) error {
	if status >= 300 && status < 400 {
		return fmt.Errorf("%w: the endpoint answered a redirect, which is not followed", ErrUnreachable)
	}
	var r reply
	if err := json.Unmarshal(raw, &r); err != nil {
		if status >= 500 || status == 429 {
			return fmt.Errorf("%w: the endpoint answered HTTP %d", ErrUnreachable, status)
		}
		return fmt.Errorf("dingtalk: HTTP %d with an answer that is not the robot API's", status)
	}
	if status >= 500 || status == 429 {
		return fmt.Errorf("%w: the endpoint answered HTTP %d", ErrUnreachable, status)
	}
	switch r.Code {
	case 0:
		return nil
	case 300005, 400101, 400102, 400106:
		return ErrBadToken
	case 400013:
		return ErrGroupGone
	case 310000:
		return ErrRefused
	case 410100:
		return &ThrottledError{RetryAfter: throttle}
	case 660026:
		// Measured, not documented: the endpoint answers this to a caller (an address, not a robot) that sends too many requests in a
		// minute, before it looks at the token. It is short; a minute is what its wording says.
		return &ThrottledError{RetryAfter: time.Minute}
	case 430101, 430102, 430103, 430104:
		return ErrContent
	case -1:
		return fmt.Errorf("%w: the endpoint was busy", ErrUnreachable)
	}
	return fmt.Errorf("%w (%d)", ErrRequest, r.Code)
}

func newUUID() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
