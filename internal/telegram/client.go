// Package telegram is the part of the Telegram Bot API securl uses: who the bot is (getMe), saying something in a chat
// (sendMessage), and reading what was said (getUpdates).
//
// The bot's token is in the path of every request (/bot<token>/method), which is where Telegram wants it, so it is also in every
// *url.Error that net/http builds and in whatever a proxy or a server says back. None of that may reach an error this package
// returns: a token that leaks is a bot that anybody can read the chats of and speak in. Every error here is made from what this
// package knows, never from what a library or a server said.
package telegram

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Errors the callers act on.
var (
	ErrBadToken    = errors.New("telegram refused the bot token")
	ErrUnreachable = errors.New("telegram could not be reached")
	ErrNotInChat   = errors.New("the bot cannot write in that chat (it is not a member, or it was removed)")
	ErrTooLong     = errors.New("the message is too long for Telegram")
	ErrWebhookSet  = errors.New("the bot has a webhook set, so its updates cannot be read with getUpdates")
	ErrConflict    = errors.New("another process is reading this bot's updates")
)

// RateLimitedError is Telegram asking the bot to slow down.
type RateLimitedError struct{ RetryAfter time.Duration }

func (e *RateLimitedError) Error() string {
	return fmt.Sprintf("telegram asked the bot to slow down; retry in %s", e.RetryAfter.Round(time.Second))
}

// Options tunes a Client. The zero value talks to api.telegram.org directly.
type Options struct {
	// BaseURL is the API's address; a test points it at a fake. Default https://api.telegram.org.
	BaseURL string
	// Proxy, when set, is used for every request, and the environment's proxy settings are not. A bot that is reached through
	// a proxy because the owner said so is not also reached through whatever HTTPS_PROXY happens to say.
	Proxy *url.URL
	// HTTP is the client to use (a test hands in the fake server's own); when nil one is made, with Proxy and Timeout.
	HTTP *http.Client
	// Timeout bounds one request; default 40 seconds (a long poll can take up to its own timeout).
	Timeout time.Duration
}

// Client talks to the Bot API as one bot.
type Client struct {
	token string
	base  string
	hc    *http.Client
}

// New makes a client for the bot with this token.
func New(token string, o Options) *Client {
	base := strings.TrimRight(o.BaseURL, "/")
	if base == "" {
		base = "https://api.telegram.org"
	}
	hc := o.HTTP
	if hc == nil {
		timeout := o.Timeout
		if timeout <= 0 {
			timeout = 40 * time.Second
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
	// A redirect is never followed: the token is in the path, and a redirect would send it to wherever it points.
	hcCopy := *hc
	hcCopy.CheckRedirect = func(*http.Request, []*http.Request) error { return http.ErrUseLastResponse }
	return &Client{token: token, base: base, hc: &hcCopy}
}

// Me is the bot, as getMe describes it.
type Me struct {
	ID       int64
	Username string
	// SeesAllGroupMessages is true when the bot's privacy mode is off: it then reads every message of a group it is in. With it
	// on, it sees only what mentions it, replies to it or is a command.
	SeesAllGroupMessages bool
}

type apiReply struct {
	OK          bool            `json:"ok"`
	Result      json.RawMessage `json:"result"`
	ErrorCode   int             `json:"error_code"`
	Description string          `json:"description"`
	Parameters  struct {
		RetryAfter int `json:"retry_after"`
	} `json:"parameters"`
}

// call makes one request and returns the result of a successful answer. It never returns an error made from the request's URL, the
// transport's error text or the server's body: those can hold the token.
func (c *Client) call(ctx context.Context, method string, args map[string]any) (json.RawMessage, error) {
	body, err := json.Marshal(args)
	if err != nil {
		return nil, fmt.Errorf("telegram %s: the arguments could not be encoded", method)
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.base+"/bot"+c.token+"/"+method, bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("telegram %s: the request could not be made", method)
	}
	req.Header.Set("Content-Type", "application/json")
	resp, err := c.hc.Do(req)
	if err != nil {
		return nil, transportError(ctx, method, err)
	}
	defer resp.Body.Close()
	raw, _ := io.ReadAll(io.LimitReader(resp.Body, 4<<20))
	if resp.StatusCode >= 300 && resp.StatusCode < 400 {
		return nil, fmt.Errorf("%w: %s answered a redirect, which is not followed", ErrUnreachable, method)
	}
	var r apiReply
	if err := json.Unmarshal(raw, &r); err != nil {
		if resp.StatusCode >= 500 || resp.StatusCode == 429 {
			return nil, fmt.Errorf("%w: %s answered HTTP %d", ErrUnreachable, method, resp.StatusCode)
		}
		return nil, fmt.Errorf("telegram %s: HTTP %d with an answer that is not the Bot API's", method, resp.StatusCode)
	}
	if r.OK {
		return r.Result, nil
	}
	return nil, apiError(method, resp.StatusCode, r)
}

// transportError turns a failure to get an answer into an error with none of the request in it.
func transportError(ctx context.Context, method string, err error) error {
	switch {
	case errors.Is(ctx.Err(), context.Canceled):
		return fmt.Errorf("telegram %s: cancelled", method)
	case errors.Is(ctx.Err(), context.DeadlineExceeded):
		return fmt.Errorf("%w: %s did not answer in time", ErrUnreachable, method)
	}
	var ne net.Error
	if errors.As(err, &ne) && ne.Timeout() {
		return fmt.Errorf("%w: %s did not answer in time", ErrUnreachable, method)
	}
	return fmt.Errorf("%w: %s", ErrUnreachable, method)
}

// apiError maps what the Bot API says to the vocabulary of this package. The description is Telegram's own words and does not
// hold the token, but it is matched, not repeated: a server that is not Telegram can put anything in it.
func apiError(method string, status int, r apiReply) error {
	d := strings.ToLower(r.Description)
	code := r.ErrorCode
	if code == 0 {
		code = status
	}
	switch {
	case code == 401:
		return ErrBadToken
	case code == 429:
		return &RateLimitedError{RetryAfter: time.Duration(max(r.Parameters.RetryAfter, 1)) * time.Second}
	case code == 409 && strings.Contains(d, "webhook"):
		return ErrWebhookSet
	case code == 409:
		return ErrConflict
	case code == 403, strings.Contains(d, "chat not found"), strings.Contains(d, "not a member"), strings.Contains(d, "kicked"):
		return ErrNotInChat
	case strings.Contains(d, "too long"):
		return ErrTooLong
	case code >= 500:
		return fmt.Errorf("%w: %s answered %d", ErrUnreachable, method, code)
	}
	return fmt.Errorf("telegram %s: refused (%d)", method, code)
}

// Me asks who the bot is. It is also the check that a token works.
func (c *Client) Me(ctx context.Context) (Me, error) {
	raw, err := c.call(ctx, "getMe", nil)
	if err != nil {
		return Me{}, err
	}
	var m struct {
		ID         int64  `json:"id"`
		Username   string `json:"username"`
		ReadsAll   bool   `json:"can_read_all_group_messages"`
		IsBot      bool   `json:"is_bot"`
		FirstNames string `json:"first_name"`
	}
	if err := json.Unmarshal(raw, &m); err != nil || m.ID == 0 {
		return Me{}, fmt.Errorf("telegram getMe: the answer is not a bot")
	}
	return Me{ID: m.ID, Username: m.Username, SeesAllGroupMessages: m.ReadsAll}, nil
}

// Send says text in a chat, as plain text: no parse mode is set, so nothing in it is read as formatting. replyTo, when not zero,
// is the message it answers. It returns the new message's id.
func (c *Client) Send(ctx context.Context, chatID int64, text string, replyTo int64) (int64, error) {
	if text == "" {
		return 0, errors.New("telegram sendMessage: the message is empty")
	}
	args := map[string]any{"chat_id": chatID, "text": text, "disable_web_page_preview": true}
	if replyTo != 0 {
		args["reply_to_message_id"] = replyTo
		args["allow_sending_without_reply"] = true
	}
	raw, err := c.call(ctx, "sendMessage", args)
	if err != nil {
		return 0, err
	}
	var m struct {
		ID int64 `json:"message_id"`
	}
	if err := json.Unmarshal(raw, &m); err != nil {
		return 0, fmt.Errorf("telegram sendMessage: the answer is not a message")
	}
	return m.ID, nil
}

// Message is something someone said in a chat the bot is in.
type Message struct {
	UpdateID  int64
	MessageID int64
	ChatID    int64
	FromID    int64
	From      string // the sender's first name (or their title): what a person called themselves, so not to be trusted
	FromBot   bool
	Text      string
	At        time.Time
	ReplyTo   int64
}

// Updates reads up to limit new updates, those at or after offset (0: from the oldest not yet confirmed). Asking for an offset
// confirms every update before it, and Telegram then forgets them: a caller that confirms what it has not stored loses it.
// wait is how long to hold the request open for something to arrive (0: answer at once).
func (c *Client) Updates(ctx context.Context, offset int64, limit int, wait time.Duration) ([]Message, error) {
	args := map[string]any{"limit": limit, "allowed_updates": []string{"message"}}
	if offset != 0 {
		args["offset"] = offset
	}
	if wait > 0 {
		args["timeout"] = int(wait / time.Second)
	}
	raw, err := c.call(ctx, "getUpdates", args)
	if err != nil {
		return nil, err
	}
	var ups []struct {
		UpdateID int64 `json:"update_id"`
		Message  *struct {
			ID   int64 `json:"message_id"`
			Date int64 `json:"date"`
			Chat struct {
				ID int64 `json:"id"`
			} `json:"chat"`
			From *struct {
				ID        int64  `json:"id"`
				IsBot     bool   `json:"is_bot"`
				FirstName string `json:"first_name"`
			} `json:"from"`
			Text    string `json:"text"`
			Caption string `json:"caption"`
			Reply   *struct {
				ID int64 `json:"message_id"`
			} `json:"reply_to_message"`
		} `json:"message"`
	}
	if err := json.Unmarshal(raw, &ups); err != nil {
		return nil, fmt.Errorf("telegram getUpdates: the answer is not a list of updates")
	}
	out := make([]Message, 0, len(ups))
	for _, u := range ups {
		m := Message{UpdateID: u.UpdateID}
		if u.Message != nil {
			m.MessageID, m.ChatID, m.At = u.Message.ID, u.Message.Chat.ID, time.Unix(u.Message.Date, 0).UTC()
			m.Text = u.Message.Text
			if m.Text == "" {
				m.Text = u.Message.Caption
			}
			if u.Message.From != nil {
				m.FromID, m.From, m.FromBot = u.Message.From.ID, u.Message.From.FirstName, u.Message.From.IsBot
			}
			if u.Message.Reply != nil {
				m.ReplyTo = u.Message.Reply.ID
			}
		}
		out = append(out, m)
	}
	return out, nil
}

// String is for logs: a client never prints its token.
func (c *Client) String() string { return "telegram.Client{token: <redacted>}" }

// GoString is the same for %#v.
func (c *Client) GoString() string { return c.String() }
