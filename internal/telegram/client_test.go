package telegram

import (
	"context"
	"errors"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/telegram/telegramtest"
)

const (
	tok    = "123456789:AAH-SECRET-TOKEN-abcdefghijklmnopqrstuv"
	chatA  = int64(-1001111111111)
	chatB  = int64(-1002222222222)
	botID  = int64(123456789)
	botNam = "securl_test_bot"
)

func fake(t *testing.T, privacy bool) (*telegramtest.API, *Client) {
	t.Helper()
	api := telegramtest.New(telegramtest.Bot{Token: tok, ID: botID, Username: botNam, Privacy: privacy,
		Chats: map[int64]bool{chatA: true, chatB: true}})
	t.Cleanup(api.Close)
	return api, New(tok, Options{BaseURL: api.URL, HTTP: api.Client()})
}

func TestGetMeSaysWhoTheBotIsAndWhetherItSeesEveryMessage(t *testing.T) {
	_, c := fake(t, false)
	me, err := c.Me(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if me.Username != botNam || me.ID != botID || !me.SeesAllGroupMessages {
		t.Errorf("%+v", me)
	}
	_, c2 := fake(t, true)
	me2, _ := c2.Me(context.Background())
	if me2.SeesAllGroupMessages {
		t.Errorf("privacy on means the bot sees only what is addressed to it: %+v", me2)
	}
}

func TestAWrongTokenIsBadCredentialsAndSaysNothingAboutTheToken(t *testing.T) {
	api, _ := fake(t, false)
	c := New("999:WRONG-TOKEN-abcdefghijklmnopqrstuvwxyz0123", Options{BaseURL: api.URL, HTTP: api.Client()})
	_, err := c.Me(context.Background())
	if !errors.Is(err, ErrBadToken) {
		t.Fatalf("a refused token is ErrBadToken: %v", err)
	}
	if strings.Contains(err.Error(), "WRONG-TOKEN") || strings.Contains(err.Error(), "999:") {
		t.Errorf("the error repeats the token: %v", err)
	}
}

func TestSendMessageSendsToTheChatAndReturnsTheMessageId(t *testing.T) {
	api, c := fake(t, false)
	id, err := c.Send(context.Background(), chatA, "hello", 0)
	if err != nil || id == 0 {
		t.Fatalf("%v %v", id, err)
	}
	got := api.Sent()
	if len(got) != 1 || got[0].ChatID != chatA || got[0].Text != "hello" {
		t.Errorf("%+v", got)
	}
}

// The text is sent as text, with no parse mode: what an agent writes must not be read as formatting, and a character that
// would be formatting in HTML or Markdown must not make the message fail or turn into a link.
func TestTheTextIsSentWithNoParseModeSoNothingIsReadAsFormatting(t *testing.T) {
	api, c := fake(t, false)
	text := "<b>x</b> [a](http://evil.example) *y* _z_ `c` & < > #"
	if _, err := c.Send(context.Background(), chatA, text, 0); err != nil {
		t.Fatal(err)
	}
	got := api.Sent()
	if len(got) != 1 || got[0].ParseMode != "" || got[0].Text != text {
		t.Errorf("parse mode %q, text %q", got[0].ParseMode, got[0].Text)
	}
}

func TestAReplyIsAReplyToTheMessageNamed(t *testing.T) {
	api, c := fake(t, false)
	if _, err := c.Send(context.Background(), chatA, "re", 777); err != nil {
		t.Fatal(err)
	}
	if got := api.Sent(); got[0].ReplyTo != 777 {
		t.Errorf("%+v", got)
	}
}

func TestTheErrorsOfSendingSaySomethingTheCallerCanActOn(t *testing.T) {
	api, c := fake(t, false)
	_, err := c.Send(context.Background(), int64(-1009999999999), "x", 0)
	if !errors.Is(err, ErrNotInChat) {
		t.Errorf("a chat the bot is not in: %v", err)
	}
	_, err = c.Send(context.Background(), chatA, strings.Repeat("x", 5000), 0)
	if !errors.Is(err, ErrTooLong) {
		t.Errorf("text over Telegram's limit: %v", err)
	}
	_, err = c.Send(context.Background(), chatA, "", 0)
	if err == nil {
		t.Error("an empty message is refused")
	}
	api.FailNext["sendMessage"] = telegramtest.Failure{Status: 429, Description: "Too Many Requests: retry after 7", RetryAfter: 7}
	_, err = c.Send(context.Background(), chatA, "x", 0)
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter != 7*time.Second {
		t.Errorf("a flood answer says when to retry: %v", err)
	}
}

// The token is in the path of every request, so it is in every *url.Error that net/http builds. None of it may reach an error
// that the caller can print, log or hand to an agent.
func TestNoErrorEverCarriesTheTokenWhateverWentWrong(t *testing.T) {
	// a server that is not there: net/http makes a *url.Error that holds the whole URL, path included
	dead := httptest.NewServer(http.NotFoundHandler())
	url := dead.URL
	dead.Close()
	c := New(tok, Options{BaseURL: url})
	for name, call := range map[string]func() error{
		"me":   func() error { _, e := c.Me(context.Background()); return e },
		"send": func() error { _, e := c.Send(context.Background(), chatA, "x", 0); return e },
		"read": func() error { _, e := c.Updates(context.Background(), 0, 10, 0); return e },
	} {
		err := call()
		if err == nil {
			t.Fatalf("%s: a dead server must be an error", name)
		}
		for _, secret := range []string{tok, "AAH-SECRET", "123456789:"} {
			if strings.Contains(err.Error(), secret) {
				t.Errorf("%s: the error carries the token (%q): %v", name, secret, err)
			}
		}
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: a server that is not there is ErrUnreachable: %v", name, err)
		}
	}
}

func TestATimeoutAndACancelledContextCarryNoTokenEither(t *testing.T) {
	slow := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer slow.Close()
	c := New(tok, Options{BaseURL: slow.URL, Timeout: 50 * time.Millisecond})
	_, err := c.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), "AAH-SECRET") || strings.Contains(err.Error(), tok) {
		t.Errorf("%v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	_, err = c.Me(ctx)
	if err == nil || strings.Contains(err.Error(), "AAH-SECRET") {
		t.Errorf("%v", err)
	}
}

// A server that answers with the token in its body (an echo, a proxy's error page) must not get it into an error either.
func TestAnAnswerThatEchoesTheTokenIsNotRepeated(t *testing.T) {
	echo := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(502)
		w.Write([]byte("bad gateway for " + r.URL.Path))
	}))
	defer echo.Close()
	c := New(tok, Options{BaseURL: echo.URL})
	_, err := c.Me(context.Background())
	if err == nil {
		t.Fatal("a 502 is an error")
	}
	if strings.Contains(err.Error(), "AAH-SECRET") || strings.Contains(err.Error(), tok) {
		t.Errorf("the error repeats what the server said, token and all: %v", err)
	}
}

func TestTheTokenGoesInThePathAndNowhereElse(t *testing.T) {
	var seenQuery, seenHeader atomic.Value
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenQuery.Store(r.URL.RawQuery)
		seenHeader.Store(strings.Join(r.Header.Values("Authorization"), ","))
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true,"username":"b"}}`))
	}))
	defer srv.Close()
	c := New(tok, Options{BaseURL: srv.URL})
	if _, err := c.Me(context.Background()); err != nil {
		t.Fatal(err)
	}
	if q, _ := seenQuery.Load().(string); strings.Contains(q, "AAH-SECRET") {
		t.Errorf("the token is in the query: %q", q)
	}
	if h, _ := seenHeader.Load().(string); h != "" {
		t.Errorf("no Authorization header is used: %q", h)
	}
}

func TestTheProxyIsUsedWhenOneIsGivenAndNeverTheEnvironmentsOtherwise(t *testing.T) {
	var viaProxy atomic.Int32
	proxy := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		viaProxy.Add(1)
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"ok":true,"result":{"id":1,"is_bot":true,"username":"viaproxy"}}`))
	}))
	defer proxy.Close()
	pu, _ := url.Parse(proxy.URL)
	// a plain http address that only the proxy can answer for: the proxy is what the client connects to
	c := New(tok, Options{BaseURL: "http://api.telegram.test", Proxy: pu})
	me, err := c.Me(context.Background())
	if err != nil || me.Username != "viaproxy" || viaProxy.Load() != 1 {
		t.Fatalf("%+v %v via=%d", me, err, viaProxy.Load())
	}
}

func TestAProxyErrorDoesNotCarryTheProxyCredentialOrTheToken(t *testing.T) {
	dead := httptest.NewServer(http.NotFoundHandler())
	addr := dead.Listener.Addr().String()
	dead.Close()
	pu, _ := url.Parse("http://user:pa55word@" + addr)
	c := New(tok, Options{BaseURL: "http://api.telegram.test", Proxy: pu})
	_, err := c.Me(context.Background())
	if err == nil {
		t.Fatal("a dead proxy is an error")
	}
	for _, secret := range []string{"pa55word", "AAH-SECRET", tok} {
		if strings.Contains(err.Error(), secret) {
			t.Errorf("the error carries %q: %v", secret, err)
		}
	}
}

func TestTheClientDoesNotFollowARedirectWithTheTokenInIt(t *testing.T) {
	var landed atomic.Int32
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { landed.Add(1) }))
	defer other.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, other.URL+r.URL.Path, http.StatusTemporaryRedirect)
	}))
	defer srv.Close()
	c := New(tok, Options{BaseURL: srv.URL})
	_, err := c.Me(context.Background())
	if err == nil {
		t.Fatal("a redirect is an error, not a request to somewhere else")
	}
	if landed.Load() != 0 {
		t.Error("the redirect was followed: the token (it is in the path) went to another host")
	}
}

func TestTheBaseURLIsTelegramsUnlessATestSaysOtherwise(t *testing.T) {
	c := New(tok, Options{})
	if c.base != "https://api.telegram.org" {
		t.Errorf("%q", c.base)
	}
}

// A 4xx that is not JSON (a captive portal, a proxy's page) is the other branch that must not repeat the server's body.
func TestANonJSONAnswerThatEchoesTheTokenIsNotRepeatedEither(t *testing.T) {
	for _, status := range []int{200, 400, 404, 407} {
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(status)
			w.Write([]byte("<html>no such page: " + r.URL.Path + "</html>"))
		}))
		c := New(tok, Options{BaseURL: srv.URL})
		_, err := c.Me(context.Background())
		srv.Close()
		if err == nil {
			t.Fatalf("%d: an answer that is not the Bot API's is an error", status)
		}
		if strings.Contains(err.Error(), "AAH-SECRET") || strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "no such page") {
			t.Errorf("%d: the error repeats what the server said: %v", status, err)
		}
	}
}

// An empty message is refused before anything is sent: it costs no round trip, and nothing is counted against a limit.
func TestAnEmptyMessageIsRefusedBeforeAnyRequestIsMade(t *testing.T) {
	api, c := fake(t, false)
	if _, err := c.Send(context.Background(), chatA, "", 0); err == nil {
		t.Fatal("an empty message is refused")
	}
	if n := api.Calls["sendMessage"]; n != 0 {
		t.Errorf("%d requests were made for a message that cannot be sent", n)
	}
}
