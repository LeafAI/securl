package dingtalk

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/dingtalk/dingtalktest"
)

const (
	tok    = "c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	secret = "SECabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
)

func fake(t *testing.T, r dingtalktest.Robot) (*dingtalktest.API, *Client) {
	t.Helper()
	if r.Token == "" {
		r.Token = tok
	}
	api := dingtalktest.New(r)
	t.Cleanup(api.Close)
	return api, New(r.Token, r.Secret, Options{BaseURL: api.URL, HTTP: api.Client()})
}

func TestSendPostsATextMessageThatMentionsNobody(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	if err := c.Send(context.Background(), "hello"); err != nil {
		t.Fatal(err)
	}
	got := api.Sent()
	if len(got) != 1 || got[0].Type != "text" || got[0].Text != "hello" {
		t.Fatalf("%+v", got)
	}
	if got[0].AtAll || len(got[0].Mobiles) != 0 || len(got[0].UserIDs) != 0 {
		t.Errorf("a message from an agent mentions nobody and never everybody: %+v", got[0])
	}
	if got[0].Uuid == "" {
		t.Error("every message carries an idempotency key, so that a retry cannot say it twice")
	}
}

// Markdown can hold links and images that the client loads by itself: an address in it is fetched without anybody clicking.
func TestTheMessageIsPlainTextNeverMarkdown(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	text := "![x](http://evil.example/p.png) [a](http://evil.example) **b** @13800000000 @all"
	if err := c.Send(context.Background(), text); err != nil {
		t.Fatal(err)
	}
	got := api.Sent()
	if got[0].Type != "text" || got[0].Text != text || got[0].Title != "" {
		t.Errorf("%+v", got[0])
	}
	if got[0].AtAll || len(got[0].Mobiles) != 0 {
		t.Errorf("an @ written in the text must not become a mention: %+v", got[0])
	}
}

func TestTheTokenIsAQueryParameterAndTheSignIsAddedWhenThereIsASecret(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{Secret: secret})
	if err := c.Send(context.Background(), "x"); err != nil {
		t.Fatalf("a signed robot must accept the request: %v", err)
	}
	reqs := api.Requests()
	if len(reqs) != 1 || !strings.HasPrefix(reqs[0], "/robot/send?") || !strings.Contains(reqs[0], "access_token="+tok) ||
		!strings.Contains(reqs[0], "timestamp=") || !strings.Contains(reqs[0], "sign=") {
		t.Errorf("%v", reqs)
	}
	api2, c2 := fake(t, dingtalktest.Robot{})
	c2.Send(context.Background(), "x")
	if r := api2.Requests()[0]; strings.Contains(r, "sign=") || strings.Contains(r, "timestamp=") {
		t.Errorf("a robot without a secret gets no sign: %v", r)
	}
}

func TestAWrongSecretIsRefusedByTheRobotAndSaidSo(t *testing.T) {
	api := dingtalktest.New(dingtalktest.Robot{Token: tok, Secret: secret})
	t.Cleanup(api.Close)
	c := New(tok, "SECwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrongwrong", Options{BaseURL: api.URL, HTTP: api.Client()})
	err := c.Send(context.Background(), "x")
	if !errors.Is(err, ErrRefused) {
		t.Fatalf("%v", err)
	}
	if strings.Contains(err.Error(), "SECwrong") || strings.Contains(err.Error(), tok) {
		t.Errorf("the error repeats a secret: %v", err)
	}
}

func TestTheErrorsOfSendingSaySomethingTheCallerCanActOn(t *testing.T) {
	for _, tc := range []struct {
		code int
		msg  string
		want error
	}{
		{300005, "token is not exist", ErrBadToken}, // what the real endpoint answers for an unknown token (measured)
		{400101, "access_token不存在", ErrBadToken},    // what its documentation says
		{400102, "机器人已停用", ErrBadToken},
		{400106, "机器人不存在", ErrBadToken},
		{400013, "群已被解散", ErrGroupGone},
		{310000, "keywords not in content", ErrRefused},
		{310000, "ip 1.2.3.4 not in whitelist", ErrRefused},
		{430101, "含有不安全的外链", ErrContent},
		{430102, "含有不合适的文本", ErrContent},
		{430103, "含有不合适的图片", ErrContent},
		{430104, "含有不合适的内容", ErrContent},
		{-1, "系统繁忙", ErrUnreachable},
	} {
		api, c := fake(t, dingtalktest.Robot{})
		api.FailNext = &dingtalktest.Failure{Code: tc.code, Message: tc.msg}
		err := c.Send(context.Background(), "x")
		if !errors.Is(err, tc.want) {
			t.Errorf("%d %s: want %v, got %v", tc.code, tc.msg, tc.want, err)
		}
	}
}

// The endpoint throttles for ten minutes after too many messages; the caller must not ask again before then.
func TestAThrottleIsTenMinutesLongAsTheDocumentationSays(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	api.FailNext = &dingtalktest.Failure{Code: 410100, Message: "send too fast"}
	err := c.Send(context.Background(), "x")
	var th *ThrottledError
	if !errors.As(err, &th) || th.RetryAfter != 10*time.Minute {
		t.Fatalf("%v", err)
	}
}

// Measured against the real endpoint (not in its documentation): too many requests from one address in a minute is 660026, and it is
// answered before the token is looked at, so a robot that is fine can be told it is throttled. It is a wait, not a refusal.
func TestTooManyRequestsFromOneAddressIsAShortWaitNotARefusal(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	api.FailNext = &dingtalktest.Failure{Code: 660026, Message: "sending too many messages per minute"}
	var th *ThrottledError
	if err := c.Send(context.Background(), "x"); !errors.As(err, &th) || th.RetryAfter != time.Minute {
		t.Fatalf("%v", err)
	}
}

func TestNoErrorEverCarriesTheTokenOrTheSecretWhateverWentWrong(t *testing.T) {
	cases := map[string]func(w http.ResponseWriter, r *http.Request){
		"echo": func(w http.ResponseWriter, r *http.Request) {
			w.Write([]byte(`{"errcode":9,"errmsg":"bad ` + r.URL.RawQuery + `"}`))
		},
		"html": func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>" + r.URL.RawQuery + "</html>")) },
		"500":  func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); w.Write([]byte(r.URL.RawQuery)) },
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			http.Redirect(w, r, "http://evil.example/?"+r.URL.RawQuery, 302)
		},
		"empty": func(w http.ResponseWriter, r *http.Request) {},
		"429":   func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429); w.Write([]byte(r.URL.RawQuery)) },
	}
	for name, h := range cases {
		srv := httptest.NewTLSServer(http.HandlerFunc(h))
		c := New(tok, secret, Options{BaseURL: srv.URL, HTTP: srv.Client()})
		err := c.Send(context.Background(), "x")
		srv.Close()
		if err == nil {
			t.Errorf("%s: an answer that is not a success must be an error", name)
			continue
		}
		for _, s := range []string{tok, "SECRETTOKEN", secret, "SECabcdef", "access_token", "sign="} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: the error carries %q: %v", name, s, err)
			}
		}
	}
}

func TestATransportFailureAndATimeoutCarryNoSecretEither(t *testing.T) {
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { time.Sleep(300 * time.Millisecond) }))
	defer srv.Close()
	hc := srv.Client()
	hc.Timeout = 50 * time.Millisecond
	for name, c := range map[string]*Client{
		"timeout": New(tok, secret, Options{BaseURL: srv.URL, HTTP: hc}),
		"refused": New(tok, secret, Options{BaseURL: "https://127.0.0.1:1"}),
	} {
		err := c.Send(context.Background(), "x")
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: %v", name, err)
			continue
		}
		for _, s := range []string{tok, secret, "access_token", "sign=", "127.0.0.1"} {
			if strings.Contains(err.Error(), s) {
				t.Errorf("%s: the error carries %q: %v", name, s, err)
			}
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := New(tok, secret, Options{BaseURL: srv.URL, HTTP: srv.Client()}).Send(ctx, "x"); err == nil || strings.Contains(err.Error(), tok) {
		t.Errorf("%v", err)
	}
}

func TestARedirectIsNeverFollowed(t *testing.T) {
	var hit atomic.Bool
	evil := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit.Store(true) }))
	defer evil.Close()
	srv := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, evil.URL+"/?"+r.URL.RawQuery, 307) }))
	defer srv.Close()
	err := New(tok, "", Options{BaseURL: srv.URL, HTTP: srv.Client()}).Send(context.Background(), "x")
	if err == nil || hit.Load() {
		t.Errorf("a redirect would carry the token to wherever it points: err=%v followed=%v", err, hit.Load())
	}
}

// A timeout leaves it unknown whether the message was posted. The documented way out is to retry with the same msgUuid.
func TestATimeoutIsRetriedOnceWithTheSameKeySoNothingIsSaidTwice(t *testing.T) {
	api := dingtalktest.New(dingtalktest.Robot{Token: tok})
	defer api.Close()
	var n atomic.Int32
	slow := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		nth := n.Add(1)
		api.Config.Handler.ServeHTTP(w, r) // the message is posted...
		if nth == 1 {
			time.Sleep(300 * time.Millisecond) // ...but the answer is too late
		}
	}))
	defer slow.Close()
	hc := slow.Client()
	hc.Timeout = 100 * time.Millisecond
	if err := New(tok, "", Options{BaseURL: slow.URL, HTTP: hc}).Send(context.Background(), "once"); err != nil {
		t.Fatalf("%v", err)
	}
	if got := api.Sent(); len(got) != 1 {
		t.Errorf("the retry said it twice: %d messages", len(got))
	}
	if got := n.Load(); got != 2 {
		t.Errorf("one retry, no more: %d requests", got)
	}
}

func TestAnAnswerThatIsDefinitelyARefusalIsNotRetried(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	api.FailNext = &dingtalktest.Failure{Code: 300005, Message: "token is not exist"}
	c.Send(context.Background(), "x")
	if n := len(api.Requests()); n != 1 {
		t.Errorf("%d requests", n)
	}
}

// The status line is part of the answer. A redirect or a server error whose body happens to read as a success is not a success: the
// caller would be told the message was sent when the group may never have seen it.
func TestAStatusThatIsNotASuccessIsNotOneWhateverTheBodySays(t *testing.T) {
	ok := `{"errcode":0,"errmsg":"ok"}`
	for name, h := range map[string]http.HandlerFunc{
		"redirect": func(w http.ResponseWriter, r *http.Request) {
			w.Header().Set("Location", "/x")
			w.WriteHeader(302)
			w.Write([]byte(ok))
		},
		"500": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500); w.Write([]byte(ok)) },
		"502": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(502); w.Write([]byte(ok)) },
		"429": func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(429); w.Write([]byte(ok)) },
		"502 that looks like a refusal": func(w http.ResponseWriter, r *http.Request) {
			w.WriteHeader(502)
			w.Write([]byte(`{"errcode":300005}`))
		},
	} {
		srv := httptest.NewTLSServer(h)
		err := New(tok, "", Options{BaseURL: srv.URL, HTTP: srv.Client()}).Send(context.Background(), "x")
		srv.Close()
		if !errors.Is(err, ErrUnreachable) {
			t.Errorf("%s: must be unreachable (the message may not have been sent), got %v", name, err)
		}
	}
}

func TestAnEmptyMessageIsRefusedBeforeAnyRequestIsMade(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	for _, s := range []string{"", "   ", "\n\t"} {
		if err := c.Send(context.Background(), s); err == nil {
			t.Errorf("%q must be refused", s)
		}
	}
	if len(api.Requests()) != 0 {
		t.Error("a request was made for an empty message")
	}
}

func TestTheDefaultEndpointIsDingTalksOwn(t *testing.T) {
	if c := New(tok, "", Options{}); c.base != "https://oapi.dingtalk.com" {
		t.Errorf("%s", c.base)
	}
}

func TestParseWebhookAcceptsOnlyTheRobotEndpointWithOnlyAToken(t *testing.T) {
	good := "https://oapi.dingtalk.com/robot/send?access_token=" + tok
	if got, err := ParseWebhook(good); err != nil || got != tok {
		t.Fatalf("%v %v", got, err)
	}
	if got, err := ParseWebhook("  " + good + "\n"); err != nil || got != tok {
		t.Errorf("surrounding space is not part of it: %v %v", got, err)
	}
	for name, raw := range map[string]string{
		"empty":        "",
		"not a url":    "not a url",
		"http":         "http://oapi.dingtalk.com/robot/send?access_token=" + tok,
		"other host":   "https://evil.example/robot/send?access_token=" + tok,
		"look-alike":   "https://oapi.dingtalk.com.evil.example/robot/send?access_token=" + tok,
		"userinfo":     "https://oapi.dingtalk.com@evil.example/robot/send?access_token=" + tok,
		"user at host": "https://u:p@oapi.dingtalk.com/robot/send?access_token=" + tok,
		"port":         "https://oapi.dingtalk.com:8443/robot/send?access_token=" + tok,
		"other path":   "https://oapi.dingtalk.com/robot/other?access_token=" + tok,
		"deeper path":  "https://oapi.dingtalk.com/robot/send/x?access_token=" + tok,
		"no token":     "https://oapi.dingtalk.com/robot/send",
		"empty token":  "https://oapi.dingtalk.com/robot/send?access_token=",
		"short token":  "https://oapi.dingtalk.com/robot/send?access_token=abc",
		"odd token":    "https://oapi.dingtalk.com/robot/send?access_token=" + strings.Repeat("a", 40) + "%0d%0a",
		"extra param":  "https://oapi.dingtalk.com/robot/send?access_token=" + tok + "&x=1",
		"two tokens":   "https://oapi.dingtalk.com/robot/send?access_token=" + tok + "&access_token=" + tok,
		"sign pasted":  "https://oapi.dingtalk.com/robot/send?access_token=" + tok + "&sign=x&timestamp=1",
		"fragment":     good + "#x",
		"scheme-less":  "oapi.dingtalk.com/robot/send?access_token=" + tok,
		"just a token": tok,
	} {
		got, err := ParseWebhook(raw)
		if err == nil || got != "" {
			t.Errorf("%s must be refused: %q %v", name, got, err)
			continue
		}
		if strings.Contains(err.Error(), tok) || strings.Contains(err.Error(), "SECRETTOKEN") {
			t.Errorf("%s: the refusal repeats the token: %v", name, err)
		}
	}
}

// The length of a signing secret is not documented where it could be read, so only what is certain is checked (it starts with SEC, as
// the setup wizard has always said, and is one word of a sane size); whether DingTalk accepts it is DingTalk's answer, 310000.
func TestParseSecretWantsOneWordThatStartsWithSEC(t *testing.T) {
	if got, err := ParseSecret("  " + secret + " "); err != nil || got != secret {
		t.Fatalf("%v %v", got, err)
	}
	for _, bad := range []string{"", "   ", "abc", "SEC", "SECx", "sec" + secret[3:], "SEC short", "https://oapi.dingtalk.com/robot/send?access_token=" + tok, secret + "\n" + secret, "SEC" + strings.Repeat("x", 200)} {
		if got, err := ParseSecret(bad); err == nil || got != "" {
			t.Errorf("%q must be refused: %q %v", bad, got, err)
		} else if strings.Contains(err.Error(), "SECabcdef") {
			t.Errorf("the refusal repeats the secret: %v", err)
		}
	}
}

// Reachability is checked with no token at all, so nothing can be posted: DingTalk answers a request without a robot with an error,
// and any answer of its own proves that the host can be reached and speaks the robot API.
func TestPingSaysTheHostIsReachableWithoutPostingAnythingAndWithoutAToken(t *testing.T) {
	api := dingtalktest.New(dingtalktest.Robot{Token: tok})
	defer api.Close()
	c := New("", "", Options{BaseURL: api.URL, HTTP: api.Client()})
	if err := c.Ping(context.Background()); err != nil {
		t.Fatalf("an answer from DingTalk's side is reachability: %v", err)
	}
	if n := len(api.Sent()); n != 0 {
		t.Errorf("a ping posted %d messages", n)
	}
	reqs := api.Requests()
	if len(reqs) != 1 || strings.Contains(reqs[0], tok) {
		t.Errorf("%v", reqs)
	}
}

func TestPingIsUnreachableWhenNothingAnswersOrTheAnswerIsNotDingTalks(t *testing.T) {
	for name, h := range map[string]http.HandlerFunc{
		"500":      func(w http.ResponseWriter, r *http.Request) { w.WriteHeader(500) },
		"html":     func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("<html>captive portal</html>")) },
		"redirect": func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, "http://portal.example/", 302) },
	} {
		srv := httptest.NewTLSServer(h)
		err := New("", "", Options{BaseURL: srv.URL, HTTP: srv.Client()}).Ping(context.Background())
		srv.Close()
		if err == nil {
			t.Errorf("%s: a host that does not speak the robot API is not DingTalk, and a ping must not say it is", name)
		}
		if strings.Contains(fmt.Sprint(err), "captive portal") || strings.Contains(fmt.Sprint(err), "portal.example") {
			t.Errorf("%s: the error repeats what the host said: %v", name, err)
		}
	}
	if err := New("", "", Options{BaseURL: "https://127.0.0.1:1"}).Ping(context.Background()); !errors.Is(err, ErrUnreachable) {
		t.Errorf("nothing listening: %v", err)
	}
}

func TestAThrottledPingIsStillAnAnswer(t *testing.T) {
	api := dingtalktest.New()
	defer api.Close()
	api.FailNext = &dingtalktest.Failure{Code: 660026, Message: "sending too many messages per minute"}
	if err := New("", "", Options{BaseURL: api.URL, HTTP: api.Client()}).Ping(context.Background()); err != nil {
		t.Errorf("a host that says slow down is a host that is there: %v", err)
	}
}

// A code this package does not know is still DingTalk answering, so it is a typed error the caller can tell from a transport failure,
// and it says the code and nothing DingTalk wrote.
func TestACodeThePackageDoesNotKnowIsATypedRefusalThatSaysOnlyTheCode(t *testing.T) {
	api, c := fake(t, dingtalktest.Robot{})
	api.FailNext = &dingtalktest.Failure{Code: 123456, Message: "something with " + tok + " in it"}
	err := c.Send(context.Background(), "x")
	if !errors.Is(err, ErrRequest) || errors.Is(err, ErrUnreachable) {
		t.Fatalf("%v", err)
	}
	if !strings.Contains(err.Error(), "123456") || strings.Contains(err.Error(), "something") || strings.Contains(err.Error(), tok) {
		t.Errorf("the code and nothing DingTalk wrote: %v", err)
	}
	api.FailNext = &dingtalktest.Failure{Code: 40035, Message: "缺少参数 access_token"}
	if err := New("", "", Options{BaseURL: api.URL, HTTP: api.Client()}).Ping(context.Background()); err != nil {
		t.Errorf("40035 for a request that names no robot is what DingTalk says, and it is an answer: %v", err)
	}
}

// A ping that carried a message would post it to a robot's group the moment anybody ran doctor with a token in the address. It names no
// robot and has no content, so the fake that knows a robot cannot be made to post by it, whatever token happens to match.
func TestAPingCannotPostEvenToARobotThatExistsAndSaysNothingAboutTheMessageType(t *testing.T) {
	api := dingtalktest.New(dingtalktest.Robot{Token: tok})
	defer api.Close()
	// even a client that holds a real robot's token pings without posting: the ping's body is empty, and so there is nothing to post
	if err := New(tok, "", Options{BaseURL: api.URL, HTTP: api.Client()}).Ping(context.Background()); err != nil {
		t.Fatal(err)
	}
	if n := len(api.Sent()); n != 0 {
		t.Fatalf("a ping posted %d messages to a robot that exists", n)
	}
}

// DingTalk says "no such robot" to a request that names none, which is the ordinary answer to a ping, and it must count as reachable:
// if it did not, doctor would call every healthy network broken.
func TestAnUnknownRobotIsTheOrdinaryAnswerToAPingAndCountsAsReachable(t *testing.T) {
	api := dingtalktest.New() // no robots at all: every token is unknown
	defer api.Close()
	if err := New("0000000000000000000000000000000000000000", "", Options{BaseURL: api.URL, HTTP: api.Client()}).Ping(context.Background()); err != nil {
		t.Errorf("%v", err)
	}
	api.FailNext = &dingtalktest.Failure{Code: 300005, Message: "token is not exist"}
	if err := New("", "", Options{BaseURL: api.URL, HTTP: api.Client()}).Ping(context.Background()); err != nil {
		t.Errorf("%v", err)
	}
}
