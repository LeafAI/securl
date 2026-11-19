package zulip

import (
	"context"
	"encoding/base64"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/zulip/zulipfake"
)

const (
	botEmail = "robot-bot@example.invalid"
	botKey   = "k3y-SECRET-0123456789abcdefghijklmnopqrstu"
)

func fake(t *testing.T, channels ...string) (*zulipfake.Server, *Client) {
	t.Helper()
	ch := map[string]bool{}
	for _, c := range channels {
		ch[c] = true
	}
	s := zulipfake.New(zulipfake.Bot{Email: botEmail, Key: botKey, ID: 77, Name: "Robot", Channels: ch})
	t.Cleanup(s.Close)
	c, err := New(s.URL, botEmail, botKey, Options{HTTP: s.Client(), AllowInsecure: true})
	if err != nil {
		t.Fatal(err)
	}
	return s, c
}

func contents(ms []Message) []string {
	var out []string
	for _, m := range ms {
		out = append(out, m.Content)
	}
	return out
}

func TestWhoAmIAsksTheServerWhoTheBotIs(t *testing.T) {
	_, c := fake(t, "engineering")
	me, err := c.Me(context.Background())
	if err != nil || me.ID != 77 || me.Email != botEmail || me.Name != "Robot" {
		t.Fatalf("%+v %v", me, err)
	}
}

func TestTheKeyIsSentAsHTTPBasicAuthAndNowhereElse(t *testing.T) {
	s, c := fake(t, "engineering")
	c.Me(context.Background())
	c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 5})
	want := "Basic " + base64.StdEncoding.EncodeToString([]byte(botEmail+":"+botKey))
	for _, a := range s.Auths() {
		if a != want {
			t.Errorf("Authorization %q", a)
		}
	}
	for _, q := range s.Queries() {
		for k, v := range q {
			if strings.Contains(k+v, botKey) {
				t.Errorf("the key is in a query parameter: %s=%s", k, v)
			}
		}
	}
}

func TestReadReturnsTheNewestMessagesOfAChannelOldestFirst(t *testing.T) {
	s, c := fake(t, "engineering")
	for i := 1; i <= 5; i++ {
		s.Say("engineering", "general chat", "ann", 1, fmt.Sprintf("m%d", i))
	}
	got, err := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 3})
	if err != nil {
		t.Fatal(err)
	}
	if fmt.Sprint(contents(got.Messages)) != "[m3 m4 m5]" {
		t.Errorf("the newest three, oldest first: %v", contents(got.Messages))
	}
	if !got.More {
		t.Errorf("there are older messages that were not returned")
	}
	all, _ := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 50})
	if len(all.Messages) != 5 || all.More {
		t.Errorf("%d messages, more=%v", len(all.Messages), all.More)
	}
}

func TestAMessageCarriesWhoWroteItWhereAndWhen(t *testing.T) {
	s, c := fake(t, "engineering")
	s.Say("engineering", "deploy notes", "Ann Lee", 9, "Hi")
	got, _ := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 5})
	m := got.Messages[0]
	if m.Content != "Hi" || m.SenderName != "Ann Lee" || m.SenderID != 9 || m.Topic != "deploy notes" || m.Channel != "engineering" || m.ID == 0 || m.At.IsZero() {
		t.Errorf("%+v", m)
	}
}

func TestReadingATopicReturnsOnlyThatTopic(t *testing.T) {
	s, c := fake(t, "engineering")
	s.Say("engineering", "a", "ann", 1, "in a")
	s.Say("engineering", "b", "ann", 1, "in b")
	got, err := c.Read(context.Background(), ReadQuery{Channel: "engineering", Topic: "b", Limit: 10})
	if err != nil || fmt.Sprint(contents(got.Messages)) != "[in b]" {
		t.Fatalf("%v %v", contents(got.Messages), err)
	}
}

// What the caller already has is not returned again: after_id asks for what is newer.
func TestReadingAfterAMessageReturnsOnlyWhatIsNewer(t *testing.T) {
	s, c := fake(t, "engineering")
	first := s.Say("engineering", "t", "ann", 1, "one")
	s.Say("engineering", "t", "ann", 1, "two")
	s.Say("engineering", "t", "ann", 1, "three")
	got, err := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 10, AfterID: first})
	if err != nil || fmt.Sprint(contents(got.Messages)) != "[two three]" {
		t.Fatalf("%v %v", contents(got.Messages), err)
	}
	none, _ := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 10, AfterID: got.Messages[1].ID})
	if len(none.Messages) != 0 {
		t.Errorf("nothing is newer: %v", contents(none.Messages))
	}
}

// The text is read as the person wrote it, not as HTML: apply_markdown is off, so a message cannot arrive as markup.
func TestTheContentIsAskedForAsRawTextNotRenderedHTML(t *testing.T) {
	s, c := fake(t, "engineering")
	s.Say("engineering", "t", "ann", 1, "**bold** text")
	c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 5})
	q := s.Queries()[0]
	// one more than the 5 asked for is taken, to know whether there is more behind them
	if q["apply_markdown"] != "false" || q["anchor"] != "newest" || q["num_before"] != "6" || q["num_after"] != "0" {
		t.Errorf("%v", q)
	}
	if !strings.Contains(q["narrow"], `"operator":"channel"`) || !strings.Contains(q["narrow"], `"operand":"engineering"`) {
		t.Errorf("narrow %s", q["narrow"])
	}
}

func TestAChannelTheBotIsNotSubscribedToIsRefusedAndNamedAsSuch(t *testing.T) {
	_, c := fake(t, "engineering")
	_, err := c.Read(context.Background(), ReadQuery{Channel: "secret", Limit: 5})
	if !errors.Is(err, ErrChannel) {
		t.Fatalf("%v", err)
	}
	_, err = c.Send(context.Background(), "secret", "t", "hello")
	if !errors.Is(err, ErrChannel) {
		t.Fatalf("%v", err)
	}
}

func TestSendPostsAChannelMessageWithItsTopicAndReturnsItsId(t *testing.T) {
	s, c := fake(t, "engineering")
	id, err := c.Send(context.Background(), "engineering", "deploy notes", "hello there")
	if err != nil || id == 0 {
		t.Fatalf("%d %v", id, err)
	}
	got := s.Sent()
	if len(got) != 1 || got[0].Channel != "engineering" || got[0].Topic != "deploy notes" || got[0].Content != "hello there" || got[0].Type != "channel" {
		t.Errorf("%+v", got)
	}
}

func TestAWrongKeyIsTold(t *testing.T) {
	s := zulipfake.New(zulipfake.Bot{Email: botEmail, Key: botKey, ID: 1, Name: "R"})
	defer s.Close()
	c, _ := New(s.URL, botEmail, "not-the-key-not-the-key-not-the-key-12", Options{HTTP: s.Client(), AllowInsecure: true})
	for name, call := range map[string]func() error{
		"me":   func() error { _, e := c.Me(context.Background()); return e },
		"read": func() error { _, e := c.Read(context.Background(), ReadQuery{Channel: "x", Limit: 1}); return e },
		"send": func() error { _, e := c.Send(context.Background(), "x", "t", "m"); return e },
	} {
		if err := call(); !errors.Is(err, ErrBadKey) {
			t.Errorf("%s: %v", name, err)
		}
	}
}

func TestATooLongMessageIsToldAndIsNotTheKeysFault(t *testing.T) {
	s, c := fake(t, "engineering")
	s.MaxLength = 20
	_, err := c.Send(context.Background(), "engineering", "t", strings.Repeat("x", 21))
	if !errors.Is(err, ErrTooLong) {
		t.Fatalf("%v", err)
	}
}

func TestAFloodIsToldWithTheTimeToWait(t *testing.T) {
	s, c := fake(t, "engineering")
	s.FailNext["POST /api/v1/messages"] = zulipfake.Failure{Status: 429, Code: "RATE_LIMIT_HIT", Msg: "API usage exceeded rate limit", RetryAfter: 28.7}
	_, err := c.Send(context.Background(), "engineering", "t", "m")
	var rl *RateLimitedError
	if !errors.As(err, &rl) || rl.RetryAfter < 28*time.Second || rl.RetryAfter > 30*time.Second {
		t.Fatalf("%v", err)
	}
}

// Whatever the server or the transport says is left out of an error: it can hold the key (the key is in the Authorization header, and
// a server may echo what it was sent).
func TestNoErrorHoldsTheKeyTheAddressOrWhatTheServerSaid(t *testing.T) {
	s, c := fake(t, "engineering")
	s.FailNext["GET /api/v1/messages"] = zulipfake.Failure{Status: 500, Code: "BAD_REQUEST", Msg: "boom " + botKey + " " + botEmail}
	_, err := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 1})
	if err == nil {
		t.Fatal("an error was expected")
	}
	for _, leak := range []string{botKey, botEmail, s.URL, "boom"} {
		if strings.Contains(err.Error(), leak) {
			t.Errorf("the error says %q: %v", leak, err)
		}
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { w.Write([]byte("not json " + botKey)) }))
	defer srv.Close()
	c2, _ := New(srv.URL, botEmail, botKey, Options{HTTP: srv.Client(), AllowInsecure: true})
	_, err = c2.Me(context.Background())
	if err == nil || strings.Contains(err.Error(), botKey) || strings.Contains(err.Error(), "not json") {
		t.Errorf("%v", err)
	}
	dead := httptest.NewServer(nil)
	deadURL := dead.URL
	dead.Close()
	c3, _ := New(deadURL, botEmail, botKey, Options{AllowInsecure: true, Timeout: time.Second})
	_, err = c3.Me(context.Background())
	if !errors.Is(err, ErrUnreachable) || strings.Contains(err.Error(), botKey) || strings.Contains(err.Error(), deadURL) {
		t.Errorf("%v", err)
	}
}

// A redirect is never followed: the key is in the headers, and a redirect would take it to wherever it points.
func TestARedirectIsNeverFollowed(t *testing.T) {
	var hit int
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { hit++ }))
	defer elsewhere.Close()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) { http.Redirect(w, r, elsewhere.URL, http.StatusFound) }))
	defer srv.Close()
	c, _ := New(srv.URL, botEmail, botKey, Options{HTTP: srv.Client(), AllowInsecure: true})
	if _, err := c.Me(context.Background()); err == nil {
		t.Error("a redirect was taken as an answer")
	}
	if hit != 0 {
		t.Errorf("the redirect was followed %d times, with the key", hit)
	}
}

func TestOnlyAnHTTPSSiteWithNothingElseInItIsAccepted(t *testing.T) {
	for _, bad := range []string{"", "http://x.zulipchat.com", "https://", "ftp://x.example", "https://user:pw@x.example", "https://x.example/path", "https://x.example?a=1", "https://x.example#f", "x.example", "https://x.example:99999", "https://127.0.0.1:1/"} {
		if _, err := New(bad, botEmail, botKey, Options{}); err == nil {
			t.Errorf("%q was accepted", bad)
		}
	}
	for _, good := range []string{"https://x.zulipchat.com", "https://x.zulipchat.com/", "https://chat.example.com:8443"} {
		if _, err := New(good, botEmail, botKey, Options{}); err != nil {
			t.Errorf("%q was refused: %v", good, err)
		}
	}
}

func TestTheClientNeverPrintsItsKey(t *testing.T) {
	_, c := fake(t, "engineering")
	for _, s := range []string{fmt.Sprint(c), fmt.Sprintf("%v", c), fmt.Sprintf("%+v", c), fmt.Sprintf("%#v", c), c.String()} {
		if strings.Contains(s, botKey) {
			t.Errorf("%s", s)
		}
	}
}

// With more new messages than fit, the caller reads on from the last one it got: so what is returned is the oldest of the newer ones,
// not the newest, or the ones in between would never be read.
func TestReadingAfterAMessageWithMoreNewerThanFitReturnsTheOldestOfThemAndSaysThereIsMore(t *testing.T) {
	s, c := fake(t, "engineering")
	first := s.Say("engineering", "t", "ann", 1, "m0")
	for i := 1; i <= 5; i++ {
		s.Say("engineering", "t", "ann", 1, fmt.Sprintf("m%d", i))
	}
	got, err := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 2, AfterID: first})
	if err != nil || fmt.Sprint(contents(got.Messages)) != "[m1 m2]" || !got.More {
		t.Fatalf("%v more=%v %v", contents(got.Messages), got.More, err)
	}
	next, _ := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 2, AfterID: got.Messages[1].ID})
	if fmt.Sprint(contents(next.Messages)) != "[m3 m4]" || !next.More {
		t.Errorf("reading on from the last one: %v more=%v", contents(next.Messages), next.More)
	}
	last, _ := c.Read(context.Background(), ReadQuery{Channel: "engineering", Limit: 2, AfterID: next.Messages[1].ID})
	if fmt.Sprint(contents(last.Messages)) != "[m5]" || last.More {
		t.Errorf("the rest: %v more=%v", contents(last.Messages), last.More)
	}
}

// A server that sends a huge answer is not believed past a bound: the answer is cut and refused, and the process does not hold it all.
func TestAnAnswerLargerThanTheBoundIsRefusedAndNotReadToTheEnd(t *testing.T) {
	var written atomic.Int64
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		w.Write([]byte(`{"result":"success","msg":"","pad":"`))
		chunk := []byte(strings.Repeat("a", 1<<20))
		for i := 0; i < 64; i++ { // 64 MiB offered
			n, err := w.Write(chunk)
			written.Add(int64(n))
			if err != nil {
				return
			}
		}
		w.Write([]byte(`"}`))
	}))
	defer srv.Close()
	c, _ := New(srv.URL, botEmail, botKey, Options{HTTP: srv.Client(), AllowInsecure: true})
	_, err := c.Me(context.Background())
	if err == nil {
		t.Fatal("an answer far over the bound was accepted")
	}
	// the server is told to stop only when the client closes the connection, which can be a moment after the call returned
	time.Sleep(200 * time.Millisecond)
	if n := written.Load(); n > 40<<20 {
		t.Errorf("%d MiB of an answer were taken before the bound was applied", n>>20)
	}
}
