package mcpserver

import (
	"fmt"
	"net/http"
	"os"
	"strings"
	"sync"
	"testing"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/zulip/zulipfake"
	"github.com/LeafAI/securl/internal/zulipsite"
)

const (
	zlEmail = "robot-bot@example.invalid"
	zlKey   = "ZKEY-abcdefghijklmnopqrstuvwxyz012345"
)

type zlEnv struct {
	*gateEnv
	api *zulipfake.Server
}

func boolPtr(b bool) *bool { return &b }

// toFake carries a request for the configured site to the fake: the configuration is checked as in the product (https, not this
// machine), and only the transport knows where the fake really is.
type toFake struct{ host string }

func (f toFake) RoundTrip(r *http.Request) (*http.Response, error) {
	c := r.Clone(r.Context())
	c.URL.Scheme, c.URL.Host = "http", f.host
	return http.DefaultTransport.RoundTrip(c)
}

const zlSite = "https://zulip.example.invalid"

// withZulip starts an open server with one Zulip server of three channels, a fake Zulip, and (optionally) a session for the bot as if
// a person had typed its key. The bot is subscribed to every channel but "hidden".
func withZulip(t *testing.T, session bool, tweak func(*config.Config)) *zlEnv {
	t.Helper()
	api := zulipfake.New(zulipfake.Bot{Email: zlEmail, Key: zlKey, ID: 77, Name: "Robot",
		Channels: map[string]bool{"Dev Team": true, "ops": true, "readonly": true}})
	t.Cleanup(api.Close)
	g := gateServer(t, "open", func(c *config.Config) {
		c.Zulip = []config.Zulip{{Name: "team", Site: zlSite, Email: zlEmail, Channels: []config.ZulipChannel{
			{Name: "dev", Channel: "Dev Team"},
			{Name: "alerts", Channel: "ops", Read: boolPtr(false)},
			{Name: "news", Channel: "readonly", Send: boolPtr(false)},
			{Name: "hidden", Channel: "hidden"},
		}}}
		if tweak != nil {
			tweak(c)
		}
	})
	g.s.zulipHTTP = &http.Client{Transport: toFake{host: strings.TrimPrefix(api.URL, "http://")}}
	e := &zlEnv{gateEnv: g, api: api}
	if session {
		e.login(t)
	}
	return e
}

func (e *zlEnv) login(t *testing.T) {
	t.Helper()
	sess := &site.Session{Tokens: map[string]string{zulipsite.TokenKey: zlKey, zulipsite.TokenName: "Robot"}}
	e.s.core.cache.Put(zulipsite.BaseURL("team"), e.s.zulipDriver(), sess)
}

func zsend(t *testing.T, e *zlEnv, channel, topic, text string) (map[string]any, bool) {
	t.Helper()
	return e.call(t, toolZulipSend, map[string]any{"server": "team", "channel": channel, "topic": topic, "text": text})
}

func zread(t *testing.T, e *zlEnv, args map[string]any) (map[string]any, bool) {
	t.Helper()
	args["server"], args["channel"] = "team", firstNonEmpty(fmt.Sprint(args["channel"]), "dev")
	if args["channel"] == "<nil>" {
		args["channel"] = "dev"
	}
	return e.call(t, toolZulipRead, args)
}

func firstNonEmpty(a, b string) string {
	if a == "" {
		return b
	}
	return a
}

// ---- zulip_targets ----

func TestZulipTargetsNamesServersAndChannelsAndNeverTheSiteTheEmailOrTheKeyOrAZulipChannelName(t *testing.T) {
	e := withZulip(t, true, nil)
	out, isErr := e.call(t, toolZulipTargets, map[string]any{})
	if isErr {
		t.Fatal(out)
	}
	s := raw(out)
	for _, want := range []string{`"team"`, `"dev"`, `"alerts"`, `"news"`, `"hidden"`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s is missing: %s", want, s)
		}
	}
	for _, secret := range []string{zlKey, zlEmail, zlSite, "zulip.example", "Dev Team", "readonly", "topic"} {
		if strings.Contains(s, secret) {
			t.Errorf("zulip_targets carries %q: %s", secret, s)
		}
	}
	if n := len(e.api.Calls); n != 0 {
		t.Errorf("listing the targets made %d requests", n)
	}
}

func TestZulipTargetsSaysWhatEachChannelAllowsAndWhetherThereIsASession(t *testing.T) {
	e := withZulip(t, true, nil)
	out, _ := e.call(t, toolZulipTargets, map[string]any{})
	srv := out["servers"].([]any)[0].(map[string]any)
	if srv["has_session"] != true {
		t.Error("a session exists")
	}
	want := map[string][2]bool{"dev": {true, true}, "alerts": {false, true}, "news": {true, false}, "hidden": {true, true}}
	for _, c := range srv["channels"].([]any) {
		m := c.(map[string]any)
		if w := want[m["name"].(string)]; m["read"] != w[0] || m["send"] != w[1] {
			t.Errorf("%v: want %v", m, w)
		}
	}
	out2, _ := withZulip(t, false, nil).call(t, toolZulipTargets, map[string]any{})
	if strings.Contains(raw(out2), `"has_session":true`) {
		t.Errorf("no session yet: %v", out2)
	}
}

// ---- zulip_send ----

func TestZulipSendPutsTheTextInTheNamedChannelUnderTheTopicTheAgentChose(t *testing.T) {
	e := withZulip(t, true, nil)
	out, isErr := zsend(t, e, "dev", "deploy 42", "the deploy finished")
	if isErr || out["sent"] != true || out["message_id"] == nil {
		t.Fatalf("%v %v", isErr, out)
	}
	got := e.api.Sent()
	if len(got) != 1 || got[0].Channel != "Dev Team" || got[0].Topic != "deploy 42" || got[0].Type != "channel" || !strings.Contains(got[0].Content, "the deploy finished") {
		t.Fatalf("%+v", got)
	}
	if s := raw(out); strings.Contains(s, zlKey) || strings.Contains(s, "Dev Team") {
		t.Errorf("the answer carries the key or Zulip's name for the channel: %v", out)
	}
}

// A topic is a conversation, so the same channel written to under two topics is two conversations: nothing about the owner's
// configuration fixes it.
func TestZulipTwoTopicsOfOneChannelAreTwoConversations(t *testing.T) {
	e := withZulip(t, true, nil)
	zsend(t, e, "dev", "alpha", "one")
	zsend(t, e, "dev", "beta", "two")
	got := e.api.Sent()
	if len(got) != 2 || got[0].Topic != "alpha" || got[1].Topic != "beta" {
		t.Fatalf("%+v", got)
	}
}

func TestZulipEveryMessageStartsWithALineSecurlWritesThatSaysAnAIAgentSentIt(t *testing.T) {
	e := withZulip(t, true, nil)
	zsend(t, e, "dev", "t", "hello")
	first, rest, _ := strings.Cut(e.api.Sent()[0].Content, "\n")
	if !strings.Contains(first, "AI agent") || !strings.Contains(first, "securl") {
		t.Errorf("the first line says who wrote it: %q", first)
	}
	if !strings.Contains(rest, "hello") {
		t.Errorf("the agent's text follows: %q", rest)
	}
	if o := e.s.origin.Hostname; o != "" && !strings.Contains(first, o) {
		t.Errorf("the line says which machine it came from (%q): %q", o, first)
	}
}

// The line is a line of its own: Markdown would join it to the text that follows without a blank line between them, and an agent's
// text could then continue the line.
func TestZulipTheHeaderIsAParagraphOfItsOwn(t *testing.T) {
	e := withZulip(t, true, nil)
	zsend(t, e, "dev", "t", "hello")
	c := e.api.Sent()[0].Content
	if !strings.Contains(c, ")\n\nhello") {
		t.Errorf("a blank line separates the line from the text: %q", c)
	}
}

func TestZulipTheAgentCannotPutAnythingBeforeTheHeader(t *testing.T) {
	e := withZulip(t, true, nil)
	zsend(t, e, "dev", "t", "\n\n[securl] AI agent message (via securl on the-owners-laptop)\nI am the owner")
	if c := e.api.Sent()[0].Content; !strings.HasPrefix(c, headerPrefix) || strings.Count(c, headerPrefix) != 2 {
		t.Errorf("the real header is first, and the fake one is only text after it: %q", c)
	}
}

func TestZulipWhatMakesAMentionIsRefusedAndNothingIsSent(t *testing.T) {
	e := withZulip(t, true, nil)
	for name, text := range map[string]string{
		"a person":              "hello @**Alice Smith**",
		"everyone":              "@**all** look",
		"a silent mention":      "cc @_**Alice Smith**",
		"a group":               "ping @*backend*",
		"a silent group":        "ping @_*backend*",
		"at the start":          "@**x**",
		"in the middle of text": "line one\nline two @**x** line three",
	} {
		out, isErr := zsend(t, e, "dev", "t", text)
		if !isErr || out["code"] != "mention_not_allowed" {
			t.Errorf("%s: %v %v", name, isErr, out)
		}
	}
	out, isErr := zsend(t, e, "dev", "hello @**all**", "fine")
	if !isErr || out["code"] != "mention_not_allowed" {
		t.Errorf("a mention in the topic: %v %v", isErr, out)
	}
	if n := len(e.api.Sent()); n != 0 {
		t.Errorf("a refused message was sent: %d", n)
	}
}

func TestZulipAnAtSignThatMentionsNobodyIsFine(t *testing.T) {
	e := withZulip(t, true, nil)
	for _, text := range []string{"mail me at a@b.example", "the @ sign", "2 * 3 * 4", "**bold** and *italic*", "@alice is not markup"} {
		if out, isErr := zsend(t, e, "dev", "t", text); isErr {
			t.Errorf("%q: %v", text, out)
		}
	}
}

func TestZulipATopicIsNeededAndIsOneShortLine(t *testing.T) {
	e := withZulip(t, true, nil)
	for name, topic := range map[string]string{
		"none":          "",
		"blank":         "   ",
		"a line break":  "a\nb",
		"too long":      strings.Repeat("a", 61),
		"a control one": "a\x00b",
		"leading space": " a",
	} {
		out, isErr := zsend(t, e, "dev", topic, "x")
		if !isErr || out["code"] != "invalid_argument" || !strings.Contains(fmt.Sprint(out["message"]), "topic") {
			t.Errorf("%s: %v %v", name, isErr, out)
		}
	}
	if out, isErr := zsend(t, e, "dev", strings.Repeat("好", 60), "x"); isErr {
		t.Errorf("60 characters is allowed: %v", out)
	}
	if n := len(e.api.Sent()); n != 1 {
		t.Errorf("only the good one was sent: %d", n)
	}
}

func TestZulipTheTextIsLimitedAndTheErrorSaysByHowMuch(t *testing.T) {
	e := withZulip(t, true, nil)
	out, isErr := zsend(t, e, "dev", "t", strings.Repeat("x", 9001))
	if !isErr || out["code"] != "text_too_long" || !strings.Contains(fmt.Sprint(out["message"]), "1 more than the 9000") {
		t.Fatalf("%v %v", isErr, out)
	}
	if out, isErr := zsend(t, e, "dev", "t", strings.Repeat("x", 9000)); isErr {
		t.Errorf("exactly the limit: %v", out)
	}
}

func TestZulipEmptyOrBlankTextIsRefusedBeforeAnythingIsSent(t *testing.T) {
	e := withZulip(t, true, nil)
	for _, text := range []string{"", "   ", "\n\t "} {
		if out, isErr := zsend(t, e, "dev", "t", text); !isErr || out["code"] != "invalid_argument" {
			t.Errorf("%q: %v %v", text, isErr, out)
		}
	}
	if len(e.api.Sent()) != 0 || len(e.api.Calls) != 0 {
		t.Error("a refused call reached Zulip")
	}
}

func TestZulipAnAgentCanOnlyUseAServerAndChannelTheOwnerWroteDown(t *testing.T) {
	e := withZulip(t, true, nil)
	for name, args := range map[string]map[string]any{
		"an unknown server":            {"server": "other", "channel": "dev"},
		"zulip's own name":             {"server": "team", "channel": "Dev Team"},
		"a channel that is subscribed": {"server": "team", "channel": "ops"},
		"an empty channel":             {"server": "team", "channel": ""},
		"an empty server":              {"server": "", "channel": "dev"},
	} {
		args["topic"], args["text"] = "t", "x"
		out, isErr := e.call(t, toolZulipSend, args)
		if !isErr || out["code"] != "unknown_target" {
			t.Errorf("%s: %v %v", name, isErr, out)
		}
	}
	if len(e.api.Sent()) != 0 {
		t.Error("something was sent")
	}
}

func TestZulipThereIsNoArgumentThatTakesASiteAKeyAnEmailOrADirectRecipient(t *testing.T) {
	e := withZulip(t, true, nil)
	for _, extra := range []string{"site", "url", "key", "api_key", "email", "to", "type", "stream", "stream_id", "user_id", "proxy", "queue_id", "widget_content"} {
		out, isErr := e.call(t, toolZulipSend, map[string]any{"server": "team", "channel": "dev", "topic": "t", "text": "x", extra: "v"})
		if !isErr || out["code"] != "invalid_argument" {
			t.Errorf("%s: an argument that is not in the schema is refused, not ignored: %v %v", extra, isErr, out)
		}
	}
	if len(e.api.Sent()) != 0 {
		t.Error("a call with an unknown argument sent something")
	}
}

func TestZulipAChannelThatCannotBeSentToIsRefusedAndOneThatCannotBeReadIsToo(t *testing.T) {
	e := withZulip(t, true, nil)
	if out, isErr := zsend(t, e, "news", "t", "x"); !isErr || out["code"] != "channel_not_writable" {
		t.Errorf("%v %v", isErr, out)
	}
	if out, isErr := e.call(t, toolZulipRead, map[string]any{"server": "team", "channel": "alerts"}); !isErr || out["code"] != "channel_not_readable" {
		t.Errorf("%v %v", isErr, out)
	}
	if out, isErr := zsend(t, e, "alerts", "t", "x"); isErr {
		t.Errorf("a send-only channel is sent to: %v", out)
	}
	if out, isErr := zread(t, e, map[string]any{"channel": "news"}); isErr {
		t.Errorf("a read-only channel is read: %v", out)
	}
}

func TestZulipWithNoSessionTheToolsSayAPersonMustTypeTheKeyAndNameTheTool(t *testing.T) {
	e := withZulip(t, false, nil)
	for _, out := range []map[string]any{
		must(zsend(t, e, "dev", "t", "x")),
		must(zread(t, e, map[string]any{})),
	} {
		if out["code"] != "no_session" || !strings.Contains(fmt.Sprint(out["hint"]), "zulip://team") || !strings.Contains(fmt.Sprint(out["hint"]), toolSessionOpen) {
			t.Errorf("%v", out)
		}
	}
	if len(e.api.Calls) != 0 {
		t.Error("Zulip was contacted with no key")
	}
}

func must(out map[string]any, isErr bool) map[string]any {
	if !isErr {
		panic("expected an error")
	}
	return out
}

// ---- the limit ----

func TestZulipTheSendLimitIsPerServerAcrossItsChannelsAndSaysWhenToRetry(t *testing.T) {
	e := withZulip(t, true, func(c *config.Config) { c.Zulip[0].SendMax = 3 })
	for i, ch := range []string{"dev", "alerts", "dev"} {
		if out, isErr := zsend(t, e, ch, "t", fmt.Sprint(i)); isErr {
			t.Fatalf("message %d: %v", i, out)
		}
	}
	out, isErr := zsend(t, e, "dev", "t", "one too many")
	if !isErr || out["code"] != "rate_limited" || !strings.Contains(fmt.Sprint(out["message"]), "retry in") {
		t.Fatalf("%v %v", isErr, out)
	}
	if len(e.api.Sent()) != 3 {
		t.Errorf("a refused message was sent: %d", len(e.api.Sent()))
	}
}

func TestZulipARefusedMessageCostsNothingAgainstTheLimit(t *testing.T) {
	e := withZulip(t, true, func(c *config.Config) { c.Zulip[0].SendMax = 2 })
	zsend(t, e, "dev", "t", "")                        // empty
	zsend(t, e, "news", "t", "x")                      // not writable
	zsend(t, e, "nope", "t", "x")                      // unknown
	zsend(t, e, "dev", "t", strings.Repeat("x", 9001)) // too long
	zsend(t, e, "dev", "", "x")                        // no topic
	zsend(t, e, "dev", "t", "@**all**")                // a mention
	for i := 0; i < 2; i++ {
		if out, isErr := zsend(t, e, "dev", "t", fmt.Sprint(i)); isErr {
			t.Fatalf("a refused call used up the limit: %v", out)
		}
	}
}

func TestZulipWhenZulipSaysSlowDownTheAnswerSaysWhenAndTheNextCallsWaitWithoutAskingAgain(t *testing.T) {
	e := withZulip(t, true, nil)
	e.api.FailNext["POST /api/v1/messages"] = zulipfake.Failure{Status: 429, Code: "RATE_LIMIT_HIT", Msg: "API usage exceeded rate limit", RetryAfter: 30}
	out, isErr := zsend(t, e, "dev", "t", "x")
	if !isErr || out["code"] != "rate_limited" || out["retryable"] != true {
		t.Fatalf("%v %v", isErr, out)
	}
	before := e.api.Calls["POST /api/v1/messages"]
	if out2, isErr2 := zsend(t, e, "dev", "t", "y"); !isErr2 || out2["code"] != "rate_limited" {
		t.Errorf("%v %v", isErr2, out2)
	}
	if e.api.Calls["POST /api/v1/messages"] != before {
		t.Error("securl asked Zulip again while it had been told to wait")
	}
}

func TestZulipSeveralSendsAtOnceNeverGoPastTheLimit(t *testing.T) {
	e := withZulip(t, true, func(c *config.Config) { c.Zulip[0].SendMax = 5 })
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, isErr := zsend(t, e, "dev", "t", fmt.Sprint(i)); !isErr {
				mu.Lock()
				ok++
				mu.Unlock()
			}
		}(i)
	}
	wg.Wait()
	if ok != 5 || len(e.api.Sent()) != 5 {
		t.Errorf("%d answers said sent, %d messages went out, the limit is 5", ok, len(e.api.Sent()))
	}
}

func TestZulipASendThatZulipFailsCostsNothingAgainstTheLimit(t *testing.T) {
	e := withZulip(t, true, func(c *config.Config) { c.Zulip[0].SendMax = 1 })
	e.api.FailNext["POST /api/v1/messages"] = zulipfake.Failure{Status: 502, Msg: "Bad Gateway"}
	if _, isErr := zsend(t, e, "dev", "t", "x"); !isErr {
		t.Fatal("the failure was not reported")
	}
	if out, isErr := zsend(t, e, "dev", "t", "y"); isErr {
		t.Errorf("an outage used up the limit: %v", out)
	}
}

// ---- Zulip's own refusals ----

func TestZulipAChannelTheBotIsNotSubscribedToIsSaidAsSuch(t *testing.T) {
	e := withZulip(t, true, nil)
	out, isErr := zsend(t, e, "hidden", "t", "x")
	if !isErr || out["code"] != "channel_not_reachable" || !strings.Contains(fmt.Sprint(out["hint"]), "subscribe") {
		t.Errorf("%v %v", isErr, out)
	}
	out, isErr = zread(t, e, map[string]any{"channel": "hidden"})
	if !isErr || out["code"] != "channel_not_reachable" {
		t.Errorf("%v %v", isErr, out)
	}
}

func TestZulipAServerThatSaysTheMessageIsTooLongIsSaidAsSuch(t *testing.T) {
	e := withZulip(t, true, nil)
	e.api.MaxLength = 100
	out, isErr := zsend(t, e, "dev", "t", strings.Repeat("x", 500))
	if !isErr || out["code"] != "text_too_long" {
		t.Errorf("%v %v", isErr, out)
	}
}

func TestZulipARevokedKeyEndsTheSessionAndSaysSo(t *testing.T) {
	e := withZulip(t, true, nil)
	e.api.Revoke(zlEmail)
	out, isErr := zsend(t, e, "dev", "t", "x")
	if !isErr || out["code"] != "session_expired" || !strings.Contains(fmt.Sprint(out["hint"]), "zulip://team") {
		t.Fatalf("%v %v", isErr, out)
	}
	if _, ok := e.s.core.cache.Peek(zulipsite.Key("team")); ok {
		t.Error("the session of a key that Zulip refuses is kept")
	}
	if s := raw(out); strings.Contains(s, zlKey) {
		t.Errorf("the key is in the error: %s", s)
	}
}

// ---- audit ----

func zaudit(t *testing.T, e *zlEnv) string {
	t.Helper()
	b, err := os.ReadFile(e.cfg.Audit.File)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

func TestZulipEverySendIsAuditedWithTheTargetTheSizeAndAHashButNeverTheTextOrTheTopic(t *testing.T) {
	e := withZulip(t, true, nil)
	zsend(t, e, "dev", "the staging password", "the staging password is hunter2 and the number is 4111-1111")
	a := zaudit(t, e)
	if !strings.Contains(a, `"event":"zulip_send"`) || !strings.Contains(a, `"server":"team"`) || !strings.Contains(a, `"channel":"dev"`) {
		t.Errorf("the send is audited with its target:\n%s", a)
	}
	if !strings.Contains(a, "text_bytes") || !strings.Contains(a, "text_sha256") {
		t.Errorf("with the size and a hash:\n%s", a)
	}
	for _, leak := range []string{"hunter2", "4111", "staging password", zlKey, zlEmail, "Dev Team"} {
		if strings.Contains(a, leak) {
			t.Errorf("the audit log carries %q:\n%s", leak, a)
		}
	}
}

func TestZulipARefusedSendIsAuditedToo(t *testing.T) {
	e := withZulip(t, true, func(c *config.Config) { c.Zulip[0].SendMax = 1 })
	zsend(t, e, "dev", "t", "ok")
	zsend(t, e, "dev", "t", "over")
	zsend(t, e, "news", "t", "not writable")
	zsend(t, e, "dev", "t", "@**all**")
	a := zaudit(t, e)
	if strings.Count(a, `"event":"zulip_send"`) < 4 {
		t.Errorf("sent, rate limited and two refused are all in the trail:\n%s", a)
	}
	for _, why := range []string{"rate_limited", "channel_not_writable", "mention_not_allowed"} {
		if !strings.Contains(a, why) {
			t.Errorf("%s is not said:\n%s", why, a)
		}
	}
}
