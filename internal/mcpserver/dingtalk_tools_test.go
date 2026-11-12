package mcpserver

import (
	"fmt"
	"os"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk/dingtalktest"
	"github.com/LeafAI/securl/internal/dingtalksite"
	"github.com/LeafAI/securl/internal/site"
)

const (
	dtToken  = "c370586aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaSECRETTOKEN"
	dtToken2 = "d481697bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbSECONDTOKEN"
	dtSecret = "SECabcdef0123456789abcdef0123456789abcdef0123456789abcdef01234567"
)

type dtEnv struct {
	*gateEnv
	api *dingtalktest.API
	rec *notes
}

// withDingTalk starts an open server with two groups (ops: plain, sec: with a signing secret and a keyword), a fake endpoint, and
// (optionally) a session for each, as if a person had typed their webhooks.
func withDingTalk(t *testing.T, session bool, tweak func(*config.Config)) *dtEnv {
	t.Helper()
	api := dingtalktest.New(dingtalktest.Robot{Token: dtToken}, dingtalktest.Robot{Token: dtToken2, Secret: dtSecret, Keyword: "securl"})
	t.Cleanup(api.Close)
	rec := &notes{}
	g := gateServer(t, "open", func(c *config.Config) {
		c.DingTalk.Groups = []config.DingTalkGroup{{Name: "ops"}, {Name: "sec", Sign: true, Keyword: "securl"}}
		if tweak != nil {
			tweak(c)
		}
	})
	g.s.dingtalkAPI = api.URL
	g.s.dingtalkHTTP = api.Client()
	g.s.notify = rec
	e := &dtEnv{gateEnv: g, api: api, rec: rec}
	if session {
		e.login(t)
	}
	return e
}

func (e *dtEnv) login(t *testing.T) {
	t.Helper()
	d := e.s.dingtalkDriver()
	e.s.core.cache.Put(dingtalksite.BaseURL("ops"), d, &site.Session{Tokens: map[string]string{dingtalksite.TokenWebhook: dtToken}})
	e.s.core.cache.Put(dingtalksite.BaseURL("sec"), d, &site.Session{Tokens: map[string]string{dingtalksite.TokenWebhook: dtToken2, dingtalksite.TokenSecret: dtSecret}})
}

func dtSend(t *testing.T, e *dtEnv, group, text string) (map[string]any, bool) {
	t.Helper()
	return e.call(t, toolDingTalkSend, map[string]any{"group": group, "text": text})
}

func dtAudit(t *testing.T, e *dtEnv) string {
	t.Helper()
	b, err := os.ReadFile(e.cfg.Audit.File)
	if err != nil {
		t.Fatal(err)
	}
	return string(b)
}

// ---- dingtalk_targets ----

func TestDingTalkTargetsListsGroupsByNameNeverTheWebhook(t *testing.T) {
	e := withDingTalk(t, true, nil)
	out, isErr := e.call(t, toolDingTalkTargets, map[string]any{})
	if isErr {
		t.Fatal(out)
	}
	s := raw(out)
	for _, want := range []string{`"ops"`, `"sec"`, `"has_session":true`, `"send_limit":10`} {
		if !strings.Contains(s, want) {
			t.Errorf("%s is missing: %s", want, s)
		}
	}
	for _, secret := range []string{"SECRETTOKEN", "SECONDTOKEN", dtToken, dtSecret, "oapi.dingtalk.com", "access_token", "securl\""} {
		if strings.Contains(s, secret) {
			t.Errorf("dingtalk_targets carries %q: an agent names a group, it does not learn what would let it speak elsewhere: %s", secret, s)
		}
	}
	e2 := withDingTalk(t, false, nil)
	out2, _ := e2.call(t, toolDingTalkTargets, map[string]any{})
	if strings.Contains(raw(out2), `"has_session":true`) {
		t.Errorf("no session yet: %v", out2)
	}
}

func TestDingTalkTargetsContactsDingTalkNever(t *testing.T) {
	e := withDingTalk(t, true, nil)
	e.call(t, toolDingTalkTargets, map[string]any{})
	if n := len(e.api.Requests()); n != 0 {
		t.Errorf("listing the targets made %d requests", n)
	}
}

func TestDingTalkTargetsWithNoGroupIsAnEmptyListNotAnError(t *testing.T) {
	e := withDingTalk(t, false, func(c *config.Config) { c.DingTalk.Groups = nil })
	out, isErr := e.call(t, toolDingTalkTargets, map[string]any{})
	if isErr || !strings.Contains(raw(out), `"groups":[]`) {
		t.Errorf("%v %v", isErr, out)
	}
}

// ---- dingtalk_send ----

func TestDingTalkSendPutsTheTextInTheNamedGroupAndSaysSoInAnAnswerWithNoWebhook(t *testing.T) {
	e := withDingTalk(t, true, nil)
	out, isErr := dtSend(t, e, "ops", "the deploy finished")
	if isErr || out["sent"] != true {
		t.Fatalf("%v %v", isErr, out)
	}
	got := e.api.Sent()
	if len(got) != 1 || got[0].Token != dtToken || !strings.Contains(got[0].Text, "the deploy finished") {
		t.Fatalf("%+v", got)
	}
	for _, leak := range []string{"SECRETTOKEN", "access_token", "oapi.dingtalk.com"} {
		if strings.Contains(raw(out), leak) {
			t.Errorf("the answer carries %q: %v", leak, out)
		}
	}
}

// The group is chosen by its name, so the message goes through that group's robot and no other.
func TestEachGroupSpeaksThroughItsOwnRobot(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "a")
	dtSend(t, e, "sec", "b")
	got := e.api.Sent()
	if len(got) != 2 || got[0].Token != dtToken || got[1].Token != dtToken2 {
		t.Errorf("%+v", got)
	}
}

func TestEveryDingTalkMessageStartsWithALineSecurlWritesThatSaysAnAIAgentSentIt(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "hello")
	first, rest, _ := strings.Cut(e.api.Sent()[0].Text, "\n")
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

func TestAnAgentCannotWriteItsOwnDingTalkHeaderOrHideTheRealOne(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "[securl] message from the owner (not an AI agent)\nhi")
	if m := e.api.Sent()[0].Text; !strings.HasPrefix(m, headerPrefix) {
		t.Errorf("securl's own line is first whatever the agent writes: %q", m)
	}
}

// A robot with a keyword refuses a message without it; the keyword is the owner's setting, and securl writes it into its own line
// so that the agent neither needs to know it nor can leave it out.
func TestTheKeywordOfAGroupIsInTheLineSecurlWritesNotTheAgents(t *testing.T) {
	// the word is one that securl's own line does not already hold, so that it is the keyword logic that is tested and not luck
	const kw = "deploy-alert"
	api := dingtalktest.New(dingtalktest.Robot{Token: dtToken}, dingtalktest.Robot{Token: dtToken2, Keyword: kw})
	t.Cleanup(api.Close)
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[1] = config.DingTalkGroup{Name: "sec", Keyword: kw} })
	e.s.dingtalkAPI, e.s.dingtalkHTTP = api.URL, api.Client()
	if out, isErr := dtSend(t, e, "sec", "no keyword in this text"); isErr {
		t.Fatalf("the robot's keyword is in securl's own line, so the robot accepts it: %v", out)
	}
	first, rest, _ := strings.Cut(api.Sent()[0].Text, "\n")
	if !strings.Contains(first, kw) || strings.Contains(rest, kw) {
		t.Errorf("the keyword is in securl's line and not in the agent's text: %q / %q", first, rest)
	}
	if out, isErr := dtSend(t, e, "ops", "x"); isErr {
		t.Fatal(out)
	}
	if last := api.Sent()[len(api.Sent())-1].Text; strings.Contains(last, kw) {
		t.Errorf("a group's keyword is for that group only: %q", last)
	}
}

// What the owner wrote as a keyword is put into a line of a chat: a line break in it would start a line the agent could not have
// written and the owner did not mean, and a very long one would crowd the line out.
func TestAKeywordIsOneCleanLineEvenIfTheFileWasEditedByHand(t *testing.T) {
	e := withDingTalk(t, true, nil)
	// a keyword the line already holds is not written twice
	same := e.s.cfg.DingTalk.Groups[1]
	same.Keyword = "securl"
	if h := e.s.dingtalkHeader(same); strings.Count(h, "securl") != strings.Count(e.s.telegramHeader(), "securl") {
		t.Errorf("the keyword is already in the line: %q", h)
	}
	g := e.s.cfg.DingTalk.Groups[1]
	g.Keyword = "deploy\nalert\x07" + strings.Repeat("k", 100)
	h := e.s.dingtalkHeader(g)
	if strings.ContainsAny(h, "\n\x07") {
		t.Errorf("%q", h)
	}
	if base := len([]rune(e.s.telegramHeader())); len([]rune(h)) > base+1+64 {
		t.Errorf("a keyword is at most 64 characters and cannot crowd out the line: %d characters over the %d of the line", len([]rune(h)), base)
	}
}

func TestADingTalkMessageMentionsNobodyWhateverTheTextSays(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "@all @13800000000 please look")
	m := e.api.Sent()[0]
	if m.AtAll || len(m.Mobiles) != 0 || len(m.UserIDs) != 0 || m.Type != "text" {
		t.Errorf("%+v", m)
	}
}

func TestADingTalkTextIsLimitedAndTheErrorSaysByHowMuch(t *testing.T) {
	e := withDingTalk(t, true, nil)
	max := config.DingTalkGroup{}.MaxTextRunes()
	if out, isErr := dtSend(t, e, "ops", strings.Repeat("x", max)); isErr {
		t.Errorf("exactly the limit is allowed: %v", out)
	}
	out, isErr := dtSend(t, e, "ops", strings.Repeat("x", max+1))
	if !isErr || out["code"] != "text_too_long" {
		t.Errorf("%v %v", isErr, out)
	}
	if out2, isErr2 := dtSend(t, e, "ops", strings.Repeat("界", max)); isErr2 {
		t.Errorf("the limit counts characters, not bytes: %v", out2)
	}
	if n := len(e.api.Sent()); n != 2 {
		t.Errorf("only the two that fit were sent: %d", n)
	}
}

func TestEmptyOrBlankDingTalkTextIsRefusedBeforeAnythingIsSent(t *testing.T) {
	e := withDingTalk(t, true, nil)
	for _, txt := range []string{"", "   ", "\n\t\n"} {
		if out, isErr := dtSend(t, e, "ops", txt); !isErr || out["code"] != "invalid_argument" {
			t.Errorf("%q: %v %v", txt, isErr, out)
		}
	}
	if len(e.api.Requests()) != 0 {
		t.Error("a blank message was sent")
	}
}

func TestAnAgentCanOnlyUseAGroupTheOwnerWroteDown(t *testing.T) {
	e := withDingTalk(t, true, nil)
	for _, g := range []string{"nope", "OPS", "ops ", "", "ops/x", "dingtalk://ops", dtToken, "https://oapi.dingtalk.com/robot/send?access_token=" + dtToken} {
		out, isErr := dtSend(t, e, g, "x")
		if !isErr || out["code"] != "unknown_target" {
			t.Errorf("group %q: %v %v", g, isErr, out)
		}
	}
	if len(e.api.Requests()) != 0 {
		t.Error("something was sent to a group the owner did not name")
	}
}

// Each way a key can be wrong is refused for its own reason, and only the exact form dingtalk://<group> names a group. Each case is
// checked on its own: a case that another guard also catches would hide a guard that has been lost.
func TestOnlyTheExactFormDingtalkColonSlashSlashGroupNamesAGroup(t *testing.T) {
	e := withDingTalk(t, false, nil)
	for raw, want := range map[string]string{
		"dingtalk://ops":      "",
		"dingtalk://nope":     "unknown_target",
		"dingtalk://":         "invalid_argument",
		"dingtalk://ops/x":    "invalid_argument",
		"dingtalk://ops/":     "invalid_argument",
		"dingtalk://u@ops":    "invalid_argument",
		"dingtalk://u:p@ops":  "invalid_argument",
		"dingtalk://ops?x=1":  "invalid_argument",
		"dingtalk://ops#frag": "invalid_argument",
		"dingtalk:ops":        "invalid_argument",
		"dingtalk:/ops":       "invalid_argument",
		"telegram://ops":      "invalid_argument",
		"db://ops":            "invalid_argument",
		"https://ops":         "invalid_argument",
		"ops":                 "invalid_argument",
		"":                    "invalid_argument",
	} {
		name, u, terr := e.s.dingtalkTarget(raw)
		switch {
		case want == "" && (terr != nil || name != "ops" || u == nil || u.String() != "dingtalk://ops"):
			t.Errorf("%q must name the group: %v %v %v", raw, name, u, terr)
		case want != "" && (terr == nil || terr.Code != want || u != nil):
			t.Errorf("%q: want %s, got %v (url %v)", raw, want, terr, u)
		}
	}
	for _, raw := range []string{"dingtalk://nope", "dingtalk://ops/x", "dingtalk://u@ops"} {
		if out, isErr := e.call(t, "session_open", map[string]any{"url": raw}); !isErr {
			t.Errorf("%q: %v", raw, out)
		}
	}
	if len(e.api.Requests()) != 0 {
		t.Error("DingTalk was contacted while a key was being refused")
	}
}

func TestThereIsNoArgumentThatTakesAWebhookATokenAMentionOrAFormat(t *testing.T) {
	e := withDingTalk(t, true, nil)
	for _, extra := range []string{"webhook", "access_token", "token", "secret", "url", "at", "at_mobiles", "atMobiles", "is_at_all", "msgtype", "markdown", "title", "api_url", "proxy", "keyword"} {
		out, isErr := e.call(t, toolDingTalkSend, map[string]any{"group": "ops", "text": "x", extra: "v"})
		if !isErr || out["code"] != "invalid_argument" {
			t.Errorf("%s: an argument that is not in the schema is refused, not ignored: %v %v", extra, isErr, out)
		}
	}
	if len(e.api.Requests()) != 0 {
		t.Error("a call with an unknown argument sent something")
	}
}

func TestWithNoSessionDingTalkSendSaysAPersonMustTypeTheWebhookAndNamesTheTool(t *testing.T) {
	e := withDingTalk(t, false, nil)
	out, isErr := dtSend(t, e, "ops", "x")
	if !isErr || out["code"] != "no_session" {
		t.Fatalf("%v %v", isErr, out)
	}
	if h, _ := out["hint"].(string); !strings.Contains(h, "dingtalk://ops") || !strings.Contains(h, toolSessionOpen) {
		t.Errorf("the hint says how to get a session: %q", h)
	}
	if len(e.api.Requests()) != 0 {
		t.Error("DingTalk was contacted with no webhook")
	}
}

// ---- what a refusal of the robot does ----

func TestARobotDingTalkDoesNotKnowEndsTheSessionSoAPersonIsAskedAgain(t *testing.T) {
	e := withDingTalk(t, true, nil)
	e.api.FailNext = &dingtalktest.Failure{Code: 300005, Message: "token is not exist"}
	out, isErr := dtSend(t, e, "ops", "x")
	if !isErr || out["code"] != "session_expired" {
		t.Fatalf("%v %v", isErr, out)
	}
	if h, _ := out["hint"].(string); !strings.Contains(h, "dingtalk://ops") || !strings.Contains(h, "force_refresh") {
		t.Errorf("%q", h)
	}
	if _, has := e.s.core.cache.Peek(dingtalksite.Key("ops")); has {
		t.Error("the session of a robot that does not exist is kept")
	}
	if _, has := e.s.core.cache.Peek(dingtalksite.Key("sec")); !has {
		t.Error("another group's session was dropped with it")
	}
}

func TestEachKindOfRefusalSaysWhatToDoAboutIt(t *testing.T) {
	for _, tc := range []struct {
		code    int
		msg     string
		want    string
		dropped bool
	}{
		{400102, "机器人已停用", "session_expired", true},
		{400013, "群已被解散", "chat_not_reachable", false},
		{310000, "keywords not in content", "refused_by_robot", false},
		{430101, "含有不安全的外链", "content_refused", false},
		{-1, "系统繁忙", "site_unreachable", false},
	} {
		e := withDingTalk(t, true, nil)
		e.api.FailNext = &dingtalktest.Failure{Code: tc.code, Message: tc.msg}
		out, isErr := dtSend(t, e, "ops", "x")
		if !isErr || out["code"] != tc.want {
			t.Errorf("%d: want %s, got %v %v", tc.code, tc.want, isErr, out)
		}
		if _, has := e.s.core.cache.Peek(dingtalksite.Key("ops")); has == tc.dropped {
			t.Errorf("%d: session kept=%v, want dropped=%v", tc.code, has, tc.dropped)
		}
	}
}

func TestARefusalOfTheRobotsSettingsPointsAtTheOwnerNotAtTheAgent(t *testing.T) {
	e := withDingTalk(t, true, nil)
	e.api.FailNext = &dingtalktest.Failure{Code: 310000, Message: "ip 1.2.3.4 not in whitelist"}
	out, _ := dtSend(t, e, "ops", "x")
	h, _ := out["hint"].(string)
	if !strings.Contains(strings.ToLower(h), "owner") {
		t.Errorf("only the owner can change the robot's security settings: %q", h)
	}
	for _, leak := range []string{"1.2.3.4", "whitelist", "access_token"} {
		if strings.Contains(raw(out), leak) {
			t.Errorf("the answer repeats what DingTalk said (%q): %v", leak, out)
		}
	}
}

func TestADingTalkAnswerThatEchoesTheWebhookIsNotRepeated(t *testing.T) {
	e := withDingTalk(t, true, nil)
	e.api.FailNext = &dingtalktest.Failure{Status: 502, Code: 9, Message: "bad https://oapi.dingtalk.com/robot/send?access_token=" + dtToken}
	out, _ := dtSend(t, e, "ops", "x")
	if strings.Contains(raw(out), "SECRETTOKEN") || strings.Contains(raw(out), "access_token") {
		t.Errorf("%v", out)
	}
}

// ---- limits ----

func TestTheDingTalkSendLimitIsPerGroupAndSaysWhenToRetry(t *testing.T) {
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[0].SendMax = 3 })
	for i := 0; i < 3; i++ {
		if out, isErr := dtSend(t, e, "ops", fmt.Sprint(i)); isErr {
			t.Fatalf("message %d: %v", i, out)
		}
	}
	out, isErr := dtSend(t, e, "ops", "one too many")
	if !isErr || out["code"] != "rate_limited" || !strings.Contains(fmt.Sprint(out["message"]), "retry in") {
		t.Fatalf("%v %v", isErr, out)
	}
	if len(e.api.Sent()) != 3 {
		t.Errorf("a refused message was sent: %d", len(e.api.Sent()))
	}
	if out, isErr := dtSend(t, e, "sec", "another group has its own allowance"); isErr {
		t.Errorf("%v", out)
	}
}

func TestARefusedDingTalkMessageCostsNothingAgainstTheLimit(t *testing.T) {
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[0].SendMax = 2 })
	dtSend(t, e, "ops", "")
	dtSend(t, e, "nope", "x")
	dtSend(t, e, "ops", strings.Repeat("x", 9000))
	for i := 0; i < 2; i++ {
		if out, isErr := dtSend(t, e, "ops", fmt.Sprint(i)); isErr {
			t.Fatalf("a refused call used up the limit: %v", out)
		}
	}
}

func TestADingTalkSendThatFailsCostsNothingAgainstTheLimit(t *testing.T) {
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[0].SendMax = 2 })
	for _, f := range []dingtalktest.Failure{{Status: 502, Code: 1}, {Code: 430101}, {Code: -1}} {
		f := f
		e.api.FailNext = &f
		if out, isErr := dtSend(t, e, "ops", "x"); !isErr {
			t.Fatalf("%+v must be an error: %v", f, out)
		}
	}
	for i := 0; i < 2; i++ {
		if out, isErr := dtSend(t, e, "ops", fmt.Sprint(i)); isErr {
			t.Fatalf("message %d after three failures: %v", i, out)
		}
	}
	if out, isErr := dtSend(t, e, "ops", "third"); !isErr || out["code"] != "rate_limited" {
		t.Errorf("but the two that were sent do count: %v %v", isErr, out)
	}
}

func TestTheDingTalkWindowSlidesSoTheLimitComesBack(t *testing.T) {
	e := withDingTalk(t, true, nil)
	// Validate refuses this rate (200 a minute) when a server starts, as it should; the group is set on the running server's own
	// configuration here to exercise the window itself, which the server uses as it is given.
	e.s.cfg.DingTalk.Groups[0].SendMax = 1
	e.s.cfg.DingTalk.Groups[0].SendPeriod = 300 * time.Millisecond
	if _, isErr := dtSend(t, e, "ops", "1"); isErr {
		t.Fatal("first")
	}
	if _, isErr := dtSend(t, e, "ops", "2"); !isErr {
		t.Fatal("second must be refused")
	}
	time.Sleep(400 * time.Millisecond)
	if out, isErr := dtSend(t, e, "ops", "3"); isErr {
		t.Errorf("after the window: %v", out)
	}
}

// DingTalk says a throttled robot is left alone for ten minutes: asking again only lengthens nothing and risks the robot.
func TestWhenDingTalkThrottlesTheRobotNobodyAsksAgainUntilItIsOver(t *testing.T) {
	e := withDingTalk(t, true, nil)
	e.api.FailNext = &dingtalktest.Failure{Code: 410100, Message: "send too fast"}
	out, isErr := dtSend(t, e, "ops", "x")
	if !isErr || out["code"] != "rate_limited" || out["retryable"] != true {
		t.Fatalf("%v %v", isErr, out)
	}
	if !strings.Contains(fmt.Sprint(out["message"]), "retry in 600s") {
		t.Errorf("it says how long: %v", out["message"])
	}
	before := len(e.api.Requests())
	out2, isErr2 := dtSend(t, e, "ops", "y")
	if !isErr2 || out2["code"] != "rate_limited" {
		t.Errorf("%v %v", isErr2, out2)
	}
	if len(e.api.Requests()) != before {
		t.Error("securl asked DingTalk again while it had been told to wait")
	}
	if out3, isErr3 := dtSend(t, e, "sec", "another robot is not throttled"); isErr3 {
		t.Errorf("%v", out3)
	}
}

func TestSeveralDingTalkSendsAtOnceNeverGoPastTheLimit(t *testing.T) {
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[0].SendMax = 5 })
	var wg sync.WaitGroup
	var mu sync.Mutex
	ok := 0
	for i := 0; i < 20; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			if _, isErr := dtSend(t, e, "ops", fmt.Sprint(i)); !isErr {
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

// ---- audit ----

func TestEveryDingTalkSendIsAuditedWithTheGroupAndTheSizeAndAHashButNeverTheText(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "the staging password is hunter2 and the number is 4111-1111")
	a := dtAudit(t, e)
	if !strings.Contains(a, `"event":"dingtalk_send"`) || !strings.Contains(a, `"group":"ops"`) {
		t.Errorf("the send is audited with its target:\n%s", a)
	}
	if !strings.Contains(a, "text_bytes") || !strings.Contains(a, "text_sha256") {
		t.Errorf("with the size and a hash:\n%s", a)
	}
	for _, leak := range []string{"hunter2", "4111", "staging password", "SECRETTOKEN", "access_token"} {
		if strings.Contains(a, leak) {
			t.Errorf("the audit log carries %q:\n%s", leak, a)
		}
	}
}

func TestARefusedDingTalkSendIsAuditedTooWithItsReason(t *testing.T) {
	e := withDingTalk(t, true, func(c *config.Config) { c.DingTalk.Groups[0].SendMax = 1 })
	dtSend(t, e, "ops", "ok")
	dtSend(t, e, "ops", "over")
	dtSend(t, e, "nope", "x")
	a := dtAudit(t, e)
	if strings.Count(a, `"event":"dingtalk_send"`) < 3 {
		t.Errorf("sent, rate limited and refused are all in the trail:\n%s", a)
	}
	// the reason is asserted on the dingtalk_send line itself: the generic tool_call line carries it too, and would hide its loss
	var ends []string
	for _, l := range strings.Split(strings.TrimSpace(a), "\n") {
		if strings.Contains(l, `"event":"dingtalk_send"`) {
			for _, r := range []string{"ok", "rate_limited", "unknown_target"} {
				if strings.Contains(l, `"result":"`+r+`"`) {
					ends = append(ends, r)
				}
			}
		}
	}
	if strings.Join(ends, ",") != "ok,rate_limited,unknown_target" {
		t.Errorf("each send line says how it ended, in order: %v\n%s", ends, a)
	}
}

func TestTheSameDingTalkMessageSentTwiceIsSentTwiceBecauseTheAgentAskedTwice(t *testing.T) {
	e := withDingTalk(t, true, nil)
	dtSend(t, e, "ops", "same")
	dtSend(t, e, "ops", "same")
	if n := len(e.api.Sent()); n != 2 {
		t.Errorf("each call has its own key, so DingTalk does not fold them into one: %d", n)
	}
}
