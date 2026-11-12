package mcpserver

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"net/url"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/config"
	"github.com/LeafAI/securl/internal/dingtalk"
	"github.com/LeafAI/securl/internal/dingtalksite"
	"github.com/LeafAI/securl/internal/slidewindow"
)

// dingtalkGroups holds, per group, what has to live as long as the vault is open: the window that limits what the group's robot sends.
// It is made on first use and dropped with the core, so nothing outlives the passphrase.
type dingtalkGroups struct {
	mu     sync.Mutex
	window map[string]*slidewindow.Window
}

func newDingTalkGroups() *dingtalkGroups {
	return &dingtalkGroups{window: map[string]*slidewindow.Window{}}
}

func (g *dingtalkGroups) windowFor(group config.DingTalkGroup) *slidewindow.Window {
	g.mu.Lock()
	defer g.mu.Unlock()
	if w, ok := g.window[group.Name]; ok {
		return w
	}
	w := slidewindow.New(group.SendLimit(), group.SendWindow(), nil)
	g.window[group.Name] = w
	return w
}

// dingtalkDriver is the login driver of every DingTalk group. The endpoint is the product's: no tool or argument chooses it.
func (s *Server) dingtalkDriver() *dingtalksite.Driver {
	return dingtalksite.New(s.cfg.DingTalkGroup, dingtalksite.Options{BaseURL: s.dingtalkAPI, HTTP: s.dingtalkHTTP})
}

// dingtalkTarget resolves the key a person or an agent named (dingtalk://<group>) to a configured group and its session key. A group
// that is not configured is refused before anyone is asked for a webhook.
func (s *Server) dingtalkTarget(raw string) (string, *url.URL, *ToolError) {
	u, err := url.Parse(raw)
	if err != nil || u.Scheme != dingtalksite.Scheme || u.Host == "" || u.Path != "" || u.User != nil || u.RawQuery != "" || u.Fragment != "" || u.Opaque != "" {
		return "", nil, errf("invalid_argument", false, "a DingTalk group is named dingtalk://<group>, with a group from %s", toolDingTalkTargets)
	}
	g, ok := s.cfg.DingTalkGroup(u.Host)
	if !ok {
		e := errf("unknown_target", false, "there is no DingTalk group named %q", clipName(u.Host))
		e.Hint = "Call " + toolDingTalkTargets + " to see the groups the owner has configured."
		return "", nil, e
	}
	return g.Name, dingtalksite.BaseURL(g.Name), nil
}

// ---- dingtalk_targets ----

func (s *Server) dingtalkTargets(_ context.Context, _ *mcp.CallToolRequest, _ Empty) (any, *ToolError) {
	out := DingTalkTargetsOutput{Groups: []DingTalkGroupInfo{}}
	var k *core
	if c, terr := s.gate(); terr == nil {
		k = c
	}
	for _, g := range s.cfg.DingTalk.Groups {
		info := DingTalkGroupInfo{Name: g.Name, SendLimit: g.SendLimit(), SendWindow: int(g.SendWindow() / time.Second)}
		if k != nil {
			_, info.HasSession = k.cache.Peek(dingtalksite.Key(g.Name))
		}
		out.Groups = append(out.Groups, info)
	}
	return out, nil
}

// ---- dingtalk_send ----

type dtCall struct {
	group  config.DingTalkGroup
	client *dingtalk.Client
	k      *core
}

// dingtalkCall resolves what the agent named. The group must be one the owner wrote down, and there must be a session (a person typed
// the webhook); a name that is not configured is refused before anything else is looked at.
func (s *Server) dingtalkCall(name string) (*dtCall, *ToolError) {
	k, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	g, ok := s.cfg.DingTalkGroup(name)
	if !ok {
		e := errf("unknown_target", false, "there is no DingTalk group named %q", clipName(name))
		e.Hint = "Call " + toolDingTalkTargets + " to see the groups the owner has configured."
		return nil, e
	}
	e, err := k.cache.Lookup(context.Background(), dingtalksite.BaseURL(g.Name), nil, s.fresh)
	if err != nil {
		te := sessionLost(err, "the DingTalk group "+g.Name, "Call "+toolSessionOpen+" with url dingtalk://"+g.Name+" and force_refresh=true: a person types the robot's webhook again.", "there is no session for the DingTalk group "+g.Name)
		if te.Code == "no_session" {
			te.Hint = "Call " + toolSessionOpen + " with url dingtalk://" + g.Name + ": a person types the group robot's webhook once, then " + toolDingTalkSend + " uses it."
		}
		return nil, te
	}
	client, err := s.dingtalkDriver().Client(e.Session)
	if err != nil {
		return nil, errf("session_expired", true, "the saved session for the DingTalk group %s holds no webhook", g.Name)
	}
	return &dtCall{group: g, client: client, k: k}, nil
}

// dingtalkErr turns what the DingTalk layer says into a tool error. None of its errors holds the webhook, and none is repeated from
// what a server said.
func (s *Server) dingtalkErr(c *dtCall, err error) *ToolError {
	var th *dingtalk.ThrottledError
	switch {
	case errors.As(err, &th):
		return rateLimitedErr(th.RetryAfter, "DingTalk throttled the robot of "+c.group.Name)
	case errors.Is(err, dingtalk.ErrBadToken):
		c.k.cache.Delete(dingtalksite.Key(c.group.Name))
		e := errf("session_expired", true, "DingTalk no longer knows the robot saved for %s (the robot was removed or switched off, or the webhook was mistyped)", c.group.Name)
		e.Hint = "Call " + toolSessionOpen + " with url dingtalk://" + c.group.Name + " and force_refresh=true: a person types the robot's webhook again."
		return e
	case errors.Is(err, dingtalk.ErrGroupGone):
		e := errf("chat_not_reachable", false, "the DingTalk group of %s no longer exists", c.group.Name)
		e.Hint = "Ask the owner to configure another group."
		return e
	case errors.Is(err, dingtalk.ErrRefused):
		e := errf("refused_by_robot", false, "the security settings of the robot for %s refused the message", c.group.Name)
		e.Hint = "Only the owner can change that: the robot's keyword, signature or address list in DingTalk, or the group's keyword and sign settings in the securl configuration."
		return e
	case errors.Is(err, dingtalk.ErrContent):
		return errf("content_refused", false, "DingTalk refused the content of the message (an unsafe link, or text it does not accept); change it and do not retry as it is")
	case errors.Is(err, dingtalk.ErrUnreachable):
		return errf("site_unreachable", true, "oapi.dingtalk.com could not be reached")
	}
	return errf("internal", false, "DingTalk refused the request")
}

func (s *Server) dingtalkSend(ctx context.Context, _ *mcp.CallToolRequest, in DingTalkSendInput) (any, *ToolError) {
	res, terr := s.doDingTalkSend(ctx, in)
	ev := audit.Event{Event: "dingtalk_send", Group: clipName(in.Group), Result: "ok"}
	if n, sum := len(in.Text), sha256.Sum256([]byte(in.Text)); n > 0 {
		ev.TextBytes, ev.TextHash = n, hex.EncodeToString(sum[:6])
	}
	if terr != nil {
		ev.Result = terr.Code
	}
	s.audit.Record(ev)
	return res, terr
}

func (s *Server) doDingTalkSend(ctx context.Context, in DingTalkSendInput) (any, *ToolError) {
	text := strings.TrimSpace(in.Text)
	if text == "" {
		return nil, errf("invalid_argument", false, "text is empty")
	}
	c, terr := s.dingtalkCall(in.Group)
	if terr != nil {
		return nil, terr
	}
	if n := len([]rune(in.Text)); n > c.group.MaxTextRunes() {
		return nil, errf("text_too_long", false, "the text is %d characters, %d more than the %d allowed", n, n-c.group.MaxTextRunes(), c.group.MaxTextRunes())
	}
	// Everything that can be refused is refused above, so that a refused call costs nothing against the limit.
	w := s.core.dingtalk.windowFor(c.group)
	retry, slot := w.TakeSlot()
	if slot == (slidewindow.Slot{}) {
		return nil, rateLimitedErr(retry, fmt.Sprintf("the robot of %s has sent %d messages in %s", c.group.Name, c.group.SendLimit(), c.group.SendWindow()))
	}
	if err := c.client.Send(ctx, s.dingtalkHeader(c.group)+"\n"+text); err != nil {
		w.GiveBackSlot(slot) // nothing was sent, so nothing is counted
		var th *dingtalk.ThrottledError
		if errors.As(err, &th) {
			w.Block(th.RetryAfter) // DingTalk asked: nobody asks it again until then
		}
		return nil, s.dingtalkErr(c, err)
	}
	return DingTalkSendOutput{Sent: true}, nil
}

// dingtalkHeader is the line securl puts first: who sent this, from which machine, and the robot's keyword if it has one (DingTalk
// refuses a message without it, and it is the owner's setting and not the agent's). The agent's text never goes into it.
func (s *Server) dingtalkHeader(g config.DingTalkGroup) string {
	h := s.telegramHeader()
	if g.Keyword != "" && !strings.Contains(h, g.Keyword) {
		h += " " + cleanLine(g.Keyword, 64)
	}
	return h
}
