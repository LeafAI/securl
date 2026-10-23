package mcpserver

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"
	"sync"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/dbsite"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/keyring"
	"github.com/LeafAI/securl/internal/ratelimit"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
)

// Closing a saved session forgets what a person typed. A database account in particular is a password that cannot be asked
// back from anywhere, so no saved session is closed until a person has said so, on a page, naming what goes. The question is
// the server's: every process of the user may reach a daemon's socket, an agent's shell among them, so nothing in a call
// stands for the answer, and the answer comes only through the page.

const (
	// closeWord is what the person types. A word, not a click: a page that a script can click through is no confirmation.
	closeWord = "DELETE"
	// maxCloseTries is how many answers one request lets the person type before it gives up.
	maxCloseTries = 3
	closeHost     = "close.invalid"
	closeField    = "confirm"
	// closeLabelMax is what the page shows of a field's label.
	closeLabelMax = 60
	// scopeAll is the scope of a request to close every saved session.
	scopeAll = "*"
	// closeKeep is how long the record of a request is kept after it was made.
	closeKeep = 30 * time.Minute
)

// closeLimitKey is what the limiter counts the questions about closing under, so that a refusal slows the next ask down.
const closeLimitKey = "securl://session-close"

// closeReq is one request to close sessions. Its keys are frozen when it is made: what the person agreed to is that list, not
// "whatever exists when they answer".
type closeReq struct {
	scope   string
	keys    []string
	made    time.Time
	flow    *flow.Flow
	removed int
	done    chan struct{} // closed when the sessions were closed or the request ended without closing them
}

// closer asks people to confirm the closing of saved sessions. It has its own flow manager, like the unlocker, so that its
// messages say what they are about; it lives in the core and so ends when the vault locks.
type closer struct {
	s    *Server
	c    *core
	mgr  *flow.Manager
	base *url.URL

	mu   sync.Mutex
	reqs map[string]*closeReq
}

func newCloser(s *Server, c *core, unlock, seal flow.CodeSource) *closer {
	base, _ := url.Parse("https://" + closeHost)
	cl := &closer{s: s, c: c, base: base, reqs: map[string]*closeReq{}}
	cfg := flow.Config{
		Keys:     keyring.NewMemoryPool(s.cfg.Keys.MaxUses, s.cfg.Keys.MaxAge),
		Notifier: s.notify, LinkViaAgent: s.linkViaAgent(), Tunnels: s.tunnels, PageURL: s.cfg.Web.PageURL, TTL: s.cfg.Web.TTL, Log: s.log,
		Admit: func(site.Driver, *url.URL, string) error {
			if lim := s.limiter.Allow(closeLimitKey); lim != nil {
				s.audit.Record(audit.Event{Event: "rate_limited", Site: "session_close", Result: lim.Reason})
				return lim
			}
			return nil
		},
		OnTunnel: func(f *flow.Flow, provider string, attempts int) {
			s.audit.Record(audit.Event{Event: "tunnel", Site: "session_close", Tunnel: provider, Attempts: attempts})
		},
		OnRound: func(f *flow.Flow, mode string, round int) {
			s.audit.Record(audit.Event{Event: "session_close_round", Round: round, Delivery: s.delivery()})
		},
		Purpose: &flow.Purpose{
			Title:   "Close saved sessions",
			Heading: "Close saved sessions",
			Step:    "type " + closeWord + " to confirm",
			Warning: "If you did not expect this, press Reject: nothing is closed until you type " + closeWord + ".",
		},
	}
	if unlock != nil {
		cfg.Unlock = unlock
	}
	if seal != nil {
		cfg.Seal = seal
	}
	cl.mgr = flow.NewManager(cfg)
	return cl
}

// closeScope is what a call asks to close: a scope that names it, and the saved sessions that are in it now.
type closeScope struct {
	scope string
	keys  []string
	base  *url.URL // the site of a single close, for cancelling a login that is still being opened
}

func (s *Server) scopeOf(c *core, in LogoutInput) (closeScope, *ToolError) {
	if in.All == (in.URL != "") {
		return closeScope{}, errf("invalid_argument", false, "give exactly one of url or all")
	}
	if in.All {
		return closeScope{scope: scopeAll, keys: c.cache.Keys()}, nil
	}
	var base *url.URL
	if strings.HasPrefix(strings.ToLower(in.URL), dbsite.Scheme+":") {
		_, b, terr := s.databaseTarget(in.URL)
		if terr != nil {
			return closeScope{}, terr
		}
		base = b
	} else {
		b, terr := baseOf(in.URL)
		if terr != nil {
			return closeScope{}, terr
		}
		base = s.root(b)
	}
	key := session.Key(base)
	var keys []string
	for _, k := range c.cache.Keys() {
		if k == key {
			keys = []string{k}
		}
	}
	return closeScope{scope: key, keys: keys, base: base}, nil
}

// logout closes saved sessions, once a person has confirmed it. A request that has nothing saved to close needs nobody's
// word: there is nothing to lose.
func (s *Server) logout(ctx context.Context, req *mcp.CallToolRequest, in LogoutInput) (any, *ToolError) {
	c, terr := s.gate()
	if terr != nil {
		return nil, terr
	}
	sc, terr := s.scopeOf(c, in)
	if terr != nil {
		return nil, terr
	}
	cl := c.closer
	max := s.maxBlock(in.MaxBlockSeconds)
	if in.CloseID != "" {
		r := cl.find(in.CloseID)
		if r == nil || r.scope != sc.scope {
			return nil, errf("invalid_argument", false, "close_id %q is not a pending confirmation for this request", clipName(in.CloseID))
		}
		return s.awaitClose(ctx, req, r, max)
	}
	if len(sc.keys) == 0 {
		return LogoutOutput{Status: "closed", Removed: cancelPending(c, sc)}, nil
	}
	r, terr := cl.request(sc, clip(in.Reason, maxReasonBytes))
	if terr != nil {
		return nil, terr
	}
	return s.awaitClose(ctx, req, r, max)
}

// cancelPending cancels a login that is still being opened for a single site. Nothing is lost by it: no credential is saved
// yet, so it needs no confirmation.
func cancelPending(c *core, sc closeScope) int {
	if sc.base != nil && c.mgr.CancelBase(session.Key(sc.base)) {
		return 1
	}
	return 0
}

func (cl *closer) find(id string) *closeReq {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	return cl.reqs[id]
}

// request asks for a confirmation, or joins the one that is already out for the same scope. Only one is out at a time: a
// second, different question while a person is looking at the first is refused, not queued behind it.
func (cl *closer) request(sc closeScope, reason string) (*closeReq, *ToolError) {
	cl.mu.Lock()
	defer cl.mu.Unlock()
	cl.prune()
	if f := cl.mgr.Running(cl.base); f != nil {
		if r := cl.reqs[f.ID]; r != nil {
			if r.scope != sc.scope {
				e := errf("close_pending", true, "a person is already being asked to confirm closing other sessions")
				e.Hint = "Wait for them to answer it, then ask again. Do not ask in a loop."
				return nil, e
			}
			return r, nil
		}
	}
	r := &closeReq{scope: sc.scope, keys: append([]string(nil), sc.keys...), made: time.Now(), done: make(chan struct{})}
	detail := closeDetail(sc.keys)
	f := cl.mgr.StartDetailed(closeDriver{cl: cl, req: r}, cl.base, reason, detail, cl.s.hc, func(f *flow.Flow, res flow.Result) {
		cl.finish(r, sc, res)
	})
	select {
	case <-f.Done(): // refused before it started (rate limit)
		if err := f.Result().Err; err != nil {
			return nil, closeErr(err)
		}
	default:
	}
	r.flow = f
	cl.reqs[f.ID] = r
	cl.s.audit.Record(audit.Event{Event: "session_close_requested", Reason: reason, Keys: r.keys, Count: len(r.keys), Delivery: cl.s.delivery()})
	return r, nil
}

func (cl *closer) prune() {
	for id, r := range cl.reqs {
		if time.Since(r.made) > closeKeep {
			delete(cl.reqs, id)
		}
	}
}

// finish runs once, when the request ended. It closes the sessions that were named, and only those.
func (cl *closer) finish(r *closeReq, sc closeScope, res flow.Result) {
	defer close(r.done)
	var rj *flow.RejectedError
	switch {
	case res.Err == nil:
		r.removed = cl.c.cache.RemoveKeys(r.keys)
		if sc.base != nil {
			r.removed += cancelPending(cl.c, sc)
		}
		cl.s.audit.Record(audit.Event{Event: "session_close_confirmed", Keys: r.keys, Count: r.removed})
	case errors.As(res.Err, &rj):
		cl.s.limiter.Rejected(closeLimitKey)
		cl.s.audit.Record(audit.Event{Event: "session_close_declined", Result: "rejected", Keys: r.keys, Count: len(r.keys)})
	default:
		cl.s.audit.Record(audit.Event{Event: "session_close_declined", Result: closeErr(res.Err).Code, Keys: r.keys, Count: len(r.keys)})
	}
}

// closeDriver asks the person to type the word. It lets them try again after a wrong one, a few times.
type closeDriver struct {
	cl  *closer
	req *closeReq
}

func (closeDriver) Name() string                                                       { return "session_close" }
func (closeDriver) Match(*url.URL) bool                                                { return false }
func (closeDriver) NeedsLogin() bool                                                   { return true }
func (closeDriver) Probe(context.Context, *url.URL, *site.Session, *http.Client) error { return nil }

func (d closeDriver) Login(ctx context.Context, _ *url.URL, ask site.Asker, _ *http.Client) (*site.Session, error) {
	fields := []site.Field{{Name: closeField, Label: closeLabel(d.req.keys)}}
	for try := 1; try <= maxCloseTries; try++ {
		creds, err := ask.Ask(ctx, "custom", fields)
		if err != nil {
			return nil, err
		}
		if strings.TrimSpace(creds[closeField]) == closeWord {
			return &site.Session{}, nil
		}
		d.cl.s.audit.Record(audit.Event{Event: "session_close_wrong_word", Round: try})
	}
	return nil, fmt.Errorf("%w: the confirmation word was wrong %d times in one request", site.ErrBadCredentials, maxCloseTries)
}

// shown is how a saved session is named to a person: a site by its address, a database by db://target.
func shown(key string) string { return strings.TrimPrefix(key, "https://") }

// closeLabel is what the page shows above the field. The page cuts a label at closeLabelMax, so what goes must come first
// and the rest is a count, never a silent cut.
func closeLabel(keys []string) string {
	names := sortedNames(keys)
	head := "Type " + closeWord + " to close: "
	var out []string
	for i, n := range names {
		rest := len(names) - i - 1
		trial := strings.Join(append(append([]string(nil), out...), n), ", ")
		more := ""
		if rest > 0 {
			more = fmt.Sprintf(" (+%d more)", rest)
		}
		if len([]rune(head+trial+more)) > closeLabelMax {
			break
		}
		out = append(out, n)
	}
	if len(out) == 0 {
		if len(names) == 1 {
			return "Type " + closeWord + " to close 1 session"
		}
		return fmt.Sprintf("Type %s to close %d sessions", closeWord, len(names))
	}
	label := head + strings.Join(out, ", ")
	if rest := len(names) - len(out); rest > 0 {
		label += fmt.Sprintf(" (+%d more)", rest)
	}
	return label
}

func sortedNames(keys []string) []string {
	out := make([]string, 0, len(keys))
	for _, k := range keys {
		out = append(out, shown(k))
	}
	sort.Strings(out)
	return out
}

// closeDetail is what the message tells the person in securl's own words: every name, and what a database account is.
func closeDetail(keys []string) string {
	names := sortedNames(keys)
	var dbs int
	for _, n := range names {
		if strings.HasPrefix(n, dbsite.Scheme+"://") {
			dbs++
		}
	}
	d := fmt.Sprintf("closes %d saved session(s), which forgets the login: %s.", len(names), strings.Join(names, ", "))
	if dbs > 0 {
		d += fmt.Sprintf(" %d of them are database targets (db://): the account and password a person typed for a database is not kept anywhere else and cannot be recovered, it must be typed again.", dbs)
	}
	return d
}

func closePending(r *closeReq, sn flow.Snapshot) LogoutOutput {
	return LogoutOutput{Status: "pending", LoginID: r.flow.ID, WaitingFor: "confirmation", ExpiresAt: fmtTime(sn.ExpiresAt),
		NextTool: toolSessionClose, LinkHandover: handover(sn, "the page")}
}

func (s *Server) awaitClose(ctx context.Context, mreq *mcp.CallToolRequest, r *closeReq, max time.Duration) (any, *ToolError) {
	f := r.flow
	tick := time.NewTicker(5 * time.Second)
	defer tick.Stop()
	timer := time.NewTimer(max)
	defer timer.Stop()
	var n float64
	var fresh <-chan time.Time
	if f.ViaAgent() {
		lt := time.NewTicker(50 * time.Millisecond)
		defer lt.Stop()
		fresh = lt.C
	}
	for {
		select {
		case <-fresh:
			if sn, ok := f.ClaimLink(); ok {
				return closePending(r, sn), nil
			}
		case <-f.Done():
			if err := f.Result().Err; err != nil {
				<-r.done
				return nil, closeErr(err)
			}
			<-r.done
			return LogoutOutput{Status: "closed", Removed: r.removed}, nil
		case <-timer.C:
			return closePending(r, f.Snapshot()), nil
		case <-tick.C:
			s.progress(ctx, mreq, &n, "waiting for the person to confirm closing the sessions (DingTalk link sent)")
		case <-ctx.Done():
			return nil, errf("internal", true, "cancelled: %v", ctx.Err())
		}
	}
}

// closeErr maps what a request can end in to a tool error. None of them carries a session.
func closeErr(err error) *ToolError {
	e := classify(err)
	var rj *flow.RejectedError
	var lim *ratelimit.Limited
	switch {
	case errors.As(err, &rj):
		// The page's wording is a login's ("rejected the login request"), and the reason is the person's own words.
		msg := "the user declined to close the sessions; nothing was closed"
		if r := strings.TrimSpace(rj.Reason); r != "" {
			msg += ": " + clip(r, maxReasonBytes)
		}
		e = errf("user_rejected", false, "%s", msg)
	case errors.As(err, &lim):
		// The limiter counts these questions under an internal key, which is not for a person or an agent to read.
		e = errf("rate_limited", true, "the user recently declined to close sessions, so nobody is asked again for now; retry in %s", lim.RetryAfter.Round(time.Second))
	}
	switch e.Code {
	case "rate_limited":
		e.Hint = "Do not ask again in a loop: the person said no. Wait, or ask the user whether they want the sessions closed."
	case "user_rejected":
		e.Hint = "The person declined to close the sessions. Nothing was closed. Do not ask again unless the user tells you to."
	case "bad_credentials":
		e = errf("bad_confirmation", false, "the confirmation word was wrong too many times; nothing was closed")
		e.Hint = "Ask the user whether they want the sessions closed, then call " + toolSessionClose + " again."
	case "human_timeout":
		e.Hint = "Nobody confirmed in time and nothing was closed. Ask the user to watch DingTalk, then call " + toolSessionClose + " again."
	}
	return e
}
