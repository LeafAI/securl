package mcpserver

import (
	"errors"
	"net/url"
	"sync"
	"time"

	"github.com/LeafAI/securl/internal/proxy"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/totp"
)

var (
	errNoSeed  = errors.New("no TOTP seed was saved with these credentials")
	errRefused = errors.New("the site refused the one-time code")
)

// refusedGrants remembers, for as long as the vault is open, the grants under which a site refused the code. A grant is named by its
// revision, which a new approval changes, so approving again is all it takes to try again, and nothing needs to be cleared.
type refusedGrants struct {
	mu  sync.Mutex
	set map[string]bool
}

func newRefusedGrants() *refusedGrants { return &refusedGrants{set: map[string]bool{}} }

func (r *refusedGrants) refuse(key, revision string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.set[key+"\x00"+revision] = true
}

func (r *refusedGrants) refused(key, revision string) bool {
	r.mu.Lock()
	defer r.mu.Unlock()
	return r.set[key+"\x00"+revision]
}

// secondFactorFor says what a request to this site carries: nothing, when the site's driver asks for no code; the code, when it does
// and the person's approval is in force and a seed was saved; and otherwise why it cannot. The seed is read from the vault here and
// is never handed to the driver, the proxy or the agent: only the function that makes a code holds it, and it holds it for one call.
func (s *Server) secondFactorFor(k *core, d site.Driver, base *url.URL, sess *site.Session) (*proxy.SecondFactor, *ToolError) {
	sf, ok := d.(site.SecondFactor)
	if !ok {
		return nil, nil
	}
	header, digits := sf.SecondFactorHeader()
	key := site.Key(base)
	if sess.ApprovalID == "" {
		return nil, secondFactorTooling(errNoSeed)
	}
	if k.refused.refused(key, sess.ApprovalID) {
		return nil, secondFactorRefused()
	}
	rec, err := remember.Load(s.vault, key)
	if err != nil || !rec.Valid(time.Now()) || rec.Revision != sess.ApprovalID {
		return nil, classify(remember.ErrApprovalRequired)
	}
	if len(rec.Secret) == 0 {
		return nil, secondFactorTooling(errNoSeed)
	}
	// Load reads the record afresh from the vault on every call, so rec.Secret is this call's own and nothing else holds it; the copy and
	// the clearing below keep the seed in memory for no longer than the one code needs it, and can be seen by nothing that a test can
	// reach (which is why a change to either is not caught: it changes how long a value lives, not what anything does).
	seed := append([]byte(nil), rec.Secret...)
	var once sync.Once
	return &proxy.SecondFactor{Header: header, Refused: sf.CodeRefused, Code: func() (string, error) {
		// One code for one request. The seed is cleared after it is used; a second ask must be an error, because a code made from a
		// cleared seed would look like any other, be wrong, and count against an account that locks after a few wrong ones.
		made, code := false, ""
		once.Do(func() {
			code = totp.Code(seed, time.Now(), 30*time.Second, digits)
			clear(seed)
			made = true
		})
		if !made {
			return "", errors.New("the code was already made for this request")
		}
		return code, nil
	}}, nil
}

func secondFactorTooling(error) *ToolError {
	e := errf("second_factor_required", false, "this site wants a one-time code on its requests, and securl has no TOTP seed to make one from")
	e.Hint = "Only the person can fix this: call " + toolSessionOpen + " with manage_credentials=true and have them tick Remember credentials and Remember TOTP, and give the authenticator's setup secret. A code is never asked of you and cannot be given by you."
	return e
}

func secondFactorRefused() *ToolError {
	e := errf("second_factor_refused", false, "the site refused the one-time code, so no more requests are sent with one until the person approves again")
	e.Hint = "A site may lock an account after a few wrong codes, so securl does not try again. Tell the user; they can approve again with " + toolSessionOpen + " and manage_credentials=true, and check the seed and the clock."
	return e
}
