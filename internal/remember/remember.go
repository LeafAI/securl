// Package remember keeps upstream login credentials in the encrypted vault,
// separately from securl's own human-interaction TOTP factors.
package remember

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"time"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
)

const (
	Prefix   = "credential/"
	Lifetime = 24 * time.Hour
)

var (
	ErrRemoved          = errors.New("saved credentials were removed; the owner can enroll them again on the protected page")
	ErrApprovalRequired = errors.New("human approval is required")
	ErrHumanChallenge   = errors.New("site requires an additional human challenge")
	ErrBindingChanged   = errors.New("saved credential authentication configuration changed; request credential management")
)

type Record struct {
	Binding    string        `json:"binding,omitempty"`
	Site       string        `json:"site"`
	Username   string        `json:"username"`
	Password   string        `json:"password"`
	Secret     []byte        `json:"totp_secret"`
	Revision   string        `json:"revision"`
	ApprovedAt time.Time     `json:"approved_at"`
	Duration   time.Duration `json:"duration,omitempty"`
}

// Scope identifies the registered web authentication capability, not a driver name
// supplied by an agent. Non-web tools and no-auth sites never opt in.
func Scope(d site.Driver) (string, *url.URL, bool) {
	if d == nil || !d.NeedsLogin() {
		return "", nil, false
	}
	cap, ok := d.(site.CredentialScope)
	if !ok {
		return "", nil, false
	}
	binding, origin := cap.RememberScope()
	return binding, origin, true
}
func Supports(d site.Driver) bool { _, _, ok := Scope(d); return ok }
func (r *Record) Matches(d site.Driver) bool {
	binding, _, ok := Scope(d)
	return ok && d.Name() == r.Site && binding == r.Binding
}

func (r *Record) validate() error {
	if r.Site == "" || r.Username == "" || r.Password == "" || (len(r.Secret) != 0 && len(r.Secret) < 10) || len(r.Revision) != 32 || r.Duration < 0 {
		return errors.New("invalid saved credential")
	}
	return nil
}

func Load(v *vault.Vault, key string) (*Record, error) {
	b, err := v.GetCurrent(Prefix + key)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	if string(b) == "removed" {
		return nil, ErrRemoved
	}
	var r Record
	if json.Unmarshal(b, &r) != nil {
		return nil, errors.New("invalid saved credential")
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	return &r, nil
}

// changeRevision invalidates outstanding login flows, even if a grant was already expired.
func (r *Record) changeRevision() error {
	var id [16]byte
	if _, err := rand.Read(id[:]); err != nil {
		return err
	}
	r.Revision = hex.EncodeToString(id[:])
	return nil
}

// Enroll replaces credentials and always starts with no authorization.
func Enroll(v *vault.Vault, key string, r Record) error {
	r.ApprovedAt = time.Time{}
	if err := r.changeRevision(); err != nil {
		return err
	}
	if err := r.validate(); err != nil {
		return err
	}
	b, err := json.Marshal(&r)
	if err != nil {
		return err
	}
	defer clear(b)
	return v.Put(Prefix+key, b)
}

// EnrollApproved commits validated credentials and their initial grant atomically.
// A concurrent enrollment, replacement or removal must not be overwritten.
func EnrollApproved(v *vault.Vault, key string, r Record, previous *Record, removed bool, now time.Time, duration time.Duration) (*Record, error) {
	r.ApprovedAt = now.UTC()
	r.Duration = duration
	if duration <= 0 {
		return nil, errors.New("authorization duration must be positive")
	}
	if err := r.changeRevision(); err != nil {
		return nil, err
	}
	if err := r.validate(); err != nil {
		return nil, err
	}
	b, err := json.Marshal(&r)
	if err != nil {
		return nil, err
	}
	defer clear(b)
	switch {
	case previous != nil:
		err = replace(v, key, previous, &r)
	case removed:
		err = v.CompareAndSwap(Prefix+key, []byte("removed"), b)
	default:
		err = v.PutNew(Prefix+key, b)
	}
	if err != nil {
		return nil, err
	}
	return &r, nil
}

func replace(v *vault.Vault, key string, old, next *Record) error {
	a, err := json.Marshal(old)
	if err != nil {
		return err
	}
	defer clear(a)
	b, err := json.Marshal(next)
	if err != nil {
		return err
	}
	defer clear(b)
	return v.CompareAndSwap(Prefix+key, a, b)
}

// Approve starts a fixed-duration grant, only for the exact record the human was asked about.
func Approve(v *vault.Vault, key string, old *Record, now time.Time, duration time.Duration) (*Record, error) {
	next := *old
	next.ApprovedAt = now.UTC()
	next.Duration = duration
	if duration <= 0 {
		return nil, errors.New("authorization duration must be positive")
	}
	if err := next.changeRevision(); err != nil {
		return nil, err
	}
	if err := replace(v, key, old, &next); err != nil {
		return nil, err
	}
	return &next, nil
}

// Revoke invalidates the grant and pending approvals while keeping the credential.
func Revoke(v *vault.Vault, key string) error {
	r, err := Load(v, key)
	if errors.Is(err, vault.ErrNoEntry) || errors.Is(err, ErrRemoved) {
		return nil
	}
	if err != nil {
		return err
	}
	next := *r
	next.ApprovedAt = time.Time{}
	if err := next.changeRevision(); err != nil {
		return err
	}
	return replace(v, key, r, &next)
}

// Remove forgets the credential. The non-secret tombstone prevents other processes
// from falling back to cached legacy sessions until the owner enrolls again.
func Remove(v *vault.Vault, key string) error {
	r, err := Load(v, key)
	if errors.Is(err, ErrRemoved) {
		return nil
	}
	if err != nil {
		return err
	}
	return RemoveExpected(v, key, r)
}

// RemoveExpected removes only the record offered for confirmation.
func RemoveExpected(v *vault.Vault, key string, r *Record) error {
	b, err := json.Marshal(r)
	if err != nil {
		return err
	}
	defer clear(b)
	return v.CompareAndSwap(Prefix+key, b, []byte("removed"))
}

// Deadline preserves the duration granted by the human, even across config changes.
// A zero duration is the legacy 24-hour format.
func Deadline(at time.Time, duration time.Duration) time.Time {
	if at.IsZero() {
		return time.Time{}
	}
	if duration == 0 {
		duration = Lifetime
	}
	return at.Add(duration)
}
func (r *Record) Valid(now time.Time) bool {
	return r.Duration >= 0 && !r.ApprovedAt.IsZero() && !now.Before(r.ApprovedAt) && now.Before(Deadline(r.ApprovedAt, r.Duration))
}

// LoginChallenge recognizes only the driver-defined login fields. Never infer
// reusable credentials from arbitrary custom fields or save CAPTCHA answers.
func LoginChallenge(mode string, fields []site.Field) (bool, []site.Field) {
	if mode == "login" {
		return true, nil
	}
	if mode != "custom" {
		return false, nil
	}
	user, pass := false, false
	var challenge []site.Field
	for _, f := range fields {
		switch f.Name {
		case "username":
			user = true
		case "password":
			pass = true
		case "verifyvalue":
			if f.Image == "" {
				return false, nil
			}
			challenge = append(challenge, f)
		default:
			return false, nil
		}
	}
	return user && pass, challenge
}
func TOTPChallenge(mode string, fields []site.Field) bool {
	return mode == "totp" || (mode == "custom" && len(fields) == 1 && fields[0].Name == "code")
}

// Ask generates an upstream code only when the driver asks. It cannot satisfy
// a CAPTCHA or a newly enabled second factor without human involvement.
func (r *Record) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	if login, challenge := LoginChallenge(mode, fields); login {
		if len(challenge) > 0 {
			return nil, ErrHumanChallenge
		}
		return site.Credentials{"username": r.Username, "password": r.Password}, nil
	}
	if TOTPChallenge(mode, fields) {
		if len(r.Secret) == 0 {
			return nil, ErrHumanChallenge
		}
		return site.Credentials{"code": totp.Code(r.Secret, time.Now(), 30*time.Second, 6)}, nil
	}
	return nil, ErrHumanChallenge
}

type savedAsker struct {
	r     *Record
	human site.Asker
}

func (a savedAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if login, challenge := LoginChallenge(mode, fields); login && len(challenge) > 0 {
		if a.human == nil {
			return nil, ErrHumanChallenge
		}
		values, err := a.human.Ask(ctx, "custom", challenge)
		if err != nil {
			return nil, err
		}
		return site.Credentials{"username": a.r.Username, "password": a.r.Password, "verifyvalue": values["verifyvalue"]}, nil
	}
	// If the site requires a one-time code and no reusable TOTP seed
	// was enrolled, the person must supply a fresh code. Do not store it.
	if TOTPChallenge(mode, fields) && len(a.r.Secret) == 0 && a.human != nil {
		return a.human.Ask(ctx, mode, fields)
	}
	return a.r.Ask(ctx, mode, fields)
}

// Track the trusted human/asker error separately so upstream error text can
// always be sanitized, without hiding rejection or challenge errors.
type trackedAsker struct {
	site.Asker
	err error
}

func (a *trackedAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	values, err := a.Asker.Ask(ctx, mode, fields)
	if err != nil {
		a.err = err
	}
	return values, err
}

type scopedTransport struct {
	next    http.RoundTripper
	allowed []*url.URL
}

func sameOrigin(a, b *url.URL) bool {
	return a != nil && b != nil && a.Scheme == "https" && b.Scheme == "https" && a.Host == b.Host && a.User == nil && b.User == nil
}
func (t scopedTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	for _, u := range t.allowed {
		if sameOrigin(req.URL, u) {
			return t.next.RoundTrip(req)
		}
	}
	if req.Body != nil {
		req.Body.Close()
	}
	return nil, errors.New("credential login refused request outside configured HTTPS origins")
}

// Run confines all driver requests (including manually followed OAuth redirects)
// to the site and its explicitly configured HTTPS identity provider, if any.
// Ordinary HTTP redirects must stay on the request's origin; the OAuth driver
// validates cross-origin transitions itself.
func Run(ctx context.Context, d site.Driver, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	_, idp, ok := Scope(d)
	if !ok || base.Scheme != "https" || base.User != nil || (idp != nil && (idp.Scheme != "https" || idp.User != nil)) {
		return nil, errors.New("remembered login requires supported HTTPS origins")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	c := *hc
	tr := c.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	allowed := []*url.URL{base}
	if idp != nil {
		allowed = append(allowed, idp)
	}
	c.Transport = scopedTransport{next: tr, allowed: allowed}
	old := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if len(via) == 0 || !sameOrigin(req.URL, via[len(via)-1].URL) {
			return errors.New("credential login refused cross-origin redirect")
		}
		if old != nil {
			return old(req, via)
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	tracked := &trackedAsker{Asker: ask}
	sess, err := d.Login(ctx, base, tracked, &c)
	if err != nil {
		if tracked.err != nil {
			return nil, tracked.err
		}
		for _, kind := range []error{site.ErrBadCredentials, site.ErrUnreachable, site.ErrLoginRejected} {
			if errors.Is(err, kind) {
				return nil, fmt.Errorf("%w: protected credential login failed", kind)
			}
		}
		return nil, errors.New("protected credential login failed")
	}
	if sess == nil {
		return nil, errors.New("site returned no session")
	}
	return sess, nil
}

func Login(ctx context.Context, d site.Driver, base *url.URL, r *Record, hc *http.Client, human site.Asker) (*site.Session, error) {
	if !r.Matches(d) {
		return nil, ErrBindingChanged
	}
	return Run(ctx, d, base, savedAsker{r: r, human: human}, hc)
}
