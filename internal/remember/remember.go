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
	"strings"
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
	Binding  string `json:"binding,omitempty"`
	Site     string `json:"site"`
	Username string `json:"username"`
	Password string `json:"password"`
	Secret   []byte `json:"totp_secret"`
	// Extras are the values of the fields a driver asks for beside the username and the password (a salt, say), by the name the
	// driver gave them. They are saved and handed back like the password, and a record made before a driver asked for any has none.
	Extras     map[string]string `json:"extras,omitempty"`
	Revision   string            `json:"revision"`
	ApprovedAt time.Time         `json:"approved_at"`
	Duration   time.Duration     `json:"duration,omitempty"`
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
	if !ok || d.Name() != r.Site {
		return false
	}
	extras, err := Extras(d)
	if err != nil {
		return false
	}
	return joinBinding(binding, ExtrasBinding(extras)) == r.Binding
}

// joinBinding is the binding of a record: what the driver says its authentication is, and, when it asks for more than a username
// and a password, which fields. A driver with no extras keeps the binding it always had, so that records made before extras existed
// stay valid.
func joinBinding(driverBinding, extras string) string {
	switch {
	case extras == "":
		return driverBinding
	case driverBinding == "":
		return extras
	}
	return driverBinding + "|" + extras
}

// BindingOf is the binding a record made now for this driver carries.
func BindingOf(d site.Driver) (string, error) {
	binding, _, ok := Scope(d)
	if !ok {
		return "", errors.New("the driver does not take part in remembered credentials")
	}
	extras, err := Extras(d)
	if err != nil {
		return "", err
	}
	return joinBinding(binding, ExtrasBinding(extras)), nil
}

const (
	// maxExtraBytes bounds one saved extra value. A salt is a short string; this is generous, and keeps a record small.
	maxExtraBytes = 4096
	maxExtraName  = 32
	maxExtraLabel = 60
)

// Extras returns the fields a driver asks for beside the username and the password, checked: a plain lower-case name that securl
// does not use itself, a short one-line label, no image, every name once. They are always secret, because a page cannot tell a salt
// from a password. A driver that asks for none gives none. There is no limit on how many a driver may ask for here; the page has one
// for the fields of any link.
func Extras(d site.Driver) ([]site.Field, error) {
	e, ok := d.(site.LoginExtras)
	if !ok {
		return nil, nil
	}
	seen := map[string]bool{}
	var out []site.Field
	for _, f := range e.LoginExtraFields() {
		if !validExtraName(f.Name) || site.ReservedFieldNames[f.Name] || seen[f.Name] {
			return nil, errors.New("a login field the driver asks for has a name that is not allowed (lower-case letters, digits and _, starting with a letter, once, and not one securl uses)")
		}
		if f.Label == "" || len([]rune(f.Label)) > maxExtraLabel || strings.ContainsAny(f.Label, "\r\n\x00") || f.Image != "" {
			return nil, errors.New("a login field the driver asks for has a label that is not allowed (one short line, and no image)")
		}
		seen[f.Name] = true
		out = append(out, site.Field{Name: f.Name, Label: f.Label, Secret: true})
	}
	return out, nil
}

func validExtraName(n string) bool {
	if n == "" || len(n) > maxExtraName || n[0] < 'a' || n[0] > 'z' {
		return false
	}
	for i := 0; i < len(n); i++ {
		c := n[i]
		if !(c >= 'a' && c <= 'z' || c >= '0' && c <= '9' || c == '_') {
			return false
		}
	}
	return true
}

// ExtrasBinding says which fields a record was made with: their names, in the order the driver asked. It is empty for none. A label
// is not part of it, because changing the words on a page does not change what was saved.
func ExtrasBinding(fields []site.Field) string {
	if len(fields) == 0 {
		return ""
	}
	names := make([]string, len(fields))
	for i, f := range fields {
		names[i] = f.Name
	}
	return "extras:" + strings.Join(names, ",")
}

func (r *Record) validate() error {
	if r.Site == "" || r.Username == "" || r.Password == "" || (len(r.Secret) != 0 && len(r.Secret) < 10) || len(r.Revision) != 32 || r.Duration < 0 {
		return errors.New("invalid saved credential")
	}
	for name, v := range r.Extras {
		if !validExtraName(name) || site.ReservedFieldNames[name] || v == "" || len(v) > maxExtraBytes {
			return errors.New("invalid saved credential")
		}
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
	return LoginChallengeWith(mode, fields, nil)
}

// LoginChallengeWith is LoginChallenge for a driver that also asks for extra fields in its login round: the fields it declared
// (see site.LoginExtras) are part of the login, and nothing else that is not a username, a password or a captcha is. A round that
// lacks one of them, or has another, is not the round the driver declared and is not saved.
func LoginChallengeWith(mode string, fields []site.Field, extras []site.Field) (bool, []site.Field) {
	if mode != "custom" && mode != "login" {
		return false, nil
	}
	// The standard login round asks for the username and the password and nothing else; it has no field list of its own to check.
	if mode == "login" && fields == nil && len(extras) == 0 {
		return true, nil
	}
	want := map[string]bool{}
	for _, f := range extras {
		want[f.Name] = true
	}
	user, pass := false, false
	got := map[string]bool{}
	var challenge []site.Field
	for _, f := range fields {
		switch {
		case f.Name == "username":
			user = true
		case f.Name == "password":
			pass = true
		case f.Name == "verifyvalue":
			if f.Image == "" {
				return false, nil
			}
			challenge = append(challenge, f)
		case want[f.Name]:
			got[f.Name] = true
		default:
			return false, nil
		}
	}
	if !user || !pass || len(got) != len(want) {
		return false, nil
	}
	return true, challenge
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
	r      *Record
	human  site.Asker
	extras []site.Field // what the driver declared (site.LoginExtras): the saved values of these are sent in its login round
}

func (a savedAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if login, challenge := LoginChallengeWith(mode, fields, a.extras); login {
		out, err := a.loginAnswer()
		if err != nil {
			return nil, err
		}
		if len(challenge) > 0 {
			if a.human == nil {
				return nil, ErrHumanChallenge
			}
			values, err := a.human.Ask(ctx, "custom", challenge)
			if err != nil {
				return nil, err
			}
			out["verifyvalue"] = values["verifyvalue"]
		}
		return out, nil
	}
	// If the site requires a one-time code and no reusable TOTP seed
	// was enrolled, the person must supply a fresh code. Do not store it.
	if TOTPChallenge(mode, fields) && len(a.r.Secret) == 0 && a.human != nil {
		return a.human.Ask(ctx, mode, fields)
	}
	return a.r.Ask(ctx, mode, fields)
}

// loginAnswer is the saved username and password and the saved value of each extra the driver declared, and nothing else that was
// saved. A declared extra that was not saved cannot be left out or sent empty: the driver would log in wrongly (or lock the account
// with a wrong attempt), so it is an error and nothing is sent.
func (a savedAsker) loginAnswer() (site.Credentials, error) {
	out := site.Credentials{"username": a.r.Username, "password": a.r.Password}
	for _, f := range a.extras {
		v, ok := a.r.Extras[f.Name]
		if !ok || v == "" {
			return nil, ErrBindingChanged
		}
		out[f.Name] = v
	}
	return out, nil
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
	// Matches has already refused a driver whose extras are not allowed, so this cannot fail today; it is kept so that a later change
	// to Matches can never let a login go ahead without them being checked.
	extras, err := Extras(d)
	if err != nil {
		return nil, ErrBindingChanged
	}
	return Run(ctx, d, base, savedAsker{r: r, human: human, extras: extras}, hc)
}
