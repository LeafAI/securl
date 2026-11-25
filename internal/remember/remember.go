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
)

type Record struct {
	Site       string        `json:"site"`
	Username   string        `json:"username"`
	Password   string        `json:"password"`
	Secret     []byte        `json:"totp_secret"`
	Revision   string        `json:"revision"`
	ApprovedAt time.Time     `json:"approved_at"`
	Duration   time.Duration `json:"duration,omitempty"`
}

func Supported(name string) bool { return name == "gitlab" || name == "archery" }

func (r *Record) validate() error {
	if !Supported(r.Site) || r.Username == "" || r.Password == "" || len(r.Secret) < 10 || len(r.Revision) != 32 || r.Duration < 0 {
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

// Ask generates an upstream code only when the site driver needs it.
func (r *Record) Ask(ctx context.Context, mode string, _ []site.Field) (site.Credentials, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	switch mode {
	case "login":
		return site.Credentials{"username": r.Username, "password": r.Password}, nil
	case "totp":
		return site.Credentials{"code": totp.Code(r.Secret, time.Now(), 30*time.Second, 6)}, nil
	default:
		return nil, errors.New("unsupported saved credential challenge")
	}
}

// Login only allows the exact configured HTTPS origin. It never returns
// upstream error text that could echo a password or OTP in an error page.
func Login(ctx context.Context, d site.Driver, base *url.URL, r *Record, hc *http.Client) (*site.Session, error) {
	if d.Name() != r.Site || base.Scheme != "https" || base.User != nil {
		return nil, errors.New("saved credentials require matching HTTPS site")
	}
	if hc == nil {
		hc = http.DefaultClient
	}
	c := *hc
	old := c.CheckRedirect
	c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
		if req.URL.Scheme != base.Scheme || req.URL.Host != base.Host || req.URL.User != nil {
			return errors.New("saved credential login refused cross-origin redirect")
		}
		if old != nil {
			return old(req, via)
		}
		if len(via) >= 10 {
			return errors.New("too many redirects")
		}
		return nil
	}
	sess, err := d.Login(ctx, base, r, &c)
	if err != nil {
		for _, kind := range []error{site.ErrBadCredentials, site.ErrUnreachable, site.ErrLoginRejected} {
			if errors.Is(err, kind) {
				return nil, fmt.Errorf("%w: saved credential login failed", kind)
			}
		}
		return nil, errors.New("saved credential login failed")
	}
	if sess == nil {
		return nil, errors.New("site returned no session")
	}
	return sess, nil
}
