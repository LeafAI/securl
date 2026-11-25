package mcpserver

import (
	"context"
	"errors"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/audit"
	"github.com/LeafAI/securl/internal/flow"
	"github.com/LeafAI/securl/internal/remember"
	"github.com/LeafAI/securl/internal/session"
	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/totp"
	"github.com/LeafAI/securl/internal/vault"
	"github.com/LeafAI/securl/internal/web"
)

type rememberedDriver struct {
	site.Driver
	s      *Server
	cache  *session.Cache
	reason string
	manage bool
}

// enrollmentAllowed keeps reusable secrets on independently verified HTTPS flows.
func (s *Server) enrollmentAllowed(base *url.URL, d site.Driver) bool {
	_, idp, ok := remember.Scope(d)
	if !ok || base.Scheme != "https" || base.User != nil {
		return false
	}
	if idp != nil && (idp.Scheme != "https" || idp.User != nil || checkHost(s.cfg, idp) != nil) {
		return false
	}
	return len(flow.AuthorizationSite(base, s.cfg.Security.AuthorizationTTL(), idp)) <= web.MaxSiteLen &&
		(!s.linkViaAgent() || s.cfg.Security.LinkTOTP.Enabled || s.cfg.Security.SealTOTP.Enabled)
}

func (d rememberedDriver) RememberScope() (string, *url.URL) {
	binding, origin, _ := remember.Scope(d.Driver)
	return binding, origin
}

// setupAsker intercepts only known driver challenges, after the driver's own
// preflight. It preserves temporary CAPTCHA answers and the legacy TOTP round.
type setupAsker struct {
	human      site.Asker
	mode       string
	record     remember.Record
	consent    bool
	gotLogin   bool
	approvedAt time.Time
}

func (a *setupAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if login, challenge := remember.LoginChallenge(mode, fields); login {
		if a.gotLogin {
			return nil, errors.New("unexpected repeated login challenge")
		}
		a.gotLogin = true
		values, err := a.human.Ask(ctx, a.mode, []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "remember"}, {Name: "totp_secret", Secret: true}})
		if err != nil {
			return nil, err
		}
		if values["username"] == "" || values["password"] == "" {
			return nil, site.ErrBadCredentials
		}
		a.consent = a.mode == "credential_replace" || values["remember"] == "yes"
		if !a.consent && values["totp_secret"] != "" {
			return nil, errors.New("unexpected setup secret without consent")
		}
		a.record.Username, a.record.Password = values["username"], values["password"]
		a.approvedAt = time.Now()
		if a.consent && strings.TrimSpace(values["totp_secret"]) != "" {
			seed, err := totp.ParseSecret(values["totp_secret"])
			if err != nil {
				return nil, errors.New("invalid Base32 TOTP setup secret")
			}
			a.record.Secret = seed
		}
		out := site.Credentials{"username": a.record.Username, "password": a.record.Password}
		if len(challenge) > 0 {
			answer, err := a.human.Ask(ctx, "custom", challenge)
			if err != nil {
				return nil, err
			}
			out["verifyvalue"] = answer["verifyvalue"]
		}
		return out, nil
	}
	if remember.TOTPChallenge(mode, fields) {
		if !a.consent {
			return a.human.Ask(ctx, mode, fields)
		}
		if len(a.record.Secret) == 0 {
			values, err := a.human.Ask(ctx, "credential_totp", []site.Field{{Name: "totp_secret", Secret: true}, {Name: "code", Secret: true}})
			if err != nil {
				return nil, err
			}
			seedText, code := strings.TrimSpace(values["totp_secret"]), strings.TrimSpace(values["code"])
			if seedText == "" && code != "" {
				return site.Credentials{"code": code}, nil
			}
			if seedText == "" || code != "" {
				return nil, errors.New("enter either the TOTP setup secret or a one-time code")
			}
			seed, err := totp.ParseSecret(seedText)
			if err != nil {
				return nil, errors.New("invalid Base32 TOTP setup secret")
			}
			a.record.Secret = seed
		}
		return a.record.Ask(ctx, mode, fields)
	}
	return nil, remember.ErrHumanChallenge
}

func (d rememberedDriver) setup(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client, old *remember.Record, removed bool) (*site.Session, error) {
	if ask == nil {
		return nil, remember.ErrApprovalRequired
	}
	if !d.s.enrollmentAllowed(base, d.Driver) {
		return nil, errors.New("credential setup requires HTTPS and independently verified human delivery")
	}
	mode := "credential_setup"
	if old != nil || removed {
		mode = "credential_replace"
	}
	binding, _, _ := remember.Scope(d.Driver)
	a := &setupAsker{human: ask, mode: mode, record: remember.Record{Site: d.Name(), Binding: binding}}
	defer func() { clear(a.record.Secret) }()
	sess, err := remember.Run(ctx, d.Driver, base, a, hc)
	if err != nil {
		return nil, err
	}
	if !a.gotLogin {
		return nil, errors.New("site did not request login credentials")
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	key := site.Key(base)
	if !a.consent {
		if _, err := remember.Load(d.s.vault, key); !errors.Is(err, vault.ErrNoEntry) {
			return nil, errors.New("credential enrollment changed during login")
		}
		d.cache.Put(base, d.Driver, sess)
		return sess, nil
	}
	if !time.Now().Before(a.approvedAt.Add(d.s.cfg.Security.AuthorizationTTL())) {
		return nil, remember.ErrApprovalRequired
	}
	saved, err := remember.EnrollApproved(d.s.vault, key, a.record, old, removed, a.approvedAt, d.s.cfg.Security.AuthorizationTTL())
	if err != nil {
		return nil, err
	}
	sess.ApprovalAt, sess.ApprovalID, sess.ApprovalDuration = saved.ApprovedAt, saved.Revision, saved.Duration
	d.cache.Put(base, d.Driver, sess)
	event := "credential_enrolled"
	if old != nil {
		event = "credential_replaced"
	}
	d.s.audit.Record(audit.Event{Event: event, Site: d.Name(), Host: key})
	d.s.audit.Record(audit.Event{Event: "credential_approved", Site: d.Name(), Host: key})
	return sess, nil
}

// challengeAsker applies the normal human-request limit if a saved login needs
// a fresh CAPTCHA during an existing grant.
type challengeAsker struct {
	site.Asker
	admit func() error
}

func (a challengeAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if err := a.admit(); err != nil {
		return nil, err
	}
	return a.Asker.Ask(ctx, mode, fields)
}

func (d rememberedDriver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	key := site.Key(base)
	r, err := remember.Load(d.s.vault, key)
	if errors.Is(err, vault.ErrNoEntry) || errors.Is(err, remember.ErrRemoved) {
		if ask == nil {
			return nil, remember.ErrApprovalRequired
		}
		if e := d.s.admit(d.Driver, base, d.reason); e != nil {
			return nil, e
		}
		return d.setup(ctx, base, ask, hc, nil, errors.Is(err, remember.ErrRemoved))
	}
	if err != nil {
		return nil, err
	}
	if !r.Matches(d.Driver) {
		if !d.manage || ask == nil {
			return nil, remember.ErrBindingChanged
		}
		if err := d.s.admit(d.Driver, base, d.reason); err != nil {
			return nil, err
		}
		return d.setup(ctx, base, ask, hc, r, false)
	}
	if _, idp, _ := remember.Scope(d.Driver); idp != nil && (idp.Scheme != "https" || checkHost(d.s.cfg, idp) != nil) {
		return nil, remember.ErrBindingChanged
	}
	approved := r.Valid(time.Now()) && !d.manage
	if !approved {
		if ask == nil {
			return nil, remember.ErrApprovalRequired
		}
		// A bare link handed to the agent is not evidence of human consent.
		if !d.s.enrollmentAllowed(base, d.Driver) {
			return nil, errors.New("daily approval requires DingTalk delivery or a securl link/seal TOTP factor")
		}
		if err := d.s.admit(d.Driver, base, d.reason); err != nil {
			return nil, err
		}
		fields, err := ask.Ask(ctx, "daily_approval", []site.Field{{Name: "confirm", Label: "Approve, update or forget credentials"}})
		if err != nil {
			d.s.audit.Record(audit.Event{Event: "credential_approval_failed", Site: d.Name(), Host: key})
			return nil, err
		}
		switch strings.TrimSpace(fields["confirm"]) {
		case "REPLACE":
			return d.setup(ctx, base, ask, hc, r, false)
		case "FORGET":
			if err := ctx.Err(); err != nil {
				return nil, err
			}
			if err := remember.RemoveExpected(d.s.vault, key, r); err != nil {
				return nil, err
			}
			d.cache.Delete(key)
			d.s.audit.Record(audit.Event{Event: "credential_removed", Site: d.Name(), Host: key})
			return nil, &flow.RejectedError{Reason: "saved credentials were removed"}
		case "APPROVE":
		default:
			return nil, errors.New("approval not confirmed")
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
	}
	client := hc
	if approved {
		client = d.s.grantClient(hc, base, r.Revision)
	}
	approvedAt := time.Now()
	var human site.Asker
	if ask != nil && d.s.enrollmentAllowed(base, d.Driver) {
		human = ask
		if approved {
			human = challengeAsker{Asker: ask, admit: func() error { return d.s.admit(d.Driver, base, d.reason) }}
		}
	}
	sess, err := remember.Login(ctx, d.Driver, base, r, client, human)
	if err != nil {
		return nil, err
	}
	if !approved {
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if !time.Now().Before(approvedAt.Add(d.s.cfg.Security.AuthorizationTTL())) {
			return nil, remember.ErrApprovalRequired
		}
		r, err = remember.Approve(d.s.vault, key, r, approvedAt, d.s.cfg.Security.AuthorizationTTL())
		if err != nil {
			return nil, err
		}
		d.s.audit.Record(audit.Event{Event: "credential_approved", Site: d.Name(), Host: key})
	}

	if err := ctx.Err(); err != nil {
		return nil, err
	}
	current, err := remember.Load(d.s.vault, key)
	if err != nil || !current.Valid(time.Now()) || current.Revision != r.Revision {
		return nil, errors.New("authorization changed or expired during login")
	}
	sess.ApprovalAt, sess.ApprovalID, sess.ApprovalDuration = r.ApprovedAt, r.Revision, r.Duration
	// Store before the flow reports completion: callers may immediately use it.
	d.cache.Put(base, d.Driver, sess)
	if approved {
		d.s.audit.Record(audit.Event{Event: "credential_renewed", Site: d.Name(), Host: key})
	}
	return sess, nil
}

func (s *Server) remembered(base *url.URL, d site.Driver, c *session.Cache, reason string) (site.Driver, error) {
	_, err := remember.Load(s.vault, site.Key(base))
	if errors.Is(err, vault.ErrNoEntry) {
		if !s.enrollmentAllowed(base, d) {
			return d, nil
		}
	} else if errors.Is(err, remember.ErrRemoved) {
		if !s.enrollmentAllowed(base, d) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if !remember.Supports(d) {
		return nil, remember.ErrBindingChanged
	}

	return rememberedDriver{Driver: d, s: s, cache: c, reason: reason}, nil
}

// grantTransport checks each outbound request, including redirects and Archery
// workflow polling. Requests already sent cannot be recalled by revocation.
type grantTransport struct {
	next          http.RoundTripper
	v             *vault.Vault
	key, revision string
}

func (g grantTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	r, err := remember.Load(g.v, g.key)
	if err == nil {
		d, resolveErr := site.Resolve(r.Site, nil)
		if resolveErr != nil || !r.Matches(d) {
			err = remember.ErrBindingChanged
		}
	}
	if err != nil || !r.Valid(time.Now()) || r.Revision != g.revision {
		if req.Body != nil {
			req.Body.Close()
		}
		return nil, remember.ErrApprovalRequired
	}
	return g.next.RoundTrip(req)
}
func (s *Server) grantClient(hc *http.Client, base *url.URL, revision string) *http.Client {
	if revision == "" {
		return hc
	}
	c := *hc
	tr := c.Transport
	if tr == nil {
		tr = http.DefaultTransport
	}
	c.Transport = grantTransport{next: tr, v: s.vault, key: site.Key(base), revision: revision}
	return &c
}
