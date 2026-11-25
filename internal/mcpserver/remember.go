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

// enrollmentAllowed preserves ordinary login on HTTP or unverified agent links.
func (s *Server) enrollmentAllowed(base *url.URL) bool {
	return base.Scheme == "https" && len(flow.AuthorizationSite(base, s.cfg.Security.AuthorizationTTL())) <= web.MaxSiteLen &&
		(!s.linkViaAgent() || s.cfg.Security.LinkTOTP.Enabled || s.cfg.Security.SealTOTP.Enabled)
}

// firstLoginAsker preserves the original driver's one-time-code round for
// people who choose not to remember credentials.
type firstLoginAsker struct {
	site.Asker
	creds site.Credentials
}

func (a firstLoginAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	if mode == "login" {
		return a.creds, ctx.Err()
	}
	return a.Asker.Ask(ctx, mode, fields)
}

func (d rememberedDriver) setup(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client, old *remember.Record, removed bool) (*site.Session, error) {
	if ask == nil {
		return nil, remember.ErrApprovalRequired
	}
	if !d.s.enrollmentAllowed(base) {
		return nil, errors.New("credential setup requires HTTPS and independently verified human delivery")
	}
	mode := "credential_setup"
	if old != nil || removed {
		mode = "credential_replace"
	}
	fields, err := ask.Ask(ctx, mode, []site.Field{{Name: "username"}, {Name: "password", Secret: true}, {Name: "remember"}, {Name: "totp_secret", Secret: true}})
	if err != nil {
		return nil, err
	}
	if fields["username"] == "" || fields["password"] == "" {
		return nil, site.ErrBadCredentials
	}
	key := site.Key(base)
	if mode == "credential_setup" && fields["remember"] != "yes" {
		if fields["totp_secret"] != "" {
			return nil, errors.New("unexpected setup secret without consent")
		}
		sess, err := d.Driver.Login(ctx, base, firstLoginAsker{Asker: ask, creds: site.Credentials{"username": fields["username"], "password": fields["password"]}}, hc)
		if err != nil {
			return nil, err
		}
		if err := ctx.Err(); err != nil {
			return nil, err
		}
		if _, err := remember.Load(d.s.vault, key); !errors.Is(err, vault.ErrNoEntry) {
			return nil, errors.New("credential enrollment changed during login")
		}
		d.cache.Put(base, d.Driver, sess)
		return sess, nil
	}
	seed, err := totp.ParseSecret(fields["totp_secret"])
	if err != nil {
		return nil, errors.New("invalid Base32 TOTP setup secret")
	}
	defer clear(seed)
	r := remember.Record{Site: d.Name(), Username: fields["username"], Password: fields["password"], Secret: seed}
	approvedAt := time.Now()
	sess, err := remember.Login(ctx, d.Driver, base, &r, hc)
	if err != nil {
		return nil, err
	}
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	saved, err := remember.EnrollApproved(d.s.vault, key, r, old, removed, approvedAt, d.s.cfg.Security.AuthorizationTTL())
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
	if r.Site != d.Name() {
		return nil, errors.New("saved credential driver mismatch")
	}
	approved := r.Valid(time.Now()) && !d.manage
	if !approved {
		if ask == nil {
			return nil, remember.ErrApprovalRequired
		}
		// A bare link handed to the agent is not evidence of human consent.
		if !d.s.enrollmentAllowed(base) {
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
	sess, err := remember.Login(ctx, d.Driver, base, r, client)
	if err != nil {
		return nil, err
	}
	if !approved {
		if err := ctx.Err(); err != nil {
			return nil, err
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
	r, err := remember.Load(s.vault, site.Key(base))
	if errors.Is(err, vault.ErrNoEntry) {
		if !remember.Supported(d.Name()) || !s.enrollmentAllowed(base) {
			return d, nil
		}
	} else if errors.Is(err, remember.ErrRemoved) {
		if !remember.Supported(d.Name()) || !s.enrollmentAllowed(base) {
			return nil, err
		}
	} else if err != nil {
		return nil, err
	} else if r.Site != d.Name() {
		return nil, errors.New("saved credential driver mismatch")
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
