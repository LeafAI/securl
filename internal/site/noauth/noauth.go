// Package noauth is the driver for sites without authentication (SkyWalking today).
package noauth

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string { return "skywalking" }

// Match recognises SkyWalking by hostname hint only; use the `site` argument otherwise.
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "skywalking")
}

func (driver) NeedsLogin() bool { return false }

func (d driver) Login(ctx context.Context, base *url.URL, _ site.Asker, hc *http.Client) (*site.Session, error) {
	s := &site.Session{Tokens: map[string]string{"auth": "none"}}
	return s, d.Probe(ctx, base, s, hc)
}

// Probe asks the URL once, without following a redirect, so that a site that sends the browser to a login (an OAuth 2.0 front)
// is recognised for what it is instead of being followed to the identity provider. Nothing of the redirect (its host or its
// query, which holds a state) is put into the error.
func (driver) Probe(ctx context.Context, base *url.URL, _ *site.Session, hc *http.Client) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, base.String(), nil)
	if err != nil {
		return err
	}
	c := *hc
	c.CheckRedirect = func(r *http.Request, via []*http.Request) error {
		if !sameHost(base, r.URL) {
			return http.ErrUseLastResponse
		}
		if len(via) >= 10 {
			return fmt.Errorf("stopped after 10 redirects")
		}
		return nil
	}
	resp, err := c.Do(req)
	if err != nil {
		return err
	}
	resp.Body.Close()
	switch {
	case leavesTheSite(resp, base):
		return fmt.Errorf("skywalking: %s sends visitors to another host to log in (HTTP %d); it needs a login, so add an oauth2_sites entry for it (see docs/OPERATING.md)", base, resp.StatusCode)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return fmt.Errorf("skywalking: %s returned %s: it needs a login, so add an oauth2_sites entry or a sites: entry for it", base, resp.Status)
	case resp.StatusCode >= 400:
		return fmt.Errorf("skywalking: %s returned %s (site may need auth; use the generic driver)", base, resp.Status)
	}
	return nil
}

// leavesTheSite reports whether the answer is a redirect to another host (the redirect was not followed, so its target is
// the Location header, read against the request that was answered).
func leavesTheSite(resp *http.Response, base *url.URL) bool {
	if resp.StatusCode < 300 || resp.StatusCode >= 400 {
		return false
	}
	next, err := resp.Request.URL.Parse(resp.Header.Get("Location"))
	return err == nil && !sameHost(base, next)
}

func sameHost(a, b *url.URL) bool { return strings.EqualFold(a.Host, b.Host) }
