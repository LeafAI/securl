// Package oauth2flow logs in to a site that sits behind an OAuth 2.0 front (an AWS Application Load Balancer with an OIDC
// action, or a proxy such as oauth2-proxy) with GitLab as the identity provider.
//
// The front is the OAuth client: it sends an anonymous browser to GitLab's /oauth/authorize, redeems the code that GitLab
// sends back to its callback, and then issues its own session cookies. The person gives securl their GitLab login (the same
// sealed page and the same GitLab sign-in code as the gitlab driver), and securl then plays the browser, in one go and with
// its own cookie jar, so the state, the nonce cookie and the code are never stale:
//
//  1. preflight, anonymously: the site must redirect to GitLab's authorize endpoint of the configured idp (and no other host),
//     asking for a code that returns to the site itself. Otherwise the login ends here and nobody is asked;
//  2. one human round for the GitLab login (and one for a second factor if GitLab asks);
//  3. a fresh chain with the signed-in jar: site, GitLab authorize, the site's callback, the site. If GitLab asks for the
//     first-time authorisation of the application, securl presses Authorize once (on_consent: approve, the default);
//  4. only the site's cookies are kept. GitLab's cookies and the password are discarded with the jar.
//
// Redirects are followed by hand and only between the site and the idp, over https.
package oauth2flow

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"

	"github.com/LeafAI/securl/internal/site"
	"github.com/LeafAI/securl/internal/site/gitlab"
)

const maxHops = 10

type driver struct {
	spec Spec
	idp  *url.URL
}

// New validates spec and returns the driver for it.
func New(spec Spec) (site.Driver, error) {
	if err := spec.Validate(); err != nil {
		return nil, err
	}
	idp, err := spec.idpURL()
	if err != nil {
		return nil, fmt.Errorf("oauth2_sites %s: %w", spec.Name, err)
	}
	return &driver{spec: spec, idp: idp}, nil
}

func (d *driver) Name() string     { return d.spec.Name }
func (d *driver) NeedsLogin() bool { return true }
func (d *driver) Match(u *url.URL) bool {
	return d.spec.MatchHost != "" && strings.Contains(strings.ToLower(u.Hostname()), strings.ToLower(d.spec.MatchHost))
}

// Detail is securl's own account of what the person agrees to; the agent's reason is shown next to it, not instead of it.
func (d *driver) Detail(base *url.URL) string {
	t := "securl will sign in to GitLab at " + d.idp.Host + " with the username and password you type, and use that sign-in once to " +
		"log in to " + base.Host + ", which asks GitLab who you are. Your GitLab password is not kept."
	if d.spec.consent() == ConsentApprove {
		t += " If GitLab shows its first-time authorisation page for this site, securl will press Authorize."
	}
	return t
}

func (d *driver) start(base *url.URL) *url.URL {
	u := *base
	u.Path = strings.TrimRight(base.Path, "/") + d.spec.StartPath
	if d.spec.StartPath == "" {
		u.Path = base.Path
		if u.Path == "" {
			u.Path = "/"
		}
	}
	u.RawQuery, u.Fragment = "", ""
	return &u
}

func (d *driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	if hc == nil {
		hc = &http.Client{}
	}
	if ask == nil {
		return nil, errors.New("oauth2: signing in needs a person to ask")
	}
	if _, err := d.preflight(ctx, site.NoRedirect(site.JarClient(hc)), base); err != nil {
		return nil, err
	}
	jar := site.JarClient(hc)
	o := gitlab.Options{LoginMethod: d.spec.IDP.LoginMethod, LDAPProvider: d.spec.IDP.LDAPProvider}
	if err := gitlab.SignIn(ctx, jar, d.idp, idpAsker{inner: ask, host: d.idp.Host}, o); err != nil {
		return nil, err
	}
	sess, err := d.fresh(ctx, site.NoRedirect(jar), base)
	if err != nil {
		return nil, err
	}
	if err := d.Probe(ctx, base, sess, hc); err != nil {
		if errors.Is(err, site.ErrUnreachable) {
			return nil, err
		}
		return nil, fmt.Errorf("%w: the site did not accept the cookies it had just issued (%v)", site.ErrLoginRejected, err)
	}
	return sess, nil
}

// Probe asks the site for the probe path (default the base) with the session's cookies, redirects not followed: a redirect
// (to the identity provider), 401 or 403 means the session is gone.
func (d *driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	if hc == nil {
		hc = &http.Client{}
	}
	target := base.String()
	if p := d.spec.Probe.Path; p != "" {
		target = strings.TrimRight(base.String(), "/") + p
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, target, nil)
	if err != nil {
		return err
	}
	if c := site.CookieHeader(s.Cookies); c != "" {
		req.Header.Set("Cookie", c)
	}
	resp, err := site.NoRedirect(hc).Do(req)
	if err != nil {
		return site.Unreachable(err)
	}
	resp.Body.Close()
	want := d.spec.Probe.ExpectStatus
	switch {
	case want != 0 && resp.StatusCode == want, want == 0 && resp.StatusCode >= 200 && resp.StatusCode < 300:
		return nil
	case site.TemporaryStatus(resp.StatusCode):
		return site.ProbeStatus(d.spec.Name, resp.StatusCode)
	}
	return fmt.Errorf("%s session invalid: HTTP %d", d.spec.Name, resp.StatusCode)
}

// idpAsker turns the GitLab driver's login and totp rounds into rounds that name the identity provider, so that the person
// is never typing a GitLab password into a page that only says it is for the site.
type idpAsker struct {
	inner site.Asker
	host  string
}

func (a idpAsker) Ask(ctx context.Context, mode string, fields []site.Field) (site.Credentials, error) {
	h := a.host
	if len(h) > 30 {
		h = h[:30] + "..."
	}
	switch mode {
	case "login":
		fields = []site.Field{
			{Name: "username", Label: "GitLab username (" + h + ")"},
			{Name: "password", Label: "GitLab password (" + h + ")", Secret: true}}
	case "totp":
		fields = []site.Field{{Name: "code", Label: "GitLab one-time code (" + h + ")"}}
	default:
		return a.inner.Ask(ctx, mode, fields)
	}
	return a.inner.Ask(ctx, "custom", fields)
}

func isUnreachable(err error) bool { return errors.Is(err, site.ErrUnreachable) }
