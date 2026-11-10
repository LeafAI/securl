package oauth2flow

import (
	"context"
	"fmt"
	"html"
	"net/http"
	"net/url"
	"regexp"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

func hostPort(u *url.URL) string {
	p := u.Port()
	if p == "" {
		p = "80"
		if u.Scheme == "https" {
			p = "443"
		}
	}
	return strings.ToLower(u.Hostname()) + ":" + p
}

func isRedirect(code int) bool {
	switch code {
	case 301, 302, 303, 307, 308:
		return true
	}
	return false
}

func sameSite(base, u *url.URL) bool { return u.Scheme == base.Scheme && hostPort(u) == hostPort(base) }

func (d *driver) isIDP(u *url.URL) bool {
	return u.Scheme == d.idp.Scheme && hostPort(u) == hostPort(d.idp)
}

func (d *driver) authorizePath() string {
	return strings.TrimRight(d.idp.Path, "/") + "/oauth/authorize"
}

func rejected(format string, a ...any) error {
	return fmt.Errorf("%w: "+format, append([]any{site.ErrLoginRejected}, a...)...)
}

// checkAuthorize accepts only an OAuth 2.0 authorization-code request to the configured idp whose code returns to the site. It
// never puts a query value into the message.
func (d *driver) checkAuthorize(u, base *url.URL) error {
	if !d.isIDP(u) {
		return rejected("the site sends logins to %s, which is not the configured idp (%s)", u.Host, d.idp.Host)
	}
	if u.Path != d.authorizePath() {
		return rejected("the site's redirect to %s is not an OAuth 2.0 authorization request", u.Host)
	}
	q := u.Query()
	if q.Get("response_type") != "code" {
		return rejected("the authorization request does not ask for a code (response_type)")
	}
	for _, k := range []string{"client_id", "state", "redirect_uri"} {
		if q.Get(k) == "" {
			return rejected("the authorization request has no %s", k)
		}
	}
	ru, err := url.Parse(q.Get("redirect_uri"))
	if err != nil || !sameSite(base, ru) {
		return rejected("the authorization request's redirect_uri does not return to the site: the code would go to another host")
	}
	return nil
}

// fetch makes one request through nc (which does not follow redirects) and returns the answer with its body read.
func fetch(ctx context.Context, nc *http.Client, method string, u *url.URL, form url.Values) (*http.Response, string, error) {
	var body *strings.Reader
	if form != nil {
		body = strings.NewReader(form.Encode())
	}
	var req *http.Request
	var err error
	if body != nil {
		req, err = http.NewRequestWithContext(ctx, method, u.String(), body)
		if err == nil {
			req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
		}
	} else {
		req, err = http.NewRequestWithContext(ctx, method, u.String(), nil)
	}
	if err != nil {
		return nil, "", rejected("the request could not be built")
	}
	resp, err := nc.Do(req)
	if err != nil {
		return nil, "", fmt.Errorf("%w: %v", site.ErrUnreachable, err)
	}
	return resp, site.ReadBody(resp), nil
}

func location(resp *http.Response, cur *url.URL) (*url.URL, bool) {
	if !isRedirect(resp.StatusCode) {
		return nil, false
	}
	loc := resp.Header.Get("Location")
	if loc == "" {
		return nil, false
	}
	next, err := cur.Parse(loc)
	if err != nil {
		return nil, false
	}
	next.Fragment = ""
	return next, true
}

// preflightResult is what the anonymous look at the site found; it is filled in as far as the walk got.
type preflightResult struct {
	hops      int
	cookies   []string // names of the cookies the site set (never values)
	idpHost   string
	redirect  string // host of the redirect_uri
	params    []string
	authorize *url.URL
}

// preflight asks the site anonymously where it sends a login, without following the redirect to the identity provider. It makes
// no request to any host but the site.
func (d *driver) preflight(ctx context.Context, nc *http.Client, base *url.URL) (preflightResult, error) {
	var res preflightResult
	cur := d.start(base)
	for res.hops < maxHops {
		res.hops++
		resp, _, err := fetch(ctx, nc, http.MethodGet, cur, nil)
		if err != nil {
			return res, err
		}
		for _, c := range resp.Cookies() {
			res.cookies = append(res.cookies, c.Name)
		}
		next, ok := location(resp, cur)
		if !ok {
			return res, rejected("%s did not ask for a login (it answered HTTP %d without redirecting to an identity provider); it may need none, or use something other than OAuth 2.0", base.Host, resp.StatusCode)
		}
		if sameSite(base, next) {
			cur = next
			continue
		}
		res.idpHost = next.Host
		if err := d.checkAuthorize(next, base); err != nil {
			return res, err
		}
		q := next.Query()
		for k := range q {
			res.params = append(res.params, k)
		}
		ru, _ := url.Parse(q.Get("redirect_uri"))
		res.redirect, res.authorize = ru.Host, next
		return res, nil
	}
	return res, rejected("%s redirected %d times without reaching an identity provider", base.Host, maxHops)
}

// fresh runs the chain with the signed-in jar: site, authorize, callback, site. State, nonce and code are all new.
func (d *driver) fresh(ctx context.Context, nc *http.Client, base *url.URL) (*site.Session, error) {
	rec := newRecorder(base)
	cur, afterIDP, consented := d.start(base), false, false
	method, form := http.MethodGet, url.Values(nil)
	for hop := 0; hop < maxHops+2; hop++ {
		onSite := sameSite(base, cur)
		if !onSite && !d.isIDP(cur) {
			return nil, rejected("the login chain led to %s, which is neither the site nor the idp", cur.Host)
		}
		resp, body, err := fetch(ctx, nc, method, cur, form)
		if err != nil {
			return nil, err
		}
		if onSite {
			rec.add(resp.Cookies(), afterIDP)
		} else {
			afterIDP = true
		}
		if !onSite && resp.StatusCode == 200 && cur.Path == d.authorizePath() && method == http.MethodGet {
			if consented {
				return nil, rejected("GitLab asked for the authorisation of the application again after it was approved")
			}
			f, err := d.consent(cur, body)
			if err != nil {
				return nil, err
			}
			consented, method, form, cur = true, http.MethodPost, f.values, f.action
			continue
		}
		method, form = http.MethodGet, nil
		next, ok := location(resp, cur)
		if !ok {
			return d.finish(resp.StatusCode, onSite, base, rec)
		}
		if onSite && !sameSite(base, next) {
			if err := d.checkAuthorize(next, base); err != nil {
				return nil, err
			}
		}
		cur = next
	}
	return nil, rejected("the login chain did not end after %d redirects", maxHops)
}

func (d *driver) finish(status int, onSite bool, base *url.URL, rec *recorder) (*site.Session, error) {
	switch {
	case !onSite:
		return nil, rejected("GitLab did not send securl back to the site after the sign-in (HTTP %d at %s); the account may not be allowed to use this application", status, d.idp.Host)
	case site.TemporaryStatus(status) || status >= 500:
		return nil, fmt.Errorf("%w: %s answered HTTP %d after the sign-in", site.ErrUnreachable, base.Host, status)
	case status < 200 || status >= 300:
		return nil, rejected("%s answered HTTP %d after the sign-in", base.Host, status)
	}
	s := rec.session()
	if len(s.Cookies) == 0 {
		return nil, rejected("%s did not issue a session cookie", base.Host)
	}
	return s, nil
}

type consentForm struct {
	action *url.URL
	values url.Values
}

var (
	formRe  = regexp.MustCompile(`(?is)<form\b([^>]*)>(.*?)</form>`)
	inputRe = regexp.MustCompile(`(?is)<input\b[^>]*>`)
)

func attr(tag, name string) string {
	m := regexp.MustCompile(`(?is)\b` + name + `\s*=\s*(?:"([^"]*)"|'([^']*)')`).FindStringSubmatch(tag)
	if m == nil {
		return ""
	}
	return html.UnescapeString(m[1] + m[2])
}

// consent finds the "Authorize" form of GitLab's first-time authorisation page and decides whether securl may submit it. The
// "Deny" form carries _method=delete and is never used. The form is only approved when its hidden fields equal the request
// that was just made: a page that asks to authorise something else is not approved.
func (d *driver) consent(cur *url.URL, page string) (*consentForm, error) {
	if d.spec.consent() == ConsentFail {
		return nil, rejected("GitLab asks to authorise the application for the first time. Open the site once in your own browser and press Authorize, then retry")
	}
	asked := cur.Query()
	for _, m := range formRe.FindAllStringSubmatch(page, -1) {
		action, err := cur.Parse(attr(m[1], "action"))
		if err != nil || !d.isIDP(action) || action.Path != d.authorizePath() || !strings.EqualFold(attr(m[1], "method"), "post") {
			continue
		}
		vals, deny := url.Values{}, false
		for _, in := range inputRe.FindAllString(m[2], -1) {
			name := attr(in, "name")
			if name == "" || !strings.EqualFold(attr(in, "type"), "hidden") {
				continue
			}
			if name == "_method" {
				deny = true
			}
			vals.Set(name, attr(in, "value"))
		}
		if deny {
			continue
		}
		for _, k := range []string{"client_id", "redirect_uri", "response_type", "state"} {
			if vals.Get(k) != asked.Get(k) {
				return nil, rejected("GitLab's authorisation page does not match the request that was made; securl did not approve it")
			}
		}
		if asked.Get("scope") != "" && vals.Get("scope") != asked.Get("scope") {
			return nil, rejected("GitLab's authorisation page does not match the request that was made; securl did not approve it")
		}
		return &consentForm{action: action, values: vals}, nil
	}
	return nil, rejected("GitLab showed an authorisation page that securl could not read; open the site once in your own browser and press Authorize, then retry")
}

// recorder keeps the site's cookies from the Set-Cookie headers the chain saw, because the jar forgets their expiry.
type recorder struct {
	host  string
	order []string
	m     map[string]*recorded
	now   func() time.Time
}

type recorded struct {
	c    http.Cookie
	post bool // set after GitLab was visited, i.e. at or after the callback
}

func newRecorder(base *url.URL) *recorder {
	return &recorder{host: base.Hostname(), m: map[string]*recorded{}, now: time.Now}
}

func (r *recorder) add(cs []*http.Cookie, afterIDP bool) {
	now := r.now()
	for _, c := range cs {
		if c.Name == "" || (c.Domain != "" && !domainMatch(r.host, c.Domain)) {
			continue
		}
		key := c.Name + "\x00" + strings.ToLower(strings.TrimPrefix(c.Domain, ".")) + "\x00" + c.Path
		if c.MaxAge < 0 || (!c.Expires.IsZero() && !c.Expires.After(now)) {
			delete(r.m, key)
			continue
		}
		cp := *c
		if cp.MaxAge > 0 {
			cp.Expires = now.Add(time.Duration(cp.MaxAge) * time.Second)
		}
		cp.MaxAge, cp.Raw, cp.Unparsed = 0, "", nil
		if _, seen := r.m[key]; !seen {
			r.order = append(r.order, key)
		}
		r.m[key] = &recorded{c: cp, post: afterIDP}
	}
}

func (r *recorder) session() *site.Session {
	s := &site.Session{}
	for _, k := range r.order {
		e, ok := r.m[k]
		if !ok {
			continue
		}
		c := e.c
		s.Cookies = append(s.Cookies, &c)
		if e.post && !c.Expires.IsZero() && (s.ExpiresAt.IsZero() || c.Expires.Before(s.ExpiresAt)) {
			s.ExpiresAt = c.Expires
		}
	}
	return s
}

func domainMatch(host, domain string) bool {
	host, domain = strings.ToLower(host), strings.ToLower(strings.TrimPrefix(domain, "."))
	return host == domain || strings.HasSuffix(host, "."+domain)
}
