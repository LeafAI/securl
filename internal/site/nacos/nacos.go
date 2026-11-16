// Package nacos logs in to a Nacos server (the configuration and service registry) with a Nacos account.
//
// What the login is, from the Nacos documentation of 1.x, 2.x and 3.x. It has not yet been run against a live server:
//
//   - Nacos 1.x and 2.x: POST /nacos/v1/auth/login with the form fields username and password, answered with
//     {"accessToken", "tokenTtl", "globalAdmin"}. Nacos 3.x: POST /v3/auth/user/login, the same fields and the same answer.
//     A wrong account is HTTP 403, so the status is what counts.
//   - The token goes with every request as the accessToken header and as "Authorization: Bearer": a Nacos server reads at
//     least one of them, and the older way (accessToken in the URL) is never used, so no URL holds the token.
//   - The context path is /nacos unless the server was set up otherwise, and a Nacos 3 console is served at the root of its
//     own port. A path the owner gave with roots is used as it is; otherwise /nacos and then no path are tried.
//
// The token is a signed JWT that the server does not remember: it ends when tokenTtl ends (18000 seconds unless the owner
// changed it) and the session says so. The probe asks for the namespace list, an address the Nacos console itself uses.
//
// There is no request policy. Nacos holds the configuration of the services behind it, passwords included, and its write
// operations (publish, delete) are reachable with whatever the account may do: use an account that can only read, and
// that is used for nothing else.
package nacos

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"

	"github.com/LeafAI/securl/internal/site"
)

type driver struct{}

func init() { site.Register(driver{}) }

func (driver) Name() string     { return "nacos" }
func (driver) NeedsLogin() bool { return true }
func (driver) Match(u *url.URL) bool {
	return strings.Contains(strings.ToLower(u.Hostname()), "nacos")
}

// generation is one family of Nacos addresses, below the context path.
type generation struct {
	name  string
	login string
	check string
	state string
}

// The generations, in the order they are tried: v1 is Nacos 1.x and 2.x (the most used), v3 is Nacos 3.x. A Nacos server
// answers 404 for an address of a generation it does not have, so asking for the wrong one tells nothing about the account.
var generations = []generation{
	{name: "v1", login: "/v1/auth/login", check: "/v1/console/namespaces", state: "/v1/console/server/state"},
	{name: "v3", login: "/v3/auth/user/login", check: "/v3/console/core/namespace/list", state: "/v3/console/server/state"},
}

func generationOf(name string) generation {
	for _, g := range generations {
		if g.name == name {
			return g
		}
	}
	return generations[0]
}

// prefixes lists the context paths to try: the one the owner gave with roots, or else /nacos (the default of every Nacos
// release) and then none (a Nacos 3 console is served at the root of its own port).
func prefixes(base *url.URL) []string {
	if p := strings.TrimRight(base.EscapedPath(), "/"); p != "" {
		return []string{p}
	}
	return []string{"/nacos", ""}
}

func endpoint(base *url.URL, prefix, path string) string {
	return base.Scheme + "://" + base.Host + prefix + path
}

type loginReply struct {
	AccessToken string `json:"accessToken"`
	TokenTTL    int64  `json:"tokenTtl"`
}

// Login asks for the account and logs in once: a wrong attempt is counted by whatever guards the account, so the account is
// sent only to an address that exists, and the first one that answers decides.
func (driver) Login(ctx context.Context, base *url.URL, ask site.Asker, hc *http.Client) (*site.Session, error) {
	creds, err := ask.Ask(ctx, "login", site.LoginFields)
	if err != nil {
		return nil, err
	}
	user, pass := strings.TrimSpace(creds["username"]), creds["password"]
	creds["password"] = ""
	if user == "" || pass == "" {
		return nil, fmt.Errorf("%w: the username and the password are both needed", site.ErrBadCredentials)
	}
	form := url.Values{"username": {user}, "password": {pass}}.Encode()
	c := site.NoRedirect(site.JarClient(hc))
	for _, prefix := range prefixes(base) {
		for _, g := range generations {
			s, found, err := tryLogin(ctx, c, base, prefix, g, form)
			if found {
				return s, err
			}
		}
	}
	return nil, fmt.Errorf("%w: no Nacos login address answered on %s", site.ErrLoginRejected, base.Host)
}

// tryLogin posts the account to one login address. found is false when the server has no such address (404 or 405), so that
// the next one can be tried; any other answer ends the login, because the account has been looked at.
func tryLogin(ctx context.Context, c *http.Client, base *url.URL, prefix string, g generation, form string) (*site.Session, bool, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, endpoint(base, prefix, g.login), strings.NewReader(form))
	if err != nil {
		return nil, true, fmt.Errorf("%w: the address is not usable", site.ErrLoginRejected)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	resp, err := c.Do(req)
	if err != nil {
		return nil, true, site.Unreachable(err)
	}
	body := site.ReadBody(resp)
	switch {
	case resp.StatusCode == http.StatusNotFound || resp.StatusCode == http.StatusMethodNotAllowed:
		return nil, false, nil
	case site.TemporaryStatus(resp.StatusCode):
		return nil, true, site.ProbeStatus("nacos", resp.StatusCode)
	case resp.StatusCode == http.StatusUnauthorized || resp.StatusCode == http.StatusForbidden:
		return nil, true, fmt.Errorf("%w: Nacos refused that username or password", site.ErrBadCredentials)
	case resp.StatusCode != http.StatusOK:
		return nil, true, fmt.Errorf("%w: Nacos answered HTTP %d: %s", site.ErrLoginRejected, resp.StatusCode, site.Clip(body, 120))
	}
	var r loginReply
	if json.Unmarshal([]byte(body), &r) != nil || r.AccessToken == "" {
		return nil, true, fmt.Errorf("%w: %s answered the login without an access token (is authentication switched on?)", site.ErrLoginRejected, base.Host)
	}
	s := &site.Session{}
	s.Headers = map[string]string{"accessToken": r.AccessToken, "Authorization": "Bearer " + r.AccessToken}
	s.Tokens = map[string]string{"access_token": r.AccessToken, "api": g.name}
	if r.TokenTTL > 120 {
		s.ExpiresAt = time.Now().Add(time.Duration(r.TokenTTL-60) * time.Second)
	}
	return s, true, nil
}

// Probe asks the namespace list of the generation the session was made with. 403 (or 401) is the server saying it does not
// know the token; 502, 503, 504 and 429 say nothing about it, and neither does a server that has no such address, so the
// session is kept in those cases (its own expiry still applies).
func (driver) Probe(ctx context.Context, base *url.URL, s *site.Session, hc *http.Client) error {
	g := generationOf(s.Tokens["api"])
	c := site.NoRedirect(site.JarClient(hc))
	for _, prefix := range prefixes(base) {
		req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(base, prefix, g.check), nil)
		if err != nil {
			return err
		}
		for k, v := range s.Headers {
			req.Header.Set(k, v)
		}
		resp, err := c.Do(req)
		if err != nil {
			return site.Unreachable(err)
		}
		resp.Body.Close()
		switch resp.StatusCode {
		case http.StatusNotFound, http.StatusMethodNotAllowed:
			continue
		case http.StatusUnauthorized, http.StatusForbidden:
			return errors.New("nacos session invalid: the server does not accept the token")
		}
		return site.ProbeStatus("nacos", resp.StatusCode)
	}
	return nil
}

// Inspect reports what the server says about itself without any credentials (its version and whether authentication is on),
// for `securl doctor -site`. The state address is public in Nacos.
func (driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	c := site.NoRedirect(site.JarClient(hc))
	for _, prefix := range prefixes(base) {
		for _, g := range generations {
			req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint(base, prefix, g.state), nil)
			if err != nil {
				return nil, err
			}
			resp, err := c.Do(req)
			if err != nil {
				return nil, site.Unreachable(err)
			}
			body := site.ReadBody(resp)
			var state map[string]any
			if resp.StatusCode != http.StatusOK || json.Unmarshal([]byte(body), &state) != nil {
				continue
			}
			out := []string{fmt.Sprintf("server state at %s (API generation %s)", prefix+g.state, g.name)}
			for _, k := range []string{"version", "auth_enabled", "auth_system_type", "login_page_enabled"} {
				if v, ok := state[k]; ok {
					out = append(out, fmt.Sprintf("%s: %v", k, v))
				}
			}
			return out, nil
		}
	}
	return []string{"no Nacos server-state address answered (the login addresses are tried when somebody logs in)"}, nil
}
