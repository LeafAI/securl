package oauth2flow

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/LeafAI/securl/internal/site"
)

// Inspect describes, without any credentials, where the site sends a login and whether securl would go along with it. It
// shows names and hosts, never a value (state, client_id and cookie values stay out).
func (d *driver) Inspect(ctx context.Context, base *url.URL, hc *http.Client) ([]string, error) {
	if hc == nil {
		hc = &http.Client{}
	}
	res, err := d.preflight(ctx, site.NoRedirect(site.JarClient(hc)), base)
	var out []string
	if res.hops > 0 {
		out = append(out, fmt.Sprintf("the site answered %d request(s) before it sent the browser away", res.hops))
	}
	if len(res.cookies) > 0 {
		names := dedupe(res.cookies)
		out = append(out, "cookies the site set on the way: "+strings.Join(names, ", ")+" (an AWSALBAuthNonce cookie is what an AWS load balancer with an OIDC action sets)")
	}
	if res.idpHost != "" {
		verdict := "matches idp.url"
		if res.idpHost != d.idp.Host {
			verdict = "is NOT the configured idp " + d.idp.Host + ": securl would refuse this login and ask nobody"
		}
		out = append(out, "the site sends its sign-in to "+res.idpHost+", which "+verdict)
	}
	if len(res.params) > 0 {
		sort.Strings(res.params)
		out = append(out, "the authorization request carries "+strings.Join(res.params, ", ")+" (values not shown)")
	}
	if res.redirect != "" {
		out = append(out, "its redirect_uri returns to "+res.redirect)
	}
	if err != nil {
		if isUnreachable(err) {
			return out, err
		}
		out = append(out, "NOT OK: "+err.Error())
		return out, nil
	}
	out = append(out, "the preflight passes: securl would ask for a GitLab login and then run the chain")
	if d.spec.consent() == ConsentApprove {
		out = append(out, "on_consent: approve: if GitLab shows its first-time authorisation page, securl presses Authorize once")
	} else {
		out = append(out, "on_consent: fail: if GitLab shows its first-time authorisation page, the login stops with instructions")
	}
	return out, nil
}

func dedupe(in []string) []string {
	seen := map[string]bool{}
	var out []string
	for _, s := range in {
		if !seen[s] {
			seen[s] = true
			out = append(out, s)
		}
	}
	return out
}
