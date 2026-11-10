# SPEC: log in through GitLab OAuth 2.0 for sites behind an OAuth 2.0 front (SkyWalking first)

Status: **v4, approved by the reviewer; implemented (not yet run against a real ALB).** Decisions: ALB confirmed; giving securl the GitLab password is
acceptable; `on_consent` defaults to `approve`; securl does not sign out of GitLab; names are fine (section 11).
Work item: "Need to support GitLab OAuth2.0 for SkyWalking".

History: v1 made securl an OAuth client; v2 had the person paste the callback URL back. v3 (this one) follows the reviewer's
correction: a code that went through the person's browser is stale or spent by the time securl could use it, so the person
gives securl their **GitLab login, exactly as for the existing `gitlab` driver**, and securl performs the whole redirect
chain itself, in one go, with its own cookie jar.

## 1. Problem and what is known about the target

securl logs in by driving a site's own login. SkyWalking has none, so `internal/site/noauth` probes and returns an empty
session. The target SkyWalking is protected by an OAuth 2.0 front. From the reviewer's anonymous `curl` (host names kept
out of this repository on purpose; placeholders below):

- `GET https://skywalking.corp.example/` answers `302` with `Set-Cookie: AWSALBAuthNonce=...; Secure; HttpOnly` and
  `Location: https://gitlab.corp.example/oauth/authorize?client_id=..&redirect_uri=https://skywalking.corp.example/oauth2/idpresponse&response_type=code&scope=openid&state=..`
- `AWSALBAuthNonce` and `/oauth2/idpresponse` are what an **AWS Application Load Balancer with an `authenticate-oidc`
  action** produces. The ALB is the OAuth client: it redeems the code itself and then issues session cookies
  (`AWSELBAuthSessionCookie-0`, `-1`, ...). SkyWalking sees only authenticated traffic.
- Today `session_open` calls this site `auth: none` (a `302` is below the driver's `>= 400` check) and `request` gets a
  redirect it cannot use.

Nothing about the front is assumed beyond that. Appendix A is a redacted-output script to confirm it (section 4).

## 2. The flow

```
Agent           securl                                   Person         GitLab                     Site (ALB -> SkyWalking)
 | session_open |                                            |              |                              |
 |------------->| 1. GET / (own jar) ---------------------------------------------------------------------->|
 |              |<-- 302 Location: <idp>/oauth/authorize?..&state=A, Set-Cookie nonce                        |
 |              |    check: host == configured idp host, redirect_uri host == site host. Else STOP, nobody asked.
 |              | 2. round: "GitLab username/password (idp host)", then TOTP if GitLab asks (existing gitlab code)
 |              |<---- sealed answer through the tunnel ----|              |                              |
 |              | 3. sign in to GitLab (jar now holds _gitlab_session)------>|                              |
 |              | 4. FRESH GET / (new state B, new nonce) -------------------------------------------------->|
 |              |<-- 302 authorize?..state=B                                                                |
 |              | 5. GET authorize with the GitLab cookie ----------------->|                              |
 |              |<-- 302 redirect_uri?code=C&state=B  (no consent page when the app is already authorised)  |
 |              | 6. GET redirect_uri?code=C&state=B (nonce cookie present) -------------------------------->| redeems C
 |              |<-- 302 / + Set-Cookie AWSELBAuthSessionCookie-0/-1 ----------------------------------------|
 |              | 7. GET / with the session cookies -> 200; store the SITE cookies in the vault; drop GitLab's.
 |<-- ok, cookie|
 | request()  --> securl adds the cookies; the agent never sees them
```

Steps 4 to 7 run back to back inside securl, seconds after the person answered, so the state, nonce and code are never
stale. Step 4 repeats step 1 on purpose: the state and nonce from step 1 were issued before a human round that can last
minutes, so they are **not reused**.

## 3. Goals and non-goals

Goals
1. The person types GitLab credentials only into securl's sealed page (same trust model as the `gitlab` driver); the
   agent never sees them, the authorize URL, the code, or any cookie.
2. GitLab second factor and LDAP work as they already do (the existing GitLab sign-in code is reused, not copied).
3. Owner configuration only, no Go per site. With no `oauth2_sites` entry nothing changes.
4. Provider-pluggable (`idp.type`), GitLab the only one implemented and tested in phase 1.

Non-goals (phase 1)
- Identity providers other than GitLab; the person completing the provider's own login in a browser (section 12).
- Silent renewal without a person. The ALB's own session lifetime applies; when it ends the agent gets `session_expired`
  and a person logs in again, as for every other cookie site. (ALB refresh-token handling happens inside the ALB.)
- A `securl config` wizard (YAML only; `securl doctor -site` covers inspection).

## 4. Assumptions and how to confirm them

- A1. **Confirmed by the reviewer:** the front is an AWS ALB OIDC client that answers anonymous requests with a `302` to GitLab
  and issues cookies after the callback.
- A2. The GitLab application behind the ALB is already authorised for the accounts that will use securl, or is marked
  trusted, so GitLab redirects straight back with a code. If a consent page appears, securl stops with a clear message (3).
- A3. The GitLab accounts that will be used can sign in with the forms the `gitlab` driver already supports
  (standard or LDAP, TOTP optional). WebAuthn/passkey/email-only second factors are not supported (same as today).
- A4. The site accepts the cookies on later requests without a browser-only secret (no JavaScript-set value). The
  probe in step 7 tests this.

## 5. Design

### 5.1 New driver `internal/site/oauth2flow`

Built from config like `generic` (`oauth2flow.New(spec) (site.Driver, error)`); registered with `site.Replace` in
`mcpserver.New` and `configcli.registerSites`. Standard library only, no new dependency. `NeedsLogin()` is true; `Match` is
`match_host`. An entry named `skywalking` replaces the built-in no-login driver; other hosts are untouched.

### 5.2 Configuration (strict-parsed; the parser walks structs by reflection, so typos get suggestions for free)

```yaml
oauth2_sites:
  - name: skywalking
    match_host: skywalking              # or use aliases:
    idp:
      type: gitlab                      # only value in phase 1
      url: https://gitlab.corp.example  # REQUIRED. The only host a login may be sent to.
      login_method: auto                # same meaning as site_options.gitlab: auto | ldap | standard
      ldap_provider: ""                 # optional
    on_consent: approve                 # approve (default) | fail
    start_path: ""                      # optional: GET this instead of / to start the redirect chain
    probe: {path: /, expect_status: 200}   # optional; default GET the base, 2xx, redirects not followed
```

`Validate` rejects: missing `name`; missing or non-https `idp.url` (http only for a local host under
`security.allow_local_addresses`); unknown `idp.type`, `login_method`, `on_consent`; `start_path` not starting with `/`.
`idp.url` must also pass `security.allowed_hosts` when that is set. The IdP host comes **only** from this file, never from
the site's redirect or from the agent.

### 5.3 Login algorithm

All requests use `site.JarClient(hc)` over the guarded `netguard` transport (local and metadata addresses blocked; the
driver follows redirects **by hand**, never through the client's automatic policy).

1. **Preflight (no person asked).** GET the base (or `start_path`) and walk redirects by hand, at most 10 hops. Stop at the
   first hop whose host is not the site host. Require: https, host equals `idp.url`'s host, path `/oauth/authorize`, query has
   `response_type=code`, `client_id`, `redirect_uri`, `state`, and the `redirect_uri` host equals the site host (the code can only
   return to the site). Otherwise end with `login_rejected` and a precise reason; **no human round, no credential is sent
   anywhere**:
   - redirect to another host: "the site sends logins to <host>, which is not the configured idp";
   - no redirect: "this site did not ask for a login (it may need none, or use something other than OAuth 2.0)".
2. **Ask.** Run GitLab's sign-in through the existing code, behind a small asker wrapper that turns its `login` and `totp` rounds
   into `custom` rounds whose labels name the IdP host ("GitLab username (gitlab.corp.example)", "GitLab password",
   "GitLab one-time code"), so the person is never typing a GitLab password into a page that only says it is for the site.
   The message gets securl's own explanation through `StartDetailed` (see 5.5): "securl will sign in to GitLab at <idp host>
   with what you type, and use that sign-in once to log in to <site host>. Your GitLab password is not kept."
3. **Sign in to GitLab** with the shared jar (reused code: `gitlab.SignIn`, 5.5). Wrong password, wrong code, unsupported
   second factor map to the same errors as the `gitlab` driver (`bad_credentials`, `login_rejected`).
4. **Fresh chain.** GET the base again (new nonce cookie, new state), then walk by hand with the hop rule *every hop host is the
   site host or the idp host, https only, at most 10 hops*, sending nothing the jar would not scope to that host:
   `authorize` (GitLab, now signed in) -> `redirect_uri?code&state` (site) -> `/` (site).
5. **Consent page.** If the idp answers `200` at `/oauth/authorize` with the authorize form, then with `on_consent: approve`
   (the default) securl submits the *approve* form (never the *deny* form, which carries `_method=delete`), but only if its hidden
   fields `client_id`, `redirect_uri`, `response_type`, `state` (and `scope` when present) equal the query of the URL securl just
   requested; it does this at most once per login. With `on_consent: fail` it stops with: "GitLab asks to authorise the application
   for the first time. Open the site once in your own browser and press Authorize, then retry." The person is told in securl's own
   message that securl will approve it.
6. **Check.** The last hop is a 2xx (not a redirect to the idp, not an error page) and at least one site cookie was issued
   in the callback hop. 5xx/429/network is `site_unreachable`; anything else is `login_rejected` with the status and a clipped body.
7. **Keep.** The session is the **site-host cookies only**, built from the `Set-Cookie` headers seen (name, value, domain,
   path, secure, `Expires`/`Max-Age`), with deletions honoured (the ALB deletes the nonce cookie). The jar's view is not used
   because it drops expiry. `ExpiresAt` is the earliest `Expires` among cookies set in the callback hop (none: no expiry
   recorded, the probe decides). GitLab's cookies are discarded with the jar; the person's password is never stored.
   `Probe` then runs once; failure there is `login_rejected` ("the site did not accept the cookies it just issued").

### 5.4 Probe and use

`Probe` sends the cookies to the probe path, redirects not followed: 2xx valid; 3xx (a redirect to the idp), 401, 403 invalid
(session dropped, agent told `session_expired`); 429/502/503/504 `site_unreachable` via `site.ProbeStatus`, session
kept. `request` already injects cookies, follows same-origin redirects only, refuses an agent-set `Cookie`/`Authorization`,
redacts cookie values in answers, and stores rotated cookies (`proxy` state, `cache.Update`), which covers an ALB that
re-issues its session cookie. `session_list` shows `cookie`.

### 5.5 Changes to existing code (small, each covered by the existing tests as a safety net)

- `gitlab`: extract `SignIn(ctx, c *http.Client, base *url.URL, ask site.Asker, o Options) (*SignInResult, error)` from
  `Login` (the body up to and including the cookie check); `Login` becomes `JarClient` + `SignIn` + session. **No behaviour
  change**; `gitlab_test.go` (LDAP, TOTP, bad password, rejection) must pass untouched.
- `site`: optional `Detailer` interface `Detail() string`; `mcpserver.ensureLogin` calls `StartDetailed` when the driver
  implements it (`session_close` already uses `StartDetailed`). `Detail` is securl's own text, escaped by the existing flow code.
- `config`: `Config.OAuth2Sites []oauth2flow.Spec \`yaml:"oauth2_sites"\``; `configedit.Validate` and
  `configcli.registerSites` also build them.
- `noauth` (built-in `skywalking`): a `3xx` to another host, or 401/403, now says "this site needs a login; add an
  `oauth2_sites` entry" instead of reporting `auth: none`.
- `securl doctor -site`: `site.Inspector`, no credentials: runs step 1 only and reports the hops, the idp host, whether it matches the
  config, the `redirect_uri` host, the cookie names seen, and what `on_consent` will do (never prints query values).
- `link_via_agent`: allowed. The link is securl's page, as for every driver; the existing caveat (the agent relays it) applies
  unchanged and is repeated in `docs/OPERATING.md`.

## 6. Security analysis

| Risk | Control |
|---|---|
| GitLab password handled by securl | Same model as the `gitlab` driver: typed on the sealed page, held in memory for the one sign-in, never stored, logged or returned; the agent never sees it |
| Site (or the agent) steers securl to a phishing host and gets GitLab credentials | Credentials go only to `idp.url`, from the owner's file; preflight aborts **before** asking anyone when the redirect host differs |
| Code redeemed somewhere else | `redirect_uri` host must equal the site host; every hop host must be the site or idp host; https only; hop cap |
| Person types GitLab password into a page that looks like the site's | Round labels and message name the IdP host in securl's own words; key code and sealing as today |
| Stale state, nonce or code | Fresh chain after the human round (5.3 step 4); nothing from the preflight is reused |
| Silent over-authorisation | Approval is stated in securl's own message, happens at most once per login, only when the form's hidden fields equal the request just made, and can be switched off with `on_consent: fail` |
| GitLab session left behind | securl does not sign out (reviewer's decision): its GitLab session simply stays until GitLab expires it; securl itself discards the cookie with the jar and never reuses it |
| Cookies leak to the wrong host | Only site-host cookies are kept; `request` sends them to the site only; redaction of values in answers |
| SSRF through redirects | `netguard` client, manual walk, https required, local addresses blocked unless allowed |
| Secrets in logs/errors | URLs, query values, cookie values and form values are never logged or put in errors; audit records the idp host, not URLs |
| Rate / flooding | Existing per-site limits and reject cool-down apply |

## 7. Test plan (written first, TDD)

Fakes (httptest, no network): `fakeGitLab` (sign-in form with CSRF token and `_gitlab_session`, optional TOTP page, `/oauth/authorize`
that redirects to `redirect_uri?code&state` only for a signed-in session, optional consent page) and `fakeALB`+SkyWalking
(`/` sets a nonce cookie and redirects with a **new state each time**, remembers only the latest state; `/oauth2/idpresponse` requires
the nonce cookie, the latest state and an unused code, sets sharded session cookies with `Expires` and deletes the nonce;
protected paths answer 200 only with the session cookies).

`oauth2flow`: preflight accepts the good redirect and rejects each defect (other host, http, wrong path, missing parameter,
`redirect_uri` on another host, no redirect) **with no human round and zero requests to the foreign host**; whole flow succeeds
(rounds asked: one custom login, then a TOTP round when GitLab asks); **the state from the preflight is not reused** (the fake
rejects it; test fails if the driver reused it); GitLab cookie not present in the stored session; nonce deletion honoured;
`ExpiresAt` from the callback cookies; consent page with `fail` (message text) and with `approve` (form check; tampered
fields refused); wrong password, wrong TOTP, rejected by the person, unreachable GitLab, unreachable site, callback 4xx and 5xx; hop cap;
probe statuses (200, 204, 302 to idp, 401, 403, 429, 503, network error); no password, code, cookie value or URL query in any
error string, log line or audit record; `Detail` text present and escaped.

Other packages: `gitlab` suite unchanged and green after the `SignIn` extraction; `config` strict parse/`Validate` rules and typo
suggestion for `oauth2_sites`; `mcpserver` e2e on the existing fixtures: `session_open` -> two custom rounds with IdP labels,
`request` reaches the fake SkyWalking with the cookies and the response is redacted, `session_list` reports `cookie`, expiry
drops the session, reject and rate limit behave as for other sites, and with no `oauth2_sites` `skywalking` is still `auth: none`;
`docs_test.go` stays green.

Not covered by CI (needs the real stack): a first real login. The implementation PR will carry a checklist: Appendix A,
`securl doctor -site`, login with and without TOTP, a `request`, and a request after the ALB session lifetime.

## 8. Compatibility and migration

Additive: one optional config key, one optional interface, one refactor of `gitlab.Login` with no behaviour change, one clearer
error in `noauth`. No vault-format change (the session record already holds cookies with expiry). An older securl rejects a config
with `oauth2_sites` (strict parsing), as for any new key.

## 9. Docs to update on implementation

README (config example and the flow), `docs/OPERATING.md` (site table row, what the person sees, consent note,
`link_via_agent` caveat), `DESIGN.md` (4.5 table row, decisions), `skills/securl/SKILL.md` (agent: call `session_open`, relay
nothing, wait), `MCP_TOOLS.md` only if tool text changes (it does not). No real host name appears in any file.

## 10. Rollout

Phase 1: this spec. Phase 2 (separate specs): other IdPs behind `idp.type`; a person-completes-the-IdP-in-a-browser mode for
IdPs where a password cannot be given to securl (SSO with WebAuthn only); securl as the OAuth client with PKCE (sites that accept
provider tokens as bearer); silent renewal.

## 11. Decisions (resolved by the reviewer)

1. The front is an AWS ALB (confirmed; Appendix A output not needed).
2. Giving securl the GitLab password is acceptable.
3. First-time consent page: **approve by default** (`on_consent: approve`; `fail` remains available).
4. No GitLab sign-out after the login.
5. Names `oauth2_sites`, `oauth2flow`, `idp.type: gitlab` are fine.

## Appendix A. Inspect what fronts the site (no credentials; output is safe to paste)

Run `sh inspect-front.sh skywalking.corp.example` (needs `sh`, `curl`, `perl`; `dig` optional; works on macOS). It sends
anonymous requests only, spends no login code, and replaces the site name, its parent domain, every other host, query values
(`client_id`, `state`, `code`, ...) and cookie values with placeholders before printing.

```sh
#!/bin/sh
H="$1"; SCHEME="${2:-https}"
[ -n "$H" ] || { echo "usage: sh $0 <site-host> [http|https]" >&2; exit 2; }
NAME="${H%%:*}"; PARENT="${NAME#*.}"
redact() {
  NAME="$NAME" PARENT="$PARENT" perl -pe '
    s/\r$//;
    s/\Q$ENV{NAME}\E/SITE/g; s/\Q$ENV{PARENT}\E/DOMAIN/g;
    s{(https?(?:://|%3A%2F%2F))[A-Za-z0-9.:-]+}{$1OTHER-HOST}gi;
    s/\b(client_id|state|code|nonce|id_token|access_token|session_state)=[^&\s]+/$1=<redacted>/g;
    s/^((?:Set-)?Cookie: [^=]+)=[^;]*/$1=<redacted>/i;'
}
get() { curl -sS -o /dev/null -D - --max-time 15 $CURL_EXTRA "$@" 2>&1; }   # headers only; redirects NOT followed
echo "== 1. GET /  (anonymous)";                                          get "$SCHEME://$H/" | redact
echo; echo "== 2. GET /oauth2/idpresponse  (no code: who answers the callback path)"
get "$SCHEME://$H/oauth2/idpresponse" | redact
echo; echo "== 3. POST /graphql  (is the API path protected too?)"
get -X POST -H 'Content-Type: application/json' -d '{"query":"{__typename}"}' "$SCHEME://$H/graphql" | redact
echo; echo "== 4. the identity provider's answer to an anonymous GET of the first Location"
LOC=$(curl -sS -o /dev/null -w '%{redirect_url}' --max-time 15 $CURL_EXTRA "$SCHEME://$H/")
case "$LOC" in http*) get "$LOC" | redact ;; *) echo "(step 1 did not redirect)" ;; esac
echo; echo "== 5. DNS: AWS load balancer? (provider suffix only)"
dig +short CNAME "$NAME" 2>/dev/null | perl -pe 's/^.*\.elb(?:-[a-z]+)?\.([a-z0-9-]+)\.amazonaws\.com\.?$/AWS ELB, region $1\n/ or s/^.+$/(a CNAME exists; not an AWS ELB name; hidden)/'
```

What to look for in the output: step 1 `302` with a `AWSALBAuthNonce` cookie and a `/oauth/authorize` Location (already seen);
step 2 `Server: awselb/2.0` or a 4xx/5xx page from the load balancer; step 3 whether the API path is also redirected or answers
`401`; step 4 whether GitLab answers the authorize URL with a redirect to its sign-in page (expected, anonymous); step 5 whether
the name is an ELB.
