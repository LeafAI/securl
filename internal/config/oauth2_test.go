package config

import (
	"strings"
	"testing"
)

const oauthYAML = `
oauth2_sites:
  - name: skywalking
    match_host: skywalking
    idp:
      type: gitlab
      url: https://gitlab.corp.example
      login_method: ldap
    on_consent: fail
    probe: {path: /graphql, expect_status: 200}
`

func TestOAuth2SitesParseAndValidate(t *testing.T) {
	if err := ParseStrict([]byte(oauthYAML)); err != nil {
		t.Fatalf("strict: %v", err)
	}
	c, err := Parse([]byte(oauthYAML), t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if len(c.OAuth2Sites) != 1 {
		t.Fatalf("sites = %+v", c.OAuth2Sites)
	}
	s := c.OAuth2Sites[0]
	if s.Name != "skywalking" || s.IDP.URL != "https://gitlab.corp.example" || s.IDP.LoginMethod != "ldap" || s.OnConsent != "fail" || s.Probe.Path != "/graphql" {
		t.Errorf("parsed wrongly: %+v", s)
	}
	if err := c.Validate(); err != nil {
		t.Errorf("a valid configuration: %v", err)
	}
}

func TestOAuth2SitesTyposAreReportedWithASuggestion(t *testing.T) {
	err := ParseStrict([]byte("oauth2_sites:\n  - name: sw\n    idp: {type: gitlab, ulr: https://gitlab.corp.example}\n"))
	if err == nil || !strings.Contains(err.Error(), `"ulr"`) || !strings.Contains(err.Error(), `"url"`) {
		t.Errorf("err = %v", err)
	}
	err = ParseStrict([]byte("oauth2_site:\n  - name: sw\n"))
	if err == nil || !strings.Contains(err.Error(), "oauth2_sites") {
		t.Errorf("top-level typo: %v", err)
	}
}

func TestOAuth2SitesValidationRules(t *testing.T) {
	cases := map[string]struct{ yaml, want string }{
		"no idp url":     {"oauth2_sites:\n  - {name: sw, idp: {type: gitlab}}\n", "idp.url"},
		"idp over http":  {"oauth2_sites:\n  - {name: sw, idp: {type: gitlab, url: 'http://gitlab.corp.example'}}\n", "https"},
		"unknown idp":    {"oauth2_sites:\n  - {name: sw, idp: {type: okta, url: 'https://x.corp.example'}}\n", "idp.type"},
		"duplicate name": {"oauth2_sites:\n  - {name: sw, idp: {type: gitlab, url: 'https://g.corp.example'}}\n  - {name: sw, idp: {type: gitlab, url: 'https://g.corp.example'}}\n", "twice"},
		"idp not allowed": {"security: {allowed_hosts: ['*.apps.example']}\noauth2_sites:\n  - {name: sw, idp: {type: gitlab, url: 'https://gitlab.corp.example'}}\n",
			"allowed_hosts"},
	}
	for name, tc := range cases {
		t.Run(name, func(t *testing.T) {
			c, err := Parse([]byte(tc.yaml), t.TempDir())
			if err != nil {
				t.Fatal(err)
			}
			err = c.Validate()
			if err == nil || !strings.Contains(err.Error(), tc.want) {
				t.Errorf("err = %v, want %q", err, tc.want)
			}
		})
	}
	ok := "security: {allowed_hosts: ['gitlab.corp.example', '*.apps.example']}\noauth2_sites:\n  - {name: sw, idp: {type: gitlab, url: 'https://gitlab.corp.example'}}\n"
	c, _ := Parse([]byte(ok), t.TempDir())
	if err := c.Validate(); err != nil {
		t.Errorf("an idp that is allowed: %v", err)
	}
	withPort := "security: {allowed_hosts: ['gitlab.corp.example']}\noauth2_sites:\n  - {name: sw, idp: {type: gitlab, url: 'https://gitlab.corp.example:8443'}}\n"
	c, _ = Parse([]byte(withPort), t.TempDir())
	if err := c.Validate(); err != nil {
		t.Errorf("an allowed host on another port: %v", err)
	}
}
