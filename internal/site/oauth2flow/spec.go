package oauth2flow

import (
	"fmt"
	"net/url"
	"regexp"
	"strings"

	"github.com/LeafAI/securl/internal/netguard"
)

// Identity provider types, and what to do about GitLab's first-time authorisation page.
const (
	IDPGitLab = "gitlab"

	ConsentApprove = "approve"
	ConsentFail    = "fail"
)

// IDP names the identity provider a site's login is sent to. Credentials are only ever given to this host, which comes from
// the owner's configuration and never from the site's redirect.
type IDP struct {
	Type         string `yaml:"type"`
	URL          string `yaml:"url"`
	LoginMethod  string `yaml:"login_method,omitempty"`  // auto | ldap | standard, as site_options.gitlab
	LDAPProvider string `yaml:"ldap_provider,omitempty"` // "" detects it from the sign-in page
}

// Probe says how a session is checked: a GET of Path (default "/") that must answer ExpectStatus (default: any 2xx).
type Probe struct {
	Path         string `yaml:"path,omitempty"`
	ExpectStatus int    `yaml:"expect_status,omitempty"`
}

// Spec describes one site that is protected by an OAuth 2.0 front (an AWS ALB or a proxy) with GitLab as the provider.
type Spec struct {
	Name      string `yaml:"name"`
	MatchHost string `yaml:"match_host,omitempty"`
	IDP       IDP    `yaml:"idp"`
	OnConsent string `yaml:"on_consent,omitempty"` // approve (default) | fail
	StartPath string `yaml:"start_path,omitempty"` // requested instead of "/" to start the redirect chain
	Probe     Probe  `yaml:"probe,omitempty"`
}

var ldapProviderName = regexp.MustCompile(`^[A-Za-z0-9_]*$`)

// Validate checks the settings that can be checked without a network.
func (s Spec) Validate() error {
	if strings.TrimSpace(s.Name) == "" {
		return fmt.Errorf("oauth2_sites: every site needs a name")
	}
	if _, err := s.idpURL(); err != nil {
		return fmt.Errorf("oauth2_sites %s: %w", s.Name, err)
	}
	if s.IDP.Type != IDPGitLab {
		return fmt.Errorf("oauth2_sites %s: idp.type must be %q (the only identity provider supported), got %q", s.Name, IDPGitLab, s.IDP.Type)
	}
	switch s.IDP.LoginMethod {
	case "", "auto", "ldap", "standard":
	default:
		return fmt.Errorf("oauth2_sites %s: idp.login_method must be auto, ldap or standard", s.Name)
	}
	if !ldapProviderName.MatchString(s.IDP.LDAPProvider) {
		return fmt.Errorf("oauth2_sites %s: idp.ldap_provider may only hold letters, digits and underscores", s.Name)
	}
	switch s.OnConsent {
	case "", ConsentApprove, ConsentFail:
	default:
		return fmt.Errorf("oauth2_sites %s: on_consent must be %s or %s", s.Name, ConsentApprove, ConsentFail)
	}
	for what, p := range map[string]string{"start_path": s.StartPath, "probe.path": s.Probe.Path} {
		if p != "" && !strings.HasPrefix(p, "/") {
			return fmt.Errorf("oauth2_sites %s: %s must start with /", s.Name, what)
		}
	}
	return nil
}

// idpURL parses idp.url: an https URL (http only for this machine's own names, for labs and tests) with no credentials, query
// or fragment.
func (s Spec) idpURL() (*url.URL, error) {
	raw := strings.TrimRight(strings.TrimSpace(s.IDP.URL), "/")
	if raw == "" {
		return nil, fmt.Errorf("idp.url is required: it is the only host a login may be sent to")
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" || (u.Scheme != "https" && u.Scheme != "http") {
		return nil, fmt.Errorf("idp.url must be an https URL such as https://gitlab.corp.example")
	}
	if u.User != nil || u.RawQuery != "" || u.Fragment != "" {
		return nil, fmt.Errorf("idp.url must not carry credentials, a query or a fragment")
	}
	if u.Scheme == "http" && !netguard.LocalHost(u.Host) {
		return nil, fmt.Errorf("idp.url must be https: a password is sent to it")
	}
	return u, nil
}

// IDPHost is the host (and port) logins go to, for policy checks outside this package; "" for an invalid spec.
func (s Spec) IDPHost() string {
	u, err := s.idpURL()
	if err != nil {
		return ""
	}
	return u.Host
}

func (s Spec) consent() string {
	if s.OnConsent == "" {
		return ConsentApprove
	}
	return s.OnConsent
}
