package config

import (
	"fmt"
	"path"
	"strings"
)

// validateOAuth2Sites checks the oauth2_sites entries. Besides each entry's own rules, the identity provider's host has to
// satisfy security.allowed_hosts when that list is set: a password is typed for it, so it is as explicit as a site.
func (c *Config) validateOAuth2Sites() error {
	seen := map[string]bool{}
	for _, s := range c.OAuth2Sites {
		if err := s.Validate(); err != nil {
			return err
		}
		if seen[s.Name] {
			return fmt.Errorf("oauth2_sites: %q is defined twice", s.Name)
		}
		seen[s.Name] = true
		if !c.hostListed(s.IDPHost()) {
			return fmt.Errorf("oauth2_sites %s: the identity provider %s is not in security.allowed_hosts", s.Name, s.IDPHost())
		}
	}
	return nil
}

// hostListed applies security.allowed_hosts to a "host" or "host:port" (an empty list allows every host).
func (c *Config) hostListed(hostport string) bool {
	if len(c.Security.AllowedHosts) == 0 {
		return true
	}
	host := hostport
	if i := strings.LastIndex(hostport, ":"); i >= 0 && !strings.Contains(hostport[i:], "]") {
		host = hostport[:i]
	}
	for _, pat := range c.Security.AllowedHosts {
		for _, h := range []string{hostport, host} {
			if ok, _ := path.Match(strings.ToLower(pat), strings.ToLower(h)); ok {
				return true
			}
		}
	}
	return false
}
