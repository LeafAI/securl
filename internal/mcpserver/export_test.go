package mcpserver

import (
	"net/http"
	"net/url"

	"github.com/LeafAI/securl/internal/dbsite"
	"github.com/LeafAI/securl/internal/site"
)

// SeedSession puts a session in the cache of an open server, as if a person had logged in. It exists in test builds only, so that the
// external tests (which drive the real page in a browser) can have sessions to close without a login for each of them.
func (s *Server) SeedSession(rawURL, siteName string) error {
	u, err := url.Parse(rawURL)
	if err != nil {
		return err
	}
	d, err := site.Resolve(siteName, u)
	if err != nil {
		return err
	}
	k, terr := s.gate()
	if terr != nil {
		return terr
	}
	k.cache.Put(u, d, &site.Session{Cookies: []*http.Cookie{{Name: "sid", Value: "SECRET-SEEDED-COOKIE-" + u.Host, Path: "/"}}})
	return nil
}

// SeedDatabaseSession is SeedSession for a database target: the account is the one a person typed for it.
func (s *Server) SeedDatabaseSession(target string) error {
	k, terr := s.gate()
	if terr != nil {
		return terr
	}
	k.cache.Put(dbsite.BaseURL(target), s.openDriver(), &site.Session{Tokens: map[string]string{dbsite.TokenUser: "alice", dbsite.TokenPassword: "SECRET-DB-PASSWORD"}})
	return nil
}
