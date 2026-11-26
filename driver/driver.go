// Package driver is the part of securl that a login driver written outside this module may use.
//
// securl keeps its own code under internal/, which Go does not let another module import. A driver that lives in its own
// repository (a private one, say) is built into securl by listing it when securl is built (see docs/DRIVERS.md), and it needs
// to name the types a driver is made of. This package names them, and nothing else: every type here is an alias of the one
// securl itself uses, so a driver written against this package is run by the same code as a built-in one.
//
// A driver registers itself in an init function and is linked in by a blank import:
//
//	func init() { driver.Register(myDriver{}) }
//
// To take part in remembered credentials a driver implements CredentialScope, and it asks a person only for the two kinds of
// round securl knows how to remember: "login" (username and password) and "totp" (a one-time code). Anything else it asks for
// is shown to the person as it is and is never saved.
//
// This is an experimental interface: it follows the internal one and may change with it.
package driver

import (
	"net/http"
	"net/url"

	"github.com/LeafAI/securl/internal/site"
)

// The types of a driver and of its dealings with a person.
type (
	// Driver implements the login of one kind of website.
	Driver = site.Driver
	// Session is what a login produces: cookies, headers and tokens that securl adds to requests and removes from answers.
	Session = site.Session
	// Field is one input a person is asked for in a round.
	Field = site.Field
	// Credentials are the values a person submitted in one round.
	Credentials = site.Credentials
	// Asker runs one human round and returns what was submitted.
	Asker = site.Asker
)

// Interfaces a driver may also implement.
type (
	// CredentialScope opts the driver in to remembered credentials.
	CredentialScope = site.CredentialScope
	// Detailer gives the text that explains, in securl's words, what a person is agreeing to.
	Detailer = site.Detailer
	// Inspector describes what the driver will do against a server, without credentials.
	Inspector = site.Inspector
	// Configurable takes the per-site options of the site_options section of the configuration.
	Configurable = site.Configurable
	// LoginExtras lets the driver ask for more than a username and a password in its login round (a salt, say).
	LoginExtras = site.LoginExtras
	// SecondFactor makes securl put a one-time code, made from the seed the person saved, on the driver's site's requests.
	SecondFactor = site.SecondFactor
)

// The errors a driver wraps so that securl can tell what went wrong.
var (
	ErrBadCredentials = site.ErrBadCredentials
	ErrLoginRejected  = site.ErrLoginRejected
	ErrUnreachable    = site.ErrUnreachable
)

// ReservedFieldNames are the names securl's own pages use, which a field a driver asks for may not have. It is a copy.
func ReservedFieldNames() []string {
	var out []string
	for n := range site.ReservedFieldNames {
		out = append(out, n)
	}
	return out
}

// Register adds a driver. It panics if the name is taken, so two drivers can never share one.
func Register(d Driver) { site.Register(d) }

// Names lists the registered drivers.
func Names() []string { return site.Names() }

// Key identifies a site: scheme://host[:port] and its path prefix.
func Key(u *url.URL) string { return site.Key(u) }

// Unreachable marks a failure to ask a site at all, so that a saved session is kept.
func Unreachable(err error) error { return site.Unreachable(err) }

// TemporaryStatus reports whether an HTTP status says only that the site could not answer just now (429, 502, 503, 504).
func TemporaryStatus(code int) bool { return site.TemporaryStatus(code) }

// ProbeStatus is what a session probe answers for the status a site returned.
func ProbeStatus(what string, code int) error { return site.ProbeStatus(what, code) }

// Clip shortens a string for an error message.
func Clip(s string, n int) string { return site.Clip(s, n) }

// ReadBody reads a bounded part of a response body as text and closes it.
func ReadBody(resp *http.Response) string { return site.ReadBody(resp) }

// JarClient returns a client that keeps cookies across the steps of a login.
func JarClient(hc *http.Client) *http.Client { return site.JarClient(hc) }

// NoRedirect returns a client that does not follow redirects.
func NoRedirect(c *http.Client) *http.Client { return site.NoRedirect(c) }

// LoginFields are the fields of the "login" round securl can remember: a username and a password.
func LoginFields() []Field { return append([]Field(nil), site.LoginFields...) }

// TOTPFields are the fields of the "totp" round securl can remember: a one-time code.
func TOTPFields() []Field { return append([]Field(nil), site.TOTPFields...) }

// CookiesFrom returns the cookies a client's jar holds for a site.
func CookiesFrom(c *http.Client, base *url.URL) []*http.Cookie { return site.CookiesFrom(c, base) }

// CookieHeader renders cookies as the value of a Cookie header.
func CookieHeader(cs []*http.Cookie) string { return site.CookieHeader(cs) }
