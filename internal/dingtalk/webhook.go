package dingtalk

import (
	"errors"
	"net/url"
	"regexp"
	"strings"
)

// A token is a long run of lowercase hex digits and letters in practice; the shape is kept loose on purpose (what DingTalk issues
// is its to change) and tight on what could break out of a query: letters, digits, '-' and '_' only, and long enough that a pasted
// word is not taken for one.
var tokenShape = regexp.MustCompile(`^[A-Za-z0-9_-]{32,128}$`)

// ParseWebhook takes what a person pasted and returns the access_token in it, or an error that does not repeat what was pasted. Only
// the robot endpoint is accepted: https, the host oapi.dingtalk.com and no other (no user, no port), the path /robot/send, one
// access_token and no other parameter. The address is the whole credential, and a person can be tricked into pasting an address
// that goes somewhere else; accepting it would send the token there.
func ParseWebhook(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	bad := func(why string) (string, error) {
		return "", errors.New("that is not a DingTalk robot webhook: " + why + " (copy the whole address from the robot's settings: https://oapi.dingtalk.com/robot/send?access_token=...)")
	}
	if raw == "" {
		return bad("nothing was entered")
	}
	u, err := url.Parse(raw)
	switch {
	case err != nil:
		return bad("it is not an address")
	case u.Scheme != "https":
		return bad("it must start with https://")
	case u.User != nil:
		return bad("it must not have a user name in it")
	case u.Hostname() != Host || u.Port() != "":
		return bad("the host must be " + Host)
	case u.Path != sendPath:
		return bad("the path must be " + sendPath)
	case u.Fragment != "" || u.Opaque != "":
		return bad("it has more in it than the robot's address")
	}
	q, err := url.ParseQuery(u.RawQuery)
	if err != nil {
		return bad("its parameters are not readable")
	}
	toks := q["access_token"]
	switch {
	case len(toks) == 0 || toks[0] == "":
		return bad("it has no access_token=...")
	case len(toks) > 1 || len(q) > 1:
		return bad("it must carry the access_token and nothing else (the signing secret is typed apart)")
	case !tokenShape.MatchString(toks[0]):
		return bad("the access_token is not the shape DingTalk issues")
	}
	return toks[0], nil
}

// ParseSecret takes what a person pasted as the robot's signing secret ("加签"; the one that starts with SEC) and returns it, or an
// error that does not repeat it.
func ParseSecret(raw string) (string, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" || !strings.HasPrefix(raw, "SEC") || len(raw) < 8 || len(raw) > 128 || strings.IndexFunc(raw, func(r rune) bool { return r <= ' ' || r > '~' }) >= 0 {
		return "", errors.New("that is not a signing secret: it is one word that starts with SEC, shown when the robot's \"sign\" security setting is turned on")
	}
	return raw, nil
}
