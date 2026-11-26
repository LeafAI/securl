// Package driverbuild builds securl with login drivers that live in other repositories (a private one, say).
//
// A driver is named by a Spec: where its repository is and the exact revision to build. What is given is checked before anything
// is run, because it ends up in a Go source file and in the arguments of git and go; nothing but a plain host, a plain path and
// a pinned revision gets through. See docs/DRIVERS.md.
package driverbuild

import (
	"errors"
	"fmt"
	"regexp"
	"strconv"
	"strings"
)

const (
	// MaxSpecs bounds how many drivers one build takes.
	MaxSpecs = 16
	// maxSpecLen bounds one spec: a path longer than this is a mistake, not a repository.
	maxSpecLen = 256
	// maxPathParts bounds the depth of a repository path: GitLab nests groups, not without end.
	maxPathParts = 10
)

// A pinned revision is a full commit hash (40 hex digits: git cannot fetch an abbreviated one) or a version tag like v1.2.3 (with an optional
// pre-release part). A branch name, "latest" and "upgrade" move, and a build that can change under its own name cannot be
// reviewed: the code that runs inside the process that holds every credential is exactly the code that was looked at.
var (
	hashRev    = regexp.MustCompile(`^[0-9a-f]{40}$`)
	versionRev = regexp.MustCompile(`^v(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)\.(0|[1-9][0-9]*)(-[0-9A-Za-z]+(\.[0-9A-Za-z]+)*)?$`)
	hostName   = regexp.MustCompile(`^[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?(\.[A-Za-z0-9]([A-Za-z0-9-]*[A-Za-z0-9])?)+$`)
	pathPart   = regexp.MustCompile(`^[A-Za-z0-9_][A-Za-z0-9_.-]*$`)
)

// Spec is one external driver: the repository and the revision of it to build.
type Spec struct {
	Host string // gitlab.example.com or gitlab.example.com:2222
	Path string // group/subgroup/repo, without a .git suffix
	Rev  string // a commit hash or a version tag
}

// ParseSpec reads host/path@revision. The error says what is wrong and never repeats what was given.
func ParseSpec(in string) (Spec, error) {
	in = strings.TrimSpace(in)
	switch {
	case in == "":
		return Spec{}, errors.New("a driver is empty: write host/group/repo@revision")
	case len(in) > maxSpecLen:
		return Spec{}, fmt.Errorf("a driver is too long (at most %d characters)", maxSpecLen)
	}
	for _, r := range in {
		if !(r >= 'a' && r <= 'z' || r >= 'A' && r <= 'Z' || r >= '0' && r <= '9' || strings.ContainsRune("/.-_:@+", r)) {
			return Spec{}, errors.New("a driver holds a character that is not allowed (letters, digits and / . - _ : @ only)")
		}
	}
	if strings.Contains(in, "://") || isScpForm(in) {
		return Spec{}, errors.New("a driver is host/path@revision, with no scheme and no user: the build clones it over ssh")
	}
	if in[0] == '/' || in[0] == '.' {
		return Spec{}, errors.New("a driver is a repository on a host, not a path on this machine: host/group/repo@revision")
	}
	at := strings.Index(in, "@")
	if at < 0 || at == len(in)-1 {
		return Spec{}, errors.New("a driver needs a revision: host/group/repo@revision")
	}
	loc, rev := in[:at], in[at+1:]
	if strings.Contains(rev, "@") {
		return Spec{}, errors.New("a driver has one revision: host/group/repo@revision")
	}
	if strings.ContainsAny(rev, "/:") {
		return Spec{}, errors.New("the revision holds a / or a : which no commit hash or version tag has")
	}
	if !hashRev.MatchString(rev) && !versionRev.MatchString(rev) {
		return Spec{}, errors.New("the revision must be pinned: a full commit hash (40 lowercase hex digits) or a version tag like v1.2.3, not a branch, latest, upgrade or a short hash")
	}
	host, path, ok := strings.Cut(loc, "/")
	if !ok || path == "" {
		return Spec{}, errors.New("a driver needs a path: host/group/repo@revision")
	}
	if err := checkHost(host); err != nil {
		return Spec{}, err
	}
	path = strings.TrimSuffix(path, ".git")
	parts := strings.Split(path, "/")
	if len(parts) > maxPathParts {
		return Spec{}, fmt.Errorf("the path is too deep (at most %d names)", maxPathParts)
	}
	if len(parts) < 2 {
		return Spec{}, errors.New("the path needs a group and a repository: host/group/repo@revision")
	}
	for _, p := range parts {
		// pathPart already refuses "." and "..": they are named here as well so that loosening the pattern, to let a name start with a
		// dot, can never let a parent directory through.
		if p == "" || p == "." || p == ".." || !pathPart.MatchString(p) {
			return Spec{}, errors.New("the path must be plain names separated by single slashes (no .., no empty part, nothing starting with - or .)")
		}
	}
	s := Spec{Host: host, Path: path, Rev: rev}
	if isSecurl(s) {
		return Spec{}, errors.New("this is securl itself, not a driver: a driver lives in its own repository")
	}
	return s, nil
}

// isScpForm recognises user@host:path, the way git writes an ssh address. The first @ comes before the first / and a : follows it;
// in host/path@revision the first / comes before the @.
func isScpForm(in string) bool {
	at, slash := strings.Index(in, "@"), strings.Index(in, "/")
	return at >= 0 && (slash < 0 || at < slash)
}

func checkHost(h string) error {
	name, port, hasPort := strings.Cut(h, ":")
	if hasPort {
		n, err := strconv.Atoi(port)
		if err != nil || n < 1 || n > 65535 || strconv.Itoa(n) != port {
			return errors.New("the host's port must be a number from 1 to 65535")
		}
	}
	if !hostName.MatchString(name) {
		return errors.New("the host must be a name with a dot, like gitlab.example.com (no user, no scheme, no address)")
	}
	allDigits := true
	for _, label := range strings.Split(name, ".") {
		if _, err := strconv.Atoi(label); err != nil {
			allDigits = false
		}
	}
	if allDigits {
		return errors.New("the host must be a name, not an address")
	}
	return nil
}

// isSecurl says whether the spec names securl or something inside it: building it in again would register its drivers twice.
func isSecurl(s Spec) bool {
	m := strings.ToLower(s.Host + "/" + s.Path)
	return m == "github.com/leafai/securl" || strings.HasPrefix(m, "github.com/leafai/securl/")
}

// ParseList reads drivers separated by white space or commas.
func ParseList(in string) ([]Spec, error) {
	fields := strings.FieldsFunc(in, func(r rune) bool { return r == ',' || r == ' ' || r == '\t' || r == '\n' || r == '\r' })
	if len(fields) > MaxSpecs {
		return nil, fmt.Errorf("too many drivers (at most %d)", MaxSpecs)
	}
	seen := map[string]bool{}
	out := make([]Spec, 0, len(fields))
	for _, f := range fields {
		s, err := ParseSpec(f)
		if err != nil {
			return nil, err
		}
		if seen[s.Module()] {
			return nil, fmt.Errorf("the driver %s is listed twice", s.Module())
		}
		seen[s.Module()] = true
		out = append(out, s)
	}
	return out, nil
}

// Module is the Go module path of the driver's repository.
func (s Spec) Module() string { return s.Host + "/" + s.Path }

// CloneURL is the ssh address git clones from: the scp form, or ssh:// when the host has a port (the scp form cannot carry one).
func (s Spec) CloneURL() string {
	if host, port, ok := strings.Cut(s.Host, ":"); ok {
		return "ssh://git@" + host + ":" + port + "/" + s.Path + ".git"
	}
	return "git@" + s.Host + ":" + s.Path + ".git"
}

// String is the spec as it was written.
func (s Spec) String() string { return s.Module() + "@" + s.Rev }
