package driverbuild

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"
)

// fetchTimeout bounds one clone: a driver is a small repository, and a build that waits for a prompt or a dead server is stuck.
const fetchTimeout = 3 * time.Minute

// Fetched is a driver's source as it was checked out.
type Fetched struct {
	Spec   Spec
	Commit string // the commit the revision names, in full: for a tag, the commit it points at
	Dir    string // where the source is
}

// gitEnv is everything git is run with. It is built from nothing: the caller's own git settings (a signing key, a url rewrite, a
// credential helper) must not decide what a build fetches. extra carries what the build deliberately adds (the ssh command).
func gitEnv(extra []string) []string {
	env := []string{
		"PATH=" + os.Getenv("PATH"),
		"HOME=" + os.Getenv("HOME"),
		"GIT_CONFIG_GLOBAL=/dev/null",
		"GIT_CONFIG_SYSTEM=/dev/null",
		"GIT_CONFIG_NOSYSTEM=1",
		"GIT_TERMINAL_PROMPT=0",
	}
	if v := os.Getenv("SSH_AUTH_SOCK"); v != "" {
		env = append(env, "SSH_AUTH_SOCK="+v)
	}
	return append(env, extra...)
}

func git(ctx context.Context, dir string, env []string, args ...string) (string, error) {
	cmd := exec.CommandContext(ctx, "git", args...)
	cmd.Dir = dir
	cmd.Env = gitEnv(env)
	out, err := cmd.Output()
	return strings.TrimSpace(string(out)), err
}

// Fetch checks out the revision a Spec names, from cloneURL, into dest (which must not exist), and says which commit it is.
// Only that revision is fetched, with no history, and the .git directory is removed once the tree is out, so what is built is
// exactly the files of that commit. The errors say what failed and never what git printed: it can name a user, a path or a token.
func Fetch(s Spec, cloneURL, dest string, env []string) (*Fetched, error) {
	if _, err := os.Lstat(dest); err == nil {
		return nil, fmt.Errorf("driver %s: %s already exists", s.Module(), "the destination")
	}
	if err := os.MkdirAll(dest, 0o700); err != nil {
		return nil, fmt.Errorf("driver %s: could not make the build directory", s.Module())
	}
	ctx, cancel := context.WithTimeout(context.Background(), fetchTimeout)
	defer cancel()
	fail := func(what string) (*Fetched, error) {
		os.RemoveAll(dest)
		return nil, fmt.Errorf("driver %s: %s", s.Module(), what)
	}
	if _, err := git(ctx, dest, env, "init", "-q"); err != nil {
		return fail("could not start a checkout")
	}
	if _, err := git(ctx, dest, env, "remote", "add", "origin", cloneURL); err != nil {
		return fail("could not set the repository")
	}
	// A version is fetched as the tag it is, by its full name: git itself prefers a tag to a branch of the same name, but a build
	// should not depend on how a particular git resolves that.
	ref := s.Rev
	if versionRev.MatchString(s.Rev) {
		ref = "refs/tags/" + s.Rev + ":refs/tags/" + s.Rev
	}
	if _, err := git(ctx, dest, env, "fetch", "-q", "--depth", "1", "--no-tags", "origin", ref); err != nil {
		return fail("could not fetch " + s.Rev + " (is the repository there, does the ssh key reach it, and does the revision exist?)")
	}
	// The two checks below cannot fail with git as it is today (rev-parse prints a full object id, and git fetches an object by the id
	// it was asked for), and are kept because what is built into this program must be the commit that was reviewed, and a build
	// should not rest on that being true of every git it may meet.
	commit, err := git(ctx, dest, env, "rev-parse", "--verify", "FETCH_HEAD^{commit}")
	if err != nil || len(commit) != 40 {
		return fail("the revision is not a commit")
	}
	if hashRev.MatchString(s.Rev) && commit != s.Rev {
		return fail("the commit fetched is not the one asked for")
	}
	if _, err := git(ctx, dest, env, "-c", "advice.detachedHead=false", "checkout", "-q", "--detach", commit); err != nil {
		return fail("could not check out the revision")
	}
	if err := os.RemoveAll(filepath.Join(dest, ".git")); err != nil {
		return fail("could not remove the history")
	}
	return &Fetched{Spec: s, Commit: commit, Dir: dest}, nil
}

var errNoModule = errors.New("no go.mod")

// ModulePath reads the module path a checked-out driver declares.
func ModulePath(dir string) (string, error) {
	b, err := os.ReadFile(filepath.Join(dir, "go.mod"))
	if err != nil {
		return "", errNoModule
	}
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if rest, ok := strings.CutPrefix(line, "module"); ok && (rest == "" || rest[0] == ' ' || rest[0] == '\t') {
			return strings.Trim(strings.TrimSpace(rest), `"`), nil
		}
	}
	return "", errNoModule
}
