# Drivers from other repositories

securl logs in to a website with a *driver*. The drivers that come with securl (GitLab, Jenkins, Kibana, ...) are part of this
repository. A driver for a system that is only yours (an internal admin console, say) can live in a repository of its own, a private
one if you like, and be **built into your copy of securl** when you build it. Nothing is downloaded or loaded when securl runs.

```sh
make rpm DRIVERS="gitlab.example.com/group/subgroup/securl-driver-console@v1.2.0"
make deb DRIVERS="gitlab.example.com/a/one@v1.0.0 gitlab.example.com/b/two@4b5a6fc17bbd68ba7390b6b944aa1cf43140271e"
make macos DRIVERS="gitlab.example.com/group/repo@v1.2.0"

# or, for any other build command
go run generate.go --driver gitlab.example.com/group/repo@v1.2.0 -- go build -o securl .
SECURL_DRIVERS="gitlab.example.com/group/repo@v1.2.0" go run generate.go -- go build -o securl .
```

`securl version` then says which drivers the binary holds and from which commit:

```
securl 0.1.0~git.20261125.8a0801b +drivers[gitlab.example.com/group/repo@4b5a6fc17bbd] go1.26.9 darwin/arm64
```

## What a driver is named by

`host/path@revision`, for example `gitlab.example.com/group/subgroup/repo@v1.2.0`.

- **host/path** is where the repository is, and is also the Go module path the repository's `go.mod` must declare. A repository that
  declares another module path is refused.
- **revision** is **pinned**: a version tag (`v1.2.0`, `v1.2.0-rc.1`) or a **full 40-digit commit hash**. A branch name, `latest`,
  `upgrade` and an abbreviated hash are refused. Code that runs inside the process that holds every credential must be the code that
  was looked at, and a name that moves cannot promise that. A tag is followed to the commit it names, and the commit is what is
  reported by `securl version`.
- Several drivers are separated by a space or a comma. At most 16. The same module twice is an error.
- No scheme, no user, no `..`: only letters, digits and `/ . - _ : @`. A port is written `host:2222/path@revision`.

## How it is built

`generate.go` (run by `make` when `DRIVERS` is set, or by hand) does this, in order, and does nothing else:

1. Checks every driver, before anything is run.
2. Clones each one **over ssh** into a temporary directory, only the named revision and no history, with git run with none of your
   own git configuration. The host's key must already be in your `known_hosts` (the build never learns a host by itself) and it never
   waits for a password. Your ssh agent (`SSH_AUTH_SOCK`) is how you are known; or name a key with `--ssh-key /abs/path` or
   `SECURL_DRIVERS_SSH_KEY`, which is then the only key offered.
3. Checks that the checkout is the module it was asked for.
4. Adds `drivers_extra.go` to the main package, a blank import of each driver and a record of which commits they are, and writes the
   module file the build uses **somewhere else** (`go build -modfile`). **Your `go.mod` and `go.sum` are never touched.**
5. Runs your build command.
6. Removes `drivers_extra.go` and the temporary directory, whether or not the build worked.

Every error says what failed and never repeats what git or ssh printed, because a build log is shared and what they print can name
a user, a path or a token.

## The official build never holds one

`scripts/release.sh` (the nightly build) and `scripts/publish-nightly.sh` **refuse to run when `SECURL_DRIVERS` is set**. A binary
with a driver from another repository in it is for whoever built it, and is never published as the official one. Its version line
says so.

## Writing a driver

A driver is a Go module that imports only `github.com/LeafAI/securl/driver`. securl's own packages are `internal/`, which another
module cannot import; `driver` is the part meant for you, and every type in it is an alias of the one securl uses, so your driver is
run by the same code as a built-in one.

```go
package admin

import (
	"context"
	"net/http"
	"net/url"

	"github.com/LeafAI/securl/driver"
)

type admin struct{}

func init() { driver.Register(admin{}) }

func (admin) Name() string                       { return "myadmin" }
func (admin) Match(u *url.URL) bool              { return u.Hostname() == "admin.example.com" }
func (admin) NeedsLogin() bool                   { return true }
func (admin) RememberScope() (string, *url.URL)  { return "", nil } // takes part in remembered credentials

func (admin) Login(ctx context.Context, base *url.URL, ask driver.Asker, hc *http.Client) (*driver.Session, error) {
	creds, err := ask.Ask(ctx, "login", driver.LoginFields()) // a person types these; the agent never sees them
	if err != nil {
		return nil, err
	}
	_ = creds // ... log in, then:
	return &driver.Session{Headers: map[string]string{"x-session": "..."}}, nil
}

func (admin) Probe(ctx context.Context, base *url.URL, s *driver.Session, hc *http.Client) error { return nil }
```

Rules that keep a private driver inside securl's model:

- **Ask a person only through `ask.Ask`**, and only for the two rounds securl knows how to remember: `"login"` (username and password)
  and `"totp"` (a one-time code). Anything else you ask for is shown as it is and is **never saved**.
- **Implement `RememberScope`** to take part in remembered credentials (saved in the vault, approved per day). Without it the
  driver works, and a person types the credentials each time.
- **Put session secrets in `Session` (`Headers`, `Cookies`, `Tokens`)**: securl adds them to requests and removes them from
  answers. Never log them, put them in an error, or return them.
- **Do not repeat what a site said in an error**: it may hold a token. Wrap `driver.ErrBadCredentials`, `driver.ErrLoginRejected` or
  `driver.ErrUnreachable` so that securl can tell what went wrong.
- A driver that cannot ask the site (a refused connection) returns `driver.Unreachable(err)` from `Probe`, so a good session is kept.

The `driver` package is **experimental**: it follows securl's internal interface and may change with it. Pin the securl commit your
driver was written against in its README.

## Trust

A driver is code that runs in the process that holds every credential, from its first `init`. **Write access to a driver's
repository is therefore write access to securl.** So:

- turn on protected branches and required approval for the repository, and build only from a tag or a commit someone reviewed;
- the build records the commit it built in, so a binary can be matched to a review;
- do not hand a binary built with a driver to anyone you would not hand the source.
