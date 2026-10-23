# securl

A secure URL requestor for AI agents: an MCP server that gets an agent into sites that need a human to type credentials
(GitLab, Jenkins, Kibana, KubeSphere, Nightingale v7, Archery, RocketMQ Dashboard, SkyWalking, and any site you describe in YAML). A person
types the credential once, on a page opened from a DingTalk link, and the agent never sees the password.

Secrets are kept in an encrypted vault that is locked at start and opened by the person typing its passphrase
(`vault_unlock`). The agent then uses a site through `request`: securl adds the credentials to the request and removes
them from the answer, so the agent never holds a cookie, a token or a password.

First get the `securl` binary. Pick the way that fits the machine (`go version` tells you):

**Go 1.21 or newer, for a Go developer:** install it directly. securl needs Go 1.26.9, and Go downloads that
toolchain itself unless `GOTOOLCHAIN=local` is set.

```
go install github.com/LeafAI/securl@latest
```

`@latest` is the newest `master`; the repository has no release tags. For a fixed version give a commit:
`go install github.com/LeafAI/securl@<commit>`.

**No Go toolchain:** download the nightly build for your platform, check it, and put it on your `PATH`. There is one
release, tagged `nightly`, built from `master` and replaced every night when `master` has changed
([releases](https://github.com/LeafAI/securl/releases/tag/nightly)):

```
# macOS / Linux: <os> is darwin or linux, <arch> is arm64 or amd64
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS.sig
curl -LO https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers      # the key comes from the repository, not the release
ssh-keygen -Y verify -f allowed_signers -I securl-release -n securl-release -s SHA256SUMS.sig < SHA256SUMS   # must print "Good"
shasum -a 256 --ignore-missing -c SHA256SUMS            # sha256sum on Linux; must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                          # nightly-<date>-<commit>
```

**macOS: the installer package.** On a Mac, `securl_macos.pkg` (a universal binary, Apple silicon and Intel) installs
`/usr/local/bin/securl`, which is on every Mac's default `PATH`. Check it the same way, then open it:

```
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_macos.pkg
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS.sig
curl -LO https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I securl-release -n securl-release -s SHA256SUMS.sig < SHA256SUMS   # must print "Good"
shasum -a 256 --ignore-missing -c SHA256SUMS                                                                 # must print OK
open securl_macos.pkg            # or: sudo installer -pkg securl_macos.pkg -target /
securl version
```

- **The package is not signed by Apple**, which needs a Developer ID certificate that this project does not have. macOS will stop
  the first double-click ("cannot be opened because it is from an unidentified developer"): right-click the file and choose Open,
  or allow it in System Settings, Privacy & Security. The signature of `SHA256SUMS` above is what shows who published the file, and
  it is checked by you, not by macOS. `sudo installer -pkg` is not stopped by Gatekeeper, and is the same installation.
- **When it finishes, `securl daemon` is running** for you, and is started for every user of the Mac each time they log in. The
  package's last step makes one login agent for the machine, `/Library/LaunchAgents/com.leafai.securl.plist`, and loads it into the
  session of the person at the console. launchd runs it for each user as that user, so every user gets their own daemon, with their
  own configuration, vault and socket; nobody's daemon runs as root and none serves another user. If nobody is logged in, the agent is
  put in place and starts at each user's next login. If that step fails, the file is still installed, the package says why, and tells
  you to run `sudo securl daemon install` yourself.
- **Check that it worked:** `securl daemon status` must say `running` and `login agent: installed and loaded`. If it says
  `installed, not loaded for you yet` (or `not running`), the installer could not start the daemon; the file is still installed.
  The reason is in the installer's own log, `grep postinstall /var/log/install.log | tail`, and `sudo securl daemon install` starts
  it. **Upgrading** over a running daemon restarts it with the new binary, locked again (`securl unlock`); a command that prints
  "the daemon is version X and this command is Y" means a daemon that was not restarted: `launchctl kickstart -k
  gui/$(id -u)/com.leafai.securl`.
- **Another copy of `securl` earlier on `PATH`** (a `go install` copy in `~/go/bin` comes before `/usr/local/bin` on many
  machines) is run instead of the package's: `command -v securl` shows it. Move it aside, do not rely on `PATH` order.
- **What is running is locked.** The daemon starts with its vault shut: it holds no secret, and nothing is typed into the Installer.
  The first time, run `securl vault init` (you choose the passphrase) and `securl config init`; then `securl unlock` sends you a link
  and you type the passphrase on its page. Once you unlock it, every process of your account can use your sessions through the
  daemon (never a credential) until it locks again. `vault.idle_lock` sets how long that is (`securl config set vault.idle_lock 30m`);
  without it the vault stays open until the daemon stops. The daemon's own log is `~/Library/Logs/securl-daemon.log`.
- To remove securl: `sudo securl daemon uninstall` (no user gets a daemon at login any more, and yours is stopped), then
  `sudo rm /usr/local/bin/securl` and `sudo pkgutil --forget com.leafai.securl`. Its configuration, vault and audit log are in
  `~/Library/Application Support/securl/` and are yours to keep or delete. A daemon that another user is running stops when they log out.

**What the signature proves.** `SHA256SUMS` is signed with the release key, whose public half is `keys/securl-release.pub` in this
repository (ed25519, fingerprint `SHA256:QSdbV2Da6NA2sJZ7wFj08onoUQ1qJvQO8w+AZAYweQI`). The first
`ssh-keygen` command shows that `SHA256SUMS` is the file the publishers signed, and the `shasum` command then shows that your
archive is the one it lists. Without the signature, whoever could replace an archive could replace `SHA256SUMS` next to it, and
the hashes would prove nothing. Take the key from the repository, as above, and not from the release: a key that came with the
files could be replaced with them. You can compare the fingerprint with `ssh-keygen -lf keys/securl-release.pub`. `ssh-keygen` is
part of OpenSSH, which macOS and most Linux systems have; Windows 10 and later has it too (`ssh-keygen.exe`). The signature does
not make macOS or Windows trust the program: Gatekeeper and SmartScreen look for signatures of their own, which the build does
not have, so the first run may need a confirmation from the system.

Every archive is published twice, as `securl_<version>_<os>_<arch>` and as `securl_<os>_<arch>` (the same file), so the
command above never goes stale. The release is a pre-release, so GitHub's "latest" link does not point at it: use the
`download/nightly` address. Each build lists `SHA1SUMS` and `SHA256SUMS`. Both catch a damaged download; rely on
SHA-256 against tampering, because SHA-1 collisions can be made. Windows gets a `.zip`: check it with
`certutil -hashfile securl_windows_<arch>.zip SHA256` and compare the line in `SHA256SUMS`. `--ignore-missing` is needed
because you downloaded one archive and the file lists all of them. The nightly is a build of the newest `master`, not a
tested release.

Then register it with your MCP client:

```
claude mcp add securl -- securl          # or add "securl" to any MCP client's server list
```

An agent skill that teaches install, update, setup and use is in [`skills/securl/SKILL.md`](skills/securl/SKILL.md). Copy
the `skills/securl` directory into your client's skills directory (for Claude Code: `~/.claude/skills/securl/`).


## How a login works

1. The agent calls `session_open(url)`. A valid cached session is reused (probed first).
2. `login` takes a key pair from a local pool (each key: ≤ 8 uses and ≤ 24 h), starts a one-shot JSON API on
   `127.0.0.1` and exposes it through an SSH reverse tunnel (pinggy, localhost.run, serveo, tunnl.gg, or your own).
3. A DingTalk robot message carries **one link** to a static login page. The link's `#fragment` holds the mode
   (`login`/`totp`), the tunnel API address and the **public key**; nothing in it reaches any server.
4. The human opens the link, types the credential; the page encrypts it (OpenPGP) to the key from the link and
   posts it to the API. The human can instead press **Reject** and give an optional reason — the agent receives
   `user_rejected` with that reason.
5. `login` decrypts it and runs the site's real login flow. If the site wants a second factor, the driver
   starts another round (a new link in DingTalk). The cookie/token is returned to the agent.

The static page is served by GitHub Pages (version-pinned) or from your disk (`securl page [dir]`); the tunnel
carries only ciphertext. See `DESIGN.md` (architecture, threat model) and `MCP_TOOLS.md` (tool schemas).

## Production deployment

![securl: production deployment architecture](docs/architecture.svg)

`securl` runs as one process next to the agent (the nightly binary, `go install`, or the Docker image) and talks to the agent over stdio.
Its config, key pool, encrypted sessions and audit log live in one private directory (a volume in Docker).
Nothing listens on a public port: the only inbound path is the `ssh -R` tunnel that `login` itself opens, and it
exists only while a person is being asked.

1. The agent calls `session_open(url)`; the session is opened and its use is described below.
2. `login` sends one link through the DingTalk robot (signed webhook).
3. The person receives it in DingTalk.
4. The link opens the static page from GitHub Pages (or your own copy); it carries the key and tunnel address in
   its `#fragment`, which no server sees.
5. The page encrypts what the person types and posts it to the tunnel address; the provider sees ciphertext only.
6. The tunnel forwards it to the one-shot API on `127.0.0.1`, where it is decrypted.
7. The site driver runs the real login against the target site inside your network.

## Security notes

- The static login page was reviewed in depth: see `docs/static-page-review.md` (findings, fixes, residual risks).
  Notably, the human must compare a short **key code** shown on the page with the one in the DingTalk message
  before the page lets them submit, and after a link is accepted the page can only talk to that link's tunnel.
- Agent-supplied text (`reason`, SQL title/remark/SQL) is escaped before it is put in DingTalk markdown, so it
  cannot add links or formatting to the message the human acts on.
- `security.allowed_hosts` limits which sites the agent can target.
- The agent chooses the URL, so the HTTP client refuses this machine's own addresses (loopback, link-local, the cloud
  metadata endpoint) unless `security.allow_local_addresses: true`; it checks the address it actually connects to, so
  a name that resolves to one is refused too. Private networks (10/8, 172.16/12, 192.168/16) stay reachable: that is
  where your sites live. A redirect that leaves the site (another host or port, or https to http) is not followed,
  so a site cannot bounce a login request, body included, to a second host; list an SSO server in `allowed_hosts`
  if a site legitimately redirects to it.
- Unknown keys in `config.yaml` are an error at startup and in `securl doctor`, with a suggestion ("did you mean
  `allowed_hosts`?"), so a typo cannot silently switch a protection off.
- The `request` tool refuses Archery, so an agent cannot post or approve a workflow itself and skip the approval, the
  DDL check and the limits that the `archery_*` tools apply. `security.allow_archery_requests: true` lifts it; it is
  the owner's switch, and it is off by default.
- With no DingTalk robot, `security.link_via_agent: true` returns the login link to the agent to show the person. It is the
  owner's switch and off by default. It gives up one thing: the person no longer reads a message that securl itself wrote, so
  what the agent says about the link is not checked by anything. A configured robot always wins.
- **Databases** (`databases:`) are reachable only by the names the owner lists; an agent supplies no host, port or
  connection string. The account is typed by a person on the usual page and kept in the vault, and the password is never in an answer,
  an error, the audit log or a message (a query that echoes it has it removed; the user name is not a secret and is not). A `read_only` target runs every statement
  in a read-only transaction on a read-only session, after a lexical check that it is one statement that only reads; a
  `read_write` target rolls back a change that touches more than `max_changed_rows`, refuses DDL unless `allow_ddl` is
  on, and tells the team in DingTalk afterwards. `environment: prod` is refused when the configuration loads. securl
  cannot know that a host is really not production, and an agent can read whatever the account can: give the account
  only what an agent may do there, and no `dblink`, `postgres_fdw` or `FEDERATED` route to a production server.
- `archery.allow_ddl: false` is enforced by a SQL scanner (comments, strings and `;` aware, MySQL executable
  comments included, `PREPARE`/`EXECUTE` refused, anything unparsable refused), not a pattern match.
- Every secret securl keeps (logged-in sessions, TOTP secrets) is in one **vault**: AES-256-GCM under a random master
  key that is wrapped with a key derived from your passphrase (argon2id, at least 16 characters). Nothing secret is on
  disk in the clear: no key file next to the data, and the OpenPGP keys that protect a link in transit live in memory
  only. The vault is locked when the process starts; the agent calls `vault_unlock`, you get a DingTalk link and type
  the passphrase on that page. Wrong passphrases are slowed (3 free attempts, then 30 s doubling to 15 min). Make it
  with `securl vault init`, which also moves anything an earlier version left in plain files into it. Every reuse of a
  session is validated against the site first; stale entries are dropped.
- **The agent never holds a credential.** `session_open` says that a session exists, not what it contains; `request`
  sends an HTTP request with the session's cookies and tokens put in here, and removes them from the answer (every
  value in the encodings a server repeats them in, `Set-Cookie`, credential headers). The agent can reach only the
  session's own site, cannot supply a `Cookie` or `Authorization` header, and redirects are never followed off the site.
  The scrubber is a safety net with stated limits (see `MCP_TOOLS.md`), not the only layer.

## Set it up without editing YAML

```
securl config init                 # DingTalk robot + safety settings, with a test message
securl config site add https://gitlab.corp.example   # detects the driver, asks that driver's own questions
securl config site custom          # any other website: answer questions, no YAML
securl config db add               # a PostgreSQL / MySQL database (dev, test, staging): answer questions, no YAML
securl config db list              # what is configured; `db remove <name>` forgets one
securl config set                  # list every setting; `set <key> <value>`, `get`, `unset`, `show`
```

Each change is checked before it is saved (a typo such as `dingtalk.webhok` is refused with a suggestion), the
file stays private (0600), your comments are kept and the previous version is saved as `config.yaml.bak`.
Secrets are asked without echo and shown masked.

`securl config db add` asks for the name, the engine, the host, the port (the engine's own is offered), the environment
(dev, test or staging: production is not offered), which databases an agent may use, whether it may change data, and how
the connection is protected. Every answer is checked as it is given, with the check the server applies when it loads the
configuration. For scripts, give the answers as flags and nothing is asked:

```
securl config db add --name gm-dev-pg --driver postgres --host pg.dev.corp.example --environment dev --databases appdb
securl config db add --name gm-dev-my --driver mysql --host my.dev.corp.example --environment test --databases appdb \
  --mode read_write --yes-allow-writes [--allow-ddl] [--max-changed-rows 100]
```

A `read_write` target is the one answer that is a decision about risk: the guided setup asks you to confirm it, and a
script has to say `--yes-allow-writes`. No command asks for, or accepts, a database username or password: a person types
the account on the login page when an agent opens a session, and it is kept in the vault.

## First run

See `docs/OPERATING.md` for the full operator guide (setup order, per-site config, troubleshooting).

```
securl doctor                 # checks config, ssh, key dir, providers
securl doctor -tunnel         # starts each tunnel provider and fetches a page through it
securl doctor -send           # posts a test message through the DingTalk robot
securl doctor -site <url>     # no credentials: shows which driver/login method a site will get (use for every site)
securl page [dir]             # writes the static login page for local use
```

## Configuration

`~/.config/securl/config.yaml` (override with `-config`). Environment: `SECURL_DINGTALK_WEBHOOK`,
`SECURL_DINGTALK_SECRET`, `SECURL_TUNNEL_ORDER`.

```yaml
dingtalk:
  webhook: https://oapi.dingtalk.com/robot/send?access_token=...
  secret: SEC...            # signing secret, if the robot uses "加签"
  keyword: login            # only if the robot requires a keyword
  at_mobiles: ["138..."]    # phone numbers to @mention: digits only; each message starts with "@number" for every one
tunnel:
  order: [pinggy, localhost.run, serveo, tunnl]   # ssh-j is TCP-only and is never used for the web API
  timeout: 20s
  providers:                                        # extra servers
    - name: mycorp
      command: ssh -R 0.0.0.0:{{port}}:localhost:{{port}} jump.corp.example
      url: https://jump.corp.example:{{port}}       # or url_regex to parse a printed URL
web:
  page_url: https://leafai.github.io/securl/   # or file:///path/to/securl-page/index.html
  ttl: 10m                                          # per round
keys: {max_uses: 8, max_age: 24h}
sessions:
  persist: true               # keep logins (encrypted) so a new MCP server process reuses them; default false
mcp: {max_block_seconds: 50}
archery:
  allow_ddl: true            # false rejects CREATE/ALTER/DROP/TRUNCATE/RENAME (and PREPARE/EXECUTE, which hide SQL)
  default_group: dba         # Archery resource group when a call gives none
  wait_timeout: 30m          # default approval timeout
security:
  allowed_hosts: ["*.corp.example"]   # optional: the agent may only log in to matching hosts
  allow_local_addresses: false        # true lets the agent reach localhost / link-local / metadata addresses (dev only)
  allow_archery_requests: false       # true lets the request tool talk to Archery, which skips the approval gate of archery_run_sql
  link_via_agent: false               # true, with no dingtalk.webhook: the login link is returned to the agent to show you (see docs/OPERATING.md)
databases:                   # PostgreSQL / MySQL for dev, test or staging; `securl config db add` writes this
                             # production is refused (use Archery)
  - name: gm-dev-pg          # what an agent calls it; the agent never supplies a host or a port
    driver: postgres         # postgres | mysql
    host: pg.dev.corp.example
    # port: 5432             # default: the driver's own
    environment: dev         # dev | test | staging (required)
    databases: [appdb]       # the databases an agent may use; empty = any the account can open
    mode: read_only          # read_only (default) | read_write
    # allow_ddl: false       # read_write only: allow CREATE/ALTER/DROP/TRUNCATE/RENAME
    # tls: verify            # verify (default) | skip-verify | disable
    # max_rows: 1000         # rows one query may return (at most 10000)
    # max_changed_rows: 1000 # a change that touches more rows is rolled back
    # statement_timeout: 30s # per statement (at most 5m)
audit:
  enabled: true              # default; JSON lines (who/what/when, never secrets) in audit.jsonl next to this file
limits:                      # protect people from request floods; only requests that reach a person count
  per_site: 6                # per window (defaults shown)
  total: 20
  window: 1h
  reject_cooldown: 10m       # after a Reject, that site is paused
site_options:                # driver-specific settings
  gitlab:                    # LDAP-enabled GitLab: the LDAP tab is used automatically
    login_method: auto       # auto | ldap | standard (standard = local GitLab accounts)
    ldap_provider: ldapmain  # only if it differs from the name in the sign-in form
  kubesphere:                # LDAP users must log in through /oauth/login/<provider>
    identity_provider: auto  # auto (first LDAPIdentityProvider) | local | <provider name>
roots:                       # sites served under a path prefix: host -> full base URL
  elk.corp.example: https://elk.corp.example/kibana
aliases:                     # hostnames that do not hint at the product
  es.corp.example: kibana
  apm.corp.example: skywalking
sites:                       # any other website, no Go needed
  - name: grafana
    match_host: grafana
    steps: [{method: POST, path: /login, json: {user: "{{username}}", password: "{{password}}"}}]
    twofa: {detect_body: otp_required, step: {method: POST, path: /login/otp, form: {code: "{{code}}"}}}
    collect: {tokens: {access: data.token}, headers: {Authorization: "Bearer {{token:access}}"}}
    probe: {path: /api/user}
```

## Tools and resources

Every tool has a title and an output schema. Read-only resources: `securl://sites`, `securl://sessions`,
`securl://policy` (the limits that apply to the agent). The server also sends instructions on how to use the tools.

`vault_status`, `vault_unlock`, `session_open`, `session_wait`, `site_list`, `session_list`, `session_close`, `archery_instances`, `archery_groups`, `archery_query`,
`archery_run_sql`, `archery_wait`, `archery_workflow_status`, `archery_cancel`, `db_targets`, `db_query`, `db_exec`.
Long operations return a `pending` result with an id after `max_block_seconds`; resume with `session_wait` /
`archery_wait`. `session_close` is one of them: it closes nothing until a person has typed `DELETE` on a page that names the
sessions (a database account is a password that cannot be recovered), so it answers `pending` and is resumed with its `close_id`.

## From the command line

Every tool is also a command, for a person at a terminal or a script: `securl <group> <command> --flag value`. The command
runs the same server in its own process and talks to it like any MCP client does, so it has the same checks, limits, request
policies and audit trail as an agent, and its answer never carries a credential.

```
securl session open --url https://gitlab.corp.example --reason "list merge requests"
securl request --url https://gitlab.corp.example --method GET --path /api/v4/user
securl db query --target gm-dev-pg --sql @query.sql
securl archery run-sql --url https://archery.corp.example --instance x --database y --title t --sql - < change.sql
```

- A tool `group_name` is `securl group name` (`archery_run_sql` is `securl archery run-sql`); a tool with no group is one
  word (`securl request`). A field is a flag with its dashes (`max_block_seconds` is `--max-block-seconds`); `--help` lists
  them, with the tool's own description. The flags are read from the tool's input schema, so a field added to a tool is a flag
  from the next build on. A map is given as repeated `--header name=value`; JSON as `--json '{...}'`; a text value may be
  `-` (standard input) or `@file`; `@@x` is the text `@x`.
- **The answer is one JSON document on standard output; everything else (prompts, progress, a link for the person) is on
  standard error.** Exit codes: `0` answered, `1` the tool answered with an error (its JSON is the output), `2` the command
  line was wrong and nothing ran, `3` the configuration or the vault could not be set up, `4` still waiting for a person
  (the answer says how to continue: `securl session wait --login-id ...`).
- **The vault.** Each command is its own process, so it opens the vault for itself and locks it again when it ends; a session
  one command opened is in the vault for the next. On a terminal it asks for the passphrase (no echo). With no terminal (a
  pipe, a script, an agent's shell) it never reads the passphrase from anywhere: not from standard input, an argument or an
  environment variable. It opens the vault the way an agent does, with a link for the person (DingTalk, or on standard error
  with `security.link_via_agent`). `securl vault status`, `securl vault init` and `securl vault passwd` are unchanged.
- `securl` with no arguments, or with only flags (`securl -config file`), is still the MCP server on standard input and
  output, exactly as an MCP client's configuration starts it; `securl serve` is the same server by name. An unknown word is
  an error, not a server that waits for input.
- **A daemon.** `securl daemon` runs one server in the background of your session; commands then talk to it instead of each
  starting their own, so the vault is unlocked once and the session of one command is there for the next without a passphrase
  each time. `securl daemon status` says whether one is running and whether its vault is open. Commands use a running daemon by
  themselves (and say so on standard error when there is none and they run alone); `--no-daemon` makes a command run alone.
  The daemon starts locked and is opened the way an agent opens a server: the first command that needs the vault sends you the
  link, and you type the passphrase on its page. `securl unlock` does only that: it asks the running daemon to open its vault,
  waits for you, and exits 0 when it is open (4 if nobody answered in time, 3 if there is no daemon). **The passphrase never
  goes over the socket**, and `securl unlock` does not ask for it on the terminal either: it would have to travel over a socket
  that every process of your user can reach, an agent's shell among them. Without a robot, set `security.link_via_agent` and the
  link is printed on the terminal.
  **What this changes:** while the daemon is unlocked, every process of your user can use its sessions through the tools
  (never a credential). The socket is `0600` in a directory only you can write, the peer's user is checked on every connection,
  and the vault locks again after `vault.idle_lock` (set it: the default is to stay open). It is not available on Windows.
  See `DESIGN.md`, "Threat model".
- Two tools have no command: `vault_unlock` (a command opens the vault for itself) and `vault_status` (`securl vault status`
  already exists).

## Adding a website

Describe it in YAML (`sites:` above), or write a Go driver: implement `site.Driver` in
`internal/site/<name>/`, call `site.Register` in `init()`, blank-import it in `main.go`. A driver asks the human
through `ask.Ask(ctx, "login", ...)` and, when the site wants a second factor, again with `"totp"`; the flow
turns each call into its own DingTalk link. Return `site.ErrBadCredentials`, `ErrLoginRejected` or
`ErrUnreachable` (wrapped) so the agent gets a precise error code.

## Testing

`go test ./...` — unit tests, the config wizards, the audit log and rate limits, MCP output schemas validated against real results, fake-site driver tests, a real `ssh`/`sshd` reverse-tunnel test (skipped without
them), and (when Node + Playwright + Chromium exist) browser end-to-end tests that drive the real page through the full MCP → DingTalk → tunnel → decrypt → login path.

## Docker

```
docker build -t login --build-arg VERSION=$(git describe --tags --always) .
docker run -it --rm -v securl-data:/home/securl/.config/securl securl vault init
docker run -it --rm -v securl-data:/home/securl/.config/securl securl config init
docker run -i --rm -v securl-data:/home/securl/.config/securl securl          # the MCP server (stdio)
```

The image contains `ssh` (tunnels), runs as a non-root user and keeps config, keys and the audit log in the volume.
`securl version` prints the build.

## Two optional TOTP factors

```
securl config totp init     # make the secrets, register them in your authenticator (1Password: 10 min is its maximum period)
```

An **unlock code** (long period) hides the site, the tunnel address and the one-shot password in the DingTalk link until
you type the code in the page; a **sealing code** (30 s) is mixed into the key that seals what you type. They sit on top of
the always-on AES-256-GCM seal and the OpenPGP layer, are never sent anywhere, and are not a substitute for either. See
`DESIGN.md` 4.2a for what they do and do not protect against, and `docs/OPERATING.md` for the commands.

## Roadmap

Sharing one gateway between several agents (network transport, caller identity, session isolation), keeping
credentials away from the agent (`login_request`), token renewal and more authentication methods are planned:
see `docs/ROADMAP.md`.

## What has and has not been verified

Verified in automated tests: key rotation, PGP round trip between openpgp.js and Go, round API validation,
tunnel banner parsing and fallback (with a fake `ssh`), real HTTP traffic through a real `ssh -R` forward
(local `sshd`), `ssh` accepting every built-in provider command line, DingTalk signing, the full login/2FA/reject flow in a
real browser, and every site driver against *fake* servers that imitate the flows.
**Archery**: both **1.x (checked against v1.12.0)** and the newer REST generation are supported and detected at
login. Endpoints, payloads, session/CSRF handling and the 2FA flow were checked against the Archery source code
of both generations, then exercised against fake servers that reproduce those contracts (including 1.x's HTML
error pages).

**Verified against live systems** (a real DingTalk robot, the SSH tunnel, the real login page and real accounts). In every
case the session was used on the site's own API, and a forged or missing credential was refused by the site:

| Site | What was exercised |
|---|---|
| Archery 1.x | login with TOTP, instances, groups, read-only queries, submit and cancel of a no-op workflow, Reject and the cool-down |
| Nightingale v7 | login, token used on its API |
| KubeSphere 3.4.1 | LDAP login the way the web console does it (JSON body with `title`, success as 302 with the tokens in `Set-Cookie`), token probe |
| GitLab 19.2 (JiHu) | LDAP login with TOTP |
| Kibana 7.9.3 | login with the flat `{username,password}` body, session probe, search through the console proxy |
| Jenkins 2.226 | login (`j_acegi_security_check`), success decided by the `anonymous` flag of `/whoAmI/api/json`, the session-bound `Jenkins-Crumb` equals what `crumbIssuer` issues, a job listing that anonymous users get a 403 for |
| SkyWalking 8.9.0 | no login needed: the URL answers and the GraphQL API returns data |

Real runs also found and fixed bugs that the fake servers had hidden: KubeSphere's request body and success response, its token
probe (it accepted any token, because the redirect to the login page answers 200), and Kibana 7.x's request body; and, in the
tunnel, a provider whose process was alive while its public name was not routed (the link is now checked before it is sent). The
two optional TOTP factors (unlock code of 10 minutes and sealing code of 30 seconds, both 8 digits, in 1Password) were exercised
live on Kibana and Jenkins.

What each driver was checked against in the source, besides the live run above:

**Jenkins** (2.226) was checked against its source: the login form action is read from the page
(`j_acegi_security_check` in 2.226, `j_spring_security_check` in newer releases), success is decided by
`/whoAmI/api/json` (an anonymous visitor also reports `authenticated: true`, so the `anonymous` flag is used), and
the session-bound CSRF crumb is returned as the `Jenkins-Crumb` header for POST requests. Core Jenkins has no
2FA; a 2FA plugin's extra step is reported as an error, not guessed. **GitLab** was checked against the GitLab source (16.8 and master): classic server-rendered forms, the LDAP tab
(`/users/auth/<provider>/callback`) and current GitLab's Vue sign-in and 2FA steps. **KubeSphere** 3.4.1 was checked
against its source and a browser capture of a real console login: LDAP users must use `/oauth/login/<provider>`
(the local `/oauth/token` grant cannot authenticate them), the provider is discovered from the published OAuth
config, the body is JSON, and success is a 302 whose `Set-Cookie` carries the tokens. A wrong password and an
unreachable LDAP both answer `200 {"status":500}`, so that message names both causes. **Kibana**'s login route and provider discovery were checked against
its source, and 7.9.3 against a live site. **Nightingale** (v7) was checked against its source: login payload, the optional math-image captcha (shown to
the human inside the login step) and optional RSA password encryption.

**RocketMQ Dashboard** was checked against a real Dashboard 2.0.1 (with a NameServer and a Broker) in a container, in the tests
(`scripts/mqtest`): login, the session probe, reads, the refusal of every write and of the message paths by the request policy,
and that a normal user gets "no permission" on `.do` writes. It was **not** run against the production Dashboard: its login
page and its public certificate were looked at, nothing was logged in to. The Dashboard takes the password in the URL query;
securl removes it from every error and result it produces, but it cannot reach the logs of a gateway or of the Dashboard.

**Not verified against live systems:**
- the RocketMQ Dashboard of the company (only the 2.0.1 image was driven);
- the individual SSH provider services (use `securl doctor -tunnel`);
- Kibana's, Jenkins's and KubeSphere's second-factor paths: stock versions have none, and the retry path for custom setups is a
  guess that has never run against a real one (a 2FA plugin's extra step on Jenkins is reported as an error, not guessed);
- Nightingale's optional captcha and RSA password encryption (this instance has neither);
- other versions than the ones in the table: GitLab 16.8, Kibana 8.x, Nightingale versions other than v7 and the newer
  Archery REST generation were checked against their source (and fake servers) only; the versions in the table are the ones
  that were run.
