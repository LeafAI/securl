---
name: securl
description: Install, update, set up and use the securl MCP server, which lets an AI agent reach websites that need a human login (GitLab, Jenkins, Kibana, KubeSphere, Nightingale, Archery, RocketMQ Dashboard, SkyWalking) without ever seeing a password, cookie or token. Use when the user wants to install or configure securl, unlock its vault, log in to an internal site, call a site's API through it, or run Archery SQL; also when a securl tool answers vault_locked, no_session or session_expired.
---

# securl

securl is an MCP server that sits between an agent and sites that need a person to log in. A person types the
credential once, on a page opened from a DingTalk link. The agent never holds a password, cookie or token: it sends
requests through the `request` tool, and securl adds the credentials on the way out and removes them from the answer.

**The one rule: never ask the user for a password, a TOTP code or the vault passphrase in the chat, and never pass one
to a tool.** Every secret is typed by the person on the page that securl links to. A tool that takes a passphrase does
not exist, and an extra argument is refused.

## 1. Install

You need an outbound `ssh` client (tunnels use it). Then pick the way that fits the machine: run `go version`.

- **No Go, or Go older than 1.21: download the nightly build** (a prebuilt binary, section 1a). Most machines that only
  use securl are in this group.
- **Go 1.21 or newer, for a developer who already builds Go programs: `go install` directly** (section 1b). securl needs
  Go 1.26.9; Go downloads that toolchain by itself, unless `GOTOOLCHAIN=local` is set.

### 1a. No Go toolchain: the nightly build


```
# macOS / Linux: <os> is darwin or linux, <arch> is arm64 or amd64
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS.sig
curl -LO https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I securl-release -n securl-release -s SHA256SUMS.sig < SHA256SUMS   # it must print "Good"
shasum -a 256 --ignore-missing -c SHA256SUMS      # sha256sum on Linux; it must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                    # nightly-<date>-<commit>
```

- Do not skip the checks. If `ssh-keygen` does not print `Good` or `shasum` does not print `OK` for your file, delete the
  download and do not run it. The first shows that `SHA256SUMS` was signed by the release key (`keys/securl-release.pub`,
  fingerprint `SHA256:QSdbV2Da6NA2sJZ7wFj08onoUQ1qJvQO8w+AZAYweQI`); the second that your archive is the one it lists. Take `allowed_signers` from the repository, as above,
  never from the release: a key that came with the files could be replaced with them.
- `--ignore-missing` is needed because you downloaded one archive and `SHA256SUMS` lists all of them.
- Use `uname -sm` to find the platform (`Darwin arm64` is `darwin` and `arm64`, `x86_64` is `amd64`, `aarch64` is `arm64`).
- Windows gets a `.zip` (`securl_windows_<arch>.zip`): check it with `certutil -hashfile securl_windows_<arch>.zip SHA256`
  and compare the line in `SHA256SUMS`, then unzip and put `securl.exe` on `PATH`.
- `SHA1SUMS` is published too. SHA-1 collisions can be made, so it only catches a damaged download. Rely on SHA-256 against
  tampering.
- The address is `releases/download/nightly`. GitHub's "latest release" link does not point at it, because the nightly is
  a pre-release.
- The nightly is the newest `master`, built each night when it has changed. It is not a tested release.

**On a Mac, the installer package** is an alternative to the archive above (the same binary, universal, installed as `/usr/local/bin/securl`):

```
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_macos.pkg
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS.sig
curl -LO https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I securl-release -n securl-release -s SHA256SUMS.sig < SHA256SUMS   # it must print "Good"
shasum -a 256 --ignore-missing -c SHA256SUMS                                                                 # it must print OK
sudo installer -pkg securl_macos.pkg -target /       # the user types their password; or they open the file
```

- Do the two checks first; do not install a package that fails either. The package is not signed by Apple, so opening it by
  double-click is stopped by macOS: `sudo installer -pkg` is not, and is the same installation. Do not run `sudo` yourself with a
  password you were given: the user runs it.
- It installs one file and **starts the daemon** for the user who installed it, locked: `securl daemon status` says so. It is one login
  agent for the machine (`/Library/LaunchAgents`), run by launchd as each user at login (`sudo securl daemon uninstall` removes it). Do not unlock it yourself: `securl unlock` sends the user a link, and the
  passphrase is theirs to type. See "Daemon" in section 4.
- **Check that it worked**: `securl daemon status` must say `running` and `login agent: installed and loaded`. If it says `not
  running`, or the agent is `installed, not loaded for you yet`, the installer could not start the daemon (nobody was at the
  console, or launchd refused). The package is still installed; the reason is in the installer's own log:
  `grep postinstall /var/log/install.log | tail`. Start it by hand with `sudo securl daemon install` (it loads the agent for the
  user who runs it), or log out and in. A daemon is never started by anything but the user's own session.
- If a command prints `the daemon is version X and this command is Y; they may answer differently`, the daemon is an older
  process than the binary on disk (it was started before an update and never restarted). Restart it:
  `launchctl kickstart -k gui/$(id -u)/com.leafai.securl`, then `securl unlock`.

### 1b. Go 1.21 or newer: go install

```
go install github.com/LeafAI/securl@latest
securl version                                    # securl 0.1.0 (it builds master as it is, with no nightly name)
```

The binary is `$(go env GOPATH)/bin/securl` (or `$GOBIN`); make sure that directory is on `PATH`. `@latest` is the newest
`master`, because the repository has no release tags. For a fixed version, give a commit: `go install
github.com/LeafAI/securl@<commit>`. If it answers `no matching versions` right after a push, the module proxy has not seen
the new commit yet: run it again in a minute, or use `GOPROXY=direct`.

### 1c. Linux packages (DEB / RPM)

For Debian/Ubuntu or Amazon Linux 2023, use `make deb` / `make rpm` from a trusted checkout of this repository.
These packages are **not published** by the nightly workflow. Building needs Git, Make and Go 1.21 or newer (with toolchain
download enabled); installing a finished package needs neither Go nor a build. `make` only builds, never installs.
Use the package manager for the target platform:

```bash
# Debian/Ubuntu: dpkg-deb is supplied by dpkg-dev; Docker can do the package assembly instead.
sudo apt install dpkg-dev
make deb VERSION=0.1.0 DEB_ARCH=amd64
sudo apt install ./dist/securl_0.1.0_amd64.deb

# Amazon Linux 2023:
sudo dnf install rpm-build
make rpm VERSION=0.1.0 RPM_ARCH=x86_64
sudo dnf install ./dist/securl-0.1.0-1.x86_64.rpm
```

Use `DEB_ARCH=arm64` / `RPM_ARCH=aarch64` for ARM64 or Graviton; RPM also accepts `amd64` / `arm64`.
`DIST` overrides the output directory and `RPM_RELEASE=2` bumps the RPM revision. The default version is
`0.1.0~git.<date>.<commit>` and the default architecture comes from `go env GOARCH`. Do not invent release URLs or
claim these locally built packages have the nightly release signature. Only run an installation with the user's
permission; do not change privileges, initialize a vault or enable lingering just to probe a deployment.

The packages install `/usr/bin/securl` and a **user-level** systemd unit. They start/restart daemons for active non-root
users with a session bus, and enable them for future logins. They do not set up credentials or unlock anything.
A fresh account reports `not_initialized`: ask the user to do section 3 in their own terminal, including `securl vault init`
and `securl config init`. After first-time setup or deliberate config changes, restart with
`systemctl --user restart securl` and use `securl unlock`. Existing vaults start locked; user data is preserved.

Run service diagnostics as the vault owner, **without sudo**:

```bash
systemctl --user status securl --no-pager
journalctl --user -u securl -n 50 --no-pager
securl daemon status
```

- `sudo systemctl status securl` looks for a system unit, which these packages do not install. `sudo systemctl --user`
  targets root, often failing with "No medium found". Use the person's own login session; if its user bus is missing,
  inspect `XDG_RUNTIME_DIR` and the user manager. Never borrow another user's socket or start the daemon as root.
- If the installer says "systemd is not running", it installed only the binary; users without a session bus also wait
  until login. With systemd, use `systemctl --user start securl` in that user's session; without it, a user-authorized
  supervisor can run `securl daemon`. `securl daemon install` / `uninstall` remain macOS-only.
- Stop only when asked: `systemctl --user stop securl`. Upgrade by installing a rebuilt package with a higher
  version/release; active daemons restart and lock, and pending human flows can be interrupted. To uninstall, use
  `sudo apt remove securl` / `sudo dnf remove securl`. Package files and service are removed, but user data is retained.
- Set a bounded `vault.idle_lock` (for example `30m`) with the user's approval; the default stays open until shutdown.
  Configuration is read at startup, so a changed setting needs an intentional daemon restart. Boot without login
  needs an administrator-approved lingering policy; the package does not change that policy.

### Both ways

- Make sure the directory the binary went into is on `PATH`, and that it is the only copy: if `securl version` is not what
  you just installed, an older copy comes first. `command -v securl` shows which one runs; remove the other (a `go install`
  copy is in `~/go/bin`, a download in `~/.local/bin`) or reorder `PATH`. A download says `nightly-<date>-<commit>`; a
  `go install` says `0.1.0`.
- An older copy that comes first is the usual reason that a new version "does not change anything": a command that behaves like
  the old one (it ignores a new flag, or `securl unlock` waits and nobody is sent a link) is run by that copy. `command -v
  securl` and `securl version` show it. The installer package puts the binary in `/usr/local/bin`, which often comes after
  `~/go/bin` in `PATH`: move the old one aside (`mv ~/go/bin/securl ~/go/bin/securl.old`) rather than delete it.

Register it with the MCP client (it speaks MCP over stdio):

```
claude mcp add securl -- securl
```

For any other client, add a stdio server whose command is `securl`. To use another config file, pass `-config <file>`.
For a Linux package, an absolute path avoids an older Go/archive copy earlier on `PATH`:

```json
{
  "mcpServers": {
    "securl": { "command": "/usr/bin/securl", "args": [] }
  }
}
```

**MCP is not the CLI daemon.** `securl` / `securl serve` starts its own stdio MCP server and does not attach to the
CLI daemon. Keep that process/connection alive for the whole vault-unlock, site-login and tool-call workflow.
Unlocking one does not unlock the other.

For contexts, check `contexts server list` first, then add only if absent:

```bash
contexts server add securl -- /usr/bin/securl
contexts status
contexts exec securl site_list '{}'
```

`contexts exec` creates a fresh connection and starts a fresh securl process for this stdio entry each time. It closes
that server when done, including pending login tunnels. Do not call `vault_unlock` through one `exec` and expect the
next `exec` to retain its unlocked vault or pending login. For stateful operations use a persistent contexts
gateway/client connection, or use the CLI against its daemon. Inspect JSON `isError`, not just the contexts exit code;
a tool failure can exit 0. Never bypass a gateway's authorization or tool-deny policy by switching to direct `exec`.

Docker is another alternative: see the README ("Docker"). It keeps config and the vault in a volume.

## 2. Update

Update the way you installed, so that the new binary replaces the old one and is the only copy.

- **Downloaded (1a):** run the same commands again, including the check.

```
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/securl_<os>_<arch>.tar.gz
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS
curl -LO https://github.com/LeafAI/securl/releases/download/nightly/SHA256SUMS.sig
curl -LO https://raw.githubusercontent.com/LeafAI/securl/master/keys/allowed_signers
ssh-keygen -Y verify -f allowed_signers -I securl-release -n securl-release -s SHA256SUMS.sig < SHA256SUMS   # it must print "Good"
shasum -a 256 --ignore-missing -c SHA256SUMS      # it must print OK
tar -xzf securl_<os>_<arch>.tar.gz
install -m 0755 securl_*_<os>_<arch>/securl ~/.local/bin/securl
securl version                                    # the new nightly-<date>-<commit>
```

- **Mac package:** run the package commands of section 1a again (`securl_macos.pkg`, the same checks, `sudo installer -pkg
  securl_macos.pkg -target /`). It replaces `/usr/local/bin/securl` and **restarts the running daemon** with the new binary, which
  starts **locked**: `securl unlock` sends the user a link. Sessions are in the vault, so logins survive. Then
  `securl daemon status` must say `running` with the new version; if it does not, see "Check that it worked" above.
- **Linux package (1c):** rebuild from the intended source with a higher `VERSION` (or higher `RPM_RELEASE` for the
  same RPM version), then use `sudo apt install ./dist/<package>.deb` / `sudo dnf install ./dist/<package>.rpm`.
  The package restarts active user daemons, which start locked again; pending login flows are interrupted. Check
  `systemctl --user status securl --no-pager` and `securl daemon status` without sudo. It does not overwrite user data.
- **Go (1b):** run `go install github.com/LeafAI/securl@latest` again. It does not change `securl version` (`0.1.0`), so to
  know it moved, look at the build: in `go version -m $(command -v securl)` the `mod` line ends with the commit it was
  built from (`v0.0.0-<time>-<commit>`).

Then restart the MCP server process (the client or gateway starts it again; it is a separate process from the daemon, and
keeps running the old binary until it is restarted). **A restart locks the vault**: the user types
the passphrase once more (section 4). Sessions are kept in the vault, so logins survive the restart.

A new build can change the login page (it is published separately, from `master`). If logins start failing right after an
update, check that the page is current: `securl doctor` prints the page address.

## 3. Set up (once)

Do these in a terminal, in this order. They ask the user questions, so the user types the answers.

```
securl vault init                      # passphrase, at least 16 characters, typed twice
securl config init                     # DingTalk robot and safety settings; can send a test message
securl config site add https://gitlab.corp.example   # one per site: detects the driver, asks its questions
securl config db add                   # one per PostgreSQL / MySQL database (dev, test or staging), if agents will run SQL
securl doctor                          # everything should be [ok]; the vault shows as locked, which is normal
```

- **The vault passphrase cannot be recovered.** Tell the user to keep it in a password manager.
- `securl vault init` also moves anything an earlier version kept in plain files (TOTP secrets, stored sessions, keys) into
  the vault and removes the files.
- `securl config init` needs a DingTalk custom robot (group settings, bots, add bot, custom). Use the signing secret
  (`dingtalk.secret`) or a keyword (`dingtalk.keyword`). Check with `securl doctor -send`.
- No DingTalk robot (one user on their own machine): `securl config set security.link_via_agent true`. Login and unlock links
  are then returned to you instead of being sent; see "Link in the answer" in section 4. A configured robot always wins.
- Check the tunnels from the user's network: `securl doctor -tunnel`. Free providers come and go; put the ones that pass
  first with `securl config set tunnel.order pinggy,localhost.run`.
- Check each site before the first login (needs no credentials): `securl doctor -site https://gitlab.corp.example`.
- A site whose host name does not hint at the product needs an alias: `securl config set aliases.es.corp.example kibana`.
  A site served under a path needs a root: `securl config set roots.elk.corp.example https://elk.corp.example/kibana`.
- To limit what an agent may reach: `securl config set security.allowed_hosts "*.corp.example"`.
- A site that is not built in: `securl config site custom` asks for the login form step by step.
- **List the databases of every target.** Without a list of databases, any database name an agent gives is tried: the account
  decides what it can reach. With a list, any other name is refused (`database_not_allowed`) before a connection is made.
  `securl config db add` asks for them.
- A database: `securl config db add` asks for the name, engine, host, environment (dev, test or staging), which databases
  and whether the agent may change data. It never asks for a database account: a person types that when a session is
  opened. `securl config db list` shows what exists; `securl config db remove <name>` forgets one. Do not hand-write the
  `databases:` section for the user, and never put a username or a password in it.
- `securl config show` prints the configuration with secrets masked. `securl config set` with no arguments lists every
  setting. Each change is checked before it is saved and the previous file is kept as `config.yaml.bak`.

Optional hardening: `securl config totp init` makes two authenticator codes. The unlock code hides the site and tunnel
address in the DingTalk link until the user types it; the sealing code (30 s) is mixed into the key that seals what is
typed. 1Password supports periods up to 10 minutes. Check with `securl config totp status`.

## 4. Use it: the order of tool calls

The server starts **locked**. Follow this order and do not skip a step.

1. `vault_status`. It needs no unlock and shows no secret. `state` is `not_initialized`, `locked` or `unlocked`. While the vault
   is locked only `vault_status`, `vault_unlock`, `site_list` and `db_targets` answer (`db_targets` lists the targets without
   `has_session`: whether an account exists is the vault's to say); everything else answers `vault_locked`.
   - `not_initialized`: tell the user to run `securl vault init`. Nothing else works until then.
2. `vault_unlock` when it is `locked`. The user gets a DingTalk link and types the passphrase on that page. (With no
   DingTalk robot and `security.link_via_agent`, the `pending` answer carries the link instead: see "Link in the answer".) The call waits
   up to `max_block_seconds` and may return `pending`: call `vault_unlock` again (with `unlock_id` set to the returned
   `login_id`, or with no argument: it joins the same unlock and sends no second link). Repeat until `unlocked`.
3. `site_list` shows which sites securl can handle and whether each needs a login; `session_list` shows which already have
   a session. Reuse them: a person is asked only when none is valid.
4. `session_open` with `url` (any URL on the site) when there is none. Give a short `reason`: it is shown to the person.
   It returns `pending` with a `login_id` while the person types; call `session_wait` with that id until `status` is `ok`.
   Some sites need a second round (a TOTP code): `waiting_for` says which, and the person gets another link.
   The result says that a session exists (`auth` is `cookie`, `bearer` or `none`), never what it contains.
5. `request` to use the site. Give `url`, `method` and `path`:

```json
{"url": "https://gitlab.corp.example", "method": "GET", "path": "/api/v4/projects", "query": {"per_page": 20}}
```

   - `path` is absolute and has no query string or host; use `query`. Bodies are `json`, `form`, `text` or `base64`.
   - Never put a `Cookie` or `Authorization` header in it: it is refused. The session's credentials are added for you.
   - Only the session's own site can be reached. A redirect to another site is returned, not followed. Set
     `follow_redirects` to follow redirects that stay on the same site.
   - Big answers are cut at `max_response_bytes` (default 262144, at most 1048576); `truncated` and `total_bytes` say so.
     Ask for less (`per_page`, `fields`, a narrower path) instead of raising the limit.
   - `redactions` counts the secret values removed from the answer. Treat any `[REDACTED]` as intended.
   - Archery is not reachable with `request` (`request_not_allowed`): use the `archery_*` tools below. Only the owner
     can lift this (`security.allow_archery_requests`); do not look for another way around it.
   - RocketMQ Dashboard has a request policy: only `GET` of `.query` paths, and nothing under `/message/`,
     `/messageTrace/` or `/dlqMessage/` (message bodies; the owner opens them with `site_options.rocketmq.allow_message_body`).
     Anything else answers `request_not_allowed` and is never sent; do not look for another way around it.
6. A site that needs no login (SkyWalking) works with `request` directly; `session_open` just confirms `auth: none`.

When `request` answers `401` or `session_expired`, the session ended: call `session_open` with `force_refresh: true`.
securl never logs in again by itself, so a person is asked each time and you cannot loop on it.

### Link in the answer

With `security.link_via_agent` on and no DingTalk robot, a `pending` answer of `session_open`, `session_wait` or `vault_unlock`
carries `link`, `key_code` and `instruction`. Nothing was sent to anybody, so you are the only way the user gets the link:

- Show the `link` to the user exactly as it is, say which site (or the vault) it is for and why you asked, and give them the
  `key_code`: it must equal the code the page shows, and if it does not they must type nothing.
- Then call the tool named in `next_tool` (`session_wait`, or `vault_unlock` with `unlock_id`). It waits for the user. A second
  step (a TOTP) comes back as a new `pending` answer with a new link.
- Never open the link yourself, change it, shorten it, or describe the request as anything other than what it is. Never ask the
  user to type a credential anywhere but on that page. Never put the link anywhere but in your reply to the user.
- A `pending` answer with no `link` means nothing new: keep waiting. If the user lost the link, call `session_wait` again: it
  answers with the same link.

### Closing sessions

Answers you will see: `pending` (a person has not typed `DELETE` yet), `closed` with `removed` (done; `0` when there was nothing to
close, and nobody was asked), `user_rejected` (they said no; nothing was closed), `bad_confirmation` (the wrong word three times; nothing
was closed), `rate_limited` (they said no a moment ago; nobody is asked again for now) and `close_pending` (another confirmation is
open for other sessions; wait for it).

`session_close` (a `url`, or `all`) closes nothing by itself. The user gets a page that names every session that would go and asks
them to type `DELETE`; until they do, the answer is `pending` with a `login_id`. Call it again with that id as `close_id` and the
**same** `url` or `all`. A database account (`db://...`) is a password the user typed and cannot be recovered, so:

- Close a session only when the user told you to, and say which. Never to "clean up", to retry a login (use `force_refresh`), or
  because a command failed.
- Prefer one URL to `all`. Never use `all` unless the user asked for every session to go.
- `user_rejected` means they said no: stop, and do not ask again unless they tell you to. There is no argument that confirms for
  them, and none will be honoured.
- With `link_via_agent` the `pending` answer carries the link: show it as described above.

### Command line

Every tool is also a command, for the user's terminal or a script, and the commands are what to use when you have a shell and
no MCP connection (or when the user asks for a command to run). **Prefer the MCP tools when you have them.** Nothing here
works differently from the tool of the same name: the same checks, the same limits, the same audit trail, and no answer ever
carries a credential. With no arguments (or only `-config`), `securl` is still the MCP server on standard input and output.

- **Never ask the user for the vault passphrase, and never put it in a command, a pipe or the environment.** In a terminal the
  command asks for it itself, in a process of its own. With a daemon, or with no terminal (your own shell), nothing is typed: the
  command opens the vault with a link for the user (DingTalk, or on standard error with `security.link_via_agent`) and waits. Tell
  the user to watch for it.
- The name of a command is the name of its tool: `session_open` is `securl session open`, `archery_run_sql` is `securl archery
  run-sql`. `securl <group> <command> --help` prints its flags; **a flag is the name of the tool's field with `-` for `_`**
  (`max_block_seconds` is `--max-block-seconds`).

#### Command line reference

| The tool | The command |
|---|---|
| `session_open` | `securl session open` |
| `session_wait` | `securl session wait` |
| `session_list` | `securl session list` |
| `session_close` | `securl session close` |
| `site_list` | `securl site list` |
| `request` | `securl request` |
| `db_targets` | `securl db targets` |
| `db_query` | `securl db query` |
| `db_exec` | `securl db exec` |
| `archery_instances` | `securl archery instances` |
| `archery_groups` | `securl archery groups` |
| `archery_query` | `securl archery query` |
| `archery_run_sql` | `securl archery run-sql` |
| `archery_wait` | `securl archery wait` |
| `archery_workflow_status` | `securl archery workflow-status` |
| `archery_cancel` | `securl archery cancel` |

`vault_status` and `vault_unlock` are not commands: `securl vault status` (text) and `securl unlock` do their work.

**Sessions and sites**

- `securl session open --url <url> [--site <driver>] [--reason <text>] [--force-refresh] [--wait=false] [--max-block-seconds <n>]`
  opens a session; a person types the credential on a page. `--wait=false` returns the pending answer at once (exit `4`) instead
  of waiting. A database is `--url db://<target>`.
- `securl session wait --login-id <id> [--max-block-seconds <n>]` keeps waiting for a login that answered pending.
- `securl session list` shows which sessions exist. Names and times, never a credential. It needs the vault open.
- `securl session close (--url <url> | --all) [--reason <text>] [--close-id <id>] [--max-block-seconds <n>]` asks the person to
  confirm, and waits for them (see "Closing sessions"). `--url` and `--all` are exclusive. Never use `--all` unless the user asked
  for every session to go.
- `securl site list` lists the websites securl can handle. It needs no vault.

**Requests**

- `securl request --url <url> --method <GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS> --path </absolute/path> [--query name=value]...
  [--header name=value]... [--timeout-seconds <n>] [--max-response-bytes <n>] [--follow-redirects]` and **one** body flag:
  `--json <json>`, `--form name=value` (given again for more fields), `--text <text>` or `--base64 <base64>`. The path has no query
  string and no host: use `--query`. A name given twice becomes a list (`--query tag=a --query tag=b`). `Cookie`, `Authorization`
  and `Host` are refused as `--header`. The answer holds the status, the headers and the body, scrubbed.

**Databases** (PostgreSQL, MySQL; not production)

- `securl db targets` lists the targets and whether each has an account.
- `securl db query --target <name> --sql <statement> [--database <db>] [--limit <n>]` runs one read-only statement.
- `securl db exec --target <name> --sql <statement> --reason <text> [--database <db>]` changes data, only on a `read_write`
  target; `--reason` is required and the team reads it in DingTalk afterwards.

**Archery** (each takes `--url <archery url>`, and `--site <driver>` when the host name does not say Archery)

- `securl archery instances --url <url> [--site <driver>] [--instance <name>]` lists instances, and with `--instance` that
  instance's databases.
- `securl archery groups --url <url> [--site <driver>] [--group <name>]` lists resource groups, and with `--group` that group's
  writable instances.
- `securl archery query --url <url> [--site <driver>] --instance <name> --database <db> --sql <statement> [--schema <s>]
  [--limit <n>]` runs one read-only statement, no approval.
- `securl archery run-sql --url <url> [--site <driver>] --instance <name> --database <db> --resource-group <group> --sql
  <statement> --title <text> [--remark <text>] [--backup] [--wait=false] [--approval-timeout-seconds <n>]
  [--max-block-seconds <n>]` submits SQL for approval; it is a real workflow that approvers are told about, so use it only for
  what the user asked for.
- `securl archery workflow-status --url <url> [--site <driver>] --workflow-id <id>` reads a workflow's state.
- `securl archery wait --url <url> [--site <driver>] --workflow-id <id> [--max-block-seconds <n>]` waits for a workflow; it runs it
  once when it is approved. Safe to repeat.
- `securl archery cancel --url <url> [--site <driver>] --workflow-id <id> [--reason <text>]` aborts a workflow that has not started
  executing.
- With no Archery session, `instances`, `groups` and `query` wait for the person's login and then print **their own answer**.

**Giving a value**

- A text flag takes the text itself, `-` for standard input, or `@<file>` for a file's contents (`--sql @query.sql`,
  `--sql -`). `@@x` is the text `@x`. One trailing newline is dropped.
- `--json` takes a JSON value. `--query`, `--header` and `--form` take `name=value` and are given once per pair.
- A flag takes its value as the next word or after `=` (`--limit 5`, `--limit=5`). A boolean is `--flag` or `--flag=false`:
  `--wait false` is not a value, it is `--wait` followed by a stray word, which is a usage error.
- `-config <file>` and `--no-daemon` may stand anywhere in the command. The first uses another configuration file; the second
  runs the command alone even when a daemon is running (an unlocked daemon is the whole point of one: do not use it to get round it).

**What comes back**

- The answer is JSON on **standard output** and nothing else is. Progress, the waiting-for-a-person line and any link go to
  **standard error**: read the answer from the first and show the second to the user.
- The exit code says what kind of end it was:
  - `0`: the tool answered.
  - `1`: the tool answered with an error. Its JSON, with `code` and `hint`, is on standard output, and the table in section 6 applies.
  - `2`: a usage error: the command line was wrong and nothing ran.
  - `3`: setup: the configuration or the vault could not be set up, or there is no daemon for `securl unlock`.
  - `4`: pending: a person has not answered yet. The answer says how to continue (`securl session wait --login-id ...`,
    `securl archery wait --workflow-id ...`).
- Waiting commands wait by themselves. Do not loop on exit `4`: it is a person, not a fault.

**Commands that are not tools**

- `securl vault init`, `securl vault status` (never asks for the passphrase), `securl vault passwd` and `securl vault migrate`
  (the vault); `securl unlock` (open a running daemon's vault by link); `securl daemon`, `securl daemon status`, `securl daemon install` and `securl daemon uninstall`; `securl doctor [-send] [-tunnel]
  [-site <url>]`; `securl config` (section 3), which also has `securl config get <key>`, `securl config unset <key>`,
  `securl config path`, `securl config site list` and `securl config site remove <host|name>`; `securl page [dir]` (write the login page to a directory, to host it yourself),
  `securl serve` (the MCP server, by name) and `securl version`. **Do not run `securl vault init`, `securl vault passwd` or `sudo
  securl daemon install` yourself:** the first two are the user's to type a new passphrase into, and the third needs root.

### Daemon

`securl daemon` is a long-running server that the commands share: the vault is unlocked once, and a session one command makes
is there for the next. `securl daemon status` says whether one runs. Commands use it on their own; `--no-daemon` runs one alone.

- A locked daemon is opened by link (DingTalk, or `security.link_via_agent`): the user types the passphrase on the page.
  `securl unlock` asks for that and waits; run it when a command answered `vault_locked` and the user is at their desk.
  **Never pass a passphrase to a command to open a daemon: there is no way to, by design.**
- Do not start a daemon on your own, and do not run `securl daemon install`: on a Mac it writes `/Library/LaunchAgents` and needs
  root, which is the user's to give. A daemon keeps the user's vault open for every process of their account, you included. If the
  user wants one and the package was not used, tell them to run `securl daemon`, or `sudo securl daemon install` to have launchd run
  one for every user at login, and to set `vault.idle_lock` first. On Linux with a DEB/RPM installation, use the user-level
  systemd unit from section 1c instead; do not use the macOS installer commands.

### Archery SQL

On the command line these are `securl archery instances|groups|query|run-sql|wait|workflow-status|cancel`. With no Archery
session the command waits for the person's login (a link), then prints **its own answer**, not the login's; exit `0` means the
answer is real. A command that answers `pending` and exits `4` is waiting for an approval: continue with `securl archery wait`.

For metadata-only discovery with a running CLI daemon:

```bash
securl daemon status
securl unlock
securl session list
securl archery instances --url https://archery.corp.example
securl archery instances --url https://archery.corp.example --instance '<instance>'
```

Replace the example URL and `<instance>` with the actual URL and an instance returned by the first call. Angle-bracket
placeholders are not literal shell syntax. The second instance call lists its databases; do not assume database names
match instance names. Reuse an existing valid site session; if none exists, the Archery command asks the person to log
in by link, then returns the requested list. Do not run SQL or submit a workflow merely to list databases. Direct
non-production targets are a different list, returned by `securl db targets`.

`archery_instances` and `archery_groups` list what the user may use. `archery_query` runs one read-only statement with no
approval (`url`, `instance`, `database`, `sql`; `limit` caps the rows). To change data, `archery_run_sql` submits a
workflow, notifies the approvers and waits: pass `url`, `instance`, `database`, `sql` and a short `title`
(at most 50 characters), plus `resource_group` unless `archery.default_group` is set. If approval takes longer than
`max_block_seconds` it returns `pending` with a `workflow_id`; call `archery_wait` with it. `archery_workflow_status`
reads a workflow and `archery_cancel` aborts one. Never submit SQL the user did not ask for: a person approves it, but
the title and statement are shown to them from what you wrote.

### Databases (PostgreSQL, MySQL; not production)

`db_targets` lists what the owner made reachable: `name`, `driver`, `environment`, `mode` (`read_only` or `read_write`),
`allow_ddl`, `databases` and `has_session`. You choose a `target` by name; you never give a host or a password.

1. No session (`has_session: false`, or `no_session`): `session_open` with `url: "db://<target>"` and a `reason`. A person
   types the database account on the usual page. Wait with `session_wait`, as for any login.
2. `db_query` with `target`, `sql`, and `database` unless the target lists exactly one. One statement that only reads
   (`SELECT`, `SHOW`, `EXPLAIN`, `DESCRIBE`, `WITH ... SELECT`). Ask for what you need (`limit`, `WHERE`, columns):
   `truncated: true` means rows or bytes were left out.
3. `db_exec` changes data, only on a `read_write` target, with a `reason` the team will read in DingTalk after the
   change. Everything runs in one transaction; a change that touches more than `max_changed_rows` is rolled back
   (`too_many_rows`), so narrow the `WHERE`. DDL needs `allow_ddl` on the target (`ddl_disabled`).
4. `session_expired` means the database stopped accepting the saved account: `session_open` again with `force_refresh`.
   `session_close` with the same `db://` URL forgets the account, after the user confirms (see below).

Never use a database target for production: the owner cannot list one, and Archery (`archery_run_sql`) is where a person
approves each change there. Do not look for another way to reach a host you were not given.

## 5. Work efficiently

- **Check before asking.** `vault_status`, then `session_list`. A session is reused, so most calls need no person at all.
- **Do not poll.** `vault_unlock`, `session_open`, `session_wait` and `archery_wait` already wait up to
  `max_block_seconds`. A call that returns `pending` is normal: call the `next_tool` it names with the id it gives.
  Two calls in a row to `session_open` for the same site join one login and send one message.
- **Do not loop on a refusal.** `user_rejected` means the person pressed Reject: do not retry unless they ask. A rejected
  site is paused for 10 minutes, and people are asked at most 6 times per site and 20 per hour (`rate_limited`).
- **Batch your reads.** Prefer one `request` with a list endpoint and `fields`/`per_page` over many small ones.
- **Keep the person's time in mind.** A login is a message in a group chat. Say in `reason` what for, once.
- **If the client times out** (many abort a tool call after 30 s), lower the wait: `securl config set mcp.max_block_seconds 25`.
- **The vault stays open until the process ends.** To lock it again after a period of no use:
  `securl config set vault.idle_lock 1h`.

## 6. When something fails

| Answer | What it means | What to do |
|---|---|---|
| `vault_locked` | the vault is not open | call `vault_unlock` |
| `vault_not_initialized` | no vault yet | the user runs `securl vault init` |
| `no_session` | no valid session for that site | call `session_open` |
| `session_expired` or a `401` | the session ended | `session_open` with `force_refresh: true` |
| `human_timeout` | nobody finished within 10 minutes | ask again; check the DingTalk group |
| `user_rejected` | the person pressed Reject | do not retry unless asked |
| `bad_credentials` | the site refused what was typed | retry carefully; accounts can lock |
| `rate_limited` | people were asked too often, or wrong passphrases are being slowed, or a person just declined to close sessions | wait for the retry time |
| `close_pending` | a confirmation to close other sessions is already open | wait for the person to answer it; do not ask again |
| `bad_confirmation` | the confirmation word was wrong three times; nothing was closed | ask the user whether they want the sessions closed |
| `host_not_allowed` | outside `security.allowed_hosts`, or one of this machine's own addresses | ask the user to change the setting; do not try other spellings |
| `tunnel_unavailable` | no tunnel carried traffic | the user runs `securl doctor -tunnel` |
| `notify_failed` | DingTalk refused the message, or there is no webhook | the user runs `securl doctor -send`, or sets `security.link_via_agent true` if there is no robot |
| `site_unreachable` | the site could not be contacted | network, VPN or the `roots` path |
| `unknown_target` / `database_not_allowed` | a database or target name that is not configured | `db_targets`; use a name it lists |
| `target_read_only` / `not_read_only` | a change on a read-only target, or a `db_query` that is not one plain read | use `db_exec` on a `read_write` target |
| `too_many_rows` / `statement_timeout` | the change was rolled back, or the statement ran too long | narrow the statement |
| `invalid_argument` | a wrong or extra argument | read the message; a passphrase argument is always refused |

`securl doctor` is the first thing to run for anything about setup. It never asks for the passphrase.

## 7. What securl does not do

- It never shows the agent a credential, and it cannot be made to: no tool returns one and no tool accepts a passphrase.
- It does not log in without a person. There is no automatic re-login and no token renewal.
- It does not reach the machine it runs on (loopback, link-local, the cloud metadata address) unless
  `security.allow_local_addresses` is on, and it does not follow a redirect to another site.
- The response scrubber is a safety net, not a proof: a site that transforms a secret in an unusual way before echoing it
  can get past it. Do not ask a site to echo the session back.
- Not supported: GitLab reCAPTCHA, WebAuthn-only accounts, Jenkins 2FA plugins.

More: `README.md` (overview and configuration), `MCP_TOOLS.md` (every tool's schema), `docs/OPERATING.md` (operator
guide), `DESIGN.md` (threat model).
