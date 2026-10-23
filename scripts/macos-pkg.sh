#!/usr/bin/env bash
# Builds the macOS installer package of securl from the two darwin builds that scripts/release.sh makes.
#
#   scripts/macos-pkg.sh <version> <arm64-binary> <amd64-binary> <output.pkg>
#
# Needs macOS: pkgbuild, productbuild and lipo are Apple's, and exist nowhere else.
#
# What the package is:
#   - one universal binary (lipo of the two), installed as /usr/local/bin/securl. /usr/local/bin is on the default PATH of every
#     Mac, so nothing has to be added to a profile;
#   - rooted at /usr/local/bin with the one file in it, so the package owns that file and no directory above it: on a Mac with
#     Homebrew, /usr/local/bin belongs to the user, and a package that listed it could take it away from them;
#   - installed for the whole machine only (the Installer offers no other choice).
#
# What it does at the end of the installation: it starts `securl daemon` for the person who ran the Installer. The agent is the
# machine's: one plist in /Library/LaunchAgents, which launchd loads for every user at graphical login, as that user, in that user's
# session. The postinstall script runs as root, which is what writing that directory needs, so it runs `securl daemon install -uid <uid>`
# itself; with -uid the agent is also loaded into the login session of that user now, so the daemon is running when the Installer is
# done and not only after the next login. The uid is the owner of /dev/console (never root, never the login window, never a name that
# is not an account); root's own session is never used, because a daemon there would run as root. The plist names no user and no path
# under anybody's home. If there is no one at the console, the agent is still put in place and each user gets a daemon at their next
# login; if that fails, the package is still installed (the script exits 0) and says why and what to run by hand. The daemon starts
# locked: opening its vault is `securl unlock`, by a link, and the passphrase is never typed into the Installer.
#
# --test-hooks builds a variant whose script also reads SECURL_TEST_* variables: a file to take the console's owner from instead of
# /dev/console, a name to use when there is no such file to make (no owner, root, the login window), and a program to run in place of
# the installed securl. It is for the tests, which must not write /Library/LaunchAgents or start anything in a real login session. The package that is shipped is built without
# it and has no such variable in it: a script that runs as root must not take the choice of account, or of program, from an
# environment.
#
# It is not signed: that needs a Developer ID Installer certificate, which is the publisher's, not something a script can
# make up. Without it the first double-click is stopped by Gatekeeper (right-click, Open). The signature of SHA256SUMS
# (scripts/sign-release.sh) shows who published the file; it is not something macOS looks at.
set -euo pipefail

usage="usage: macos-pkg.sh [--test-hooks] <version> <arm64-binary> <amd64-binary> <output.pkg>"
hooks=0
if [ "${1:-}" = "--test-hooks" ]; then hooks=1; shift; fi
version="${1:?$usage}"
arm="${2:?$usage}"
amd="${3:?$usage}"
out="${4:?$usage}"

die() { echo "macos-pkg.sh: $*" >&2; exit 1; }
[[ "$version" =~ ^nightly-[0-9]{8}-[0-9a-f]{7,40}$ ]] || die "bad version '$version': it is nightly-<date>-<commit>, as release.sh names a build"
for t in pkgbuild productbuild lipo pkgutil; do command -v "$t" >/dev/null 2>&1 || die "$t is required (this script runs on macOS)"; done
[ -f "$arm" ] || die "$arm is not a file"
[ -f "$amd" ] || die "$amd is not a file"
[ "$(cd "$(dirname "$arm")" && pwd)/$(basename "$arm")" != "$(cd "$(dirname "$amd")" && pwd)/$(basename "$amd")" ] || die "the two binaries are the same file"
# An existing output is replaced only if it is an earlier package of this script: never one of the inputs, and never a file that is
# not a package (a mistyped argument must not overwrite a binary or a document).
if [ -e "$out" ]; then
  [ -f "$out" ] || die "$out exists and is not a file"
  # `pwd -P` resolves the directories of a path, not a link that is the file itself: that one is followed here, so that a link to an
  # input is the input.
  real() {
    local p="$1" i=0
    while [ -L "$p" ] && [ "$i" -lt 40 ]; do
      local t; t="$(readlink "$p")"
      case "$t" in /*) p="$t" ;; *) p="$(dirname "$p")/$t" ;; esac
      i=$((i + 1))
    done
    echo "$(cd "$(dirname "$p")" && pwd -P)/$(basename "$p")"
  }
  same() { [ "$(real "$1")" = "$(real "$2")" ]; }
  if same "$out" "$arm" || same "$out" "$amd"; then die "the output is one of the inputs: $out"; fi
  case "$(head -c 4 "$out" 2>/dev/null)" in xar!) ;; *) die "$out exists and is not an installer package: it is not overwritten" ;; esac
fi
outdir="$(dirname "$out")"
mkdir -p "$outdir" 2>/dev/null || die "cannot make $outdir"
[ -d "$outdir" ] || die "$outdir is not a directory"
case "$(lipo -archs "$arm" 2>/dev/null)" in arm64) ;; *) die "$arm is not an arm64 binary" ;; esac
case "$(lipo -archs "$amd" 2>/dev/null)" in x86_64) ;; *) die "$amd is not an x86_64 binary" ;; esac

work="$(mktemp -d "${TMPDIR:-/tmp}/securl-pkg.XXXXXX")"
trap 'rm -rf "$work"' EXIT
root="$work/root"
scripts="$work/scripts"
mkdir -p "$root" "$scripts"

lipo -create -output "$root/securl" "$arm" "$amd"
chmod 755 "$root/securl"
# The payload records the time of each file, so two builds of the same binaries a second apart would differ. A fixed time, the one
# release.sh gives the files of its archives, makes the same inputs give the same payload.
touch -t 200001010000.00 "$root/securl" "$root"

cat > "$scripts/postinstall" <<'POST'
#!/bin/sh
# Runs as root at the end of the installation (see scripts/macos-pkg.sh). It makes the login agent of the machine and loads it into the
# session of the person at the console, with `securl daemon install -uid`. It always exits 0: the binary is installed either way.
PATH=/usr/bin:/bin:/usr/sbin:/sbin
export PATH
SECURL=/usr/local/bin/securl
#@TEST-HOOKS-BEGIN
SECURL="${SECURL_TEST_SECURL-$SECURL}"
#@TEST-HOOKS-END

say() { printf '%s\n' "$*"; }

# The user at the console: the owner of /dev/console. Not $USER, not $SUDO_USER, not $HOME: as root, those are root's or are chosen
# by whoever started the Installer.
console=/dev/console
#@TEST-HOOKS-BEGIN
console="${SECURL_TEST_CONSOLE_FILE-$console}"
#@TEST-HOOKS-END
who="$(stat -f %Su "$console" 2>/dev/null)"
#@TEST-HOOKS-BEGIN
who="${SECURL_TEST_CONSOLE_USER-$who}"
#@TEST-HOOKS-END

manual() {
  say ""
  say "To do it yourself, in a terminal:   sudo securl daemon install"
}

finish() {
  say ""
  say "securl is installed as /usr/local/bin/securl."
  say ""
  say "First time:"
  say "  securl vault init      make the vault that holds every secret (once; you choose the passphrase)"
  say "  securl config init     the DingTalk robot and the safety settings"
  say "  securl unlock          the daemon starts locked: you are sent a link and type the passphrase on its page"
  say "Check:   securl daemon status        Stop and remove:   sudo securl daemon uninstall"
  exit 0
}

# Nobody to load it for now: the agent is still put in place, and launchd loads it for each user at their next login.
nobody() {
  say "$1"
  if "$SECURL" daemon install; then
    say ""
    say "The daemon will start for each user the next time they log in."
  else
    say ""
    say "Could not make the login agent."
    manual
  fi
  finish
}

case "$who" in
  ""|root|loginwindow|_*)
    nobody "No user is logged in at the console, so the daemon was not started for anyone now."
    ;;
esac
uid="$(id -u "$who" 2>/dev/null)"
case "$uid" in
  ""|0|*[!0-9]*)
    nobody "'$who' is not an account the daemon can be started for now."
    ;;
esac

# The agent is the machine's and is written by root, which this is. It is loaded into the session of the user at the console too, so
# that their daemon is running now. What securl says is shown as it is: if it fails, the reason is the person's to read.
if "$SECURL" daemon install -uid "$uid"; then
  say ""
  say "The daemon is running for $who, and starts for every user when they log in."
else
  say ""
  say "Could not start the daemon for $who."
  manual
fi
finish
POST
if [ "$hooks" = 1 ]; then
  # the markers are comments: they stay, and the lines between them stay
  :
else
  # the shipped script: the lines between the markers, and the markers, are removed
  awk 'BEGIN{skip=0} /^#@TEST-HOOKS-BEGIN/{skip=1; next} /^#@TEST-HOOKS-END/{skip=0; next} skip==0{print}' "$scripts/postinstall" > "$scripts/postinstall.shipped"
  mv "$scripts/postinstall.shipped" "$scripts/postinstall"
fi
chmod 755 "$scripts/postinstall"
touch -t 200001010000.00 "$scripts/postinstall" "$scripts"

# The Installer reads a package version as dotted numbers, and a commit is not a number: the date is the version (2026.10.12), and
# the exact build is in the title and in the file name, which carry nightly-<date>-<commit> whole.
date="${version#nightly-}"; date="${date%%-*}"
pkgversion="${date:0:4}.$((10#${date:4:2})).$((10#${date:6:2}))"

component="$work/securl-component.pkg"
COPYFILE_DISABLE=1 pkgbuild --root "$root" --identifier com.leafai.securl --version "$pkgversion" \
  --install-location /usr/local/bin --scripts "$scripts" --ownership recommended "$component" >/dev/null

cat > "$work/Distribution" <<DIST
<?xml version="1.0" encoding="utf-8"?>
<installer-gui-script minSpecVersion="2">
  <title>securl ${version}</title>
  <domains enable_localSystem="true" enable_currentUserHome="false" enable_anywhere="false"/>
  <options customize="never" require-scripts="false" hostArchitectures="arm64,x86_64"/>
  <pkg-ref id="com.leafai.securl"/>
  <choices-outline><line choice="default"><line choice="com.leafai.securl"/></line></choices-outline>
  <choice id="default"/>
  <choice id="com.leafai.securl" visible="false"><pkg-ref id="com.leafai.securl"/></choice>
  <pkg-ref id="com.leafai.securl" version="${pkgversion}" onConclusion="none">securl-component.pkg</pkg-ref>
</installer-gui-script>
DIST

rm -f "$out"
productbuild --distribution "$work/Distribution" --package-path "$work" "$out" >/dev/null
[ -s "$out" ] || die "no package was written"
pkgutil --check-signature "$out" >/dev/null 2>&1 || true
echo "built $out (universal, installs /usr/local/bin/securl, signed: no)"
