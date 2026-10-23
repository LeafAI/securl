#!/usr/bin/env bash
# Adds files that were made after release.sh to SHA1SUMS and SHA256SUMS, so that the signature of SHA256SUMS covers them.
#
#   scripts/add-to-sums.sh dist securl_nightly-20261012-1a2b3c4_macos.pkg securl_macos.pkg
#
# release.sh writes the sums for the archives it makes. A file made by a later step (the macOS package, which needs a Mac) is not in
# them, and a file that is not in SHA256SUMS is not covered by its signature: it would be published next to a signed list that
# says nothing about it. Each name is the bare file name in <dir>; the lines are added in the form release.sh writes, and the files
# are then listed in name order, as they would have been had they been there from the start.
set -euo pipefail

dir="${1:?usage: add-to-sums.sh <dir> <file> [<file>...]}"
shift
[ "$#" -ge 1 ] || { echo "usage: add-to-sums.sh <dir> <file> [<file>...]" >&2; exit 2; }
die() { echo "add-to-sums.sh: $*" >&2; exit 1; }
[ -d "$dir" ] || die "$dir is not a directory"
[ -s "$dir/SHA1SUMS" ] && [ -s "$dir/SHA256SUMS" ] || die "$dir has no SHA1SUMS and SHA256SUMS to add to"

cd "$dir"
for f in "$@"; do
  case "$f" in */*|"") die "'$f' is not a bare file name" ;; esac
  [ -f "$f" ] || die "$f is not a file in $dir"
  case "$f" in SHA1SUMS|SHA256SUMS|SHA256SUMS.sig) die "$f is one of the files that hold the sums" ;; esac
  if grep -q "  $f\$" SHA256SUMS; then die "$f is already in SHA256SUMS"; fi
done

if command -v sha1sum >/dev/null 2>&1; then sha1="sha1sum"; sha256="sha256sum"; else sha1="shasum -a 1"; sha256="shasum -a 256"; fi
tmp1="$(mktemp)"; tmp256="$(mktemp)"
trap 'rm -f "$tmp1" "$tmp256"' EXIT
{ cat SHA1SUMS; $sha1 "$@"; } | LC_ALL=C sort -k2 > "$tmp1"
{ cat SHA256SUMS; $sha256 "$@"; } | LC_ALL=C sort -k2 > "$tmp256"
cat "$tmp1" > SHA1SUMS
cat "$tmp256" > SHA256SUMS
echo "added $# file(s) to SHA1SUMS and SHA256SUMS"
