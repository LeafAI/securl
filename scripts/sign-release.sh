#!/usr/bin/env bash
# Signs <dir>/SHA256SUMS with the release key and writes <dir>/SHA256SUMS.sig, then checks the signature the way a user will.
#
#   scripts/sign-release.sh dist keys/securl-release.pub
#
# One file is signed, not each archive: SHA256SUMS lists the hash of every archive, so a signature on it covers them all.
# The signature is made with the namespace "securl-release", so it cannot be taken for a signature of anything else the same
# key signs (a git commit is signed under "git"), nor can a signature of something else pass here.
#
# The private key comes from, in this order:
#   SIGNING_KEY_FILE  the path of a file that holds it (a CI step writes the secret there with a restrictive mode);
#   SIGNING_KEY       its text, which is written to a temporary file that is removed when the script ends;
#   SSH_AUTH_SOCK     an ssh-agent that holds the key whose public half is <pubkey>.
# It is never printed. If none is available the script stops and signs nothing.
#
# A signature that does not verify against <pubkey> is never left in <dir>: a mismatch between the key that signs and the
# key that is published would otherwise be found by the first user, not by the build.
set -euo pipefail

dir="${1:?usage: sign-release.sh <dir> <public-key-file>}"
pub="${2:?usage: sign-release.sh <dir> <public-key-file>}"
ns="securl-release"
identity="securl-release"

die() { echo "sign-release.sh: $*" >&2; exit 1; }
[ -d "$dir" ] || die "$dir is not a directory"
[ -s "$dir/SHA256SUMS" ] || die "$dir/SHA256SUMS is missing or empty"
[ -s "$pub" ] || die "$pub is missing or empty"
command -v ssh-keygen >/dev/null 2>&1 || die "ssh-keygen is required"
grep -q '^ssh-ed25519 ' "$pub" || die "$pub is not an ssh-ed25519 public key"

# What is signed is what the files are: sums that do not match the archives are not signed.
(
  cd "$dir"
  if command -v sha256sum >/dev/null 2>&1; then sha256sum --check --strict --quiet SHA256SUMS; else shasum -a 256 --check --quiet SHA256SUMS; fi
) >/dev/null 2>&1 || die "SHA256SUMS does not match the files in $dir: nothing is signed"

sig="$dir/SHA256SUMS.sig"
rm -f "$sig"
tmpkey=""
cleanup() { [ -n "$tmpkey" ] && rm -f "$tmpkey"; return 0; }
trap cleanup EXIT

if [ -n "${SIGNING_KEY_FILE:-}" ]; then
  [ -s "$SIGNING_KEY_FILE" ] || die "SIGNING_KEY_FILE names a file that is missing or empty"
  keyfile="$SIGNING_KEY_FILE"
  agent=""
elif [ -n "${SIGNING_KEY:-}" ]; then
  tmpkey="$(mktemp "${TMPDIR:-/tmp}/securl-sign-key.XXXXXX")"
  chmod 600 "$tmpkey"
  printf '%s\n' "$SIGNING_KEY" > "$tmpkey"
  keyfile="$tmpkey"
  agent=""
elif [ -n "${SSH_AUTH_SOCK:-}" ]; then
  # The agent signs with the key named by the public file, and only with it: -U makes ssh-keygen ask the agent.
  keyfile="$pub"
  agent="-U"
else
  die "no signing key: set SIGNING_KEY_FILE or SIGNING_KEY, or run an ssh-agent that holds the release key"
fi

# $agent is "-U" or empty, and is left unquoted on purpose: an empty one must vanish, not become an empty argument. (An empty
# array would do the same, but bash 3.2, which macOS ships, treats "${empty[@]}" as unset under `set -u`.)
# shellcheck disable=SC2086
ssh-keygen -Y sign $agent -f "$keyfile" -n "$ns" "$dir/SHA256SUMS" >/dev/null 2>&1 || {
  rm -f "$sig"
  die "signing failed (is the key the release key?)"
}
[ -s "$sig" ] || die "no signature was written"

# The check a user makes, against the public key that is published.
signers="$(mktemp "${TMPDIR:-/tmp}/securl-signers.XXXXXX")"
trap 'cleanup; rm -f "$signers"' EXIT
read -r type key _ < "$pub"
printf '%s namespaces="%s" %s %s\n' "$identity" "$ns" "$type" "$key" > "$signers"
if ! ssh-keygen -Y verify -f "$signers" -I "$identity" -n "$ns" -s "$sig" < "$dir/SHA256SUMS" >/dev/null 2>&1; then
  rm -f "$sig"
  die "the signature does not verify against $pub: the key that signed is not the published release key"
fi
echo "signed $dir/SHA256SUMS; the signature verifies against $pub"
