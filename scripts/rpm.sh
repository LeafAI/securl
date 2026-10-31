#!/usr/bin/env bash
set -euo pipefail

out="${1:?usage: rpm.sh <output dir> <version> <architecture> <release>}"
version="${2:?usage: rpm.sh <output dir> <version> <architecture> <release>}"
arch="${3:?usage: rpm.sh <output dir> <version> <architecture> <release>}"
release="${4:?usage: rpm.sh <output dir> <version> <architecture> <release>}"

if ! [[ "$version" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]; then
  echo 'rpm.sh: invalid version; use a digit followed by letters, digits, dots, + or ~' >&2
  exit 2
fi
if ! [[ "$release" =~ ^[1-9][0-9A-Za-z.+~]*$ ]]; then
  echo 'rpm.sh: invalid release; start with a nonzero digit and use letters, digits, dots, + or ~' >&2
  exit 2
fi
case "$arch" in
  amd64|x86_64) goarch=amd64; rpmarch=x86_64 ;;
  arm64|aarch64) goarch=arm64; rpmarch=aarch64 ;;
  *) echo 'rpm.sh: invalid architecture; use amd64/x86_64 or arm64/aarch64' >&2; exit 2 ;;
esac
for tool in go rpmbuild install mktemp; do
  command -v "$tool" >/dev/null || { echo "rpm.sh: $tool is required (Amazon Linux: sudo dnf install rpm-build)" >&2; exit 2; }
done

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
payload="$stage/payload"
install -d "$payload/usr/bin" "$payload/usr/libexec/securl" "$payload/usr/share/doc/securl" \
  "$payload/usr/lib/systemd/user/default.target.wants"
CGO_ENABLED=0 GOOS=linux GOARCH="$goarch" go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X github.com/LeafAI/securl/internal/mcpserver.Version=${version}" \
  -o "$payload/usr/bin/securl" .
install -m 0644 packaging/securl.service "$payload/usr/lib/systemd/user/securl.service"
ln -s ../securl.service "$payload/usr/lib/systemd/user/default.target.wants/securl.service"
install -m 0755 packaging/user-service.sh "$payload/usr/libexec/securl/user-service"
install -m 0644 README.md THIRD_PARTY_NOTICES.md "$payload/usr/share/doc/securl/"
rpmbuild -bb --target "$rpmarch" \
  --define "_topdir $stage/rpmbuild" \
  --define "_securl_version $version" --define "_securl_release $release" \
  --define "_securl_payload $payload" \
  packaging/securl.spec
name="securl-${version}-${release}.${rpmarch}.rpm"
install -m 0644 "$stage/rpmbuild/RPMS/$rpmarch/$name" "$out/$name"
printf 'Built %s\nInstall with: sudo dnf install %q\n' "$out/$name" "$out/$name"
