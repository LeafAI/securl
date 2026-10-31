#!/usr/bin/env bash
set -euo pipefail

out="${1:?usage: deb.sh <output dir> <version> <amd64|arm64>}"
version="${2:?usage: deb.sh <output dir> <version> <amd64|arm64>}"
arch="${3:?usage: deb.sh <output dir> <version> <amd64|arm64>}"

if ! [[ "$version" =~ ^[0-9][0-9A-Za-z.+~]*$ ]]; then
  echo 'deb.sh: version must start with a digit and contain only letters, digits, dots, + or ~' >&2
  exit 2
fi
case "$arch" in
  amd64|arm64) ;;
  *) echo 'deb.sh: architecture must be amd64 or arm64' >&2; exit 2 ;;
esac
for tool in go install mktemp; do
  command -v "$tool" >/dev/null || { echo "deb.sh: $tool is required" >&2; exit 2; }
done
if command -v dpkg-deb >/dev/null; then
  builder=dpkg-deb
elif command -v docker >/dev/null; then
  builder=docker
else
  echo 'deb.sh: dpkg-deb or Docker is required to build a Debian package' >&2
  exit 2
fi

mkdir -p "$out"
out="$(cd "$out" && pwd)"
stage="$(mktemp -d)"
trap 'rm -rf "$stage"' EXIT
root="$stage/package"
install -d "$root/DEBIAN" "$root/usr/bin" "$root/usr/share/doc/securl" \
  "$root/usr/lib/systemd/user/default.target.wants"
CGO_ENABLED=0 GOOS=linux GOARCH="$arch" go build -trimpath -buildvcs=false \
  -ldflags "-s -w -X github.com/LeafAI/securl/internal/mcpserver.Version=${version}" \
  -o "$root/usr/bin/securl" .
install -m 0644 packaging/securl.service "$root/usr/lib/systemd/user/securl.service"
ln -s ../securl.service "$root/usr/lib/systemd/user/default.target.wants/securl.service"
for script in postinst prerm; do
  install -m 0755 packaging/user-service.sh "$root/DEBIAN/$script"
done
install -m 0644 README.md THIRD_PARTY_NOTICES.md "$root/usr/share/doc/securl/"
cat > "$root/DEBIAN/control" <<EOF
Package: securl
Version: $version
Section: net
Priority: optional
Architecture: $arch
Maintainer: LeafAI <securl@leafai.cc>
Depends: openssh-client, ca-certificates, systemd, dbus-user-session, util-linux
Description: Secure URL requestor for AI agents
 Human-mediated login and an encrypted credential vault for MCP clients.
 Includes a per-user systemd daemon, started locked at login, never as root.
EOF
name="securl_${version}_${arch}.deb"
if [ "$builder" = dpkg-deb ]; then
  dpkg-deb --root-owner-group --build "$root" "$stage/$name"
else
  docker run --rm --network=none --user "$(id -u):$(id -g)" \
    -v "$stage:/build" debian:bookworm-slim \
    dpkg-deb --root-owner-group --build /build/package "/build/$name"
fi
install -m 0644 "$stage/$name" "$out/$name"
printf 'Built %s\nInstall with: sudo apt install %q\n' "$out/$name" "$out/$name"
