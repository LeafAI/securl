#!/usr/bin/env bash
# Builds both Darwin architectures and packs them with scripts/macos-pkg.sh, as `make macos` does. It is a script of its own so that
# `make macos DRIVERS=...` can run all of it inside generate.go, which builds the drivers into both binaries.
#
#   scripts/macos-build.sh <version> <output dir>
set -euo pipefail

version="${1:?usage: macos-build.sh <version> <output dir>}"
dist="${2:?usage: macos-build.sh <version> <output dir>}"
module="github.com/LeafAI/securl"

if [ "$(uname -s)" != Darwin ]; then
  echo "make macos requires macOS (pkgbuild, productbuild and lipo)" >&2
  exit 1
fi
work="$(mktemp -d -t securl-macos)"
trap 'rm -rf "$work"' EXIT
for arch in arm64 amd64; do
  CGO_ENABLED=0 GOOS=darwin GOARCH="$arch" go build -trimpath -buildvcs=false \
    -ldflags "-s -w -X ${module}/internal/mcpserver.Version=${version}" -o "$work/securl-$arch" .
done
bash scripts/macos-pkg.sh "$version" "$work/securl-arm64" "$work/securl-amd64" "$dist/securl_macos.pkg"
