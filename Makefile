VERSION ?= 0.1.0~git.$(shell git show -s --format=%cs HEAD | tr -d -).$(shell git rev-parse --short HEAD)
DEB_ARCH ?= $(shell go env GOARCH)
RPM_ARCH ?= $(shell go env GOARCH)
RPM_RELEASE ?= 1
DIST ?= dist
MACOS_VERSION ?= nightly-$(shell git show -s --format=%cs HEAD | tr -d -)-$(shell git rev-parse --short=12 HEAD)

.PHONY: deb rpm macos
deb:
	bash scripts/deb.sh "$(DIST)" "$(VERSION)" "$(DEB_ARCH)"

rpm:
	bash scripts/rpm.sh "$(DIST)" "$(VERSION)" "$(RPM_ARCH)" "$(RPM_RELEASE)"

# Build both Darwin architectures and reuse the same installer as the nightly release.
macos:
	@set -eu; \
	if [ "$$(uname -s)" != Darwin ]; then echo "make macos requires macOS (pkgbuild, productbuild and lipo)" >&2; exit 1; fi; \
	work="$$(mktemp -d -t securl-macos)"; \
	trap 'rm -rf "$$work"' EXIT; \
	CGO_ENABLED=0 GOOS=darwin GOARCH=arm64 go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/LeafAI/securl/internal/mcpserver.Version=$(MACOS_VERSION)" -o "$$work/securl-arm64" .; \
	CGO_ENABLED=0 GOOS=darwin GOARCH=amd64 go build -trimpath -buildvcs=false -ldflags "-s -w -X github.com/LeafAI/securl/internal/mcpserver.Version=$(MACOS_VERSION)" -o "$$work/securl-amd64" .; \
	bash scripts/macos-pkg.sh "$(MACOS_VERSION)" "$$work/securl-arm64" "$$work/securl-amd64" "$(DIST)/securl_macos.pkg"
