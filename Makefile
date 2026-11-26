VERSION ?= 0.1.0~git.$(shell git show -s --format=%cs HEAD | tr -d -).$(shell git rev-parse --short HEAD)
DEB_ARCH ?= $(shell go env GOARCH)
RPM_ARCH ?= $(shell go env GOARCH)
RPM_RELEASE ?= 1
DIST ?= dist
MACOS_VERSION ?= nightly-$(shell git show -s --format=%cs HEAD | tr -d -)-$(shell git rev-parse --short=12 HEAD)

# DRIVERS builds login drivers from other repositories into the binary (docs/DRIVERS.md), for example
#   make rpm DRIVERS="gitlab.example.com/group/repo@v1.2.3"
# Each is host/path@revision, cloned over ssh, with the revision pinned (a version tag or a full commit hash); several are separated by
# a space or a comma. DRIVERS_SSH_KEY names a key to clone with instead of the agent's. With none, the build is the one it always
# was: not a character of the recipes below changes.
#
# What a person wrote is text, and make must never read it as anything else. Make expands a variable given on its command line or in
# the environment whenever it is read with $(...), and expanding $(shell ...) runs a command; so it is only copied with $(value ...)
# into SECURL_DRIVERS, which reaches generate.go in the environment. generate.go reads it as a list of specs and refuses whatever is
# not a plain host/path@revision. DRIVERS is not exported: make would export the expanded text.
ifneq ($(origin DRIVERS),undefined)
SECURL_DRIVERS := $(value DRIVERS)
endif
ifneq ($(origin DRIVERS_SSH_KEY),undefined)
SECURL_DRIVERS_SSH_KEY := $(value DRIVERS_SSH_KEY)
endif
unexport DRIVERS DRIVERS_SSH_KEY
export SECURL_DRIVERS SECURL_DRIVERS_SSH_KEY
GENERATE = go run generate.go --

.PHONY: deb rpm macos
# Whether any driver is asked for is decided on the text ($(value) of a variable that is not there is empty, and is never expanded)
# and in a variable of this file's own name, so that nothing in the environment can say it. GNU make 3.81, which macOS ships, has no
# undefine: SECURL_PLAIN is set to a value each way.
ifeq ($(strip $(value SECURL_DRIVERS)),)
SECURL_PLAIN := yes
else
SECURL_PLAIN := no
endif
ifeq ($(SECURL_PLAIN),yes)
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
else
deb:
	$(GENERATE) bash scripts/deb.sh "$(DIST)" "$(VERSION)" "$(DEB_ARCH)"

rpm:
	$(GENERATE) bash scripts/rpm.sh "$(DIST)" "$(VERSION)" "$(RPM_ARCH)" "$(RPM_RELEASE)"

# With drivers the whole macOS build runs inside the generator, so both architectures hold them.
macos:
	$(GENERATE) bash scripts/macos-build.sh "$(MACOS_VERSION)" "$(DIST)"
endif
