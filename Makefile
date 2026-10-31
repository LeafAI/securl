VERSION ?= 0.1.0~git.$(shell git show -s --format=%cs HEAD | tr -d -).$(shell git rev-parse --short HEAD)
DEB_ARCH ?= $(shell go env GOARCH)
RPM_ARCH ?= $(shell go env GOARCH)
RPM_RELEASE ?= 1
DIST ?= dist

.PHONY: deb rpm
deb:
	bash scripts/deb.sh "$(DIST)" "$(VERSION)" "$(DEB_ARCH)"

rpm:
	bash scripts/rpm.sh "$(DIST)" "$(VERSION)" "$(RPM_ARCH)" "$(RPM_RELEASE)"
