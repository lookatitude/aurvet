# aurvet build and release targets.
#
# Everything here honours spec §16's build contract, which is a security
# contract rather than a style preference:
#
#   CGO_ENABLED=0, static, -trimpath, -mod=vendor, -buildvcs=false, no strip,
#   ONE merged -ldflags, version+commit injected but NEVER a build date.
#
# Two traps are encoded deliberately:
#
#  1. GOFLAGS is cleared on every go invocation. §16: GOFLAGS' -ldflags is
#     REPLACED, not merged, by a command-line -ldflags. An inherited
#     GOFLAGS=-ldflags=... would silently drop our injection or change the link
#     mode from static to dynamic -- and a dynamically-linked aurvet can be
#     subverted by LD_PRELOAD before it can report on /etc/ld.so.preload.
#  2. LDFLAGS is a single string with both -X inside it. Two -ldflags flags mean
#     the second replaces the first and one -X vanishes with no error.
#
# There is no -s -w. Those strip symbols at link time, and §16 requires
# options=('!strip') so the packaged binary is the binary that was hashed.

BIN         := aurvet
PKG         := ./cmd/aurvet
DIST        := dist
BUILDINFO   := github.com/lookatitude/aurvet/internal/buildinfo

# VERSION comes from the tag when building a release, else from git describe,
# else empty. Empty is a legitimate outcome: buildinfo renders it as
# "not injected" rather than inventing a value.
VERSION ?= $(shell git describe --tags --exact-match 2>/dev/null | sed 's/^v//')
COMMIT  ?= $(shell git rev-parse HEAD 2>/dev/null)

# SOURCE_DATE_EPOCH is the COMMIT date, never "now" -- a wall-clock timestamp
# would make every build differ and destroy reproducibility.
SOURCE_DATE_EPOCH ?= $(shell git log -1 --format=%ct 2>/dev/null)
export SOURCE_DATE_EPOCH

LDFLAGS := -X $(BUILDINFO).Version=$(VERSION) -X $(BUILDINFO).Commit=$(COMMIT)

# GOTOOLCHAIN=local refuses to silently download a different toolchain than the
# one pinned in go.mod, which would break reproducibility invisibly.
GO_ENV := CGO_ENABLED=0 GOTOOLCHAIN=local GOFLAGS=
GO_BUILD_FLAGS := -trimpath -buildvcs=false -mod=vendor

.DEFAULT_GOAL := build
.PHONY: build test test-short vet fmt-check fmt dist checksums verify-reproducible version clean help

## build: build the binary for the host platform
build:
	$(GO_ENV) go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(BIN) $(PKG)

## test: run the full test suite
test:
	$(GO_ENV) go test ./... -count=1

## test-short: skip the tests that build a binary (faster inner loop)
test-short:
	$(GO_ENV) go test ./... -count=1 -short

## vet: run go vet
vet:
	$(GO_ENV) go vet ./...

## fmt-check: fail if any file is not gofmt-clean
fmt-check:
	@unformatted=$$(gofmt -l . | grep -v '^vendor/' || true); \
	if [ -n "$$unformatted" ]; then \
		echo "not gofmt-clean:"; echo "$$unformatted"; exit 1; \
	fi; \
	echo "gofmt: clean"

## fmt: format the tree
fmt:
	gofmt -w .

## version: print the version identity this build would report
version: build
	@./$(BIN) version

## dist: build release artifacts for every supported platform + source tarball
dist: clean
	@mkdir -p $(DIST)
	@if [ -z "$(VERSION)" ]; then \
		echo "dist: refusing to build unversioned release artifacts."; \
		echo "      VERSION is empty -- check out a tag or pass VERSION=x.y.z."; \
		exit 1; \
	fi
	@echo "building $(BIN) $(VERSION) (commit $(COMMIT))"
	@# arch=('x86_64' 'aarch64') per spec §16. GOARCH names differ from Arch's.
	GOOS=linux GOARCH=amd64 $(GO_ENV) go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BIN)-$(VERSION)-x86_64 $(PKG)
	GOOS=linux GOARCH=arm64 $(GO_ENV) go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" \
		-o $(DIST)/$(BIN)-$(VERSION)-aarch64 $(PKG)
	@# Source tarball via git archive, NEVER GitHub's auto-generated archive:
	@# §16 -- their checksums are not contractually stable and they contain LFS
	@# pointers rather than content. --mtime pins entry times to the commit date
	@# so the tarball is byte-reproducible.
	git archive --format=tar --prefix=$(BIN)-$(VERSION)/ \
		$$(git rev-parse HEAD) | gzip -n > $(DIST)/$(BIN)-$(VERSION).tar.gz
	@echo "artifacts:"; ls -1 $(DIST)

## checksums: write SHA256SUMS over the dist directory
checksums:
	@test -d $(DIST) || { echo "checksums: no $(DIST)/ -- run make dist first"; exit 1; }
	@# Glob the artifacts explicitly rather than `*`: a bare `*` would include
	@# SHA256SUMS itself on a re-run (checksumming the checksum file), and
	@# shellcheck SC2035 warns that unanchored globs let a leading dash be read
	@# as an option. `--` ends option parsing for the same reason.
	cd $(DIST) && rm -f SHA256SUMS && sha256sum -- aurvet-* > SHA256SUMS
	@cat $(DIST)/SHA256SUMS

## verify-reproducible: build twice and confirm the binaries are byte-identical
verify-reproducible:
	@echo "toolchain identity: $$(go version)"
	@echo
	@# A patched toolchain (e.g. a GOEXPERIMENT build such as
	@# go1.26.5-X:nodwarf5) emits different bytes from a stock release of the
	@# SAME version. go.mod's toolchain directive and GOTOOLCHAIN=local pin the
	@# version but CANNOT pin a GOEXPERIMENT, so reproducing a published release
	@# requires a STOCK toolchain. This target prints the identity it used so a
	@# mismatch can be told apart from tampering -- which is the whole point:
	@# an unexplained mismatch in a security tool reads as compromise.
	@case "$$(go version)" in \
		*X:*) echo "WARNING: this toolchain carries a GOEXPERIMENT (see 'X:' above)."; \
		      echo "         Its output will NOT match a stock-toolchain release build."; \
		      echo "         A mismatch below is explained by the toolchain, not tampering."; echo ;; \
	esac
	@rm -rf $(DIST)/repro-a $(DIST)/repro-b
	@mkdir -p $(DIST)
	$(GO_ENV) go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/repro-a $(PKG)
	$(GO_ENV) go build $(GO_BUILD_FLAGS) -ldflags "$(LDFLAGS)" -o $(DIST)/repro-b $(PKG)
	@a=$$(sha256sum $(DIST)/repro-a | cut -d' ' -f1); \
	 b=$$(sha256sum $(DIST)/repro-b | cut -d' ' -f1); \
	 echo "build A: $$a"; echo "build B: $$b"; \
	 if [ "$$a" = "$$b" ]; then echo "REPRODUCIBLE (identical)"; else \
	   echo "MISMATCH -- not reproducible on this toolchain"; exit 1; fi

## clean: remove build output
clean:
	rm -rf $(DIST) $(BIN)

## help: list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/^## /  /'
