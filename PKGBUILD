# Maintainer: Miguel Pinto <miguel@aloware.com>
#
# aurvet -- the canonical SOURCE package. This recipe is the one the project
# stands behind; an `aurvet-bin` asks a user to trust a build machine, which is
# precisely the trust this tool exists to question, so if it is ever published it
# is secondary and carries options=('!strip') so its bytes match the artifact the
# release hashed (spec §16, decision D-2).
#
# ---------------------------------------------------------------------------
# WHY THIS RECIPE DEVIATES FROM ARCH'S GO PACKAGING GUIDELINES -- ON PURPOSE
# ---------------------------------------------------------------------------
# The guidelines mandate `-buildmode=pie -linkmode=external`, which requires CGO
# and produces a DYNAMICALLY LINKED binary. This package builds a STATIC binary
# with CGO_ENABLED=0 instead, and that is a security requirement rather than a
# preference:
#
#   aurvet reports on /etc/ld.so.preload and rates a hostile entry critical.
#   A dynamically-linked aurvet can be subverted by LD_PRELOAD or
#   /etc/ld.so.preload BEFORE it reaches its own main() -- that is, before it
#   can report on the very mechanism used to silence it. A detector that the
#   attacker's loader hook runs first is not a detector.
#
# The consequences are accepted deliberately and are not free:
#   - no PIE, so no ASLR of the executable image itself. aurvet parses
#     attacker-controlled input, so this is a real cost; it is bounded by the
#     staged privilege drop (internal/privdrop) and by every parser running
#     unprivileged (spec §11.1).
#   - no automatic dependency-on-glibc tracking. There is nothing to track: the
#     binary has no DT_NEEDED at all, and TestBinaryIsStaticallyLinked in
#     cmd/aurvet asserts no DT_NEEDED and no PT_INTERP on every CI run. If that
#     test ever fails, this comment has become false and the package is wrong.
#   - namcap emits `not linked` / static-binary notes. They are acknowledged
#     explicitly in CI's namcap step, with an allow-list naming each one --
#     never silenced wholesale (spec §16).
#
# ---------------------------------------------------------------------------
# WHY options=('!strip') -- decision D-2, and it is load-bearing
# ---------------------------------------------------------------------------
# `strip` is ON in makepkg's default OPTIONS and runs AFTER build(). Without
# '!strip' the packaged binary is not the binary that was built, so its hash is
# not the hash the release publishes, `SHA256SUMS` describes nothing a user
# holds, and self-verification becomes impossible. It costs a marginally larger
# package and buys the only verification path an ordinary user will ever
# actually exercise.
#
# '!debug' is stated rather than inherited for the same reason: a debug split
# strips the binary to produce the -debug package.
#
# ---------------------------------------------------------------------------
# WHY THE SOURCE IS A RELEASE ASSET AND NOT GITHUB'S AUTO-GENERATED ARCHIVE
# ---------------------------------------------------------------------------
# The tarball below is produced by `git archive` (`make dist`) and uploaded as a
# release ASSET. GitHub's auto-generated /archive/ tarballs are NOT used: their
# checksums are not contractually stable (they have changed for an unchanged tag
# in the past, which would break every pinned sha256sums line in the AUR), and
# they contain LFS pointers rather than content. See spec §16.
#
# ---------------------------------------------------------------------------
# WHY build() DOES NOT REACH THE NETWORK, AND WHY THAT IS TESTED
# ---------------------------------------------------------------------------
# All dependencies are vendored (golang.org/x/sys is the only one), so -mod=vendor
# builds offline. This is not a nicety: aurvet's own critical rule
# `pkgbuild-build-network-fetch` fires on a build step that fetches, and CI runs
# `aurvet review` against THIS FILE and fails the build on any finding at or
# above the default floor. If vendoring were ever dropped, `go mod download`
# would appear here and aurvet would condemn its own package.

pkgname=aurvet
pkgver=0.0.1
pkgrel=1
pkgdesc='Provenance, integrity and persistence auditing for AUR-installed packages'
arch=('x86_64' 'aarch64')
url='https://github.com/lookatitude/aurvet'
license=('MIT')
# The binary itself has NO library dependencies at all -- it is static, so there
# is no DT_NEEDED for anything to track. 'sh' is here for the one shipped script:
# /usr/share/aurvet/aurvet-hook is #!/bin/sh, and namcap correctly reports the
# missing dependency otherwise. It is the virtual provide rather than 'bash'
# because the wrapper is POSIX sh and does not need bash.
depends=('sh')
# 'go' rather than a version constraint on purpose: go.mod carries the floor
# (go 1.24, for os.Root) and the release pin (toolchain go1.26.5). Arch ships
# 1.26.x, and duplicating a floor in two places is how the two drift apart.
makedepends=('go' 'scdoc')
# Helper support is optdepends ONLY, never a hard dependency: `aurvet install`
# hands a vetted directory to a helper and refuses to run one for you (INV-2).
optdepends=(
  'paru: helper handover for aurvet install'
  'yay: helper handover for aurvet install'
)
# '!strip' -- D-2, see the header. '!debug' -- a debug split would strip.
# '!lto' -- LTOFLAGS are C compiler flags; with CGO_ENABLED=0 nothing here
# consumes them, and leaving lto on advertises a property this build does not
# have.
options=('!strip' '!debug' '!lto')
# There is deliberately no install= scriptlet. The only thing one would plausibly
# do here is enable the timer, and enabling units is the administrator's
# decision, not the packager's (Arch policy). No scriptlet also means nothing of
# this package runs as root at install time.

# _commit is the FULL SHA of the tagged commit this tarball was archived from.
# The release tarball is a `git archive` and therefore carries no git metadata,
# so the commit cannot be derived from the source; it is recorded here and then
# VERIFIED by check(), which asserts that the built binary reports exactly this
# version and commit. A wrong or stale _commit fails the build rather than
# shipping a binary that misreports its own provenance -- `aurvet version` ends
# up quoted in incident reports, and a confidently wrong identity there is worse
# than an absent one (internal/buildinfo).
_commit='0000000000000000000000000000000000000000'

source=("$pkgname-$pkgver.tar.gz::$url/releases/download/v$pkgver/$pkgname-$pkgver.tar.gz")
# A real sha256, never SKIP: SKIP on a fixed URL means the build accepts whatever
# the host serves, which is what a repointed mirror needs -- and aurvet's own
# `pkgbuild-skip-fixed-url` rule reports it at the default floor, so its own
# recipe must not do it.
#
# The all-zero value below is a SENTINEL meaning "this version has not been
# published yet". It is not a hash and cannot be mistaken for one: makepkg fails
# loudly on it. CI asserts that once tag v$pkgver exists in the repository, this
# line equals the sha256 of that tag's `git archive` tarball -- so the sentinel
# cannot survive a release.
sha256sums=('0000000000000000000000000000000000000000000000000000000000000000')

build() {
  cd "$pkgname-$pkgver"

  # Refuse to build with the unpublished-release sentinels. check() below
  # compares `aurvet version` against $_commit, which would happily accept a
  # sentinel and ship a binary reporting commit 000000000000 -- a confidently
  # wrong provenance string in a tool whose output is quoted in incident
  # reports. Failing here is the whole point: an unreleased recipe is not
  # installable, and saying so is better than installing a binary that lies
  # about which source built it.
  if [[ ! $_commit =~ ^[0-9a-f]{40}$ ]] || [[ $_commit == 0000000000000000000000000000000000000000 ]]; then
    printf '%s\n' \
      "this PKGBUILD carries the unpublished-release sentinel for _commit," \
      "so v$pkgver has not been released yet and this recipe is not installable." \
      "Release first; the sentinel is replaced with the tagged commit and the" \
      "tarball's real sha256 at that point." >&2
    return 1
  fi

  # The build contract, spec §16. Every element earns its place:
  #
  #   CGO_ENABLED=0    static; see the header.
  #   GOTOOLCHAIN=local refuses to silently DOWNLOAD another toolchain
  #                    mid-build. A security tool's package must not fetch a
  #                    compiler behind the packager's back.
  #   GOFLAGS=         cleared deliberately. GOFLAGS' -ldflags is REPLACED, not
  #                    merged, by the command-line -ldflags below, so an
  #                    inherited value would silently drop the version injection
  #                    or flip the link mode from static to dynamic.
  #   GOPATH/GOMODCACHE under $srcdir so the build writes nothing into the
  #                    packager's home directory.
  #   -mod=vendor      no network; VERIFIED to work with a vendor/ directory
  #                    that carries exactly one module.
  #   -trimpath        removes $srcdir from the binary, which is what makes two
  #                    machines' builds byte-identical.
  #   -buildvcs=false  there is no VCS here (git archive), and stamping one
  #                    would embed the packager's environment.
  #   ONE merged -ldflags with BOTH -X inside it: two -ldflags flags mean the
  #                    second replaces the first and one -X vanishes silently.
  #   NO build date is injected, ever -- it would make every build differ.
  #   NO -s -w: those strip at link time and would defeat '!strip'.
  export CGO_ENABLED=0
  export GOTOOLCHAIN=local
  export GOFLAGS=
  export GOPATH="$srcdir/gopath"
  export GOMODCACHE="$srcdir/gopath/pkg/mod"
  export GOCACHE="$srcdir/gocache"

  local _bi='github.com/lookatitude/aurvet/internal/buildinfo'
  go build -trimpath -buildvcs=false -mod=vendor \
    -ldflags "-X $_bi.Version=$pkgver -X $_bi.Commit=$_commit" \
    -o aurvet ./cmd/aurvet

  # Man pages: scdoc source in, roff out, and installed UNCOMPRESSED below.
  # makepkg's `zipman` is on by default and compresses them itself; a
  # pre-gzipped page would be double-compressed.
  local page out
  for page in man/*.scd; do
    out="${page##*/}"
    scdoc <"$page" >"${out%.scd}"
  done
}

check() {
  cd "$pkgname-$pkgver"

  # Assert the identity that was injected is the identity recorded above. This
  # is the check that keeps _commit honest: without it a stale value ships a
  # binary that lies about which source built it.
  #
  # The FIRST LINE only. `version` also reports the indicator-bundle trust state
  # (root fingerprints, delegation expiry, cached bundle version) because those
  # are the facts that decide whether the tool's data can be trusted, and they
  # belong where a person already looks. Comparing the whole output against a
  # one-line identity broke this gate the moment that block shipped, and the
  # failure was needlessly hard to read: want and got were byte-identical on
  # their own line, with the difference several lines further down.
  local want got
  want="aurvet $pkgver (commit ${_commit:0:12})"
  got="$(./aurvet version | head -n 1)"
  if [[ "$got" != "$want" ]]; then
    printf 'version identity mismatch (first line of `aurvet version`):\n  want: %s\n  got:  %s\n' \
      "$want" "$got" >&2
    return 1
  fi

  # The suite includes TestBinaryIsStaticallyLinked (no DT_NEEDED, no
  # PT_INTERP), which is the assertion this recipe's linkage deviation rests on.
  # -count=1 because a cached PASS would prove nothing about this build.
  go test -mod=vendor -count=1 ./...
}

package() {
  cd "$pkgname-$pkgver"

  install -Dm755 aurvet "$pkgdir/usr/bin/aurvet"
  install -Dm644 LICENSE "$pkgdir/usr/share/licenses/$pkgname/LICENSE"
  install -Dm644 README.md "$pkgdir/usr/share/doc/$pkgname/README.md"
  install -Dm644 SECURITY.md "$pkgdir/usr/share/doc/$pkgname/SECURITY.md"
  install -Dm644 docs/reporting-malware.md "$pkgdir/usr/share/doc/$pkgname/reporting-malware.md"

  # Man pages, uncompressed: zipman does the compressing (see build()).
  local page section
  for page in *.[0-9]; do
    section="${page##*.}"
    install -Dm644 "$page" "$pkgdir/usr/share/man/man$section/$page"
  done

  # Completions. Each shell has one canonical location and one canonical name;
  # an unrecognised file is a hard error rather than a silent skip, because a
  # completion that was not installed looks exactly like "no match" to the user.
  local comp
  for comp in completions/*; do
    case "$comp" in
      *.bash) install -Dm644 "$comp" "$pkgdir/usr/share/bash-completion/completions/aurvet" ;;
      *.zsh | */_aurvet) install -Dm644 "$comp" "$pkgdir/usr/share/zsh/site-functions/_aurvet" ;;
      *.fish) install -Dm644 "$comp" "$pkgdir/usr/share/fish/vendor_completions.d/aurvet.fish" ;;
      *_test.go) ;; # the anti-rot test is source, not a completion
      *)
        printf 'unrecognised file in completions/: %s\n' "$comp" >&2
        return 1
        ;;
    esac
  done

  # systemd units and timers. NOT enabled here and NOT enabled by an .install
  # scriptlet: shipping a unit is not consent to run it, and enabling units is
  # the administrator's decision, not the packager's (Arch policy). Exit codes 1
  # and 3 are contractual and both render as `failed`, so the units carry
  # OnFailure= rather than masking them with SuccessExitStatus= -- masking would
  # turn a finding into silence, which is INV-3 violated through packaging.
  local unit
  for unit in packaging/systemd/*.service packaging/systemd/*.timer; do
    install -Dm644 "$unit" "$pkgdir/usr/lib/systemd/system/${unit##*/}"
  done

  # tmpfiles.d for the state directory, so /var/lib/aurvet exists with the right
  # ownership before anything writes to it (internal/config resolves state there
  # for euid 0).
  local tf
  for tf in packaging/tmpfiles.d/*.conf; do
    install -Dm644 "$tf" "$pkgdir/usr/lib/tmpfiles.d/${tf##*/}"
  done

  # pacman hooks and the single wrapper they both route through. The wrapper
  # lives at /usr/share/aurvet/aurvet-hook, which is the path both .hook files
  # test for before executing: with the package removed the wrapper is gone, the
  # test fails, and the hook exits 0 -- a hook whose Exec names a missing binary
  # fails EVERY subsequent transaction, including the one that would repair it.
  install -Dm755 packaging/hooks/aurvet-hook "$pkgdir/usr/share/aurvet/aurvet-hook"
  local hook
  for hook in packaging/hooks/*.hook; do
    install -Dm644 "$hook" "$pkgdir/usr/share/libalpm/hooks/${hook##*/}"
  done
}
