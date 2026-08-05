module github.com/lookatitude/aurvet

// Floor is 1.24 for os.Root, the traversal-resistant file API used by the
// P1-B collector. Arch currently ships 1.26.x.
go 1.24

// Reproducibility is a security property here, not a nicety: spec §16 makes
// reproducible builds the answer to "why should anyone trust a security tool
// that arrives as an unvetted AUR package", and two different Go versions
// produce two different binaries from identical source.
//
// The two directives above and below do DIFFERENT jobs, and deliberately carry
// different versions:
//
//   go 1.24        the floor a consumer needs. Load-bearing (os.Root, P1-B).
//                  Raising it would lock out builders for no benefit.
//   toolchain      the compiler that stamps a RELEASE.
//
// How the release pin is actually enforced -- measured 2026-08-05, because the
// obvious assumption is wrong: `GOTOOLCHAIN=local` (which the Makefile and CI
// both set) IGNORES this directive completely. A toolchain line naming a
// version the local install does not have is silently disregarded, not an
// error. So this line does NOT pin anything on its own.
//
// It binds in CI, but NOT the way the documentation suggests. Measured against
// a real run: actions/setup-go with `go-version-file: go.mod` resolved "version
// spec 1.24" and installed go1.24.13 -- it read the `go` directive and ignored
// this one, so the pin bound to NOTHING. The workflows therefore parse this
// line out of go.mod themselves, pass it to setup-go as an explicit
// `go-version`, and then assert `go env GOVERSION` matches. A reproducibility
// guarantee that is not enforced is not a guarantee.
//
// Locally, GOTOOLCHAIN=local prevents a surprise toolchain DOWNLOAD -- with the
// default GOTOOLCHAIN=auto, Go would try to fetch this version over the
// network, which is not something a security tool's build should do behind the
// maintainer's back.
//
// Consequence worth knowing: a contributor on Go 1.24 builds fine and gets a
// binary that will NOT match a release hash. That is expected; release
// reproducibility is a property of the CI toolchain, not of every dev machine.
//
// CAVEAT, and it is a real gap: this pins the toolchain VERSION but cannot pin
// a GOEXPERIMENT. A toolchain built with a non-default experiment (the dev
// machine used for P1-A ran go1.26.5-X:nodwarf5) emits different bytes from a
// stock release of the same version, so `make verify-reproducible` reports the
// toolchain identity it used and reproduction requires a STOCK toolchain. See
// docs/RELEASING.md.
toolchain go1.26.5
