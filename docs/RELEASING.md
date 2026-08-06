# Releasing aurvet

The maintainer runbook. You should not need to read any workflow YAML to cut a
release; if you do, this document has a gap worth fixing.

## The shape of it

```
   PRs ──▶ dev ──────▶ next ────────────▶ main ──▶ tag vX.Y.Z ──▶ artifacts
        integration   stabilisation      production      │
                      (release-please     (ff only)      └─ release.yml publishes
                       proposes version                     tarball + binaries
                       and changelog)                       + SHA256SUMS
```

Two tools, deliberately separated: **release-please decides the version and
writes the changelog**; **`release.yml` publishes the artifacts**. Neither does
the other's job, so a changelog mistake cannot publish an unverified binary and a
build failure cannot silently ship a version bump.

## Cutting a release

### 1. Land the work on `dev`

Ordinary pull requests, conventional-commit subjects. `dev` is the default branch
so PRs target it automatically. CI must be green.

### 2. Promote `dev` → `next`

```sh
git checkout next && git merge --ff-only dev && git push
```

Fast-forward only. If it refuses, `next` has something `dev` does not — reconcile
before continuing rather than forcing.

### 3. Merge the release PR on `next`

Pushing to `next` makes release-please open (or update) a
`chore(main): release X.Y.Z` pull request against `next`. It contains the version
bump and the generated `CHANGELOG.md` entry.

**Read the changelog before merging.** This is the one editorial checkpoint in the
process — generated entries are only as intelligible as the commit subjects they
came from. Fix wording in the PR if a line would not make sense to a stranger.

Merge it when you are happy.

### 4. Promote `next` → `main`

```sh
git checkout main && git merge --ff-only next && git push
```

### 5. Tag on `main`

```sh
git tag -a v0.0.1 -m "aurvet v0.0.1"
git push origin v0.0.1
```

The tag is what triggers publication. `release.yml` then:

1. builds the artifacts on **two independent runners**;
2. compares the hashes — **if they differ, it refuses to publish**;
3. assembles `SHA256SUMS`;
4. creates the GitHub release with the `git archive` tarball and both binaries.

### 6. Verify what was published

```sh
sha256sum -c SHA256SUMS
./aurvet-<version>-x86_64 version    # must report the version and commit
```

## Reproducibility, and how to read a mismatch

The release refuses to publish unless two runners agree byte-for-byte. To
reproduce a release yourself:

```sh
git checkout v0.0.1
make verify-reproducible
```

**A mismatch is not automatically tampering.** The overwhelmingly common cause is
a different toolchain, so `verify-reproducible` prints the toolchain identity it
used before it prints any verdict. Two things pin a build:

- `go.mod`'s `toolchain` directive — the Go **version** that stamps releases.
- `GOTOOLCHAIN=local` — prevents Go from silently downloading a *different*
  toolchain mid-build.

**How that pin is actually enforced, because the intuitive way silently fails.**
Handing `go-version-file: go.mod` to `actions/setup-go` does *not* honour the
`toolchain` directive — measured on a real run, it resolved the `go` directive
(1.24) and installed go1.24.13. `GOTOOLCHAIN=local` ignores the directive too. So
the workflows parse the `toolchain` line out of `go.mod` themselves, pass it to
`setup-go` explicitly, and then assert that `go env GOVERSION` matches, failing
the job if it does not. The release job refuses to build on a mismatch.

If you edit either workflow, keep that assertion. Without it the pipeline can
drift back to whatever toolchain `setup-go` happens to pick, and the
reproducibility story becomes a claim rather than a guarantee.

What they **cannot** pin is a `GOEXPERIMENT`. A toolchain built with a
non-default experiment — for example `go1.26.5-X:nodwarf5` — emits different bytes
from a stock release of the same version. `verify-reproducible` warns explicitly
when it detects one, and `release.yml` **fails the release** rather than publish
from such a toolchain.

So: reproducing a release requires a **stock** Go toolchain at the pinned version.
If you match that and still get a mismatch, that is worth investigating.

Note that `go 1.24` (the floor a consumer needs) and `toolchain go1.26.5` (what
builds a release) are intentionally different versions. Do not "align" them — it
would raise the minimum Go for no benefit.

## Controls that do not exist yet

Be honest about these in release notes rather than letting the reproducibility
story imply more assurance than it provides.

| Control | Status | Blocked on |
|---|---|---|
| Reproducible builds, two-runner diff | **in place** | — |
| `SHA256SUMS` for all artifacts | **in place** | — |
| Static-linkage assertion in CI | **in place** | — |
| Zero-dependency enforcement in CI | **in place** | — |
| **aurvet's own PKGBUILD passes aurvet's own indicators** | **in place** | — `ci.yml`'s `package` job runs `aurvet review` against the repository's own `PKGBUILD` and fails on any finding at or above the default floor. `internal/pkgbuild` landed in P2. |
| `.SRCINFO` asserted in sync | **in place** | — |
| namcap on the built package | **in place**, with three acknowledged notes | `lacks PIE`, `lacks FULL RELRO`, `is unstripped` are allow-listed *by exact text* in `ci.yml` and explained in the PKGBUILD; anything else namcap says fails the job. |
| `staticcheck`, `govulncheck`, `go mod verify` | **in place** | — pinned by exact version, no `\|\| true`. |
| Clean **container** build from a `git archive` tarball | **in place** | — see the caveat below: it is not a devtools chroot. |
| Every `uses:` pinned by commit SHA | **in place**, now *enforced* | a CI step rejects any `uses:` that is not a 40-hex SHA with a `# vX.Y.Z` comment. |
| **`gosec` fully clean** | **partial** | gosec gates, but with eight rule IDs excluded (`G101,G103,G104,G115,G302,G304,G401,G505`), each justified in `ci.yml`. They cover 53 real sites — mostly `f.Close()` after a successful read, `os.Open` of caller-named paths (which is the program), sha1 (git object names) and syscall struct conversions. The honest fix is a reviewed `//nosec` with a justification at each site; until then this control is **not** a clean bill of health. |
| **`pkgctl build` in a real devtools chroot** | **missing** | needs `systemd-nspawn`, which a GitHub runner's container job cannot nest. Run it by hand before any AUR push (below). The container build proves the package builds with nothing from a developer machine present; it does not prove it against the exact `[core]`/`[extra]` snapshot devtools pins. |
| **OpenPGP release signing** | **missing** | a human must generate a *second* OpenPGP identity for release artifacts. `makepkg` only understands OpenPGP (`validpgpkeys`), so ed25519 alone gives AUR users no verification path. The seam is marked in `release.yml` and deliberately not stubbed. |
| **`aurvet-bin` package** | **not written** | a decision. The source package is canonical; a `-bin` asks users to trust a build machine. If it ships it must carry `options=('!strip')` so its bytes are the bytes the release hashed. |
| **AUR packages** (`aurvet`, `-bin`, `-git`) | **not registered** | a decision, and one with a fixed earliest point: **with the first release, not before it.** The AUR has no name-reservation step, so a name is claimed by pushing a package with a valid `PKGBUILD` and `.SRCINFO` -- and this recipe sources a release asset whose hash the sentinels refuse to fake, so it cannot build until that release exists. Pushing early publishes an unbuildable package, which is what gets removed. `aurvet-git` is the exception: it builds from a VCS ref and may precede the release. The spec wants all three claimed so nobody else supplies "the convenient binary build" of a security tool. |
| **Scheduled diff of the live AUR copy against upstream** | **missing** | depends on the AUR names existing. |

## The PKGBUILD, and the two placeholders a release must replace

`PKGBUILD` and `.SRCINFO` live at the repository root and are the canonical
**source** package. Two fields carry deliberate *unpublished-release sentinels*,
and CI enforces both:

| Field | Sentinel | What must replace it |
|---|---|---|
| `sha256sums` | 64 zeros | the sha256 of the published tarball. CI asserts: while tag `v$pkgver` does not exist the sentinel **must** still be there; once it exists the value **must** equal `git archive` of that tag piped through `gzip -n` — byte-for-byte what `make dist` uploads. |
| `_commit` | 40 zeros | the full SHA of the tagged commit. `build()` **refuses to run** on the sentinel, because `check()` compares `aurvet version` against it and would otherwise ship a binary reporting `commit 000000000000`. |

So step 5 of the release (tagging) gains a follow-up: after the release exists,

```sh
v=0.0.1
sha256sum dist/aurvet-$v.tar.gz          # or download the published asset
sed -i "s/^sha256sums=.*/sha256sums=('<that hash>')/" PKGBUILD
sed -i "s/^_commit=.*/_commit='$(git rev-parse v$v^{commit})'/" PKGBUILD
makepkg --printsrcinfo > .SRCINFO        # CI fails if you forget this
```

and then, **before any AUR push**, the chroot build CI cannot do:

```sh
pkgctl build --clean                     # devtools; needs systemd-nspawn
namcap *.pkg.tar.zst                     # expect exactly the three static notes
```

`--skipchecksums` is used by the CI build and *only* by the CI build: it builds a
tarball from the commit under test, which is not the published artifact and
cannot match a published hash. The published hash is checked by its own step
instead. Do not carry `--skipchecksums` into a real release build.

## If something goes wrong

- **The two runners disagree.** The release stops on its own. Check the toolchain
  identity in both job logs first — that explains most mismatches. Do not
  re-run-until-green: a genuinely non-reproducible build is a finding.
- **A tag was pushed by mistake.** `main` forbids force-pushes and deletions for
  everyone, including you — which is deliberate. Prefer releasing a new patch
  version over rewriting history. If you must, protection has to be lifted
  explicitly and put back.
- **release-please proposes the wrong version.** It reads Conventional Commit
  subjects; a mislabelled `feat:` that should have been `fix:` is the usual cause.
  The manifest (`.release-please-manifest.json`) records the last released
  version and is seeded at `0.0.0` so the first release lands on `0.0.1`.
