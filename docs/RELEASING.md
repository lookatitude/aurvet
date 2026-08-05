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

- `go.mod`'s `toolchain` directive — the Go **version** that stamps releases. CI
  installs exactly this via `actions/setup-go`, which prefers the `toolchain`
  directive over the `go` directive.
- `GOTOOLCHAIN=local` — prevents Go from silently downloading a *different*
  toolchain mid-build.

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
| **OpenPGP release signing** | **missing** | a human must generate a *second* OpenPGP identity for release artifacts. `makepkg` only understands OpenPGP (`validpgpkeys`), so ed25519 alone gives AUR users no verification path. The seam is marked in `release.yml` and deliberately not stubbed. |
| **aurvet's own PKGBUILD passes aurvet's own indicators** | **missing** | `internal/pkgbuild`, arriving in P2. The spec requires this as an automated release gate; there is also no PKGBUILD in the repo yet. |
| **AUR packages** (`aurvet`, `-bin`, `-git`) | **not registered** | a decision. The spec advises registering all three names early so nobody else supplies "the convenient binary build" of a security tool. |

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
