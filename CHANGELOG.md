<!--
release-please OWNS the top of this file. It writes the `# Changelog` heading and
prepends each new version section directly beneath it.

Do not add a hand-written preamble under that heading. Measured 2026-08-07: an
intro paragraph there was not preserved -- release-please inserted its own h1
above it and DEMOTED the existing one to `## Changelog`, leaving a duplicate
title in the middle of the document and the intro buried below the entries.

Hand-written material goes BELOW the generated sections, under its own `##`
heading, as `## About <version>` does. Commit-message conventions are documented
in CONTRIBUTING.md, which is where a contributor looks for them.
-->

## About 0.0.1

The generated section above lists every commit. This one says what the release
*is*, and — at greater length — what it is not.

The first tagged version. **Pre-1.0, alpha, not independently audited, not
signed.** It answers one question end to end: *is anything I installed from the
AUR known-malicious, provenance-anomalous, or no longer what the package
manager says it should be?*

### The thirteen commands

- **`scan`** — the sweep. Provenance for every installed foreign (AUR) package,
  file integrity against the package's own manifest, persistence surfaces that
  no package owns, and the correlation between them. On the reference system
  that is 39 foreign packages out of 1,410, in one batched AUR request.
- **`review`** / **`install`** — the pre-install gate. Static PKGBUILD analysis,
  dependency-closure review, and a VCS delta against the last approved commit,
  *before* anything is built. Nothing in the recipe is ever executed to analyse
  it.
- **`snapshot`** / **`diff`** / **`baseline`** — the integrity record. An mtree
  baseline, an append-only hash chain over it, ed25519 signing (file key or
  ssh-agent/FIDO2), and drift classified into corroborated, adjudicated and
  unexplained. `diff --since ENTRY` measures from any chain entry.
- **`triage`** / **`adjudicate`** — the suppression lifecycle. Every suppression
  expires; there is no permanent silence, and turning a rule off host-wide takes
  an explicit force flag.
- **`bundle`** / **`update`** — the signed indicator bundle, with a root key set,
  delegation, anti-rollback, and fail-closed paths.
- **`explain <id>`** — the evidence behind one finding, plus an explicit *"what
  this does NOT prove"* section.
- **`doctor`** — every resolved path with per-key provenance.
- **`version`** — build identity, root key fingerprints, delegation expiry and
  the cached bundle version; an honest *"not injected"* when the binary was not
  built by the release pipeline.

Four verification tiers — `meta`, `triage`, `full` (default), `paranoid` — trade
how much of each file is examined against runtime.

### Design decisions you can observe from the outside

- **Coverage is reported, never inferred.** A check whose evidence is missing
  reports *unavailable* instead of passing. Exit `3` means "nothing found, but I
  could not finish" — and it **outranks** exit `1`, because a scan that found
  something *and* could not complete is still incomplete.
- **`--no-network` cannot produce a false clean.** With the network off the HTTP
  client is never constructed; the affected checks become coverage gaps and the
  run exits `3`. A network failure can never be read as "package deleted".
- **Unanalysable input is a gap, never a finding and never silence.** A recipe
  the tokeniser cannot resolve returns *could not analyse* — it is not quietly
  treated as clean, and not inflated into a detection.
- **Exit codes are contractual**: `0` clean and complete · `1` findings at or
  above the floor · `2` bad invocation · `3` incomplete coverage.
- **`--min-severity` gates the exit code, not the display.** Below-floor findings
  are still printed, sorted last — the report never hides what was observed.
- **Statically linked, no third-party dependencies** beyond a single vendored
  `golang.org/x/sys`. A dynamically-linked build could be subverted by
  `LD_PRELOAD` before it could report on `/etc/ld.so.preload`, which is a
  condition this tool rates critical.

### Release engineering

- Reproducible builds: two independent CI runners must produce byte-identical
  binaries or the release is not published. `SHA256SUMS` for every artifact,
  source tarballs from `git archive`.
- CI enforces the project's own invariants as merge gates — the zero-dependency
  policy, a test asserting the binary is statically linked, and a self-gate in
  which **aurvet reviews its own PKGBUILD with its own rules** and fails on any
  finding at or above the default floor.
- Branch flow `dev → next → main`, with `main` force-push-proof.

### Known limits at 0.0.1

Read this section as part of the release, not as small print.

- **Source is out of scope.** A clean result says nothing about whether the
  upstream *source* is malicious. A clean PKGBUILD fetching a backdoored release
  passes.
- **No release signing.** Artifacts are reproducible and hashed, but not
  OpenPGP-signed; the release key does not exist yet. `SHA256SUMS` tells you the
  files agree with each other, not who built them.
- **No AUR package.** Recipes for `aurvet`, `aurvet-bin` and `aurvet-git` live in
  `packaging/aur/`, but none of the three names is registered, so anyone may
  still take them.
- **`pacman` only.** The install gate hands over to `yay`/`paru`/`aurutils` but
  does not wrap them, so a helper invoked directly bypasses it.
- **Root-privileged behaviour is untested.** Every measurement in this release
  comes from unprivileged runs. At `full`, 33 coverage gaps are permission or
  privilege related — 28 unreadable package-owned files, 4 unreadable surface
  directories, and the degraded-run stamp. All of them are *argued* to vanish
  under root. None of it has been observed.
- **The staged privilege drop is not where spec §11.1 wants it.** Phase 2 still
  performs reads driven by parse output, so the capability is held longer than
  the spec describes. The read/parse seam exists (`internal/fsx.Source`); moving
  the drop is a decision about tier semantics, not a refactor.
- **`gosec` runs with eight rule IDs excluded**, each justified in `ci.yml`.
  Gated, but not a clean bill of health.
- **The package build is a clean container, not a devtools chroot.** It proves
  the package builds with nothing from a developer machine present; it does not
  prove it against the `[core]`/`[extra]` snapshot `pkgctl build` pins.
- **The self-gate is inherited, not re-run at tag time.** It passes on every
  commit, but `main`'s branch protection requires only the build job, so it holds
  by convention rather than by ruleset.
