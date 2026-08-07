# Changelog

## 0.0.1 (2026-08-07)


### Features

* **alpm:** pacman local/sync DB parsers and foreign classification ([3f839dc](https://github.com/lookatitude/aurvet/commit/3f839dc9a3120bfe99b7c03fe92f1e9f76e6fb6d))
* **aur,finding:** finding model and AUR client, hardened by two adversarial rounds ([be68ac7](https://github.com/lookatitude/aurvet/commit/be68ac7fb1e8f5282c794faa552a58ce8f0dc83b))
* **baseline,chain:** bootstrap refusal, replication anchor, drift buckets ([8d5c3cf](https://github.com/lookatitude/aurvet/commit/8d5c3cfc1ca4892aefb10aed8c461c786751cb78))
* **baseline,pacmanlog:** canonical serialisation, SSHSIG keys, log parsing ([cd3ad4e](https://github.com/lookatitude/aurvet/commit/cd3ad4e6a197fe9518f9adc1c7fc6b8c84b7683a))
* **bundle:** indicator bundle, root key set, delegation, fail-closed paths ([918557a](https://github.com/lookatitude/aurvet/commit/918557ad9f85d1b749c142dc4c525c46706ca9bb))
* **chain,adjudicate:** manifest, hash chain, crash safety, adjudications ([9bc7040](https://github.com/lookatitude/aurvet/commit/9bc70408c14e5fc7b9c0a12d9188249337f0eded))
* **check:** provenance checks -- the join, hardened by two adversarial rounds ([81cde1b](https://github.com/lookatitude/aurvet/commit/81cde1bc6d0154c1e2a497fab3de406e5a85dd60))
* **ci:** dev/next/main flow, reproducible release pipeline, and contributor docs ([72ff76b](https://github.com/lookatitude/aurvet/commit/72ff76b271a91bfafb4575e410725bb0bf34319c))
* **cli:** --allow-degraded, --pkg, update --check, show/diff aliases ([58ae915](https://github.com/lookatitude/aurvet/commit/58ae9151c80b11ad152ee92f4c22a6dd621affda))
* **cli:** triage ack|snooze|note and bundle, closing spec §12's middle weight ([6eb3b43](https://github.com/lookatitude/aurvet/commit/6eb3b43732a7ddb427645ccda9cab01a25ff9b98))
* **cmd:** adjudicate and update, plus the floor lock and a memory fix ([6a518ee](https://github.com/lookatitude/aurvet/commit/6a518ee3ac49f7071c1777fd000e48f79892f5cf))
* **correlate:** the three correlation keys and the critical escalation ([af05f7c](https://github.com/lookatitude/aurvet/commit/af05f7c7af241cbc0965d05e346ba8f169ce8134))
* **diff:** implement --since ENTRY, closing spec §14's last exception ([e9bb49c](https://github.com/lookatitude/aurvet/commit/e9bb49c581aef7dd686c193f22340020f69f825b))
* **fsx:** add Source, the read/parse seam spec §11.1 needs ([58ba224](https://github.com/lookatitude/aurvet/commit/58ba224ef05c82b3785ed44be4f49d40733a3ac1))
* **gate,cmd:** closure review, the review/install commands, and pacman hooks ([93aae6a](https://github.com/lookatitude/aurvet/commit/93aae6a32ec4aead505dc6ae3cf29bb7eb3bb6b7))
* **gate,snapshot,check:** PKGBUILD rules, provenance capture, approval store ([d57f9c0](https://github.com/lookatitude/aurvet/commit/d57f9c091538417ada8a9eacbe4f2a436eea7a87))
* **integrity:** P1-B — mtree, confined I/O, staged privilege, integrity tier ([e64ec07](https://github.com/lookatitude/aurvet/commit/e64ec0711c2b3d2f47ea990e6aa666187b918c25))
* module scaffold, root-derived config, doctor command ([c0ff37f](https://github.com/lookatitude/aurvet/commit/c0ff37f43050fa6b3d95ff61bbdc31e5f4a64dba))
* **own:** ownership oracle and the P1-C false-positive corpus ([464bc1a](https://github.com/lookatitude/aurvet/commit/464bc1acd0bcb85866ce4797aced43cc8c5d2b42))
* **packaging:** add the aurvet-git and aurvet-bin AUR recipes ([c562ef2](https://github.com/lookatitude/aurvet/commit/c562ef2483540f88cb96704357737774e2e4315d))
* **packaging:** PKGBUILD with a working self-gate, hardened units, docs ([ed84019](https://github.com/lookatitude/aurvet/commit/ed8401991d84013631a30b2affedcc8def77b37d))
* **pkgbuild,vcs:** static PKGBUILD analysis and a git reader that never execs ([05cd5b5](https://github.com/lookatitude/aurvet/commit/05cd5b56a10d7b102955e843c3ff0344632f418f))
* **report:** close P1-A -- persistence, --since-last, INV-8 gate, and two defect fixes ([8a9444c](https://github.com/lookatitude/aurvet/commit/8a9444c57cff6ee8b1924df2b7b12add4c910483))
* **report:** text/JSON reporting, exit codes, and scan/explain wiring ([1f12f26](https://github.com/lookatitude/aurvet/commit/1f12f2619bcc493d699be7f8ae1e4953ffd07b7b))
* **scan:** wire integrity, surfaces and correlation into the scan ([f433bbf](https://github.com/lookatitude/aurvet/commit/f433bbf4c89dcd571053ae4c67422bbd85d60e59))
* **surfaces:** a bare command that resolves to nothing is a hole, not a gap ([eb5b2a6](https://github.com/lookatitude/aurvet/commit/eb5b2a63c9aba6e554826fca661adb8c493406d4))
* **surfaces:** persistence surfaces outside package ownership ([00d214d](https://github.com/lookatitude/aurvet/commit/00d214df3457bbc73cf868a525fac7b5d394037e))


### Bug fixes

* **changelog:** stop competing with release-please for the file's top ([50fbb63](https://github.com/lookatitude/aurvet/commit/50fbb63261033290b7d5d19d24787a63c86876e7))
* **ci:** actually pin the release toolchain ([c39a7ca](https://github.com/lookatitude/aurvet/commit/c39a7ca7420199ff71e215b9577ebbf8f32742bc))
* **ci:** the dependency gate failed open the moment vendor/ existed ([729a1ed](https://github.com/lookatitude/aurvet/commit/729a1ed3ee59c819179f6ff28dba29a36c70dfe4))
* **config:** doctor warns when state_dir resolved somewhere unwritable ([a9dda4b](https://github.com/lookatitude/aurvet/commit/a9dda4baa0ab13c69fcab9a21126d27e5897ef31))
* **pkg:** the version identity check reads the first line, and a test says so ([7bdc49b](https://github.com/lookatitude/aurvet/commit/7bdc49bee6fffdddc5090e9bf6b7b4daffb34330))
* **privdrop:** a user namespace can be created and confer nothing ([b7139f5](https://github.com/lookatitude/aurvet/commit/b7139f5432afc59911120734b339c4a4afc6429a))
* **release:** pin 0.0.1, and stop publishing a stale changelog ([75f0084](https://github.com/lookatitude/aurvet/commit/75f0084e5a2763ab5bb60d1868c69c9fc88b1fef))
* **release:** the notes claimed a gate was missing that now exists ([ff9f535](https://github.com/lookatitude/aurvet/commit/ff9f535fe2b2a121d369b8c2299154c0e902b1b6))
* **repro:** annotate the seven permission sites gosec gates on ([d90b5fa](https://github.com/lookatitude/aurvet/commit/d90b5fa1c9a070671a782504d7a462d342d70660))
* **triage:** list must not call an offline tree's store "this host" ([7a7d204](https://github.com/lookatitude/aurvet/commit/7a7d204c0bc37a6d48a940f9b184819a8940b6a5))


### Refactoring

* **alpm,collect:** read the local database once, from phase 1 ([0ee5f31](https://github.com/lookatitude/aurvet/commit/0ee5f31ea1d5d15268282acb8de939b4a43aebde))
* **collect,check:** integrity derives from phase 1, per spec §11.1 ([40235d2](https://github.com/lookatitude/aurvet/commit/40235d2e70ed4f6581f71895fd505cd12eaca4fa))
* **hook:** extract the pacman hook parser into internal/hook ([2c2d241](https://github.com/lookatitude/aurvet/commit/2c2d24145667c678cb6ff6ca2ba85171cec56351))
* the six surface readers take an fsx.Source, not an *os.Root ([b186335](https://github.com/lookatitude/aurvet/commit/b186335bc95ecf09a9807bb677200b3adca7f941))


### Documentation

* AUR names are claimed WITH the first release, not on day one ([dd9f477](https://github.com/lookatitude/aurvet/commit/dd9f4773a52c05b482f1f2d771abdcdc7c9e94b3))
* **cli:** document -tier and four signing flags, and test the parity ([bd54f2e](https://github.com/lookatitude/aurvet/commit/bd54f2ebd6a4ea630144d061b4bfc79d572d7220))
* close J-0, scope the pkgbase rule, fix §4.1's counting unit ([32c36ff](https://github.com/lookatitude/aurvet/commit/32c36ff33a3b0295fa9418186e571280fc6a7ae2))
* fold lane-discovered plan defects into the plan and contract ([82cc781](https://github.com/lookatitude/aurvet/commit/82cc781792353b79e64949c9486c4c35d24039f4))
* freeze P1-A cross-lane interface contracts ([726b2b8](https://github.com/lookatitude/aurvet/commit/726b2b8e95c21a9b10f0e51e9061c9e01d3d7995))
* **integrity:** record the ratified rule for derived exemptions ([16582c7](https://github.com/lookatitude/aurvet/commit/16582c78317079350770325e5dcda4ca2d7e1a97))
* **roadmap:** re-measure the tier table; two numbers had drifted from the binary ([97bb111](https://github.com/lookatitude/aurvet/commit/97bb111b9fdcb1828e3f3a4a6e630572091defea))
* **roadmap:** record the yay/paru limitation and what the AUR item really costs ([93eea15](https://github.com/lookatitude/aurvet/commit/93eea15aee1620ca3ae1cbcb8128ebc489c179a6))
* **spec:** §11.1's remaining work is a decision, not a refactor ([9ea80fd](https://github.com/lookatitude/aurvet/commit/9ea80fd3178df9cd2aeb8cee63fefe360eea1776))
* **spec:** §13's tier numbers were stale, and its triage design is unbuildable ([c27cb97](https://github.com/lookatitude/aurvet/commit/c27cb977b3774cb9456ecf62f43dc9add4d1b456))
* **spec:** add §4.1 -- the sync-DB name oracle fails open ([e65965d](https://github.com/lookatitude/aurvet/commit/e65965de9240240a0f196de763423cc60c403bf8))
* the spec stops claiming a privilege model it only half implements ([a486dfb](https://github.com/lookatitude/aurvet/commit/a486dfb00c62e2f2b708bc5544346f9c593b370a))


### Tests

* **aur:** capture real cgit log pages as fixtures ([3db61bb](https://github.com/lookatitude/aurvet/commit/3db61bbbc33727a9feceafeff7d3522cc2ca134d))
* **integrity:** cover the confined link read with an escape, not a bad path ([8103082](https://github.com/lookatitude/aurvet/commit/81030828ea8576f0bb4d068291b94e09813a1923))


### CI

* **release-please:** add a manual trigger so a startup failure is recoverable ([3daea7c](https://github.com/lookatitude/aurvet/commit/3daea7c3bbb0e6302af787bd7f5837be82a04045))

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
