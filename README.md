# aurvet

**Vet AUR packages for signs of compromise, and check whether an Arch system has already been tampered with.**

`aurvet` is a single-binary CLI for Arch Linux. It answers two questions an
Arch user currently has no good way to ask:

1. *Is anything I installed from the AUR known-malicious?*
2. *Does what is on disk still match what the package manager says should be there?*

## Why this exists

AUR packages execute arbitrary code at install time — `PKGBUILD` runs
`prepare()`, `build()` and `package()` as you, and `.install` scriptlets run as
root. Nothing cryptographically vouches for any of it. On a typical system
**every** foreign package reports `%VALIDATION% none`: pacman recorded that it
verified nothing, because there was nothing to verify.

Real compromises have shipped this way. When one is caught, the AUR removes the
package and rewrites its git history with a removal notice — and that notice is
the only definitive, machine-readable signal that a package you have installed
was malicious. Nothing on your system tells you it happened.

## What it does

`aurvet` works in tiers, cheapest and most certain first.

| Tier | What it establishes | Needs |
|---|---|---|
| **Provenance** | Which installed packages are foreign, whether they still exist upstream, and whether any was removed *for malware* | no root, no network for the foreign set; network for upstream checks |
| **Integrity** | Whether files on disk match the digests pacman recorded at install time | root (to read every packaged file) |
| **Persistence** | Whether packages own suspicious autostart, service, hook, or shell-init surfaces | root |
| **Provenance capture** | Records what a package looked like at install time, so a later upstream deletion cannot erase the evidence | a pacman hook |

The design deliberately stops short of being a host IDS. It reasons about
*packages* and the real persistence surfaces they touch — not arbitrary system
state.

## Status

> **v0.0.1 — pre-1.0, alpha, and not independently audited.**
> The provenance tier works end to end. Nothing here is signed yet and there is
> no AUR package. Treat the output as evidence to investigate, not as a verdict.
> If you need a guarantee about your system, this is not yet the tool that gives
> you one.

Today `aurvet` covers the **provenance tier**: `scan`, `explain`, `doctor` and
`version`, with text/JSON output, report persistence and `--since-last`. It does
**not** yet verify file integrity — see [Limits](#limits).

Delivery status and roadmap are tracked outside this file; `docs/roadmap.html`
holds the plan.

## Build

Go 1.24+ (the floor is 1.24 for `os.Root`; Arch ships 1.26). No third-party
dependencies — and CI fails if one appears.

```sh
git clone https://github.com/lookatitude/aurvet && cd aurvet
make build
./aurvet doctor
```

`make help` lists every target. There is **no AUR package yet**, deliberately —
see [Status](#status).

### Verifying a release

Release artifacts ship with `SHA256SUMS`:

```sh
sha256sum -c SHA256SUMS
```

Binaries are statically linked (no `DT_NEEDED`, no `PT_INTERP`) and built
reproducibly — two independent CI runners must produce byte-identical output or
the release is not published. To reproduce a build yourself:

```sh
make verify-reproducible
```

This needs a **stock** Go toolchain matching the `toolchain` directive in
`go.mod`. A `GOEXPERIMENT`-patched toolchain emits different bytes from a stock
release of the same version, so it will report a mismatch that is explained by
your toolchain rather than by tampering — the target prints the toolchain identity
it used so you can tell the two apart.

Artifacts are **not OpenPGP-signed yet**; the release key does not exist.

## Use

```console
$ aurvet doctor
root           /                                              (flag-or-default)
db_path        /var/lib/pacman/local                          (derived)
sync_path      /var/lib/pacman/sync                           (derived)
state_dir      /var/lib/aurvet                                (derived)
min_severity   suspicious                                     (default)
```

`doctor` prints not just each resolved value but **where it came from**, so a
misconfiguration can be traced to its origin rather than guessed at.

### Examining a system you are not booted into

Every path derives from one explicit root, so inspecting a mounted filesystem is
a parameter rather than a separate mode:

```sh
aurvet -offline-root /mnt/target doctor
```

This is the intended way to examine a machine you suspect is compromised: boot
from known-good media, mount the suspect filesystem, and read it with a binary
the suspect system cannot influence.

### Exit codes

Exit codes are contractual — automation branches on them, so they will not drift.

| Code | Meaning |
|---|---|
| `0` | analysis completed; nothing at or above the severity floor |
| `1` | analysis completed; findings reported |
| `2` | the invocation itself was wrong |
| `3` | analysis could not cover what it was asked to cover |

**`3` is the one that matters.** A tool that cannot reach the AUR, or cannot read
part of the package database, must not exit `0` — that would be indistinguishable
from a clean bill of health.

## Design commitments

These are enforced by tests, not just intentions.

- **A failure is a coverage gap, never an absence.** A network error, a timeout,
  or `--no-network` produces a recorded gap. It never produces a finding that
  says a package was deleted upstream. An error must not become an accusation.
- **Coverage is reported, never inferred.** Anything that could not be read is
  named in the output. A file that failed to open is not silently treated as an
  empty file.
- **Only a malware removal is critical.** A package that vanished from the AUR
  for administrative reasons — renamed, merged, superseded — is *suspicious*, not
  critical. A tool that cries wolf gets ignored, and an ignored tool detects
  nothing.
- **When a signal is genuinely ambiguous, say so.** If a removal notice cannot be
  distinguished from an ordinary commit, `aurvet` reports a coverage gap rather
  than guessing. That is the only answer that avoids both a false accusation and
  false assurance.
- **Foreignness comes from the sync database, never from `%VALIDATION%`.** It is
  tempting to treat `%VALIDATION% none` as "from the AUR"; it is wrong.
  `python-pkg_resources` is foreign yet pgp-signed.
- **No executable logic arrives over the network.** Updatable indicators are
  data. All matching logic is compiled into the binary.

## Development

```sh
go test ./...              # 86 tests
gofmt -l . && go vet ./...
```

No test touches the network — the AUR client takes its base URL as a parameter
so tests drive an `httptest` server. This is verified by running the suite in a
network namespace with only loopback available:

```sh
unshare -rn --map-root-user sh -c 'ip link set lo up; go test ./...'
```

Test fixtures under `testdata/` contain **inert markers only** — no working
payloads and no real command-and-control addresses. The cgit fixtures in
`testdata/aur/cgit/` are verbatim captured HTTP responses; see their
`PROVENANCE.md` for what each one pins and why it was captured rather than
constructed.

## Documentation

| Document | What it is |
|---|---|
| `docs/spec.html` | the specification — invariants, evidence sources, detection catalog, trust chain |
| `docs/design-review.html` | the adversarial review that produced the spec, marking which claims were verified against a live system and which were only reported |
| `docs/roadmap.html` | full delivery plan |
| `docs/interface-contracts-p1a.md` | frozen cross-component signatures and open items |
| `docs/RELEASING.md` | how a release is cut, and which controls are still missing |
| `docs/reporting-malware.md` | what to do when a finding is real |
| `CONTRIBUTING.md` | branch flow, commit contract, invariants a patch must not break |
| `SECURITY.md` | how to report a vulnerability — including a false clean, which counts as one |

## Limits

`aurvet` cannot tell you a package is safe. It can tell you that a package was
removed upstream for malware, that files no longer match what was installed, or
that it was unable to check — and it is careful to distinguish the third case
from the first two. A determined attacker who ships a payload as legitimate
package content, and whose package is still present upstream, will not be caught
by the provenance tier.

`pacman -Qkk` already verifies packaged files against recorded digests.
`aurvet`'s contribution at that tier is tamper-evidence — detecting changes to
the recorded digests themselves — not re-implementing the file check.
