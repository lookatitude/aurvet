# Security policy

aurvet is a security tool, which makes its own failures security-relevant. This
policy is deliberately two-sided:

- **Reporting a vulnerability *in* aurvet** — this document.
- **Responding to something aurvet *found* on your system** —
  [`docs/reporting-malware.md`](docs/reporting-malware.md).

## Status

**v0.0.x is pre-1.0, alpha, and has not been independently audited.** It has no
release signing yet. Treat its output as evidence to investigate, not as a
verdict to act on blindly. If you need a guarantee, this is not yet the tool that
gives you one.

## Supported versions

Only the latest release. Pre-1.0 means no backports.

## Reporting a vulnerability

Use **[GitHub private vulnerability reporting](https://github.com/lookatitude/aurvet/security/advisories/new)**
(enabled on this repository). Please do **not** open a public issue for anything
in the in-scope list below.

**Expectations, stated honestly.** This is a single-maintainer, pre-1.0 project.
There is no paid on-call rotation and no service-level agreement. Best effort:
acknowledgement within about a week, and a fix or a documented decision when the
work allows. If that is too slow for your disclosure timeline, say so in your
report and we will agree something explicitly rather than leave you guessing. No
bug bounty is offered.

## In scope — read this part first

**A missed detection is a vulnerability in this project, not a feature request.**
That is unusual, and it is deliberate. Users act on a clean report: they install
the package, they stop investigating, they conclude the machine is fine. A tool
that says "clean" when it is not has caused the harm it exists to prevent. So the
following are explicitly vulnerabilities, and are the reports this project most
wants:

### False negatives

- **A false clean.** aurvet reports no findings — or exits `0` — on a package or
  system that is in fact compromised. This is the headline case.
- **A verification bypass.** Anything that defeats a check while leaving it
  looking as though it ran. A check that is silently a no-op is worse than a
  check that is absent, because the absence would at least be visible.
- **An evasion.** A package, repository state, or on-disk arrangement crafted so
  that a check does not fire — for example metadata shaped to dodge the
  tombstone lookup, or a package base chosen to make the AUR record unresolvable.
- **A coverage gap reported as coverage.** aurvet claiming, directly or by
  omission, to have examined something it did not. The project's invariants say
  a check with missing evidence must report *unavailable* rather than pass
  (INV-3, INV-9, INV-10); a violation of that is in scope even if no wrong
  finding is produced, because the exit code and the coverage summary are what
  automation trusts.

### Ordinary vulnerability classes

- **Parsing an attacker-controlled input unsafely.** aurvet reads the pacman
  local DB, sync DBs, and AUR HTTP responses, all of which can be hostile.
  Crashes, hangs, unbounded memory growth, or path traversal from any of those
  are in scope. Note that aurvet's design forbids *executing* what it parses
  (INV-2 — PKGBUILDs and scriptlets are tokenised, never sourced, never run); any
  path that results in execution is a serious finding.
- **Privilege or file-access issues.** Reading or writing outside the paths
  derived from the configured root, following a symlink out of an offline root,
  or resolving state into a location an unprivileged attacker can pre-seed.
- **Anything that makes output untrustworthy** — for example a finding
  fingerprint that can be forged to suppress a real finding, or a way to make
  the tool misreport its own version or provenance.
- **Network trust issues** — accepting an AUR response in a way that lets a
  network attacker manufacture a clean result, or turn a network failure into an
  "absent from the AUR" conclusion.

## Out of scope

Stated fairly, not as a way to dodge the list above:

- **A true finding you consider unhelpful.** If aurvet correctly reports that a
  package is absent from the AUR and you know why, that is working as intended.
  The tool reports what it can establish and states what it cannot.
- **Severity disagreements**, on their own. There is a documented vocabulary
  (`critical`, `suspicious`, `info`) and a reporting floor that gates the exit
  code. If you think a rule sits at the wrong level, open a normal issue — that
  is a design conversation, not a vulnerability. *Unless* the wrong level causes
  a real compromise to be filtered out of a default run, in which case it is a
  false clean and belongs above.
- **The tool's documented limits.** aurvet checks *packaging provenance*. It
  says nothing about whether upstream source code is malicious, and a clean
  provenance result on a genuinely backdoored release is a known and documented
  limitation rather than a bypass. It also cannot see what it was never given —
  an offline root missing its sync databases, for example.
- **Findings requiring an already-root attacker** on the machine being scanned,
  where the attacker could simply replace the binary.
- Vulnerabilities in Go, pacman, or the AUR itself. Report those upstream.

## Privacy

Verified against the source, not assumed
(`internal/aur/http.go`, `cmd/aurvet/main.go`, `internal/report/store.go`,
`internal/config/config.go`):

- **What leaves your machine.** aurvet contacts exactly one host,
  `https://aur.archlinux.org` — the RPC endpoint (`/rpc/`) and the cgit log
  (`/cgit/aur.git/log/`). It sends the **names of the foreign packages you have
  installed**, as query parameters, plus a `User-Agent` of `aurvet`. That
  disclosure is inherent to asking the AUR about your packages, but you should
  know it happens: the list of AUR packages on a machine can be identifying.
- **There is no telemetry.** No analytics, no crash reporting, no phone-home.
  `net/http` appears in exactly two files, both for the AUR lookups above.
- **`--no-network` means it.** On that path the HTTP client is never even
  constructed, so no request can be made. The checks that needed the network
  become coverage gaps and the scan exits `3` rather than reporting a clean
  result it did not earn.
- **What is stored locally.** Scan reports are written to
  `$XDG_STATE_HOME/aurvet/reports/` (falling back to
  `$HOME/.local/state/aurvet/reports/`), directory mode `0700` and files `0600` —
  not world-readable, because a report enumerates your installed packages and
  any findings against them. Nothing is sent anywhere else.

## Credit

Reporters are credited in the release notes and `CHANGELOG.md` unless they ask
not to be.
