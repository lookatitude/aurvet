# Contributing to aurvet

Thanks for looking. aurvet is a security tool, so a few of the conventions here
are stricter than you might expect from a project this small. Each one exists
because of a specific failure mode, and this document says which.

## Where work goes

Three branches:

| branch | role |
|---|---|
| **`dev`** | integration. **Target your pull request here** — it is the default branch, so GitHub does this for you. |
| **`next`** | release stabilisation. release-please maintains the release PR here. |
| **`main`** | tagged production only. Fast-forward from `next`; force-push-proof for everyone including the maintainer. |

Promotion is `dev → next → main`, fast-forward only. Tags are cut on `main`, and
tagging is what publishes artifacts. `main` cannot be force-pushed or deleted by
anyone, on purpose: the threat model treats "an attacker cannot rewrite remote
history" as a real control, and that is only true if the remote forbids it.

## Commit messages are a contract

This project uses [Conventional Commits](https://www.conventionalcommits.org/),
and it is not cosmetic: release-please derives the version bump and the changelog
directly from your commit subjects. A commit that ignores the convention produces
a release note nobody can read, or a version bump that does not happen.

```
feat(report): add --since-last diff against the previous scan
fix(alpm): record a coverage gap when files is unreadable
docs(spec): scope the pkgbase rule
ci: pin actions to commit SHAs
```

`fix:` → patch · `feat:` → minor · `!` or `BREAKING CHANGE:` → major. Scopes match
the package you touched (`alpm`, `aur`, `check`, `report`, `config`, `buildinfo`).

## Test-driven, strictly

The expectation is a real red/green cycle, and pull requests are read with that
in mind:

1. **Write the failing test first.**
2. **Run it and look at the failure.** Confirm it fails for the reason you
   intended — not a typo, not a build error in the wrong place.
3. Write the minimum implementation that passes.
4. Re-run.

If you are fixing a bug, the test that would have caught it goes in the same
commit. If an assertion could never have failed against the old code, say so in
the PR — a test that only appears to cover something is worse than no test,
because it reads as coverage.

## Running things

```sh
make build              # host binary
make test               # full suite
make test-short         # skips the tests that build a binary (faster loop)
make vet
make fmt-check          # CI fails if this fails
make version            # what build identity this tree reports
make dist VERSION=x.y.z # release artifacts
make checksums
make verify-reproducible
make help
```

`make test` is what CI runs. Note it is **not** run with `-short`: the short flag
skips the tests that build a binary, which are exactly the linkage and
version-injection tests, and a skipped linkage test is the same as no linkage test.

## The zero-dependency policy

aurvet has **no third-party Go dependencies**, and CI fails if one appears.

`golang.org/x/sys` is the only sanctioned future dependency, arriving at P1-B for
`capset`/`prctl` — the privilege boundary is the wrong place to hand-roll syscall
structs. Anything else must be justified in the pull request that adds it.

This is not minimalism for its own sake. Dependencies must be vendored so the
build performs no network fetch, because a build-time fetch is a critical finding
under aurvet's own rules — a packaging recipe for this tool that reached the
network would fail the tool's own analysis.

## Invariants a patch must not break

These are the load-bearing ones. The full set is in `docs/spec.html`.

- **INV-2 — parse, never execute.** No shelling out to `pacman`, `bash`, `git`, or
  any helper; no sourcing a PKGBUILD, not even sandboxed. Parse the on-disk
  formats directly. This extends to tests: use `debug/elf`, not `readelf`; never
  `ldd`, which runs the binary's interpreter.
- **INV-3 — never claim clean for what was not examined.** Coverage gaps are
  first-class and force exit `3`.
- **INV-4 — collectors are pure `(root, cfg) -> evidence`.** No ambient `$HOME`,
  no hardcoded `/`. Every path derives from an explicit root — that is what makes
  every test a fixture-root test. `internal/config` is the single place ambient
  environment is legitimately read.
- **INV-6 — findings state their own limits** in output, not in documentation.
- **INV-10 — every check declares its evidence precondition** and reports
  *unavailable* rather than passing when its evidence is missing. An absent field
  must never read as agreement.

Two consequences worth internalising: **a missed detection is a vulnerability
here, not a feature request** (see `SECURITY.md`), and **severity inflation is a
real failure mode** — a rule that fires on a third of a clean system spends the
operator's attention and trains them to ignore output.

## Reporting a security issue

Do **not** open a public issue. See [`SECURITY.md`](SECURITY.md) — and note that a
false clean, a verification bypass, and an evasion are all explicitly treated as
vulnerabilities.

## Pull request expectations

- One logical change. Conventional-commit title.
- Tests included, and a note if any assertion was not red-provable.
- Say which invariants you considered if you touched a check, a parser, or the
  build.
- Justify any dependency.
- `make test`, `make vet` and `make fmt-check` green.

Comments should explain *why*. When a change fixes a defect, the comment names the
defect — the existing code has several examples of that style; follow them.
