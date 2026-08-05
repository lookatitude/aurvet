<!-- Title must be a Conventional Commit: release-please derives the version and
     changelog from it. e.g. fix(alpm): record a gap when files is unreadable -->

## What and why

<!-- What changes, and what problem it solves. If it fixes a defect, name the
     defect — the codebase comments in that style. -->

## Tests

- [ ] Test written **before** the implementation, and observed failing for the
      intended reason
- [ ] `make test` green
- [ ] `make vet` and `make fmt-check` green

<!-- If any assertion could NOT have failed against the old code, say so. A test
     that only appears to cover something is worse than none — it reads as
     coverage. -->

## Invariants

<!-- Required if you touched a check, a parser, or the build. -->

- [ ] INV-2 — parses, never executes (no shelling out; no sourcing a PKGBUILD)
- [ ] INV-3 — never claims clean for what was not examined; gaps stay first-class
- [ ] INV-4 — paths derive from an explicit root, no ambient `$HOME`
- [ ] INV-6 — findings state their own limits in output
- [ ] INV-10 — a check with missing evidence reports *unavailable*, not a pass
- [ ] Not applicable

## Dependencies

- [ ] Adds no third-party dependency
- [ ] Adds one, justified here:

<!-- CI fails on an unsanctioned dependency. Deps must be vendored so the build
     performs no network fetch — a build-time fetch is a critical finding under
     aurvet's own rules. -->

## Severity (if you added or changed a rule)

<!-- What severity, and why that level? A rule that fires on a large share of a
     clean system is noise, and severity inflation trains operators to ignore
     output. -->
