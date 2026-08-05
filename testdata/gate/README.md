# testdata/gate — the P1-A false-positive release gate fixtures

Three on-disk roots exercise `internal/check.Provenance` through the real
alpm loaders (`alpm.LoadLocalDB`, `alpm.LoadSyncNames`), not a hand-built
`map[string]bool`. Each root's `desc`/`files` pair is checked in as plain
text, in the exact on-disk format `writeLocalPkg` (in
`cmd/aurvet/main_test.go`) produces. The pacman sync DB is a gzipped
tarball, so it is NOT checked in: `internal/check/fpgate_test.go`
materializes it into `t.TempDir()` at runtime from each root's
`sync-names.txt` (one repository package name per line), using the same
tar+gzip shape `writeSyncDB` uses, and then runs the real
`alpm.LoadSyncNames` against it.

FIXTURE CONTENT IS INERT MARKERS ONLY. No working payloads, no real or
plausible C2 addresses, no live URLs, no obfuscated blobs anywhere in this
tree. The "malicious" root is malicious only in the sense that the Go
test's `aur.Fake` reports a cgit removal tombstone for its one package; on
disk it is an ordinary plain-text `desc` file, identical in shape to every
other package fixture here.

## stock — the baseline

Every installed package's name is also listed in `sync-names.txt`, so none
of them are foreign. Zero foreign packages, zero findings, zero criticals —
trivially, and that is the point: this is what a clean, fully-covered
system looks like, with nothing left for `Provenance` to say.

## cruft — benign but messy

Every foreign package here is a shape that LOOKS alarming to a naive
scanner and must NOT reach `SevCritical`:

- `brave-bin` — foreign, present in the AUR, maintainer == submitter.
  Resolves clean: zero findings.
- `tty-clock` — foreign, orphaned in the AUR (maintainer unset).
  Suspicious, never critical: orphaning is a takeover precondition, not
  evidence of one.
- `handoff-pkg` — foreign, current maintainer differs from the original
  submitter. A legitimate maintainer handoff, reported as an identity
  delta, never as malice.
- `nosubmitter-pkg` — foreign, present in the AUR with no submitter on
  record. The identity comparison cannot run, so this produces a coverage
  gap — never a finding, never a critical.
- `dropped-pkg` — foreign, absent from the AUR entirely, with no removal
  tombstone. The dropped-from-the-official-repos case. Suspicious, never
  critical.
- `foo-headers` (declares pkgbase `foo-common`) — a foreign split package
  that resolves cleanly against its declared pkgbase. Zero findings.
- `brave-bin-debug` (declares pkgbase `brave-bin`, a published, clean
  base) — a locally built `-debug` output of a real package.
  `internal/check/provenance.go`'s T1 comment names this by name as a
  deliberate false-positive shape: makepkg never indexes `-debug` outputs
  in the AUR, so it looks unpublished. Lands at `SevSuspicious` via
  `aur-absent`, never critical.

`zlib` is also present here and listed in `sync-names.txt` — i.e. NOT
foreign — ordinary repo noise sitting alongside the messy foreign
packages above.

## malicious — the acceptance counterpart

One foreign package, `librewolf-fix-bin`, for which the test's `aur.Fake`
carries a cgit removal tombstone whose message satisfies
`aur.IsMalwareRemoval`. Exactly one `SevCritical` finding is expected,
rule `aur-tombstone`, subject `librewolf-fix-bin`.

This root exists because "zero criticals on stock and cruft" is
satisfiable by a scanner that reports nothing at all — the single worst
outcome a detection tool can ship. `malicious` is the other half of the
gate: the same `Provenance` code path, in the same test run, must still
raise the one critical it exists to raise.
