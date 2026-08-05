# `testdata/roots/stock` — a stock install, seen as an offline root

The **benign floor** of the INV-8 false-positive gate: a root where every
persistence surface is accounted for by a package. **Zero criticals here is a
release gate.** If a check fires on this root, the check is wrong, not the
fixture — so every entry below is justified in place, and an entry nobody can
justify must be deleted rather than used later as the excuse for weakening a
rule.

This root is `(root, cfg) -> evidence` input and nothing else (INV-4). It is
**parsed, never executed** (INV-2): no file in it carries the execute bit, and
the ExecStart/Exec targets are placeholder text files, not programs.

## What is here, and why each entry is legitimate

| Path | Why it is benign |
| --- | --- |
| `var/lib/pacman/local/{zlib,foo-bin,foo-lib}-*/` | The three-package local DB the `internal/alpm` tests already pin. **Do not add or remove a package here** — `TestLoadLocalDBFromStockFixture` asserts the count is 3. File *lists* were extended by P1-C; the `desc` fields it asserts on were not touched. |
| `usr/lib/systemd/system/foo.service` | Package-owned unit (in `foo-bin`'s `%FILES%`). `ExecStart=/usr/bin/foo`, also package-owned. Nothing to report. |
| `usr/lib/systemd/system/multi-user.target.wants/foo.service` | A **vendor preset** enablement link, shipped *by the package* (both the `.wants/` directory and the link are in `%FILES%`, which is what pacman records) with a **relative** target `../foo.service`. |
| `etc/systemd/system/multi-user.target.wants/foo.service` | The **admin-side enablement link** `systemctl enable` writes: an **absolute** target, `/usr/lib/systemd/system/foo.service`, which is package-owned. This is the single most common false positive in the whole phase — the link is unowned, the *target* is not. |
| `etc/systemd/system/multi-user.target.wants/` | An unowned **directory**: `systemctl enable` creates it, so no package owns it. The `*.wants` rule excludes directories for exactly this reason. |
| `usr/share/libalpm/hooks/50-foo.hook` | Package-owned pacman hook in the **system** hook dir (active by default; 57 such hooks on the reference system). |
| *(no `etc/pacman.d/hooks`)* | **Absent on purpose.** The admin hook dir does not exist on a stock install. Absence is a fact to record — not an error, and not a coverage gap. |
| `etc/pacman.conf` | No `HookDir` line: the hook set is exactly the default pair. |
| `etc/passwd` | Per-user surfaces are enumerated from *this* file, never from the running user's environment (INV-4). `alice` has a home; `nobody`/`bin` have `/` and a `nologin` shell and must not be walked as if they were real homes. |
| `home/alice/` | An ordinary readable home with nothing planted in it. |
| `usr/bin/foo`, `usr/lib/lib*.so*`, `etc/foo*.conf` | The packaged files themselves, materialised so ownership lookups have something to resolve. Placeholder text, mode `0644`. |

## Limits this fixture cannot encode (INV-6)

- **mtimes.** git does not preserve them, so the temporal correlation key
  (mtree `time=` ≈ `%INSTALLDATE%` ≈ transaction time) cannot be exercised from
  a checked-in tree. A test that needs mtimes must copy this root into a
  `t.TempDir()` and set them itself.
- **Modes and SUID.** Every file is `0644`; git records only the execute bit, so
  the unowned-SUID check needs a runtime `chmod`, not a fixture.
- **Unreadable inputs.** git cannot store a mode-`000` directory, so the INV-9
  coverage-gap path (an unreadable home) is likewise a runtime `chmod` away and
  is not encoded here.
- **Absolute symlinks dangle when read from the repo.** `etc/systemd/system/…/foo.service`
  points at `/usr/lib/systemd/system/foo.service`, which is correct *relative to
  the scanned root* and broken relative to your working directory. That is the
  real shape of an offline root; resolve link targets against the root (the
  confined `internal/fsx` reader), never against the host.
