# `testdata/roots/cruft` — a real desktop, five years in

The **hard half** of the INV-8 false-positive gate. Everything in this root is
legitimate and none of it can be explained by `pacman -Qo`. This is P1-C's
largest noise source, and a gate that does not contain it is blind to the
failure mode that matters: on the reference system the design review measured
~1,860 findings and ~427 criticals, **zero of them actionable**.

**Zero criticals here is a release gate.** Exactly one entry in this root is a
true positive (below), and it is `suspicious` at most — it is a hand-written
backup unit, not malware, and the tool cannot tell those apart.

Parsed, never executed (INV-2): every file is mode `0644` text, and the
`ExecStart`/`Exec` targets are placeholder text files.

## The `*.wants` calibration — the number that governs the rule

Measured on the reference system: **30 unowned paths under `*.wants/`** decompose
into **19 benign enablement symlinks, 8 `*.target.wants` directories, and
exactly 1 real hand-written unit.** The rule has three behaviours, not one —
resolve symlink targets, exclude directories, alert only on targets that are
unresolvable or not package-owned — and it must produce **exactly one subject.**

This root reproduces that shape:

| Kind | Count here | Must the rule report it? |
| --- | --- | --- |
| `etc/systemd/system/*.target.wants/` directories | **8** | **No** — `systemctl enable` creates them; no package owns a directory it did not ship. A rule that does not exclude directories reports all 8. |
| Enablement symlinks whose target *is* package-owned | **19** | **No** — the link is unowned, the target is not. 17 use the absolute `/usr/lib/systemd/system/…` form `systemctl enable` writes; 2 use a relative form. A rule that does not resolve the target reports all 19. |
| A `.wants` link to a **hand-written, unowned** unit | **1** | **Yes** — `multi-user.target.wants/local-backup.service` → `../local-backup.service`, owned by nothing. |
| Total unowned paths under `*.wants/` | **28** | 1 subject |

**Discrepancy, recorded rather than papered over:** 19 + 8 + 1 = **28**, not the
30 the roadmap states. The published decomposition is exhaustive *by kind* — any
further path under `*.wants/` is a directory, a link to an owned target, or a
link to an unowned one — so the missing 2 cannot be derived from it. This root
therefore pins the **kinds** and the **one-subject outcome**, which is what the
gate is stated in terms of; it does not pretend to know what the other 2 paths
were. Escalated to the lead with the P1-C receipt.

There is also a **vendor preset** link at
`usr/lib/systemd/system/multi-user.target.wants/foo-daemon.service` (relative
target, shipped by `foo-daemon` and listed in its `%FILES%`, directory entry
included). It is *owned*, so it is not one of the 28 — and it is the reason the
ownership oracle must understand `%FILES%` directory entries, which carry a
trailing `/`.

## Suppression that is benign here

`etc/pacman.d/hooks/60-depmod.hook` is a symlink to `/dev/null`, which masks the
package-owned `usr/share/libalpm/hooks/60-depmod.hook`. This is the documented
way to disable a pacman hook and a real admin practice (here: a locally-built
kernel whose modules `depmod` must not touch).

The same construct is how an attacker disables a hook. **The tool cannot
distinguish the two** (INV-6), which fixes the ceiling: masking a hook is
reportable at `suspicious`, never `critical`, or this root fails the gate. A
masked hook also regenerates nothing, so its outputs must stay under digest
verification — a suppressed hook must never contribute a derived exemption.

## Everything else, and why it is legitimate

| Path | Why `pacman -Qo` cannot explain it, and why it is benign |
| --- | --- |
| `usr/lib/python3.13/site-packages/requests/`, `…dist-info/RECORD` | `pip install` outside a venv: unowned files *inside a packaged directory*. A rule keyed on "unowned file under `/usr/lib`" drowns here. |
| `home/alice/.local/lib/python3.13/site-packages/rich/`, `home/alice/.local/bin/pipx-tool` | `pip install --user` / pipx. Inside a home, so it is only visible at all if per-user paths come from `etc/passwd`. |
| `usr/lib/node_modules/prettier/`, `usr/bin/prettier` → `../lib/node_modules/…` | `npm -g`. Note the **unowned symlink in `/usr/bin`** whose target is also unowned: the shape of an unowned binary on `PATH`, produced by a package manager rather than an attacker. |
| `usr/local/bin/hand-built-tool`, `usr/local/lib/libhand.so.1` | `make install` into `/usr/local`, which is admin territory *by definition* — no package will ever own it. |
| `usr/local/share/pacman-hooks/10-local-report.hook` | A hook in the extra `HookDir` this root's `pacman.conf` adds. Only covered if the override is honoured. |
| `etc/pacman.d/hooks/99-local-mkinitcpio.hook` | A hand-written admin hook that shadows nothing (no system hook shares its name). Unowned, and that is what the directory is *for*. |
| `usr/share/oldpkg/data.conf` | Left behind when `oldpkg` was removed: pacman does not delete a directory that still has files in it. |
| `etc/oldpkg.conf.pacsave` | The `.pacsave` of a removed package's `%BACKUP%` file. |
| `etc/profile.d/local-path.sh` | Hand-written `PATH` addition: an unowned file on a genuine persistence surface. Benign traffic on a high-signal path. |
| `etc/ld.so.preload` (0 bytes) | **Present and empty.** Existence alone is not evidence — the finding is a *non-empty* preload naming an unowned object (see `../malicious/`). A rule that fires on existence fires here. |
| `home/alice/.config/autostart/nextcloud.desktop` | An ordinary XDG autostart entry, unowned, written by an application. |
| `home/alice/.config/systemd/user/rclone-mount.service` | A hand-written **user** unit. Same shape as the system one, different scope. |
| `usr/lib/systemd/system/sysutil-modules.service`'s `ExecStop=sysutil_ioctl …` | A **package-owned** unit naming a **bare** command that resolves to no file in systemd's search path. Structurally copied from systemd's own `systemd-tpm2-swtpm.service`, which is where the shape was measured. It is **not** a coverage gap — the check ran and got a determinate answer — it is `unit-execstart-hijackable` at **`info`**: every search-path directory in this root is mode `0755`, so planting the name already needs the directory owner's privileges. It becomes `suspicious` only where a **group- or world-writable** directory would win, which git cannot store (see Limits). |
| `bob` in `etc/passwd`, no `home/bob` on disk | An **absent** home is not a coverage gap and not a finding — there is nothing to read and nothing was hidden. Only an *unreadable* home is a gap (INV-9), and git cannot store one: see Limits. |
| `buildbot` (`nologin`, `/var/lib/buildbot` absent) | A system account. Walking it as if it were a human's home invents surfaces that do not exist. |

## Limits this fixture cannot encode (INV-6)

- **mtimes** are not preserved by git, so temporal correlation cannot be
  exercised from a checked-in tree. Copy into `t.TempDir()` and set them.
- **Modes** other than the execute bit are not preserved: unowned-SUID and the
  INV-9 unreadable-home gap both need a runtime `chmod`, not a fixture.
- **Absolute symlinks dangle** when read from the repo rather than from a scan
  root. That is correct for an offline root; resolve targets against the root.
