# testdata/own — ownership-oracle fixtures

`internal/own` answers "does any installed package own this path?", and the
only interesting inputs are *shapes*, not documents: a directory symlink, an
absolute link target, a link loop, a link that leaves the scanned root. There
is nothing to check in that a text file could carry.

**Nothing is checked in here on purpose.** The tree is materialized in
`t.TempDir()` by `tree()` in `internal/own/index_test.go`, in the same spirit
as `testdata/fsx`: git cannot represent a symlink loop usefully, and a link
whose target escapes the repository is exactly the object a checkout should not
be asked to create. A fixture that makes `git clone` hostile is not a fixture.

## The tree the tests build

    <tmp>/outside/secret          a path the oracle must never resolve into
    <tmp>/root/usr/bin/hello      package-owned (coreutils)
    <tmp>/root/usr/lib/libx.so    package-owned (glibc)
    <tmp>/root/usr/local/bin/rat  an unowned file that really exists
    <tmp>/root/bin   -> usr/bin     relative directory link — Arch's own shape
    <tmp>/root/lib   -> usr/lib
    <tmp>/root/sbin  -> /usr/bin    absolute target, re-rooted at the scan root
    <tmp>/root/loopa -> loopb       a loop
    <tmp>/root/loopb -> loopa
    <tmp>/root/esc   -> ../outside  escapes the root

`usr/local/bin/rat` is an **inert marker**: the word is the whole payload. It
exists so the "unowned but present" case is a real file rather than an absence,
because absence and non-ownership are different answers and the tests assert
both separately.

## What each shape pins

| Shape                          | Expected answer                                |
| ------------------------------ | ---------------------------------------------- |
| `usr/bin/hello`                | `Owned` with no syscall at all (literal hit)   |
| `/bin/hello`, `/lib/libx.so`   | `Owned` — resolved through a directory symlink |
| `/sbin/hello`                  | `Owned` — absolute target read root-relative   |
| `/usr/local/bin/rat`           | `Unowned` — present, and nobody's              |
| `/usr/bin/nope`                | `Unowned` — ENOENT is a definite answer        |
| `/loopa/...`, `/esc/secret`    | `Unresolved` — a coverage gap (INV-9)          |
| `""`, `..`, a NUL              | `Unresolved` — refused before any syscall      |

## The live measurement

`TestLiveReferenceSystem` is skipped unless `AURVET_LIVE_OWN=1`; it reads
`/var/lib/pacman/local` and `/`, which no unit test may depend on. Measured
2026-08-05 on the reference system, unprivileged:

    packages=1410 db-gaps=0 indexed-paths=416981
    resolver: walked=416981 unchanged=367942 rewritten=49033
              rewritten-to-unowned=24 unresolvable=6

The 6 unresolvable paths are all EACCES on a parent directory
(`var/named`, `var/spool/cups`, `var/cache/cups`, `var/db/sudo`) and are
coverage gaps for an unprivileged run, not findings; the P1-B collector holds
`CAP_DAC_READ_SEARCH` and does not hit them. The 24 links that resolve to an
unowned target are legitimate — `etc/mtab -> proc/N/mounts`, the generated
`ca-certificates` bundles, JVM shims — and are the population any later
"unowned target" rule must expect to see before it calls one suspicious.
