# testdata/helper — helper-cache fixtures

`internal/helper` answers "which AUR helper caches exist on this system, and
what do they hold, keyed on pkgbase?". The only interesting inputs are
directory **shapes**, so there is nothing here a text file could carry.

**Nothing is checked in on purpose**, in the same spirit as `testdata/own` and
`testdata/fsx`. The trees are materialized in `t.TempDir()` by `fixtureRoot()`
in `internal/helper/detect_test.go`, because two of the shapes cannot be
represented in git at all:

- a **mode-0 cache directory** (the unreadable-cache case) — git does not carry
  a directory whose mode denies its owner
- a **cache symlinked out of the scanned root** (the escape case) — a fixture
  that makes `git clone` create a link pointing outside the repository is not a
  fixture, it is a hazard

## The four layouts the tests build

    <root>/home/u/.cache/yay/<pkgbase>/                clones directly in the cache dir
    <root>/home/u/.cache/paru/clone/<pkgbase>/         paru's clone/ layout
    <root>/home/u/.cache/pikaur/aur_repos/<pkgbase>/   pkgbase-keyed clones
    <root>/home/u/.cache/aurutils/sync/<pkgbase>/      AURDEST

Each clone carries `PKGBUILD`, `.SRCINFO` and a `.git/` directory, which is the
shape every real clone in the reference cache has (34 of 34).

`pikaur` also keeps `~/.cache/pikaur/build/<pkgname>`. It is **deliberately not
searched**: it is keyed on the package NAME, and 432 of 1410 installed packages
on the reference system have a pkgbase that ships more than one package, so
searching it would enter the same recipe under several keys for exactly those
432. See `DefaultLayouts`.

## What each shape pins

| Shape                                   | Expected answer                                 |
| --------------------------------------- | ----------------------------------------------- |
| any of the four layouts, populated      | a `Cache` with `Clones` keyed on pkgbase        |
| cache directory absent                  | `helper-cache-absent` gap, one per layout       |
| cache directory mode 0                  | `helper-cache-unreadable` — *not* absent        |
| cache directory present and empty       | `helper-cache-empty`, and `Covered() == true`   |
| no cache found anywhere                 | `helper-cache-none` — a run-level gap           |
| `Config.CacheDirs` empty                | `helper-cache-nothing-searched`                 |
| clone directory with no `PKGBUILD`      | reported *and* `helper-clone-no-pkgbuild`       |
| `completion.cache`, `vcs.json`          | not clones, and not gaps                        |
| cache symlinked outside the root        | a gap; never a read outside the root            |
| `CacheDirs` entry absolute or with `..` | `helper-cache-dir-unsafe`, refused before I/O   |

The distinction the whole file exists to defend: **an absent cache is a
coverage gap, not silence.** "I found no helper cache" and "there is no evidence
of AUR activity" are different statements and only the first one is true.

## Live measurement

`TestLiveHelperCaches` is skipped unless `AURVET_LIVE_HELPER=1`. Measured
2026-08-05 on the reference system, unprivileged:

    cache yay  home/miguelp/.cache/yay  clones=34 with-PKGBUILD=34 with-.git=34
    caches=1 gaps=3 covered=true

The three gaps are `paru`, `pikaur` and `aurutils`, none of which is installed.
That is the common case, and it is why the absent path is fixture-covered rather
than left to whatever happens to be on one developer's machine.
