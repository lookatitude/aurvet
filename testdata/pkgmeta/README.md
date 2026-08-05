# testdata/pkgmeta — real `.SRCINFO` and `.BUILDINFO` files

Unlike `testdata/helper` and `testdata/vcs`, these fixtures **are** checked in:
they are documents, not directory shapes, and every one of them was taken
verbatim off the reference system on 2026-08-05. Nothing here is synthesised,
because the point of each file is a real-world shape that a hand-written fixture
would have smoothed over.

| File | Provenance | What it pins |
| ---- | ---------- | ------------ |
| `kind.SRCINFO` | `~/.cache/yay/kind/.SRCINFO` | the ordinary case: one pkgbase, one pkgname, 1 remote source and 2 local files, 3 `optdepends` with descriptions |
| `flutter.SRCINFO` | `~/.cache/yay/flutter/.SRCINFO` | a **split** base: 1 pkgbase, **17** pkgnames, 25 unsuffixed sources plus **12 `source_x86_64` and 6 `source_aarch64`**, and `makedepends = dart>=3.11.0` / `dart<3.12.0` (two constraints, one package) |
| `nperf-gui-appimage.SRCINFO` | `~/.cache/yay/nperf-gui-appimage/.SRCINFO` | its `pkgname` line is **TAB-INDENTED**. A parser that splits sections on indentation reads this real file as a base with *zero* packages — and then `IsSplit`, `PkgNames` and every per-package rule are silently wrong for it |
| `rustdesk.BUILDINFO` | `.BUILDINFO` member of `~/.cache/yay/rustdesk-bin/rustdesk-1.4.6-2-x86_64.pkg.tar.zst` | `pkgbuild_sha256sum`, and **`builddir = startdir = /github/workspace/res`** — this `-bin` package's archive was built in CI, so its recorded PKGBUILD digest is over a recipe nobody on this machine ever had. 278 `installed` entries, which is why `MaxValuesPerKey` exists |

No path in these files names a person: the one `.BUILDINFO` here happens to
record a CI workspace. That was luck, not curation — a locally built package
records the user's home directory in `builddir`, so anything added later must be
checked before it is committed.

## The `.BUILDINFO` decompression decision

`.BUILDINFO` lives inside a `.pkg.tar.*`. Measured in the reference cache: **229
of 233 archives are `.pkg.tar.zst`** and the other 4 are `.pkg.tar.xz`. Neither
zstd nor xz is in the Go standard library, and the only sanctioned dependency in
this module is `golang.org/x/sys`, which is not a decompressor.

The three options were: add a module (refused by the dependency policy), shell
out to `bsdtar` (refused by INV-2), or read what is reachable and report the rest
as a coverage gap. The third is what `internal/pkgmeta` does:

- `ParseBuildInfo(io.Reader)` — the primitive; works on an unpacked file, an
  archive member, or a snapshot
- `BuildInfoFromFile(root, rel)` — an unpacked `.BUILDINFO`, confined
- `BuildInfoFromArchive(name, r)` — `.pkg.tar` and `.pkg.tar.gz` via the
  standard library; anything else returns `ErrCompression` **naming the
  algorithm** and saying where the same fact can still be read

So on a stock Arch system this reader answers from the build directory or from a
snapshot, and reports the archive as a gap. That is not a shortfall of the
reader; it is the argument for `snapshot` (spec §7), stated as a measurement:
`readable-buildinfo=0` out of 233 archives on this machine.

## The split-package trap

Four different measurements of "how many installed packages are split", all on
the same machine (`AURVET_LIVE_PKGMETA=1`, 2026-08-05, 1410 installed, 15,428
sync entries):

    (1) %BASE% != %NAME% in the local DB ............... 237
    (2) sharing a base with another INSTALLED package ... 269
    (3) either of the above ............................ 296
    (4) pkgbase ships >1 package IN THE REPOSITORIES ... 432   <- the one used
        installed packages whose base is in no repository (foreign) = 39

(4) is the roadmap's number and needs **sync**-database metadata. A splitness
test built on the local DB alone reports 237, looks like the roadmap is wrong,
and misses the ~195 packages whose siblings simply are not installed here. A
`.SRCINFO` answers (4) directly — it lists every `pkgname` the base builds
whether or not it is installed — which is why `SRCINFO.IsSplit` is the
recipe-side answer and `TestLiveSplitPackageCount` cross-checks it against the
sync databases.
