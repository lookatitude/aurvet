# AUR recipes

Three AUR names, three separate AUR git repositories, three recipes. They do not
share a `PKGBUILD`.

| Name | Recipe | Sources | Publishable |
|---|---|---|---|
| `aurvet` | `../../PKGBUILD` (repo root, canonical) | release tarball | **after** the release |
| `aurvet-git` | `aurvet-git/PKGBUILD` | `git+…#branch=main` | **now** |
| `aurvet-bin` | `aurvet-bin/PKGBUILD` | release binaries + `SHA256SUMS` | **after** the release |

The root `PKGBUILD` is the canonical source package and stays at the repository
root because CI reads it there by exact name — the `.SRCINFO` sync check, the
sentinel assertions, `namcap`, and the self-gate that runs `aurvet review .`
against it. Nothing in CI globs for `PKGBUILD`, so these two do not collide with
it, and they are **not** covered by those checks. Run them by hand (below).

## Why only `aurvet-git` can go first

Spec §16, corrected 2026-08-06: AUR names are claimed **with** the first release,
not on day one. The AUR has no reservation step — a name is claimed by pushing a
package that builds — and both the canonical and `-bin` recipes source release
assets whose hashes are unknowable until the release exists. Their sentinels make
them refuse to build until then, so pushing early publishes an unbuildable
package, which is what gets removed.

A VCS source has nothing stable to hash. `aurvet-git` is complete today.

## Before any push

These recipes are not covered by CI. Check them yourself:

```sh
cd packaging/aur/<name>
bash -n PKGBUILD                      # syntax
aurvet review .                       # aurvet's own rules on its own recipe
makepkg --printsrcinfo > .SRCINFO     # regenerate; the AUR reads this, not the PKGBUILD
pkgctl build --clean                  # devtools chroot; needs systemd-nspawn
namcap *.pkg.tar.zst
```

`aurvet review .` on `aurvet-git` exits **3**, not 0, and that is correct: the
`vcs-delta-no-anchor` gap says there is no upstream checkout beside the recipe to
diff commits against. Zero findings. Exit 3 means *incomplete coverage*, never
*findings* — do not "fix" it by ignoring the gap.

## Pushing

The repository is created by the first push. An empty-repository warning on clone
is expected for a name nobody holds. Branch is `master`, not `main`.

```sh
git clone ssh://aur@aur.archlinux.org/<name>.git aur-<name>
cd aur-<name>
cp /path/to/aurvet/packaging/aur/<name>/{PKGBUILD,.SRCINFO} .
git add PKGBUILD .SRCINFO
git commit -m "<name> <version>-1: initial release"
git push origin master
```

Only `PKGBUILD` and `.SRCINFO` (plus any small patch or `.install`). No binaries,
no tarballs, no vendored source.

## After the release: replacing the `-bin` sentinels

`aurvet-bin` carries four all-zero sentinels — one per source, plus `_commit`.
`prepare()` refuses to run on the `_commit` sentinel, so the recipe cannot ship a
binary reporting `commit 000000000000`.

```sh
v=0.0.1
cd packaging/aur/aurvet-bin
# from the published assets
sha256sum aurvet-$v-x86_64 aurvet-$v-aarch64 aurvet-$v.tar.gz SHA256SUMS
sed -i "s/^_commit=.*/_commit='$(git -C ../../.. rev-parse v$v^{commit})'/" PKGBUILD
# then replace each sha256sums* entry with the matching hash
makepkg --printsrcinfo > .SRCINFO
```

`options=('!strip')` is load-bearing in that recipe: makepkg strips after
staging, and a stripped binary is no longer the binary the release hashed, so the
published `SHA256SUMS` would stop verifying what the user installed. That is the
only verification path a `-bin` package has.

## Keeping `.SRCINFO` in sync

The AUR shows users (and helper search) the `.SRCINFO`, not the `PKGBUILD`. Every
metadata change needs `makepkg --printsrcinfo > .SRCINFO` re-run and committed in
the same commit. CI enforces this for the root recipe and **cannot see these
two** — the roadmap's scheduled diff of the live AUR copy against upstream is the
control that would.

Version bumps here are manual: release-please has no `extra-files` configured, so
it does not touch any `pkgver`.
