# testdata/pkgbuild provenance

Fixtures copied from the reference system's `yay` cache (`~/.cache/yay`,
34 PKGBUILDs, measured 2026-08-05). The cache itself is 88 GB and must not enter
the repository; these are the smallest excerpts that carry the constructs the
tokeniser has to survive.

| Fixture | Upstream | Extent | Why it is here |
| --- | --- | --- | --- |
| `gdm-settings.pkgbuild` | AUR `gdm-settings` | verbatim, whole file (26 lines) | the ordinary case: plain `source=()`, `rename::url`, `build`/`check`/`package` |
| `dart-sdk-dev.pkgbuild` | AUR `dart-sdk-dev` | verbatim, whole file (27 lines) | the corpus's only strict `${var//x/y}` substitution inside a source URL |
| `rustdesk-bin.pkgbuild` | AUR `rustdesk-bin` | verbatim, whole file (55 lines) | `source_x86_64` + `source_aarch64` with paired `sha256sums_*`, `${pkgbase%-bin}`, `${pkgver/_/-}` |
| `flutter-eval-excerpt.pkgbuild` | AUR `flutter` | lines 5-8 and 708-715, verbatim, concatenated with one blank line | `eval "package_$_p() {` — the generated package functions that are why zero cached PKGBUILDs contain a literal `package_*()` |
| `flutter-bin-heredoc-excerpt.pkgbuild` | AUR `flutter-bin` | lines 105-124 verbatim plus a synthesised closing `}` | quoted heredocs whose *bodies* contain a `source` builtin and a `$(...)`; parsing a heredoc body as commands invents an external include that the recipe never executes at build time |

The two excerpt files are excerpts, not recipes: they are not valid standalone
PKGBUILDs and are never fed to anything but the tokeniser.
