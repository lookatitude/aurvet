# `testdata/roots/malicious` — an incident's *shape*, and nothing that can run

## Read this first: nothing here is functional

This directory is named `malicious` because it is the acceptance fixture for a
security tool. **It contains no malware.**

- **No working payload.** The two "binaries" (`usr/lib/systemd/inert-marker-initd`,
  `usr/lib/systemd/libinert-marker-preload.so`) are plain text. The first is a
  shell script whose entire body is a comment and `true`. The second is a text
  file with a `.so` name — not an ELF object, no code at all.
- **Nothing is executable.** Every file is mode `0644`. `find . -type f -executable`
  prints nothing, and a test asserts that.
- **No real addresses.** Every host is in the RFC 2606 `.invalid` TLD, which
  cannot resolve. There is no C2 address, IP literal, domain, port or protocol
  handler anywhere in this tree.
- **No droppers, no encoded blobs.** No base64, no hex blobs, no compressed
  payloads, no `curl | sh`. Nothing is obfuscated, because an obfuscated fixture
  is indistinguishable from the thing it is standing in for.
- **Nothing is executed by the tool either** (INV-2). aurvet parses; it never
  runs a unit, a hook, a scriptlet or a PKGBUILD.

The fixture asserts **structure**, not behaviour. Every marker path contains the
word `inert` so that this stays obvious to a reader skimming it, and to any
scanner crawling this repository.

## The structural shape it reproduces

The 2024 AUR incident (`librewolf-fix-bin` and its siblings, shipping CHAOS RAT)
had three structural properties. Each one is a separate, weak signal; the value
is that they **correlate onto one package**.

| Fact on disk | Where | Correlation key |
| --- | --- | --- |
| **Off-upstream source.** `url=` names the project; `source=` fetches a binary from an unrelated host. | `home/alice/.cache/yay/librewolf-fix-bin/{PKGBUILD,.SRCINFO}` | package |
| **A unit installed by a scriptlet, not by the file list.** `etc/systemd/system/systemd-initd-inert.service` exists on disk and appears in **no** package's `%FILES%`. `pacman -Qo` has nothing to say about it. | `etc/systemd/system/`, `var/lib/pacman/local/librewolf-fix-bin-1.2.0-1/install` | package, path attribution |
| **`ExecStart` to an unowned binary in a package-owned directory.** `/usr/lib/systemd/inert-marker-initd`: `usr/lib/systemd/` is owned by `systemd`, the file is owned by nothing. The lookalike unit name (`systemd-initd`) and lookalike directory are the whole trick. | `usr/lib/systemd/` | path attribution |

Two supporting facts, added because nothing else in the corpus provides a
positive for them:

| Fact | Where | Why |
| --- | --- | --- |
| A **non-empty `ld.so.preload`** naming an unowned object in the *same* directory. | `etc/ld.so.preload` | Existence alone is not evidence (`../cruft/` has an empty one). Contents naming an unowned path are. The shared directory is what merges these findings into one cluster instead of three unrelated alerts. |
| A **shadowed hook**: `etc/pacman.d/hooks/60-depmod.hook` is an unowned file with the *same name* as the package-owned system hook, in the higher-priority directory. Pacman runs the replacement; the packaged hook's work silently stops. | `etc/pacman.d/hooks/` | Detection must cover hooks *suppressed*, not only hooks added. (`../cruft/` carries the benign `/dev/null` mask of the same hook, which fixes the severity ceiling for that construct.) |

The package itself is `%VALIDATION% none` with `Unknown Packager` — the ordinary
marks of a locally built AUR package, shared with every benign AUR package on the
system, and therefore worth nothing on its own.

## What this fixture proves, and the much larger thing it does not

It proves the checks fire on **sloppy** malware. That is all it proves, and the
finding text must say so.

An attacker who builds the payload into `$pkgdir` and ships an ordinary-looking
unit *in the package's file list* produces: no unowned files, a self-consistent
mtree (the mtree came from that build — the hash **is** the malware's), and an
`ExecStart` resolving to a package-owned binary. **Every check in P1-C goes
silent.** Correlation does not survive a competent attacker; the real incidents
were sloppy, but needn't have been. A clean result on this phase's checks is not
evidence of a clean system.

## Limits this fixture cannot encode (INV-6)

- **Temporal correlation.** The `%INSTALLDATE%` of `librewolf-fix-bin` (1770099000)
  is deliberately far from the repo packages' (177000xxxx) so a temporal cluster
  is *expressible* — but git does not preserve mtimes, so the mtree `time=` ≈
  `%INSTALLDATE%` ≈ transaction-time key cannot be exercised from a checked-in
  tree. Copy the root into a `t.TempDir()` and set mtimes there.
- **No mtree.** Digest-mismatch fixtures live in `testdata/mtree/`; this root
  carries no `mtree` file, so integrity checks find nothing here and should say
  so rather than imply the files verified.
- **Modes.** Deliberately uniform `0644` (see above), so this root cannot serve
  as the unowned-SUID fixture.
