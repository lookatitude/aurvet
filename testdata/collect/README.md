# testdata/collect — collect-phase fixtures

`internal/collect` is the privileged half of P1-B: it walks a tree, opens every
file through `internal/fsx`, streams sha256 from that descriptor, and buffers raw
database bytes. It parses nothing, so its fixtures are *shapes and bytes*, not
documents.

**Only `payload.txt` is checked in.** Everything hostile — a fifo, a symlink
escaping the tree, a directory symlink, an unreadable file, a file rewritten
between the open and the re-`fstat` — is materialized at runtime in
`t.TempDir()` by `fixtureRoot` in `internal/collect/collect_test.go`, for the
same reasons `testdata/fsx/README.md` gives: git cannot carry a fifo, and a
checkout should not be asked to materialize a symlink that points out of the
repository.

`payload.txt` is inert plain text whose only job is a stable content hash,
computed outside Go so a bug in this package cannot define its own expected
answer:

    $ sha256sum testdata/collect/payload.txt
    ed6656b46899bda2eaddcecf19edb370b456c526f9c929b2cdd081dfbb07fa97

The gzipped mtree fixtures the tests plant in the fake local database are reused
from `testdata/mtree/` (`a52dec.mtree.gz`, and `truncated.mtree.gz` for the case
that matters most here: a *corrupt* archive must still be buffered without
error, because collect is forbidden to decompress it — a truncated gzip is the
analyse phase's problem, and that separation is the point of the phase).

## What the runtime fixtures cover

| Shape                                     | Expected outcome                                  |
| ----------------------------------------- | ------------------------------------------------- |
| regular file                              | opened once, hashed from that fd                  |
| symlink (target contains `..`)            | recorded as `link` with the target unresolved      |
| directory symlink                         | recorded, never descended                         |
| fifo                                      | recorded as `other`, and without hanging          |
| unreadable file (mode 0000, non-root)     | coverage gap, never silence                        |
| file rewritten before its digest is taken | `mutated during scan` gap, not a digest            |
| skipped subtree                           | absent from evidence, and listed in `Raw.Skipped`  |
| panicking / hanging subject               | per-subject gap; the scan completes, exit `3`      |
