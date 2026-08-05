# testdata/fsx — confined-I/O fixtures

`internal/fsx` is the only package in the tree that touches attacker-controlled
paths on a live filesystem, so its fixtures are shapes rather than documents:
a fifo, a directory where a regular file was recorded, a symlink pointing out
of the root, a file rewritten between the open and the re-`fstat`.

**Only `payload.txt` is checked in.** git cannot represent a fifo at all, and a
symlink whose target escapes the repository is exactly the kind of object a
checkout should not be asked to materialize. Every hostile shape is therefore
constructed at runtime in `t.TempDir()` by the helpers in
`internal/fsx/open_test.go`, in the same spirit as `testdata/gate`, which
materializes its gzipped sync DB at runtime instead of checking in a tarball.

`payload.txt` is inert plain text. Its only job is to have a stable content
hash that a test can assert against a value computed outside Go:

    $ sha256sum testdata/fsx/payload.txt
    d643ba1aa2a043fda719d78864aeab57d993e53ddd71e679c86995546b5c36f8

The tests copy it into a temporary root rather than opening it in place,
because several of them mutate the file mid-scan and a fixture that a test can
corrupt is not a fixture.

## What the runtime fixtures cover

| Shape                                | Expected outcome                          |
| ------------------------------------ | ----------------------------------------- |
| regular file                         | opened, `fstat`ed from that fd, hashed    |
| symlink to a path outside the root   | refused, target never read                |
| symlink to a regular file *inside*   | refused — `O_NOFOLLOW` is not conditional |
| directory component that is an       | refused by `os.Root` before the leaf open |
| escaping symlink                     |                                           |
| fifo                                 | refused, and without hanging              |
| directory                            | refused (`S_ISREG`)                       |
| absolute / `..` / `NUL` in `rel`     | refused before any syscall                |
| rewritten between open and re-fstat  | `mutated during scan`                     |

A character device aimed at `/dev/zero` (spec §11.2) is **not** covered here:
`mknod` needs privilege the test suite does not have and must not want. The
`S_ISREG` gate that refuses the fifo is the same gate that refuses it, and the
fifo case exercises that gate.
