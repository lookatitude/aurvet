# testdata/privdrop

The hostile fixtures for `internal/privdrop`'s process-model assertions
(P1-B task 12) are **built at run time**, in the test's own temporary
directory, rather than committed here. That is deliberate, and this file
records why so the absence does not read as an oversight:

- **A fifo cannot be committed.** Git stores regular files, symlinks and
  gitlinks. There is no object type for a named pipe, so `git checkout`
  could not reproduce the node whose whole purpose is to make an
  unguarded `open` block forever.
- **A committed escaping symlink is a hazard to the repository itself.**
  The fixture points outside its root on purpose (`../../../../etc/passwd`).
  Checked in, every tool that walks the working tree — editors, linters,
  archivers, the project's own scanner during development — would be
  invited to follow it. The fixture is created inside the test's
  `t.TempDir()`, exercised, and discarded.
- **The mutation fixture must be mutated mid-scan**, between the open and
  the post-hash re-`fstat`. Its value is in the timing, not in its bytes,
  so there is nothing to store.

The fixtures and the reason each one exists are in
`internal/privdrop/drop_test.go`: `helperHostileNodes` (regular file,
fifo, escaping symlink, internal symlink, directory) and `helperMutate`.

Every assertion built on them has a paired negative control that fails
when its guard is removed — including two permanent ones,
`TestFifoWithoutNonblockHangsSoTheGuardIsLoadBearing` and
`TestUnrecoveredWorkerGoroutinePanicKillsTheScan`, which exist so the
guards cannot quietly stop mattering.
