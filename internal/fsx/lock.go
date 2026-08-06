// internal/fsx/lock.go
//
// One advisory-lock implementation, shared.
//
// There were two candidate homes for this: internal/chain, which had the
// original, and internal/bundle, which needed the same thing for the
// anti-rollback floor. Two flock loops that drift apart is a worse outcome than
// one shared thirty lines -- the failure would be a lock that is taken with
// different semantics in the two places that both guard trust-bearing state,
// and nothing in a test suite makes that visible.
//
// flock(2), not a lock FILE whose existence means "held": a lock taken by
// existence leaks when the holder is killed, and the recovery for that is a
// manual delete which people learn to do reflexively -- at which point the lock
// protects nothing. flock is released by the kernel when the process dies, so
// there is no stale-lock ritual to learn.
//
// Non-blocking with a bounded retry, so a stuck holder produces ErrBusy with an
// explanation rather than a run that never returns. A security tool that hangs
// is a security tool that gets disabled.
package fsx

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"golang.org/x/sys/unix"
)

// ErrBusy reports that another process holds the lock. Callers wrap it with
// their own sentinel so a package's users can keep testing against that
// package's error, but the distinction from a real I/O failure survives: a
// caller that cannot tell "someone else is writing" from "the disk is broken"
// will eventually report one as the other.
var ErrBusy = errors.New("fsx: the advisory lock is held by another process")

// DefaultLockTimeout bounds the wait. Bounded rather than indefinite: a hung
// run that never says why is worse than a refusal that does.
const DefaultLockTimeout = 5 * time.Second

// lockRetry is how often the non-blocking attempt is repeated. Short enough
// that an uncontended handoff is imperceptible, long enough not to spin.
const lockRetry = 10 * time.Millisecond

// Lock takes an exclusive advisory lock on path, creating it if needed, and
// returns the function that releases it.
//
// The lock file's parent directory is created 0700 and the file 0600: a lock
// file any local user can open is a lock any local user can hold, which turns
// an integrity guard into a denial-of-service handle.
//
// A zero or negative timeout means DefaultLockTimeout.
func Lock(path string, timeout time.Duration) (func() error, error) {
	if timeout <= 0 {
		timeout = DefaultLockTimeout
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o700); err != nil {
		return nil, fmt.Errorf("fsx: %w", err)
	}
	f, err := os.OpenFile(path, os.O_CREATE|os.O_RDWR, 0o600)
	if err != nil {
		return nil, fmt.Errorf("fsx: %w", err)
	}
	deadline := time.Now().Add(timeout)
	for {
		err := unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			return func() error {
				_ = unix.Flock(int(f.Fd()), unix.LOCK_UN)
				return f.Close()
			}, nil
		}
		// EWOULDBLOCK means held. Anything else is a real failure and must not
		// be retried until the deadline, because retrying an EBADF for five
		// seconds reports contention that never existed.
		if !errors.Is(err, unix.EWOULDBLOCK) {
			f.Close()
			return nil, fmt.Errorf("fsx: flock %s: %w", path, err)
		}
		if time.Now().After(deadline) {
			f.Close()
			return nil, fmt.Errorf("%w: %s", ErrBusy, path)
		}
		time.Sleep(lockRetry)
	}
}
