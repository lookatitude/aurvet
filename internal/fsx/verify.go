// internal/fsx/verify.go
package fsx

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// ErrMutatedDuringScan means the file changed underneath the descriptor while
// it was being read. It is a third outcome, alongside "matches" and "does not
// match", and callers must keep it separate from both: a digest mismatch
// accuses the package, while this accuses the scan's own timing. Reporting a
// racer's edit as a content mismatch misattributes the cause, and reporting
// nothing at all would report clean for something that was not examined
// coherently (INV-3).
var ErrMutatedDuringScan = errors.New("mutated during scan")

// afterHashForTest runs between the hash and the re-fstat. Production leaves
// it nil; verify_test.go sets it to reach the one window a test cannot open
// deterministically from the outside, since the whole point of that window is
// that it is narrow.
var afterHashForTest func()

// Digest streams SHA-256 from f -- which must be the descriptor OpenConfined
// returned, never a re-opened path -- and returns the hex digest with the
// number of bytes read.
//
// It then re-fstats that same descriptor and compares it against at, the stat
// taken at open. If anything it watches moved, the digest is discarded and the
// error is ErrMutatedDuringScan: the bytes were consistent with nothing in
// particular, so publishing their hash would be publishing a fact about a file
// that no longer exists in that form.
//
// Scope of the claim, stated rather than implied (INV-6): this detects the
// inode we hashed changing beneath us. If the PATH is repointed at a different
// inode after our open, our descriptor keeps reading the original file and
// reports its digest -- which is the correct answer to "what did the file at
// this path contain when we opened it", and the only question a single
// resolution can honestly answer.
func Digest(f *os.File, at unix.Stat_t) (string, int64, error) {
	h := sha256.New()
	// Streaming, because the collect phase must not buffer file contents: the
	// reference system carries 19.8 GiB of packaged files.
	n, err := io.Copy(h, f)
	if err != nil {
		return "", n, &fs.PathError{Op: "read", Path: f.Name(), Err: err}
	}

	if afterHashForTest != nil {
		afterHashForTest()
	}

	if err := CheckUnchanged(f, at); err != nil {
		return "", n, err
	}
	return hex.EncodeToString(h.Sum(nil)), n, nil
}

// CheckUnchanged re-fstats f and reports whether it still describes the file
// that at described. It is exported because the triage tier needs the same
// check without a hash, and because a caller that reads a file itself still
// owes the file the same question.
//
// A failed fstat is an error, never a pass: if we cannot ask, we do not know.
func CheckUnchanged(f *os.File, at unix.Stat_t) error {
	var now unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &now); err != nil {
		return &fs.PathError{Op: "fstat", Path: f.Name(), Err: err}
	}
	if !Unchanged(at, now) {
		return &fs.PathError{Op: "fstat", Path: f.Name(), Err: ErrMutatedDuringScan}
	}
	return nil
}

// Unchanged compares the four fields that identify a file's identity and its
// contents' generation: ino and dev say it is the same inode, size and mtime
// say the contents were not rewritten.
//
// Deliberately absent:
//
//   - atime, because reading a file updates it. Comparing it would flag every
//     file the scan hashes, on its own account.
//   - ctime, though it is stricter and cannot be forged from userspace. It
//     also moves on a chmod or chown that leaves the bytes alone, which would
//     turn ordinary concurrent administration into scan-timing findings. The
//     four fields below are the recorded contract; widening it is a decision
//     to take deliberately, with the noise measured first.
func Unchanged(before, after unix.Stat_t) bool {
	return before.Ino == after.Ino &&
		before.Dev == after.Dev &&
		before.Size == after.Size &&
		before.Mtim.Sec == after.Mtim.Sec &&
		before.Mtim.Nsec == after.Mtim.Nsec
}
