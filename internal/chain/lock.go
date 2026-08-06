// internal/chain/lock.go
//
// Two locks with two different jobs, and one asymmetry that is the whole point
// of the file.
//
// # pacman's db.lck: scan WARNS, baseline append REFUSES
//
// /var/lib/pacman/db.lck exists while a pacman transaction is in flight. The
// local database is being rewritten underneath any reader, so a scan taken
// during one can see a package half-installed, an mtree that does not match the
// files yet, or a file list from before an upgrade.
//
// A scan that reports those is noisy, and noise is recoverable: run it again.
// A BASELINE that records them is not, because it gets SIGNED, and every later
// run compares against it. Spurious findings baked into the trust chain do not
// wash out; they become the reference. So the same condition produces a warning
// in one path and a refusal in the other, deliberately.
//
// The check is advisory in both directions. db.lck can appear the instant after
// it is read, so its absence is not a guarantee -- it narrows a window, it does
// not close one. Nothing here waits for pacman: holding a lock on someone
// else's database is not this tool's business.
//
// # aurvet's own lock
//
// The chain file is written by temp + fsync + rename, so a concurrent reader
// always sees one whole file or the other. The advisory lock exists for the
// read-modify-write between them: two appenders that both read the same head
// would produce a fork, and a fork is one of the four attacks this subsystem
// exists to detect. Losing the race is ErrBusy, never a silent overwrite.
package chain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// DBLockRel is where pacman's transaction lock lives, relative to a root.
const DBLockRel = "var/lib/pacman/db.lck"

// lockFileName is aurvet's own advisory lock, beside the chain.
const lockFileName = ".lock"

// defaultLockTimeout bounds the wait for the advisory lock. Bounded rather than
// indefinite: a hung run that never says why is worse than a refusal that does.
const defaultLockTimeout = 5 * time.Second

var (
	// ErrDBLocked reports a pacman transaction in flight. It is a refusal for
	// `baseline append` and a warning for `scan`.
	ErrDBLocked = errors.New("chain: a pacman transaction is in flight (db.lck present)")

	// ErrBusy reports another aurvet process holding the chain lock.
	ErrBusy = errors.New("chain: another aurvet process holds the chain lock")
)

// DBLockRuleID identifies the coverage gap a scan records while db.lck exists.
const DBLockRuleID = "chain.pacman-transaction-in-flight"

// DBLock is what was observed about pacman's transaction lock. Present is a
// point-in-time observation, not a guarantee about the next instant.
type DBLock struct {
	Present bool
	Path    string
}

// DetectDBLock looks for db.lck under root. root may be "" for the live system.
//
// An error here is an I/O failure, not a lock: a caller that cannot tell must
// treat that as a gap, not as "no transaction" (INV-9).
func DetectDBLock(root string) (DBLock, error) {
	if root == "" {
		root = "/"
	}
	p := filepath.Join(root, DBLockRel)
	switch _, err := os.Lstat(p); {
	case err == nil:
		return DBLock{Present: true, Path: p}, nil
	case errors.Is(err, os.ErrNotExist):
		return DBLock{Path: p}, nil
	default:
		return DBLock{Path: p}, fmt.Errorf("chain: cannot tell whether %s exists: %w", p, err)
	}
}

// ScanAdvisory is what a SCAN does about a transaction in flight: it says so
// and carries on.
//
// A gap, because some of what was read may describe a database mid-rewrite and
// INV-9 says that is coverage, not silence. A finding at suspicious severity,
// because the state may be genuinely odd -- but never critical, because the
// likeliest explanation is an upgrade running right now, and an accusation
// there trains people to ignore the tool.
func (d DBLock) ScanAdvisory() finding.Result {
	if !d.Present {
		return finding.Result{}
	}
	return finding.Result{
		Findings: []finding.Finding{{
			RuleID:      DBLockRuleID,
			SubjectKind: "system",
			Subject:     d.Path,
			Severity:    finding.SevSuspicious,
			Summary:     "a pacman transaction was in flight during this scan",
			Evidence:    []string{d.Path + " exists, so the local database was being written while it was read"},
			Limits: "findings derived from the local database during a transaction may be artefacts of a " +
				"half-applied upgrade rather than tampering; re-run once the transaction has finished",
		}},
		Gaps: []finding.Gap{{
			RuleID:  DBLockRuleID,
			Subject: d.Path,
			Reason: "the pacman local database was mid-transaction, so package metadata read during " +
				"this scan may be inconsistent with the files on disk",
		}},
	}
}

// GuardAppend is what `baseline append` does about the same condition: it
// refuses. See the file comment for why the two differ.
func (d DBLock) GuardAppend() error {
	if !d.Present {
		return nil
	}
	return fmt.Errorf("%w: %s exists, and a baseline assembled from a database mid-transaction "+
		"would sign spurious findings into the trust chain permanently; wait for the transaction "+
		"to finish and run it again", ErrDBLocked, d.Path)
}

// lock takes aurvet's advisory lock on the chain directory.
//
// The flock loop itself lives in internal/fsx (fsx.Lock), because the
// anti-rollback floor in internal/bundle needs the same one and two
// implementations of a lock over trust-bearing state would eventually disagree
// about their own semantics. What stays here is the part that is about the
// chain: the error a chain caller tests against, and the sentence that says
// nothing was written.
func (s *Store) lock(timeout time.Duration) (func() error, error) {
	if timeout <= 0 {
		timeout = defaultLockTimeout
	}
	path := filepath.Join(s.dir, lockFileName)
	release, err := fsx.Lock(path, timeout)
	switch {
	case errors.Is(err, fsx.ErrBusy):
		return nil, fmt.Errorf("%w: %s is held; nothing was written", ErrBusy, path)
	case err != nil:
		return nil, fmt.Errorf("chain: %w", err)
	}
	return release, nil
}
