// internal/bundle/floor.go
//
// The anti-rollback floor, held in root-only state.
//
// # Why not in the cache
//
// The cache is where the downloaded bundle lands. It is writable by whatever
// fetched it, it is a normal-permissions directory on most systems, and it is
// the first thing an attacker who can influence the update channel also
// influences. A version floor stored there is a floor the attacker can lower,
// which is the same as no floor at all -- and worse, because it looks like a
// control.
//
// So the floor lives in the same root-only state directory P4 established for
// the trust chain (/var/lib/aurvet, 0700), and OpenFloor REFUSES a directory
// inside the cache. That refusal is compiled, not documented: "do not put it in
// the cache" is not a control, and a later refactor that moves a path is exactly
// how this kind of thing regresses.
//
// # What the floor actually protects against, and what it does not
//
// It protects against ROLLBACK: a signed-but-old bundle replayed to reinstate
// detections that were later added, or to reinstate an online key that has since
// been rotated out. Every signature on that old bundle is valid; the version
// number is the only thing that says it is stale.
//
// It does NOT protect against an attacker who is already root on this machine.
// Such an attacker can rewrite /var/lib/aurvet at will, and no local file can
// stop them. This is stated plainly rather than papered over: the floor raises
// the bar from "influence the network" to "own the box", and a control's honest
// scope is part of it working. Truncation of the trust chain has the same shape
// and the same answer (chain.Anchor): a remote copy.
//
// # Ownership and mode are checked, not assumed
//
// Spec §11: when euid == 0, never trust state under a caller-controlled path. A
// floor file that is group- or world-writable, or not owned by root during a
// privileged run, is refused rather than read -- because an unprivileged local
// attacker who can write it chooses what a root-privileged security tool
// believes about its own rollback protection.
package bundle

import (
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// FloorSchema versions the on-disk floor document.
const FloorSchema = 1

// FloorFile is the floor's filename inside the root-only state directory.
const FloorFile = "bundle-floor.json"

// maxFloorBytes caps the floor document.
const maxFloorBytes = 64 << 10

var (
	// ErrFloor reports a malformed or unreadable floor.
	ErrFloor = errors.New("bundle: anti-rollback floor")

	// ErrRollback reports a bundle at or below the floor.
	ErrRollback = errors.New("bundle: bundle version is at or below the anti-rollback floor")

	// ErrUnsafeState reports state whose permissions mean it cannot be trusted.
	ErrUnsafeState = errors.New("bundle: refusing state an unprivileged writer could control")

	// ErrFloorInCache reports a floor located inside the bundle cache.
	ErrFloorInCache = errors.New("bundle: the anti-rollback floor may not live in the cache")

	// ErrOfflineRoot is INV-5: no writes inside the tree being examined.
	ErrOfflineRoot = errors.New("bundle: refusing to write inside the examined tree")
)

// Floor is the root-only record of how far the bundle channel has advanced on
// this host. Canonically serialised: sorted keys, integers, no floats.
type Floor struct {
	Schema int `json:"schema"`

	// MinBundleVersion is the highest bundle version ever ACCEPTED here. A
	// bundle at or below it is a rollback. Never decreases: Save refuses.
	MinBundleVersion int64 `json:"min_bundle_version"`

	// HeadDigest is sha256 over the canonical bytes of the bundle at
	// MinBundleVersion. It is what the next bundle's prev_digest must name, and
	// it is what makes a fork at the same version detectable -- two different
	// documents can carry the same version number, but not the same digest.
	HeadDigest string `json:"head_digest"`

	// MinDelegationSerial stops a superseded delegation, whose root signatures
	// remain valid forever, from being replayed to reinstate a rotated-out
	// online key.
	MinDelegationSerial int64 `json:"min_delegation_serial"`

	// IndicatorCount is how many indicators the accepted bundle carried. Stored
	// so a later drop is measurable rather than merely felt: a signed bundle
	// that removes detections is an attack.
	IndicatorCount int `json:"indicator_count"`

	// RootGeneration is the root set that was in force when this floor was
	// written.
	RootGeneration int `json:"root_generation"`

	// AcceptedAt is when a bundle was last ACCEPTED (RFC3339 with an explicit
	// offset). CheckedAt is when an update was last attempted, successful or
	// not. The two differ exactly in the freeze case -- checks continue, nothing
	// new ever arrives -- which is why both are recorded.
	AcceptedAt string `json:"accepted_at"`
	CheckedAt  string `json:"checked_at"`
}

// FloorOptions is what OpenFloor needs in order to refuse the wrong locations.
type FloorOptions struct {
	// CacheDir is the bundle cache. Supplied so OpenFloor can refuse a floor
	// inside it. Empty disables the check, which is why callers must pass it;
	// cmd wiring should pass the same value it hands the cache.
	CacheDir string

	// OfflineRoot is --offline-root. Writes into it are refused (INV-5).
	OfflineRoot string

	// EUID is the effective uid. When 0, ownership of the state is enforced.
	EUID int
}

// FloorStore is the floor on disk. Constructing one performs no I/O, so a
// read-only or offline caller can name a store it will only read.
type FloorStore struct {
	dir  string
	opts FloorOptions
}

// OpenFloor names the floor store inside the root-only state directory.
//
// It refuses, at construction, a directory inside the cache: see the file
// comment. This is the one place that refusal can be made unconditional.
func OpenFloor(stateDir string, opts FloorOptions) (*FloorStore, error) {
	if strings.TrimSpace(stateDir) == "" {
		return nil, fmt.Errorf("%w: no state directory", ErrFloor)
	}
	dir, err := filepath.Abs(filepath.Clean(stateDir))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFloor, err)
	}
	if opts.CacheDir != "" {
		cache, err := filepath.Abs(filepath.Clean(opts.CacheDir))
		if err != nil {
			return nil, fmt.Errorf("%w: %v", ErrFloor, err)
		}
		if dir == cache || strings.HasPrefix(dir, cache+string(filepath.Separator)) {
			return nil, fmt.Errorf("%w: %s is inside the cache %s, where whatever fetched the "+
				"bundle can rewrite it", ErrFloorInCache, dir, cache)
		}
	}
	return &FloorStore{dir: dir, opts: opts}, nil
}

// Path is the floor file.
func (s *FloorStore) Path() string { return filepath.Join(s.dir, FloorFile) }

// Load reads the floor.
//
// A missing floor is (zero, false, nil): a first run has no floor, and that is
// not an error. Anything else that is wrong IS an error -- unreadable,
// malformed, unsafely permissioned -- because "I could not read the floor" must
// never be presented to the caller as "there is no floor", which is precisely
// the state a rollback attack wants to manufacture.
func (s *FloorStore) Load() (Floor, bool, error) {
	if err := s.checkOwnership(s.dir, true); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Floor{}, false, nil
		}
		return Floor{}, false, err
	}
	if err := s.checkOwnership(s.Path(), false); err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return Floor{}, false, nil
		}
		return Floor{}, false, err
	}
	raw, err := readCapped(s.Path(), maxFloorBytes)
	if errors.Is(err, os.ErrNotExist) {
		return Floor{}, false, nil
	}
	if err != nil {
		return Floor{}, false, fmt.Errorf("%w: %v", ErrFloor, err)
	}
	canon, err := baseline.Canonical(raw)
	if err != nil {
		return Floor{}, false, fmt.Errorf("%w: %v", ErrFloor, err)
	}
	if string(canon) != string(raw) {
		return Floor{}, false, fmt.Errorf("%w: %s is not canonical, so it was not written by "+
			"this tool", ErrFloor, s.Path())
	}
	var f Floor
	if err := decodeStrict(canon, &f); err != nil {
		return Floor{}, false, fmt.Errorf("%w: %v", ErrFloor, err)
	}
	if err := validateFloor(f); err != nil {
		return Floor{}, false, err
	}
	return f, true, nil
}

func validateFloor(f Floor) error {
	if f.Schema != FloorSchema {
		return fmt.Errorf("%w: schema %d, this build writes %d", ErrFloor, f.Schema, FloorSchema)
	}
	if f.MinBundleVersion < 0 || f.MinDelegationSerial < 0 || f.IndicatorCount < 0 {
		return fmt.Errorf("%w: a negative counter", ErrFloor)
	}
	if f.MinBundleVersion > 0 {
		if err := ValidDigest(f.HeadDigest); err != nil {
			return fmt.Errorf("%w: head_digest: %v", ErrFloor, err)
		}
		if _, err := baseline.ParseStamp(f.AcceptedAt); err != nil {
			return fmt.Errorf("%w: accepted_at: %v", ErrFloor, err)
		}
	}
	if f.CheckedAt != "" {
		if _, err := baseline.ParseStamp(f.CheckedAt); err != nil {
			return fmt.Errorf("%w: checked_at: %v", ErrFloor, err)
		}
	}
	return nil
}

// FloorLockFile is the advisory lock guarding Save's read-modify-write.
const FloorLockFile = ".bundle-floor.lock"

// Save writes the floor, refusing any decrease.
//
// Monotonicity is enforced here rather than trusted to the caller. A caller that
// has been talked into accepting an old bundle would otherwise also write an old
// floor, and the next run would have no record that anything went backwards.
//
// # What the lock is and is not for
//
// The whole write is taken under fsx.Lock, the same advisory lock internal/chain
// uses, because `aurvet update` can now be started by a systemd timer and by a
// human at the same time (packaging/systemd/aurvet-update.timer).
//
// Do not read more into it than it does. Without the lock the floor could
// neither be CORRUPTED (writeAtomic gives every reader old-or-new, never half)
// nor LOWERED (the monotonicity check below is re-read under the lock). What a
// lost race costs is that the losing writer's IndicatorCount and AcceptedAt
// persist instead of the winner's. That is metadata: it can misreport how many
// indicators the accepted bundle carried, and so mis-scale the "the count
// dropped" gap on a later run. The anti-rollback property does not depend on
// this lock, and claiming it did would overstate the fix.
func (s *FloorStore) Save(f Floor) error {
	// INV-5 before anything is created: taking a lock means creating a file, and
	// a refusal to write inside the examined tree must not itself write inside
	// the examined tree.
	if err := s.checkOfflineRoot(); err != nil {
		return err
	}
	release, err := fsx.Lock(filepath.Join(s.dir, FloorLockFile), fsx.DefaultLockTimeout)
	if err != nil {
		if errors.Is(err, fsx.ErrBusy) {
			return fmt.Errorf("%w: another aurvet process is writing it; nothing was written", ErrFloor)
		}
		return fmt.Errorf("%w: %v", ErrFloor, err)
	}
	defer func() { _ = release() }()

	f.Schema = FloorSchema
	if err := validateFloor(f); err != nil {
		return err
	}
	cur, ok, err := s.Load()
	if err != nil {
		return err
	}
	if ok {
		if f.MinBundleVersion < cur.MinBundleVersion {
			return fmt.Errorf("%w: refusing to lower the floor from %d to %d",
				ErrFloor, cur.MinBundleVersion, f.MinBundleVersion)
		}
		if f.MinDelegationSerial < cur.MinDelegationSerial {
			return fmt.Errorf("%w: refusing to lower the delegation serial from %d to %d",
				ErrFloor, cur.MinDelegationSerial, f.MinDelegationSerial)
		}
	}
	raw, err := baseline.Marshal(f)
	if err != nil {
		return fmt.Errorf("%w: %v", ErrFloor, err)
	}
	return writeAtomic(s.Path(), raw, 0o600)
}

func (s *FloorStore) checkOfflineRoot() error {
	off := s.opts.OfflineRoot
	if off == "" || off == "/" {
		return nil
	}
	root, err := filepath.Abs(filepath.Clean(off))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOfflineRoot, err)
	}
	if s.dir == root || strings.HasPrefix(s.dir, root+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s is inside %s, and a scan must not write into the filesystem "+
			"it is auditing", ErrOfflineRoot, s.dir, root)
	}
	return nil
}

// checkOwnership refuses state an unprivileged writer could control.
//
// A group- or world-writable path is refused for every caller, not only for
// root: a floor any local user can lower is not a floor. Ownership is enforced
// only when euid == 0, because an unprivileged run legitimately keeps its state
// under $HOME and owns it itself.
func (s *FloorStore) checkOwnership(path string, isDir bool) error {
	var st unix.Stat_t
	if err := unix.Lstat(path, &st); err != nil {
		if errors.Is(err, unix.ENOENT) {
			return os.ErrNotExist
		}
		return fmt.Errorf("%w: %s: %v", ErrFloor, path, err)
	}
	kind := "file"
	if isDir {
		kind = "directory"
	}
	if st.Mode&unix.S_IFMT == unix.S_IFLNK {
		return fmt.Errorf("%w: %s is a symlink; trust-bearing state is never followed through "+
			"one", ErrUnsafeState, path)
	}
	if isDir != (st.Mode&unix.S_IFMT == unix.S_IFDIR) {
		return fmt.Errorf("%w: %s is not a %s", ErrFloor, path, kind)
	}
	if st.Mode&0o022 != 0 {
		return fmt.Errorf("%w: %s is mode %04o (group- or world-writable), so a local "+
			"unprivileged user chooses what this build believes about rollback protection",
			ErrUnsafeState, path, st.Mode&0o7777)
	}
	if s.opts.EUID == 0 && st.Uid != 0 {
		return fmt.Errorf("%w: %s is owned by uid %d, not root, and this is a privileged run",
			ErrUnsafeState, path, st.Uid)
	}
	return nil
}

// -- io helpers --------------------------------------------------------------

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", path, max)
	}
	return b, nil
}

// writeAtomic is temp + fsync + rename + fsync-dir, the same discipline
// internal/chain uses. A half-written floor would read as malformed, which Load
// treats as an error rather than as "no floor" -- correct, but a crash is not
// tampering and should not look like it.
func writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }
	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("bundle: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("bundle: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("bundle: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("bundle: %w", err)
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("bundle: %w", err)
	}
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("bundle: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("bundle: fsync %s: %w", dir, err)
	}
	return nil
}

// stampOf renders t the way every signed document in this codebase spells a
// timestamp: RFC3339 with an explicit offset. Exported behaviour is via Save's
// callers, which supply the instant, so nothing here reads a clock.
func stampOf(t time.Time) string { return t.Format(time.RFC3339) }
