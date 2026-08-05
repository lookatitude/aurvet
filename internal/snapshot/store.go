// internal/snapshot/store.go
//
// The store is the one place in the provenance path that writes, so it is
// written as a set of refusals with a write at the end of them.
//
// Three of those refusals are the point:
//
//   - INV-5. A snapshot taken while examining someone else's disk must not land
//     on that disk. The test is containment, not mode: a state directory outside
//     the examined tree is a legitimate destination, and refusing it would mean
//     --offline-root could never capture anything.
//   - An attacker-influenced key. A pkgbase comes out of a PKGBUILD, a .SRCINFO
//     or a directory name in a user's cache, and it decides this package's
//     filesystem layout. It is validated to a single conservative component
//     before any syscall -- never encoded, never cleaned, never concatenated on
//     trust.
//   - A known-unwritable state directory. config.Resolve has one degraded case
//     (an unprivileged live run with neither XDG_STATE_HOME nor HOME absolute)
//     that resolves to a root-owned path. Failing at the mkdir reads as a bug
//     here; saying so up front reads as what it is.
package snapshot

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/config"
)

// snapshotsSubdir is the state-directory subtree this package owns. It sits
// beside reports/ under the SAME state directory config.Resolve produced: a
// second path scheme would mean two answers to "where is aurvet's state".
const snapshotsSubdir = "snapshots"

// The refusals a caller switches on.
var (
	// ErrUnsafePkgBase is a key that is not a usable, safe single path
	// component. See ValidPkgBase.
	ErrUnsafePkgBase = errors.New("snapshot: pkgbase is not a safe record key")

	// ErrOfflineRoot is INV-5: the destination is inside the tree being
	// examined.
	ErrOfflineRoot = errors.New("snapshot: refusing to write inside the examined tree")

	// ErrStateUnwritable is a state directory that is known not to be writable
	// by this process before anything is attempted.
	ErrStateUnwritable = errors.New("snapshot: state directory is not writable by this user")
)

// Store is a snapshot directory, and the decision about whether it may be
// written at all.
type Store struct {
	dir string

	// refuseErr and refuseWhy are set when every write must fail, and carry the
	// reason so a command can print it instead of a bare errno.
	refuseErr error
	refuseWhy string
}

// StoreAt is a store rooted at an explicit directory, with no policy attached.
// It is the seam tests use and the shape a future --report-dir needs; production
// callers go through New so the INV-5 and unwritable-state decisions are made in
// one place.
func StoreAt(stateDir string) *Store {
	return &Store{dir: filepath.Join(stateDir, snapshotsSubdir)}
}

// New resolves the store for one run. stateDir overrides cfg.StateDir when
// non-empty; "" means "wherever config.Resolve decided".
//
// It never fails: an unusable destination is recorded as a refusal so a caller
// can report it (and still render the captured record, which is the useful half)
// rather than aborting the capture.
func New(cfg config.Config, stateDir string) *Store {
	dir := stateDir
	fallback := false
	if dir == "" {
		dir = cfg.StateDir
		for _, l := range cfg.Doctor() {
			if l.Key == "state_dir" && l.Source == config.SourceFallbackUnwritable {
				fallback = true
			}
		}
	}
	s := StoreAt(dir)

	if fallback {
		s.refuseErr = ErrStateUnwritable
		s.refuseWhy = "the state directory resolved to the system path because neither XDG_STATE_HOME nor HOME " +
			"is an absolute path, and an unprivileged process cannot write there; no snapshot was persisted"
		return s
	}
	// INV-5, stated as containment. cfg.Root is "/" for a live run, in which
	// case everything is trivially "inside" it -- so the check only applies when
	// a target tree was named.
	if cfg.Root != "" && cfg.Root != "/" && underRoot(cfg.Root, dir) {
		s.refuseErr = ErrOfflineRoot
		s.refuseWhy = fmt.Sprintf("--offline-root: %s is inside the examined tree %s, and a scan must not write "+
			"into the filesystem it is auditing; pass a state directory outside the target to capture", dir, cfg.Root)
	}
	return s
}

// underRoot reports whether dir is root itself or below it, comparing cleaned
// absolute paths. A prefix test on raw strings would treat /mnt/x2 as being
// under /mnt/x, so the separator is required.
func underRoot(root, dir string) bool {
	r, err := filepath.Abs(filepath.Clean(root))
	if err != nil {
		return true // cannot prove it is outside; refuse.
	}
	d, err := filepath.Abs(filepath.Clean(dir))
	if err != nil {
		return true
	}
	if d == r {
		return true
	}
	if !strings.HasSuffix(r, string(filepath.Separator)) {
		r += string(filepath.Separator)
	}
	return strings.HasPrefix(d, r)
}

// Dir is the snapshots directory, whether or not it may be written.
func (s *Store) Dir() string { return s.dir }

// Writable reports whether this store may be written, and why not when it may
// not. The reason is prose for an operator: a command prints it, and it is NOT a
// coverage gap -- failing to persist a cache file is an operational fact about
// the host, not an analysis that did not run.
func (s *Store) Writable() (bool, string) {
	if s.refuseErr != nil {
		return false, s.refuseWhy
	}
	return true, ""
}

// ValidPkgBase reports whether name may be used as a record key.
//
// The accepted set is deliberately narrower than "what a filesystem allows" and
// close to what pacman itself permits in a package name: alphanumerics plus
// @ . _ + - and no leading hyphen or dot. Everything else is refused rather than
// escaped, because an encoding is a second interpretation of the name and the
// bug class here (a pkgbase of "../../etc/cron.d/x" reaching a path) is not one
// to be clever about. The names this rejects do not exist in the AUR; the names
// it accepts include every pkgbase on the reference system.
func ValidPkgBase(name string) error {
	if name == "" {
		return fmt.Errorf("%w: empty", ErrUnsafePkgBase)
	}
	if len(name) > 255 {
		return fmt.Errorf("%w: %d bytes, over the 255 byte component limit", ErrUnsafePkgBase, len(name))
	}
	if name[0] == '-' || name[0] == '.' {
		return fmt.Errorf("%w: %q starts with %q", ErrUnsafePkgBase, firstN(name, 40), string(name[0]))
	}
	for i := 0; i < len(name); i++ {
		c := name[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9':
		case c == '@' || c == '.' || c == '_' || c == '+' || c == '-':
		default:
			return fmt.Errorf("%w: %q contains byte %#02x at offset %d, which is not in the accepted set "+
				"[A-Za-z0-9@._+-]", ErrUnsafePkgBase, firstN(name, 40), c, i)
		}
	}
	return nil
}

// Save writes rec, unless it does not have to.
//
// wrote is false when the latest stored record for this pkgbase has the same
// content digest: capture runs from a PostTransaction hook and opportunistically
// from every scan, so a store that appended per run would turn "a few KB per
// package" into a few KB per package per scan. The returned path is then the
// existing record.
//
// The write is a temp file created in the destination directory (so the rename
// never crosses a filesystem boundary), Sync'd, then renamed into place, with
// the temp file removed on every error path: an interrupted capture must not
// leave a half-written record that a later read treats as authoritative.
//
// The directory is 0o700 and the file 0o600. A snapshot names a package, its
// remote, its build directory and its packager; none of that is world-readable.
func (s *Store) Save(rec Record, stamp string) (path string, wrote bool, err error) {
	if err := ValidPkgBase(rec.PkgBase); err != nil {
		return "", false, err
	}
	if s.refuseErr != nil {
		return "", false, fmt.Errorf("%w: %s", s.refuseErr, s.refuseWhy)
	}
	if rec.SchemaVersion == 0 {
		rec.SchemaVersion = SchemaVersion
	}

	// Idempotence is checked before the directory is created, so a no-op capture
	// against a fresh state directory does not leave an empty tree behind.
	if prev, ok, _ := s.latest(rec.PkgBase); ok && prev.Digest() == rec.Digest() {
		return prev.path, false, nil
	}

	dir := filepath.Join(s.dir, rec.PkgBase)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", false, err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", false, err
	}

	blob, err := json.MarshalIndent(rec, "", "  ")
	if err != nil {
		return "", false, err
	}

	tmp, err := os.CreateTemp(dir, ".snapshot-*.tmp")
	if err != nil {
		return "", false, err
	}
	tmpName := tmp.Name()
	fail := func(err error) (string, bool, error) {
		tmp.Close()
		os.Remove(tmpName)
		return "", false, err
	}
	if err := tmp.Chmod(0o600); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(blob); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", false, err
	}

	final := filepath.Join(dir, stamp+".json")
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return "", false, err
	}
	return final, true, nil
}

// storedRecord is Record plus where it was read from. path is unexported and
// carries no JSON tag, so it never reaches disk and never enters Digest.
type storedRecord struct {
	Record
	path string
}

// Latest returns the newest valid stored record for one pkgbase.
//
// Stamps are fixed-width and zero-padded, so a descending string sort is a
// descending time sort -- the same assumption report.LoadPrevious rests on.
//
// A damaged newest record must not hide a healthy older one, and must never read
// as "no snapshot": every unreadable, unparsable or foreign-schema file is
// skipped and the walk continues. Absence is (zero, false, nil), because a
// pkgbase that was never captured is a fact and not a failure.
func (s *Store) Latest(pkgbase string) (Record, bool, error) {
	rec, ok, err := s.latest(pkgbase)
	return rec.Record, ok, err
}

func (s *Store) latest(pkgbase string) (storedRecord, bool, error) {
	if err := ValidPkgBase(pkgbase); err != nil {
		return storedRecord{}, false, err
	}
	dir := filepath.Join(s.dir, pkgbase)
	ents, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return storedRecord{}, false, nil
		}
		return storedRecord{}, false, err
	}

	var names []string
	for _, e := range ents {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	for _, name := range names {
		p := filepath.Join(dir, name)
		blob, err := os.ReadFile(p)
		if err != nil {
			continue
		}
		var rec Record
		if err := json.Unmarshal(blob, &rec); err != nil {
			continue
		}
		if rec.SchemaVersion != SchemaVersion {
			continue
		}
		return storedRecord{Record: rec, path: p}, true, nil
	}
	return storedRecord{}, false, nil
}

// List returns every pkgbase with at least one stored record, sorted.
//
// The listing is of BASES, never of package names: a split base's output
// packages do not appear here, because there is one recipe and therefore one
// record.
func (s *Store) List() ([]string, error) {
	ents, err := os.ReadDir(s.dir)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}
	var out []string
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		// A directory whose name is not a valid key cannot have been written by
		// this package. Reporting it as a pkgbase would launder something that
		// was planted there.
		if ValidPkgBase(e.Name()) != nil {
			continue
		}
		out = append(out, e.Name())
	}
	sort.Strings(out)
	return out, nil
}
