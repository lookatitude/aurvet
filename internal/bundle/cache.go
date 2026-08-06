// internal/bundle/cache.go
//
// The bundle cache: where fetched bytes are parked between runs.
//
// The cache is UNTRUSTED storage, and that is not a hedge. Everything in it is
// re-verified from raw bytes on every run (Verify), so an attacker who can write
// the cache can at most make the tool refuse -- which is loud -- or replay an
// older signed bundle, which is what the root-only floor exists to catch. That
// division is why the floor may never live here (floor.go).
//
// Load therefore returns BYTES, never a parsed document, and an unreadable or
// missing artefact is absence rather than an error: absence is a coverage state
// the caller must report (INV-10), not a failure to abort on.
package bundle

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
)

// Cache filenames. Fixed rather than derived from a URL: a filename computed
// from attacker-influenced input is a path-traversal question nobody needs to
// answer.
const (
	CacheBundleFile     = "bundle.json"
	CacheDelegationFile = "delegation.json"

	// delegationSigPrefix names the per-root-key detached signatures:
	// delegation.json.sig.1 ... .N, one per signing root. Multiple files rather
	// than one concatenated blob so a partially collected 2-of-3 is visibly
	// partial.
	delegationSigPrefix = CacheDelegationFile + ".sig."

	// maxDelegationSigs bounds how many signature files are read, so a cache
	// full of junk cannot turn a scan into a verification marathon.
	maxDelegationSigs = 8
)

// ErrCache reports a cache that could not be read for a reason that is not
// absence.
var ErrCache = errors.New("bundle: cache")

// Cache is the bundle cache directory.
type Cache struct{ dir string }

// OpenCache names the cache. It performs no I/O.
func OpenCache(dir string) *Cache { return &Cache{dir: dir} }

// Dir is the cache directory.
func (c *Cache) Dir() string { return c.dir }

// Artifacts is the raw material Verify consumes. Every field is bytes as
// received. Nothing here has been parsed, and nothing here is trusted.
type Artifacts struct {
	DelegationRaw  []byte
	DelegationSigs [][]byte
	BundleRaw      []byte
	BundleSig      []byte
}

// Load reads whatever is cached.
//
// A missing file yields an empty field, not an error: the caller turns that into
// StateUnavailable. An unreadable file (permissions, I/O) IS an error, because
// "I could not read the cache" must not be presented as "there is no bundle".
func (c *Cache) Load() (Artifacts, error) {
	var a Artifacts
	var err error
	if a.DelegationRaw, err = c.read(CacheDelegationFile, MaxDelegationBytes); err != nil {
		return Artifacts{}, err
	}
	if a.BundleRaw, err = c.read(CacheBundleFile, MaxBundleBytes); err != nil {
		return Artifacts{}, err
	}
	if a.BundleSig, err = c.read(CacheBundleFile+".sig", maxFloorBytes); err != nil {
		return Artifacts{}, err
	}

	entries, err := os.ReadDir(c.dir)
	if errors.Is(err, os.ErrNotExist) {
		return a, nil
	}
	if err != nil {
		return Artifacts{}, fmt.Errorf("%w: %v", ErrCache, err)
	}
	var names []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasPrefix(e.Name(), delegationSigPrefix) {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Strings(names)
	if len(names) > maxDelegationSigs {
		names = names[:maxDelegationSigs]
	}
	for _, n := range names {
		b, err := c.read(n, maxFloorBytes)
		if err != nil {
			return Artifacts{}, err
		}
		if len(b) > 0 {
			a.DelegationSigs = append(a.DelegationSigs, b)
		}
	}
	return a, nil
}

// Store writes artefacts into the cache. Each write is temp + fsync + atomic
// rename, so an interrupted update leaves the previous artefact intact rather
// than a truncated one that reads as a signature failure.
func (c *Cache) Store(a Artifacts) error {
	if len(a.DelegationSigs) > maxDelegationSigs {
		return fmt.Errorf("%w: %d delegation signatures", ErrCache, len(a.DelegationSigs))
	}
	if err := writeAtomic(filepath.Join(c.dir, CacheDelegationFile), a.DelegationRaw, 0o644); err != nil {
		return err
	}
	for i, sig := range a.DelegationSigs {
		name := fmt.Sprintf("%s%d", delegationSigPrefix, i+1)
		if err := writeAtomic(filepath.Join(c.dir, name), sig, 0o644); err != nil {
			return err
		}
	}
	// Signature before document, as internal/chain does: the window an
	// interruption leaves open should be the one that reads as absent.
	if err := writeAtomic(filepath.Join(c.dir, CacheBundleFile+".sig"), a.BundleSig, 0o644); err != nil {
		return err
	}
	return writeAtomic(filepath.Join(c.dir, CacheBundleFile), a.BundleRaw, 0o644)
}

func (c *Cache) read(name string, max int64) ([]byte, error) {
	b, err := readCapped(filepath.Join(c.dir, name), max)
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrCache, err)
	}
	return b, nil
}
