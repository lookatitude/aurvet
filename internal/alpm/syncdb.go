// internal/alpm/syncdb.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stripVersion turns "python-pkg_resources-81.0.0-1" into
// "python-pkg_resources" by removing the trailing <ver>-<rel> fields. Package
// names legitimately contain hyphens, so only the last two are removed.
func stripVersion(dir string) string {
	for i := 0; i < 2; i++ {
		idx := strings.LastIndex(dir, "-")
		if idx <= 0 {
			return ""
		}
		dir = dir[:idx]
	}
	return dir
}

// LoadSyncNames returns the set of package names present in any *.db sync
// archive. Unreadable archives are reported as gaps: a missing sync DB would
// otherwise make every repo package look foreign.
func LoadSyncNames(syncPath string) (map[string]bool, []string, error) {
	dbs, err := filepath.Glob(filepath.Join(syncPath, "*.db"))
	if err != nil {
		return nil, nil, err
	}
	names := make(map[string]bool)
	var gaps []string
	for _, db := range dbs {
		entries, extracted, err := readSyncDB(db, names)
		if err != nil {
			// One unreadable DB, one gap entry — do not also apply the
			// zero-names rule below to a DB that already errored out.
			gaps = append(gaps, filepath.Base(db))
			continue
		}
		// spec.html §4.1: a DB with at least one tar entry that still
		// extracted zero names means the reader did not understand the
		// format it was given — a coverage gap. Zero entries is a
		// legitimate empty repository, not a gap; flagging it would
		// manufacture false gaps on healthy, empty repos. `extracted`
		// counts names this DB itself contributed, not map growth: a
		// second DB whose packages are already known from a prior one
		// must not be gapped just because it added no new keys.
		if entries > 0 && extracted == 0 {
			gaps = append(gaps, filepath.Base(db))
		}
	}
	return names, gaps, nil
}

// readSyncDB walks the gzipped tar at path, adding every name it can parse
// out of a top-level entry to into. It returns the number of tar entries
// seen and the number of names this DB itself extracted (regardless of
// whether those names were already present in into), so the caller can
// apply the §4.1 zero-names-with-entries gap rule without conflating it
// with map growth across DBs.
func readSyncDB(path string, into map[string]bool) (entries int, extracted int, err error) {
	f, err := os.Open(path)
	if err != nil {
		return 0, 0, err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return 0, 0, err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return entries, extracted, nil
		}
		if err != nil {
			return entries, extracted, err
		}
		entries++
		dir := strings.TrimSuffix(h.Name, "/")
		if i := strings.IndexByte(dir, '/'); i >= 0 {
			dir = dir[:i]
		}
		if n := stripVersion(dir); n != "" {
			into[n] = true
			extracted++
		}
	}
}

// IsForeign reports whether a package is absent from every configured sync DB.
// %VALIDATION% is deliberately not consulted: on the reference system
// python-pkg_resources is foreign (dropped from the repos) yet validated pgp.
func IsForeign(p Package, syncNames map[string]bool) bool {
	return !syncNames[p.Name]
}
