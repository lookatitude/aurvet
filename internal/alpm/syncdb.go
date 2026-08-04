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
		if err := readSyncDB(db, names); err != nil {
			gaps = append(gaps, filepath.Base(db))
		}
	}
	return names, gaps, nil
}

func readSyncDB(path string, into map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		dir := strings.TrimSuffix(h.Name, "/")
		if i := strings.IndexByte(dir, '/'); i >= 0 {
			dir = dir[:i]
		}
		if n := stripVersion(dir); n != "" {
			into[n] = true
		}
	}
}

// IsForeign reports whether a package is absent from every configured sync DB.
// %VALIDATION% is deliberately not consulted: on the reference system
// python-pkg_resources is foreign (dropped from the repos) yet validated pgp.
func IsForeign(p Package, syncNames map[string]bool) bool {
	return !syncNames[p.Name]
}
