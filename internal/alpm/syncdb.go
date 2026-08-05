// internal/alpm/syncdb.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"io/fs"
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
	// E-9: syncPath is caller-supplied (--offline-root composes it) and was
	// unescaped, so filepath.Glob(filepath.Join(syncPath, "*.db")) let a root
	// containing '*', '?', '[' or '\' make the pattern resolve to a
	// different directory than the one the caller named -- the oracle then
	// silently answers about the wrong tree, and since foreignness is
	// !syncNames[p.Name], a wrong name set is wrong for every package in the
	// run. Fixed by removing the failure mode rather than escaping around
	// it: read the directory and filter by suffix instead of globbing it.
	dirEntries, err := os.ReadDir(syncPath)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// filepath.Glob on a missing directory returned (nil, nil): empty
			// names, no gaps, nil error. os.ReadDir returns fs.ErrNotExist
			// instead, which we convert to empty names, one gap naming
			// syncPath, and a nil error -- louder at the library level, but
			// unchanged at the exit-code level: cmd/aurvet's sweep already
			// has its own len(syncNames) == 0 gap for this case. Any other
			// ReadDir error (e.g. EACCES) is returned as-is, since that is
			// not "the path doesn't exist" but "something is wrong reading
			// it", and callers already treat a non-nil error as a hard
			// failure.
			return map[string]bool{}, []string{syncPath}, nil
		}
		return nil, nil, err
	}
	// os.ReadDir sorts its result by filename, exactly as filepath.Glob did,
	// so iteration order stays deterministic.
	var dbs []string
	for _, de := range dirEntries {
		if strings.HasSuffix(de.Name(), ".db") {
			dbs = append(dbs, filepath.Join(syncPath, de.Name()))
		}
	}
	names := make(map[string]bool)
	var gaps []string
	for _, db := range dbs {
		total, failed, err := readSyncDB(db, names)
		if err != nil {
			// One unreadable DB, one gap entry, exactly the bare filename —
			// internal/check and internal/report tests pin this string, so
			// this path must not grow the count-bearing format below.
			gaps = append(gaps, filepath.Base(db))
			continue
		}
		// spec.html §4.1 (corrected 2026-08-04): the rule is per PACKAGE
		// ENTRY, not per database. A DB whose entries mostly fail to parse
		// still extracts a non-empty name set from the entries it did
		// understand, so a database-granularity check ("entries > 0 &&
		// extracted == 0") would declare the whole DB understood on the
		// strength of one lucky parse — the E-2 bug. Per-entry accounting
		// instead counts every package entry independently: any failures at
		// all is a gap, and the count is load-bearing, because a partial
		// read is neither an empty repo (total == 0) nor a total failure
		// (failed == total) — only the count distinguishes it from either.
		// total == 0 is a legitimate empty repository and never a gap;
		// flagging it would manufacture false gaps on healthy, empty repos.
		if failed > 0 {
			gaps = append(gaps, fmt.Sprintf("%s: %d of %d package entries yielded no name",
				filepath.Base(db), failed, total))
		}
	}
	return names, gaps, nil
}

// readSyncDB walks the gzipped tar at path and adds every name it can parse
// to into. It returns the number of distinct package entries in the archive
// and how many of those failed to yield a name.
//
// E-3: a package entry is a distinct top-level path component (h.Name, minus
// a trailing "/", up to the first remaining "/"), deduplicated within this
// DB via a set — NOT "tar entries with Typeflag == tar.TypeDir". Each
// package contributes both a directory entry and a desc entry, so counting
// either raw tar entries or TypeDir entries specifically is fragile: an
// archive that ships only "<pkg>/desc" members with no directory members
// (a layout real archives use — see TestLoadSyncNamesDescOnlyLayoutCounts-
// PackagesCorrectly) would count zero TypeDir entries, be misclassified as
// an empty repository, and never gap even though every entry failed to
// parse — reopening the exact hole §4.1 exists to close. The distinct-
// top-level-component definition is robust to both layouts.
//
// Pax metadata members (global/extended headers) are not packages and are
// skipped so they don't inflate either the denominator or the failure count.
func readSyncDB(path string, into map[string]bool) (total int, failed int, err error) {
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
	seen := make(map[string]bool)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return total, failed, nil
		}
		if err != nil {
			return total, failed, err
		}
		if h.Typeflag == tar.TypeXGlobalHeader || h.Typeflag == tar.TypeXHeader || h.Name == "pax_global_header" {
			continue
		}
		dir := strings.TrimSuffix(h.Name, "/")
		if i := strings.IndexByte(dir, '/'); i >= 0 {
			dir = dir[:i]
		}
		if seen[dir] {
			continue // the desc entry for a package already counted via its dir entry, or vice versa
		}
		seen[dir] = true
		total++
		if n := stripVersion(dir); n != "" {
			into[n] = true
		} else {
			failed++
		}
	}
}

// IsForeign reports whether a package is absent from every configured sync DB.
// %VALIDATION% is deliberately not consulted: on the reference system
// python-pkg_resources is foreign (dropped from the repos) yet validated pgp.
func IsForeign(p Package, syncNames map[string]bool) bool {
	return !syncNames[p.Name]
}
