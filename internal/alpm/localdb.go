// internal/alpm/localdb.go
package alpm

import (
	"bytes"
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Package is one installed package as recorded in the local DB.
type Package struct {
	Name        string
	Version     string
	Base        string
	Validation  string
	Packager    string
	InstallDate time.Time
	Files       []string
	Backup      map[string]string
}

func first(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Buffered is one local-database directory as phase 1 collected it: the
// directory name and the raw bytes of its desc and files. Nothing here is
// interpreted, which is the point -- the interpretation is PackagesFrom's, and
// it happens after the read capability is gone (spec §11.1).
//
// An absent Desc or Files is nil, and nil is not the same as empty: nil means
// phase 1 could not buffer it and PackagesFrom gaps the entry, empty means the
// file was there and held nothing.
type Buffered struct {
	Dir   string
	Desc  []byte
	Files []byte
}

// PackagesFrom parses the local package set from bytes already in memory.
//
// It exists because the local database was being read twice on every scan:
// once by internal/collect, which buffers desc, files and mtree for all 1410
// packages while the read capability is held, and once by LoadLocalDB, which
// opened the same 59 MB again through ordinary os.Open. Two reads of one
// hostile input can disagree, and the second one is a format parse running
// inside the privileged window that spec §11.1 exists to empty.
//
// LoadLocalDB is this function plus a directory walk, so the two cannot drift:
// there is one parse and two ways of getting bytes to it.
func PackagesFrom(entries []Buffered) ([]Package, []string) {
	var (
		pkgs []Package
		gaps []string
	)
	for _, e := range entries {
		if e.Desc == nil {
			// Phase 1 recorded its own gap for the unreadable file; this one is
			// about the consequence -- there is no package here to analyse --
			// and it is the gap the package set's own consumers look for.
			gaps = append(gaps, e.Dir)
			continue
		}
		p, ok := parseEntry(e.Dir, e.Desc, e.Files, &gaps)
		if !ok {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, gaps
}

// parseEntry builds one Package from one entry's raw bytes, appending whatever
// it could not interpret to gaps. It reports false when the entry yielded no
// usable package at all.
func parseEntry(dir string, desc, files []byte, gaps *[]string) (Package, bool) {
	fields, err := ParseDesc(bytes.NewReader(desc))
	if err != nil {
		*gaps = append(*gaps, dir)
		return Package{}, false
	}
	p := Package{
		Name:       first(fields, "NAME"),
		Version:    first(fields, "VERSION"),
		Base:       first(fields, "BASE"),
		Validation: first(fields, "VALIDATION"),
		Packager:   first(fields, "PACKAGER"),
		Backup:     map[string]string{},
	}
	if p.Base == "" {
		p.Base = p.Name
	}
	if secs, err := strconv.ParseInt(first(fields, "INSTALLDATE"), 10, 64); err == nil {
		p.InstallDate = time.Unix(secs, 0).UTC()
	}
	if files == nil {
		*gaps = append(*gaps, dir+"/files")
	} else if paths, backup, perr := ParseFiles(bytes.NewReader(files)); perr != nil {
		*gaps = append(*gaps, dir+"/files")
	} else {
		p.Files, p.Backup = paths, backup
	}
	if p.Name == "" {
		*gaps = append(*gaps, dir)
		return Package{}, false
	}
	return p, true
}

// LoadLocalDB enumerates package directories under dbPath. It returns the
// packages it could read and the directory names it could not, which become
// coverage gaps under INV-9 rather than being silently dropped.
//
// A scan does not use this path: fullScan parses the package set from what
// phase 1 buffered (PackagesFrom), because a scan must not read the database
// twice. This remains for the provenance-only entry point and for the tests
// that pin the parse against a real directory.
func LoadLocalDB(dbPath string) ([]Package, []string, error) {
	entries, err := os.ReadDir(dbPath)
	if err != nil {
		return nil, nil, err
	}
	var pkgs []Package
	var gaps []string
	for _, e := range entries {
		dir := filepath.Join(dbPath, e.Name())

		// E-8: DirEntry.IsDir() is an lstat, so a package directory reached
		// through a symlink reports IsDir() == false and a bare "!IsDir() ->
		// skip" guard drops it with no gap at all -- no package, no finding,
		// no gap, and the run can still exit 0. os.Stat follows symlinks, so
		// it tells us what the entry actually is rather than what it looks
		// like from the outside.
		info, err := os.Stat(dir)
		if err != nil {
			// Broken symlink, EACCES, dangling entry -- we could not tell
			// what this was, which is precisely a gap, not a silent skip.
			gaps = append(gaps, e.Name())
			continue
		}
		if !info.IsDir() {
			// Measured on the reference system (/var/lib/pacman/local, this
			// project, 2026-08-04): 1410 dirs, 0 symlinks, exactly one
			// non-dir non-symlink entry, named ALPM_DB_VERSION. That is the
			// entire benign non-directory population, so it is allowlisted
			// by exact name -- an explicit one-name list is auditable, a
			// pattern or prefix guess is a hiding place. Every other
			// non-directory entry is unexpected and must be gapped: the
			// measured cost of that rule is zero gaps on this system, which
			// is why it is affordable.
			if e.Name() != "ALPM_DB_VERSION" {
				gaps = append(gaps, e.Name())
			}
			continue
		}
		desc, err := os.ReadFile(filepath.Join(dir, "desc"))
		if err != nil {
			gaps = append(gaps, e.Name())
			continue
		}
		// A missing `files` is nil, which is what PackagesFrom gaps on. An
		// unreadable one is nil for the same reason: neither yields a package
		// with an empty file list presented as a complete one.
		files, err := os.ReadFile(filepath.Join(dir, "files"))
		if err != nil {
			files = nil
		}
		p, ok := parseEntry(e.Name(), desc, files, &gaps)
		if !ok {
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, gaps, nil
}
