// internal/alpm/localdb.go
package alpm

import (
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

// LoadLocalDB enumerates package directories under dbPath. It returns the
// packages it could read and the directory names it could not, which become
// coverage gaps under INV-9 rather than being silently dropped.
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
		df, err := os.Open(filepath.Join(dir, "desc"))
		if err != nil {
			gaps = append(gaps, e.Name())
			continue
		}
		fields, err := ParseDesc(df)
		df.Close()
		if err != nil {
			gaps = append(gaps, e.Name())
			continue
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
		if ff, err := os.Open(filepath.Join(dir, "files")); err == nil {
			paths, backup, perr := ParseFiles(ff)
			ff.Close()
			if perr == nil {
				p.Files, p.Backup = paths, backup
			} else {
				gaps = append(gaps, e.Name()+"/files")
			}
		} else {
			gaps = append(gaps, e.Name()+"/files")
		}
		if p.Name == "" {
			gaps = append(gaps, e.Name())
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, gaps, nil
}
