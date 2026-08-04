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
		if !e.IsDir() {
			continue // ALPM_DB_VERSION and friends
		}
		dir := filepath.Join(dbPath, e.Name())
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
