// internal/alpm/localdb_test.go
package alpm

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEntry(t *testing.T, dbPath, dir, desc, files string) {
	t.Helper()
	full := filepath.Join(dbPath, dir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "files"), []byte(files), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLocalDBReadsPackages(t *testing.T) {
	db := t.TempDir()
	writeEntry(t, db, "zlib-1.3.1-2",
		"%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n%BASE%\nzlib\n\n%VALIDATION%\npgp\n\n%PACKAGER%\nA Dev <a@archlinux.org>\n\n%INSTALLDATE%\n1770760629\n\n",
		"%FILES%\nusr/lib/libz.so\n\n")
	writeEntry(t, db, "foo-bin-1.0-1",
		"%NAME%\nfoo-bin\n\n%VERSION%\n1.0-1\n\n%BASE%\nfoo-bin\n\n%VALIDATION%\nnone\n\n%PACKAGER%\nUnknown Packager\n\n%INSTALLDATE%\n1770760700\n\n",
		"%FILES%\nusr/bin/foo\n\n")

	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if byName["zlib"].Validation != "pgp" {
		t.Errorf("zlib validation = %q", byName["zlib"].Validation)
	}
	if byName["foo-bin"].Packager != "Unknown Packager" {
		t.Errorf("foo-bin packager = %q", byName["foo-bin"].Packager)
	}
	if byName["zlib"].InstallDate.Unix() != 1770760629 {
		t.Errorf("zlib installdate = %v", byName["zlib"].InstallDate)
	}
}

// ALPM_DB_VERSION and other non-package files must be skipped, not parsed.
func TestLoadLocalDBSkipsNonPackageEntries(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "ALPM_DB_VERSION"), []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, db, "zlib-1.3.1-2", "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n", "%FILES%\nusr/lib/libz.so\n\n")
	pkgs, _, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
}

// A package whose files file cannot be opened is still loaded (its desc was
// readable) but must be reported as a gap for its file list, per INV-9: coverage
// is reported, never inferred from a silently-empty Files slice.
func TestLoadLocalDBReportsMissingFilesAsGap(t *testing.T) {
	db := t.TempDir()
	dir := filepath.Join(db, "nofiles-1.0-1")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "%NAME%\nnofiles\n\n%VERSION%\n1.0-1\n\n"
	if err := os.WriteFile(filepath.Join(dir, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}

	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "nofiles" {
			found = true
		}
	}
	if !found {
		t.Errorf("pkgs = %v, want nofiles present", pkgs)
	}
	wantGap := "nofiles-1.0-1/files"
	gapFound := false
	for _, g := range gaps {
		if g == wantGap {
			gapFound = true
		}
	}
	if !gapFound {
		t.Errorf("gaps = %v, want %q present", gaps, wantGap)
	}
}

func TestLoadLocalDBFromStockFixture(t *testing.T) {
	pkgs, gaps, err := LoadLocalDB("../../testdata/roots/stock/var/lib/pacman/local")
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if byName["zlib"].Validation != "pgp" {
		t.Errorf("zlib validation = %q, want pgp", byName["zlib"].Validation)
	}
	if byName["foo-bin"].Validation != "none" {
		t.Errorf("foo-bin validation = %q, want none", byName["foo-bin"].Validation)
	}
	if byName["foo-bin"].Packager != "Unknown Packager" {
		t.Errorf("foo-bin packager = %q, want Unknown Packager", byName["foo-bin"].Packager)
	}
	if _, ok := byName["foo-bin"].Backup["etc/foo.conf"]; !ok {
		t.Errorf("foo-bin backup = %v, want etc/foo.conf present", byName["foo-bin"].Backup)
	}
}
