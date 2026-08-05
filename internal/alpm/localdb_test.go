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
// E-8: ALPM_DB_VERSION is the one measured benign non-directory entry (see
// localdb.go), so skipping it must not produce a gap -- but this test would
// have passed even if every other non-directory entry were silently dropped
// too, which is exactly the E-8 hole. The dedicated "unexpected plain file"
// test below covers that.
func TestLoadLocalDBSkipsNonPackageEntries(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "ALPM_DB_VERSION"), []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, db, "zlib-1.3.1-2", "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n", "%FILES%\nusr/lib/libz.so\n\n")
	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: ALPM_DB_VERSION is the one measured allowlisted filename", gaps)
	}
}

// E-8: os.ReadDir's DirEntry.IsDir() is an lstat, so a package directory
// reached through a symlink reports IsDir() == false and the old
// "!e.IsDir() { continue }" guard dropped it with no gap at all -- no
// package, no finding, no gap, exit 0. This test reproduces that: it must
// fail against the pre-fix code (the symlinked package silently absent from
// pkgs, with zero gaps to explain why).
func TestLoadLocalDBFollowsSymlinkedPackageDir(t *testing.T) {
	db := t.TempDir()
	real := t.TempDir()
	realDir := filepath.Join(real, "zlib-1.3.1-2")
	if err := os.MkdirAll(realDir, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n"
	if err := os.WriteFile(filepath.Join(realDir, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(realDir, "files"), []byte("%FILES%\nusr/lib/libz.so\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	link := filepath.Join(db, "zlib-1.3.1-2")
	if err := os.Symlink(realDir, link); err != nil {
		t.Fatal(err)
	}

	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none: symlinked package dir must be analysed", gaps)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("pkgs = %v, want zlib present via symlinked dir", pkgs)
	}
}

// E-8: a broken symlink is a stat failure, not a directory and not the
// allowlisted plain file -- it must be gapped by name, never silently
// dropped, and it must not cost other packages in the same db their entries.
func TestLoadLocalDBGapsBrokenSymlink(t *testing.T) {
	db := t.TempDir()
	writeEntry(t, db, "zlib-1.3.1-2", "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n", "%FILES%\nusr/lib/libz.so\n\n")
	dangling := filepath.Join(db, "ghost-1.0-1")
	if err := os.Symlink(filepath.Join(db, "does-not-exist"), dangling); err != nil {
		t.Fatal(err)
	}

	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != "ghost-1.0-1" {
		t.Errorf("gaps = %v, want [ghost-1.0-1]", gaps)
	}
	found := false
	for _, p := range pkgs {
		if p.Name == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("pkgs = %v, want zlib still present alongside the broken symlink", pkgs)
	}
}

// E-8: a plain file that is not the one measured allowlisted name
// (ALPM_DB_VERSION) must be gapped, not silently skipped -- an explicit
// one-name allowlist is auditable, a pattern/prefix guess is a hiding place.
func TestLoadLocalDBGapsUnexpectedPlainFile(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "README"), []byte("not a package\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(pkgs) != 0 {
		t.Errorf("pkgs = %v, want none", pkgs)
	}
	if len(gaps) != 1 || gaps[0] != "README" {
		t.Errorf("gaps = %v, want [README]", gaps)
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
	if len(pkgs) != 3 {
		t.Fatalf("got %d packages, want 3", len(pkgs))
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
	// The split-package fixture: %BASE% must be READ from the file, not
	// defaulted from %NAME% via LoadLocalDB's `if p.Base == "" { p.Base =
	// p.Name }` fallback. Every other fixture package has Base == Name, so
	// this is the only assertion in the suite that can tell "parsed" from
	// "defaulted" apart.
	if byName["foo-lib"].Base != "foo-common" {
		t.Errorf("foo-lib base = %q, want foo-common (declared %%BASE%%, not defaulted from %%NAME%%)", byName["foo-lib"].Base)
	}
}
