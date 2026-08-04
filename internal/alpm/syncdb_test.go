// internal/alpm/syncdb_test.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// Sync DBs are gzipped tar archives whose entries are <name>-<ver>-<rel>/desc.
func writeSyncDB(t *testing.T, path string, dirs []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, d := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		body := []byte("%NAME%\n")
		if err := tw.WriteHeader(&tar.Header{Name: d + "/desc", Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSyncNamesStripsVersion(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2", "python-pkg_resources-81.0.0-1"})
	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v", gaps)
	}
	if !names["zlib"] {
		t.Error("zlib not found")
	}
	// Name contains hyphens and underscores; only the last two fields are version.
	if !names["python-pkg_resources"] {
		t.Errorf("python-pkg_resources not found; got %v", names)
	}
}

// python-pkg_resources is foreign yet carries %VALIDATION% pgp on the
// reference system. Foreignness must be decided by sync-DB absence, never
// by %VALIDATION%.
func TestIsForeignIgnoresValidation(t *testing.T) {
	sync := map[string]bool{"zlib": true}
	dropped := Package{Name: "python-pkg_resources", Validation: "pgp"}
	if !IsForeign(dropped, sync) {
		t.Error("pgp-validated package absent from sync DBs must be foreign")
	}
	repo := Package{Name: "zlib", Validation: "pgp"}
	if IsForeign(repo, sync) {
		t.Error("package present in a sync DB must not be foreign")
	}
}

// A corrupt or unreadable sync DB must be reported as a gap, never silently
// dropped: INV-9. It must not make every repo package look foreign, and a
// valid DB alongside it must still be read.
func TestLoadSyncNamesReportsUnreadableDBAsGap(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "bad.db"), []byte("not gzip"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != "bad.db" {
		t.Errorf("gaps = %v, want [bad.db]", gaps)
	}
	if !names["zlib"] {
		t.Errorf("zlib not found; got %v", names)
	}
}

func TestLoadSyncNamesEmptyDir(t *testing.T) {
	dir := t.TempDir()
	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want empty", names)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want empty", gaps)
	}
}

func TestStripVersion(t *testing.T) {
	tests := []struct {
		in   string
		want string
	}{
		{"python-pkg_resources-81.0.0-1", "python-pkg_resources"},
		{"zlib-1.3.1-2", "zlib"},
		{"nohyphens", ""},
		{"one-hyphen", ""},
	}
	for _, tt := range tests {
		if got := stripVersion(tt.in); got != tt.want {
			t.Errorf("stripVersion(%q) = %q, want %q", tt.in, got, tt.want)
		}
	}
}
