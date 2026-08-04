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

// writeEmptySyncDB writes a valid gzipped tar with zero entries: a legitimate
// empty repository, per spec §4.1 the non-gap side of the rule.
func writeEmptySyncDB(t *testing.T, path string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

// A valid gzipped tar with zero tar entries is an empty repository, not a
// coverage gap: spec §4.1 explicitly rejects gapping this case since it would
// manufacture false gaps on every healthy, empty repo.
func TestLoadSyncNamesEmptyDBIsNotAGap(t *testing.T) {
	dir := t.TempDir()
	writeEmptySyncDB(t, filepath.Join(dir, "empty.db"))

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want empty (zero entries is an empty repo, not a gap)", gaps)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want empty", names)
	}
}

// A DB with at least one tar entry whose names stripVersion rejects yields
// zero names from that DB: spec §4.1 says that is a coverage gap, since the
// reader did not understand the format it was given. A healthy DB alongside
// it must still contribute its names.
func TestLoadSyncNamesUnparsableEntriesAreAGap(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "unparsable.db"), []string{"garbage", "nohyphens", "one-hyphen"})
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != "unparsable.db" {
		t.Errorf("gaps = %v, want [unparsable.db]", gaps)
	}
	if !names["zlib"] {
		t.Errorf("zlib not found; a bad DB must not cost the others their names: got %v", names)
	}
}

// Two DBs with identical package entries: the second contributes no new map
// keys (they're already present from the first) but did extract names from
// its own entries. Counting "names contributed" by map growth would wrongly
// gap the second DB even though it understood every entry it read.
func TestLoadSyncNamesDuplicateContentDoesNotGap(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2"})
	writeSyncDB(t, filepath.Join(dir, "core-mirror.db"), []string{"zlib-1.3.1-2"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want empty: duplicate content must not gap the second DB", gaps)
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

// End to end: real local-DB parse feeding a real sync-DB parse feeding
// IsForeign. testdata/roots/stock has no var/lib/pacman/sync, so this is the
// only place IsForeign is exercised against packages LoadLocalDB actually
// produced rather than a hand-built Package literal.
func TestIsForeignEndToEnd(t *testing.T) {
	pkgs, gaps, err := LoadLocalDB("../../testdata/roots/stock/var/lib/pacman/local")
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 0 {
		t.Fatalf("gaps = %v, want empty", gaps)
	}

	var zlib, fooBin *Package
	for i := range pkgs {
		switch pkgs[i].Name {
		case "zlib":
			zlib = &pkgs[i]
		case "foo-bin":
			fooBin = &pkgs[i]
		}
	}
	if zlib == nil {
		t.Fatal("zlib not found among packages loaded from stock local DB")
	}
	if fooBin == nil {
		t.Fatal("foo-bin not found among packages loaded from stock local DB")
	}

	syncDir := t.TempDir()
	writeSyncDB(t, filepath.Join(syncDir, "core.db"), []string{"zlib-1.3.1-2"})
	syncNames, syncGaps, err := LoadSyncNames(syncDir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(syncGaps) != 0 {
		t.Fatalf("syncGaps = %v, want empty", syncGaps)
	}

	if IsForeign(*zlib, syncNames) {
		t.Error("zlib is present in the sync DB and must not be foreign")
	}
	if !IsForeign(*fooBin, syncNames) {
		t.Error("foo-bin is absent from every sync DB and must be foreign")
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
