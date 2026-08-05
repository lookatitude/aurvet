// internal/alpm/syncdb_test.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"strings"
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

// spec.html §4.1 (corrected 2026-08-04): the rule is per PACKAGE ENTRY, not
// per database. A DB with at least one package entry whose name stripVersion
// rejects gaps with a count of how many out of the total failed. A healthy
// DB alongside it must still contribute its names.
func TestLoadSyncNamesUnparsableEntriesAreAGap(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "unparsable.db"), []string{"garbage", "nohyphens", "one-hyphen"})
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 || !strings.HasPrefix(gaps[0], "unparsable.db") {
		t.Fatalf("gaps = %v, want one entry with prefix \"unparsable.db\"", gaps)
	}
	// E-2: the count is load-bearing -- pin it explicitly so a future format
	// change to the gap string cannot quietly drop the number.
	if !strings.Contains(gaps[0], "3 of 3") {
		t.Errorf("gaps[0] = %q, want it to contain the count \"3 of 3\"", gaps[0])
	}
	if !names["zlib"] {
		t.Errorf("zlib not found; a bad DB must not cost the others their names: got %v", names)
	}
}

// E-2 regression test: this must fail against the pre-fix, per-DB-granularity
// code. spec.html §4.1 (corrected 2026-08-04): the old rule ("zero names but
// at least one entry") is DB granularity -- one parseable entry among many
// unparsable ones declares the whole DB understood, so partial.db here
// (2 good, 3 bad) would extract 2 names, see entries > 0 && extracted != 0,
// and produce NO gap at all, silently reclassifying the 3 unparsable
// packages as foreign while claiming complete coverage. Measured on the
// reference system, the original wording produced 5 false suspicious
// findings against pgp-validated repository packages this way. Per-entry
// accounting must gap this DB and record "3 of 5" -- the two good names must
// still surface in the map, since a partial read must not cost the names it
// did understand.
func TestLoadSyncNamesPartialParseGapsWithCount(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "partial.db"), []string{
		"zlib-1.3.1-2", "foo-bin-1.0-1", // 2 good
		"garbage", "nohyphens", "one-hyphen", // 3 unparsable
	})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 {
		t.Fatalf("gaps = %v, want exactly one gap for partial.db", gaps)
	}
	if !strings.HasPrefix(gaps[0], "partial.db") {
		t.Errorf("gaps[0] = %q, want prefix \"partial.db\"", gaps[0])
	}
	if !strings.Contains(gaps[0], "3 of 5") {
		t.Errorf("gaps[0] = %q, want it to contain the count \"3 of 5\"", gaps[0])
	}
	if !names["zlib"] || !names["foo-bin"] {
		t.Errorf("names = %v, want zlib and foo-bin still present: a partial read must not cost the names it did understand", names)
	}
}

// E-3 regression test: writeSyncDB emits a directory member AND a desc
// member per package, so a DB with 5 packages has 10 raw tar entries. The
// denominator in the gap string must be packages (5), never raw tar entries
// (10) -- doubling it would make the count meaningless.
func TestLoadSyncNamesCountsPackagesNotTarEntries(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "denom.db"), []string{
		"garbage", "nohyphens", "one-hyphen", "also-bad", "still-bad",
	})

	_, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 {
		t.Fatalf("gaps = %v, want exactly one gap", gaps)
	}
	if !strings.Contains(gaps[0], "of 5 package entries") {
		t.Errorf("gaps[0] = %q, want denominator \"of 5\" (packages), not \"of 10\" (raw tar entries)", gaps[0])
	}
}

// writeSyncDBDescOnly writes a sync DB archive with only <pkg>/desc members
// and no separate directory members -- a layout some real archives use.
// E-3: counting package entries as "tar entries with Typeflag == TypeDir"
// would count zero packages here, misclassify this DB as an empty
// repository, and never gap it even though every entry failed to parse --
// reopening the exact hole §4.1 exists to close. Counting distinct top-level
// path components instead is robust to this layout.
func writeSyncDBDescOnly(t *testing.T, path string, names []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, n := range names {
		body := []byte("%NAME%\n")
		if err := tw.WriteHeader(&tar.Header{Name: n + "/desc", Size: int64(len(body)), Mode: 0o644}); err != nil {
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

func TestLoadSyncNamesDescOnlyLayoutCountsPackagesCorrectly(t *testing.T) {
	dir := t.TempDir()
	writeSyncDBDescOnly(t, filepath.Join(dir, "desconly.db"), []string{"zlib-1.3.1-2", "foo-bin-1.0-1"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
	if !names["zlib"] || !names["foo-bin"] {
		t.Errorf("names = %v, want zlib and foo-bin present from desc-only members", names)
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

// E-9: syncPath is caller-supplied (--offline-root composes it) and was
// passed unescaped into filepath.Glob. A root containing a glob
// metacharacter ('*', '?', '[', '\') makes the pattern resolve to a
// different directory entirely, so the oracle silently answers about the
// wrong tree -- and since foreignness is !syncNames[name], a wrong name set
// is wrong for every package in the run, not just one. This test must fail
// against the pre-fix glob-based code: the metacharacter in the directory
// name causes Glob's pattern to mismatch the intended directory, so zlib
// from the decoy (which a broken glob expansion could reach) must not leak
// in, and the real core.db in the weird directory must still be found.
func TestLoadSyncNamesRootWithGlobMetacharacter(t *testing.T) {
	parent := t.TempDir()
	weird := filepath.Join(parent, "weird[1]")
	if err := os.MkdirAll(weird, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSyncDB(t, filepath.Join(weird, "core.db"), []string{"zlib-1.3.1-2"})

	// A decoy directory that a mis-expanded "weird[1]/*.db" pattern (glob
	// class "[1]" matching literal "1") could resolve into instead.
	decoy := filepath.Join(parent, "weird1")
	if err := os.MkdirAll(decoy, 0o755); err != nil {
		t.Fatal(err)
	}
	writeSyncDB(t, filepath.Join(decoy, "decoy.db"), []string{"python-pkg_resources-81.0.0-1"})

	names, gaps, err := LoadSyncNames(weird)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
	if !names["zlib"] {
		t.Errorf("names = %v, want zlib from the intended directory", names)
	}
	if names["python-pkg_resources"] {
		t.Errorf("names = %v, want the decoy directory's names absent", names)
	}
}

// E-9: filepath.Glob on a missing directory returned (nil, nil), so the old
// code answered "empty names, no gaps, nil error" for a missing sync path --
// silent at the library level (cmd/aurvet's sweep catches it separately via
// its own len(syncNames) == 0 check). os.ReadDir instead returns
// fs.ErrNotExist; that specific error is converted to empty names, one gap
// naming syncPath, and a nil error -- louder than before at the library
// level, but identical at the exit-code level since sweep's own guard still
// fires on the empty map either way.
// A .db entry that is itself a directory (or anything else that is not a
// readable gzip archive) must gap via the existing read-error path in
// readSyncDB, never silently disappear from the sweep.
func TestLoadSyncNamesDirNamedDotDBIsAGap(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "oops.db"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2"})

	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 1 || gaps[0] != "oops.db" {
		t.Errorf("gaps = %v, want [oops.db]", gaps)
	}
	if !names["zlib"] {
		t.Errorf("zlib not found; a directory named *.db must not cost core.db its names: got %v", names)
	}
}

func TestLoadSyncNamesMissingDirIsAGap(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "does-not-exist")
	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(names) != 0 {
		t.Errorf("names = %v, want empty", names)
	}
	if len(gaps) != 1 || gaps[0] != dir {
		t.Errorf("gaps = %v, want [%s]", gaps, dir)
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
