// internal/report/store_test.go
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
)

// --- Round trip ---

func TestSaveThenLoadLatestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{Total: 1409, Foreign: 39}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("findings lost in round-trip: %+v", got.Findings)
	}
	if len(got.Gaps) != 1 || got.Gaps[0].Subject != "foo-bin" {
		t.Errorf("gaps lost in round-trip: %+v", got.Gaps)
	}
}

func TestLoadLatestOnEmptyDir(t *testing.T) {
	_, ok, err := LoadLatest(t.TempDir())
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if ok {
		t.Error("empty dir reported a previous report")
	}
}

func TestLoadPreviousOnSingleReportDir(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	_, ok, err := LoadPrevious(dir)
	if err != nil {
		t.Fatalf("LoadPrevious: %v", err)
	}
	if ok {
		t.Error("LoadPrevious found a second report where there is only one")
	}
}

func TestSaveReturnsPathThatExistsAndParses(t *testing.T) {
	dir := t.TempDir()
	path, err := Save(dir, sample(), Summary{Total: 5, Foreign: 1}, "20260804T000000Z")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatalf("returned path does not exist: %v", err)
	}
	if info.IsDir() {
		t.Fatalf("returned path is a directory: %s", path)
	}
	blob, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("could not read returned path: %v", err)
	}
	var parsed map[string]any
	if err := json.Unmarshal(blob, &parsed); err != nil {
		t.Fatalf("returned path is not valid JSON: %v", err)
	}
}

func TestSaveModeIsFilePrivate(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("posix permission bits do not apply on windows")
	}
	dir := t.TempDir()
	path, err := Save(dir, sample(), Summary{}, "20260804T000000Z")
	if err != nil {
		t.Fatalf("Save: %v", err)
	}
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if perm := info.Mode().Perm(); perm != 0o600 {
		t.Errorf("report file mode = %o, want 0600", perm)
	}
	dirInfo, err := os.Stat(filepath.Join(dir, "reports"))
	if err != nil {
		t.Fatal(err)
	}
	if perm := dirInfo.Mode().Perm(); perm != 0o700 {
		t.Errorf("reports dir mode = %o, want 0700", perm)
	}
}

func TestRoundTripNilFindingsAndGapsDoesNotPanic(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, finding.Result{}, Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing")
	}
	if len(got.Findings) != 0 || len(got.Gaps) != 0 {
		t.Errorf("expected empty result, got %+v", got)
	}
}

func TestSaveIntoUncreatableStateDirReturnsError(t *testing.T) {
	dir := t.TempDir()
	blocker := filepath.Join(dir, "blocker")
	if err := os.WriteFile(blocker, []byte("not a directory"), 0o600); err != nil {
		t.Fatal(err)
	}
	stateDir := filepath.Join(blocker, "state")
	if _, err := Save(stateDir, sample(), Summary{}, "20260804T000000Z"); err == nil {
		t.Error("expected error saving under a path blocked by a regular file, got nil")
	}
}

// --- Directory listing hygiene ---

func TestNonJSONFilesAndSubdirsIgnored(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	reportsDir := filepath.Join(dir, "reports")
	if err := os.WriteFile(filepath.Join(reportsDir, "README.txt"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, "99999999T999999Z.json.bak"), []byte("hi"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(filepath.Join(reportsDir, "99999999T999999Z"), 0o700); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("non-.json entries and subdirs were not ignored: %+v", got.Findings)
	}
}

// --- Corruption reads as absence (never an error, never a panic) ---

// TestCorruptNewestReportFallsBackToOlderValidOne pins the requirement that a
// damaged newest report must not hide a healthy older one: the state was
// written by a previous run that may have been SIGKILLed mid-upgrade, and a
// scanner that refuses to run because its own cache is damaged has converted
// a cosmetic problem into no scan at all. Falling back to an older report (or
// to "no baseline") is the safe direction.
func TestCorruptNewestReportFallsBackToOlderValidOne(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	corrupt := filepath.Join(dir, "reports", "20260804T010000Z.json")
	if err := os.WriteFile(corrupt, []byte(`{"schema_v`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest returned an error on a truncated report: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest reported nothing found; it should have fallen back to the older valid report")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("did not fall back to the healthy older report: %+v", got.Findings)
	}
}

func TestNonObjectJSONReadsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(reportsDir, "20260804T000000Z.json"), []byte(`[1,2,3]`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest returned an error on non-object JSON: %v", err)
	}
	if ok {
		t.Errorf("non-object JSON should read as absent, got %+v", got)
	}
}

func TestDirectoryMasqueradingAsJSONReadsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	fakeFile := filepath.Join(dir, "reports", "20260804T010000Z.json")
	if err := os.Mkdir(fakeFile, 0o700); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest returned an error on a directory named *.json: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing; should have fallen back past the fake directory")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("did not fall back past the directory masquerading as a report: %+v", got.Findings)
	}
}

func TestUnreadableFileReadsAsAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: permission bits do not block reads")
	}
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	unreadable := filepath.Join(dir, "reports", "20260804T010000Z.json")
	if err := os.WriteFile(unreadable, []byte(`{"schema_version":1}`), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(unreadable, 0o600) })
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest returned an error on an unreadable file: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing; should have fallen back past the unreadable file")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("did not fall back past the unreadable report: %+v", got.Findings)
	}
}

// TestFutureSchemaVersionReadsAsAbsent: a future aurvet writing v2 must not
// make today's aurvet fail — same treatment as corrupt.
func TestFutureSchemaVersionReadsAsAbsent(t *testing.T) {
	dir := t.TempDir()
	reportsDir := filepath.Join(dir, "reports")
	if err := os.MkdirAll(reportsDir, 0o700); err != nil {
		t.Fatal(err)
	}
	future := `{"schema_version":2,"findings":[{"rule_id":"x","subject":"y"}],"gaps":[]}`
	if err := os.WriteFile(filepath.Join(reportsDir, "20260804T000000Z.json"), []byte(future), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest returned an error on an unrecognized schema_version: %v", err)
	}
	if ok {
		t.Errorf("unrecognized schema_version should read as absent, got %+v", got)
	}
}

// --- Diff ---

func TestDiffReportsAddedAndResolved(t *testing.T) {
	prev := sample()
	cur := finding.Result{Findings: []finding.Finding{{
		RuleID: "aur-orphaned", SubjectKind: "package", Subject: "foo-bin",
		Severity: finding.SevSuspicious, Summary: "orphaned",
	}}}
	added, resolved := Diff(prev, cur)
	if len(added) != 1 || added[0].Subject != "foo-bin" {
		t.Errorf("added = %+v", added)
	}
	if len(resolved) != 1 || resolved[0].Subject != "librewolf-fix-bin" {
		t.Errorf("resolved = %+v", resolved)
	}
}

// TestSaveIsNotFilteredBySinceLast is the D1 regression: an earlier design
// assigned the filtered --since-last view back onto the result before
// saving, which truncated the next run's baseline so every already-seen
// finding reappeared as new, forever. Save must always persist the full,
// unfiltered result.
func TestSaveIsNotFilteredBySinceLast(t *testing.T) {
	dir := t.TempDir()
	full := sample()
	if _, err := Save(dir, full, Summary{}, "20260804T000000Z"); err != nil {
		t.Fatalf("Save (1st): %v", err)
	}
	if _, err := Save(dir, full, Summary{}, "20260804T010000Z"); err != nil {
		t.Fatalf("Save (2nd): %v", err)
	}
	prev, ok, err := LoadPrevious(dir)
	if err != nil || !ok {
		t.Fatalf("LoadPrevious: err=%v ok=%v", err, ok)
	}
	added, _ := Diff(prev, full)
	if len(added) != 0 {
		t.Errorf("unchanged findings reported as new: %+v", added)
	}
}

// --- O-6: Fingerprint/Diff version-independence ---

// TestFingerprintIsVersionIndependent: FindingID hashes only (RuleID,
// SubjectKind, Subject, "subject") — never Evidence, Summary, or Severity —
// so two findings for the same rule and package that differ only in a
// version-bearing field OTHER than Subject must fingerprint identically.
// The negative control demonstrates the failure mode is detectable: a
// caller who instead folds the version into Subject breaks this.
func TestFingerprintIsVersionIndependent(t *testing.T) {
	a := finding.Finding{
		RuleID: "aur-provenance", SubjectKind: "package", Subject: "foo-bin",
		Summary: "seen at version 1.2.3", Evidence: []string{"pkgver=1.2.3"},
	}
	b := finding.Finding{
		RuleID: "aur-provenance", SubjectKind: "package", Subject: "foo-bin",
		Summary: "seen at version 1.2.4", Evidence: []string{"pkgver=1.2.4"},
	}
	if FindingID(a) != FindingID(b) {
		t.Errorf("fingerprint changed across a version-bearing non-Subject field: %s vs %s", FindingID(a), FindingID(b))
	}

	// Negative control: a version folded INTO Subject must produce a
	// different fingerprint — that is the failure mode this test guards.
	before := finding.Finding{RuleID: "aur-provenance", SubjectKind: "package", Subject: "foo-1.2.3-1"}
	after := finding.Finding{RuleID: "aur-provenance", SubjectKind: "package", Subject: "foo-1.2.4-1"}
	if FindingID(before) == FindingID(after) {
		t.Error("expected different fingerprints when Subject itself carries a version, got identical")
	}
}

// TestDiffSurvivesAPackageUpgrade: the same finding for the same package
// across an upgrade (Subject unchanged, only descriptive fields differ)
// must produce zero added and zero resolved — at ~28 pacman transactions a
// day, this is the whole --since-last feature.
func TestDiffSurvivesAPackageUpgrade(t *testing.T) {
	prev := finding.Result{Findings: []finding.Finding{{
		RuleID: "aur-orphaned", SubjectKind: "package", Subject: "foo-bin",
		Summary: "orphaned as of 1.2.3", Severity: finding.SevSuspicious,
	}}}
	cur := finding.Result{Findings: []finding.Finding{{
		RuleID: "aur-orphaned", SubjectKind: "package", Subject: "foo-bin",
		Summary: "orphaned as of 1.2.4", Severity: finding.SevSuspicious,
	}}}
	added, resolved := Diff(prev, cur)
	if len(added) != 0 {
		t.Errorf("added = %+v, want none — package upgrade must not look like a new finding", added)
	}
	if len(resolved) != 0 {
		t.Errorf("resolved = %+v, want none — package upgrade must not look like a resolved finding", resolved)
	}
}
