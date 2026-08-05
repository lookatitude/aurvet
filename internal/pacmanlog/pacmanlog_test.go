// internal/pacmanlog/pacmanlog_test.go
//
// The attack cases come first, deliberately: a log reader whose tests only
// cover a well-formed log is a reader that has never been shown the input it
// will actually be handed under --offline-root.
package pacmanlog

import (
	"bytes"
	"compress/gzip"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
	"time"
)

func fixture(t *testing.T, name string) Config {
	t.Helper()
	return Config{Path: filepath.Join("..", "..", "testdata", "pacmanlog", name, "pacman.log")}
}

func mustRead(t *testing.T, cfg Config) Result {
	t.Helper()
	r, err := Read(cfg)
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	return r
}

func gapReasons(r Result, rule string) []string {
	var out []string
	for _, g := range r.Gaps {
		if rule == "" || g.RuleID == rule {
			out = append(out, g.Reason)
		}
	}
	return out
}

// --- offset handling: the DST boundary -------------------------------------

// TestOffsetOrdersAcrossDST is the mutation target named in the lane brief. The
// two entries are written with different offsets and their WALL-CLOCK order is
// the reverse of their real order, so a parser that drops the offset (or reads
// the stamp as local time) returns them backwards. The temporal correlation key
// in internal/correlate consumes this ordering.
func TestOffsetOrdersAcrossDST(t *testing.T) {
	r := mustRead(t, fixture(t, "dst"))
	tx := r.Transactions()
	if len(tx) != 2 {
		t.Fatalf("want 2 transactions, got %d: %+v", len(tx), tx)
	}
	if tx[0].Pkg != "alpha" || tx[1].Pkg != "beta" {
		t.Fatalf("wrong order: %s then %s; alpha is 02:00+0100 = 01:00Z, beta is 01:30Z, "+
			"so alpha is FIRST -- reversed order means the offset was ignored", tx[0].Pkg, tx[1].Pkg)
	}
	if d := tx[1].Time.Sub(tx[0].Time); d != 30*time.Minute {
		t.Fatalf("want beta 30m after alpha, got %v (offset dropped gives -30m)", d)
	}
	// Absolute instants, so a reader that "normalised" by rewriting the zone is
	// caught even if the relative order survives.
	if got, want := tx[0].Time.Unix(), time.Date(2026, 3, 29, 1, 0, 0, 0, time.UTC).Unix(); got != want {
		t.Errorf("alpha instant = %d, want %d", got, want)
	}
	if len(r.Offsets) != 2 || r.Offsets[0] != "+0000" || r.Offsets[1] != "+0100" {
		t.Errorf("Offsets = %v, want [+0000 +0100]", r.Offsets)
	}
	if !r.MixedOffsets() {
		t.Error("MixedOffsets() = false on a log carrying two offsets")
	}
}

// TestNoOffsetIsAGap covers the pre-5.1 pacman format, whose stamps carry no
// offset at all. Reading them as local time would order them by the reader's
// zone, so they are a gap (INV-9) and never a silently accepted timestamp.
func TestNoOffsetIsAGap(t *testing.T) {
	r := mustRead(t, fixture(t, "legacy"))
	if len(r.Entries) != 1 || r.Entries[0].Pkg != "modern" {
		t.Fatalf("want only the offset-bearing entry, got %+v", r.Entries)
	}
	joined := strings.Join(gapReasons(r, RuleUnparsed), " | ")
	if !strings.Contains(joined, "offset") {
		t.Fatalf("no gap naming the missing offset: %q", joined)
	}
	// The unparseable head must not become the earliest timestamp: an
	// unorderable stamp cannot anchor the manifest's truncation detector.
	if want := time.Date(2026, 5, 1, 8, 0, 4, 0, time.UTC); r.Earliest.Unix() != want.Unix() {
		t.Errorf("Earliest = %s, want %s", r.Earliest, want)
	}
	if r.MaxSeverityIsCritical() {
		t.Error("an unparseable line produced a critical; it is a gap")
	}
}

// --- [ALPM] only -----------------------------------------------------------

func TestOnlyALPMLinesBecomeTransactions(t *testing.T) {
	r := mustRead(t, fixture(t, "hostile"))
	for _, e := range r.Entries {
		if e.Category != CategoryALPM {
			t.Errorf("entry from category %q: %+v", e.Category, e)
		}
	}
	if r.ScriptletLines != 1 {
		t.Errorf("ScriptletLines = %d, want 1", r.ScriptletLines)
	}
	// [ALPM-SCRIPTLET] shares a prefix with [ALPM]; a prefix match would count
	// it and inflate the transaction total. The [ALPM] line carrying a broken
	// timestamp is not counted either: an unorderable line is a gap, and
	// counting it as a recognised [ALPM] line would overstate coverage.
	if r.ALPMLines != 3 {
		t.Errorf("ALPMLines = %d, want 3 (scriptlet and the unstamped line excluded)", r.ALPMLines)
	}
	if got := len(r.Transactions()); got != 2 {
		t.Errorf("Transactions = %d, want 2 (good, later)", got)
	}
}

func TestUnknownALPMMessageIsAGapNotAnEntry(t *testing.T) {
	r := mustRead(t, fixture(t, "hostile"))
	if len(r.Entries) != 2 {
		t.Fatalf("entries = %+v", r.Entries)
	}
	joined := strings.Join(gapReasons(r, RuleUnparsed), " | ")
	if !strings.Contains(joined, "verbified") {
		t.Errorf("the gap does not quote the line it could not parse: %q", joined)
	}
	if !strings.Contains(joined, "unrecognised") {
		t.Errorf("no gap for the unrecognised [ALPM] verb: %q", joined)
	}
	if r.Unparsed != 3 {
		t.Errorf("Unparsed = %d, want 3 (no structure, bad timestamp, unknown verb)", r.Unparsed)
	}
}

// --- another root ----------------------------------------------------------

// TestForeignRootEntriesAreNotAttributedHere: entries under `-r /mnt` describe
// a different filesystem. Counting them as facts about this one is a false
// statement, so they are separated and reported as a coverage gap.
func TestForeignRootEntriesAreNotAttributedHere(t *testing.T) {
	r := mustRead(t, fixture(t, "foreignroot"))
	var here []string
	for _, e := range r.Entries {
		here = append(here, e.Pkg)
	}
	sort.Strings(here)
	want := []string{"openssl", "vim"}
	if strings.Join(here, ",") != strings.Join(want, ",") {
		t.Fatalf("attributed here = %v, want %v", here, want)
	}
	if len(r.Foreign) != 4 {
		t.Fatalf("foreign entries = %d, want 4 (iana-etc, filesystem, gcc, cowsay): %+v",
			len(r.Foreign), r.Foreign)
	}
	for _, root := range []string{"/mnt", "/srv/chroot"} {
		if r.ForeignRoots[root] == 0 {
			t.Errorf("ForeignRoots missing %s: %v", root, r.ForeignRoots)
		}
	}
	// `-Sr/mnt` clusters the flag with its value; missing that shape silently
	// attributes another root's install to this one.
	if r.ForeignRoots["/mnt"] != 3 {
		t.Errorf("ForeignRoots[/mnt] = %d, want 3 (the clustered -Sr/mnt form counted)",
			r.ForeignRoots["/mnt"])
	}
	if reasons := gapReasons(r, RuleForeignRoot); len(reasons) != 1 ||
		!strings.Contains(reasons[0], "/mnt") {
		t.Errorf("want one gap naming /mnt, got %v", reasons)
	}
	if r.MaxSeverityIsCritical() {
		t.Error("foreign-root entries produced a critical")
	}
}

func TestForeignRootTargetSelectsTheOtherSide(t *testing.T) {
	cfg := fixture(t, "foreignroot")
	cfg.Root = "/mnt/"
	r := mustRead(t, cfg)
	var here []string
	for _, e := range r.Entries {
		here = append(here, e.Pkg)
	}
	sort.Strings(here)
	if strings.Join(here, ",") != "cowsay,filesystem,iana-etc" {
		t.Fatalf("with Root=/mnt attributed = %v", here)
	}
}

// --- rotation --------------------------------------------------------------

func TestRotatedSiblingsAreRead(t *testing.T) {
	r := mustRead(t, fixture(t, "rotate"))
	var pkgs []string
	for _, tx := range r.Transactions() {
		pkgs = append(pkgs, tx.Pkg)
	}
	// Oldest first: rotation order is by rotation number descending, and the
	// result is time-sorted regardless.
	if strings.Join(pkgs, ",") != "oldest,older,old,current" {
		t.Fatalf("transactions = %v, want oldest,older,old,current", pkgs)
	}
	if want := time.Date(2025, 1, 1, 0, 0, 0, 0, time.UTC); r.Earliest.Unix() != want.Unix() {
		t.Errorf("Earliest = %s, want %s -- a reader that opens only pacman.log reports "+
			"a short window as the whole history", r.Earliest, want)
	}
	if len(r.Files) != 4 {
		t.Errorf("read %d files, want 4 readable: %+v", len(r.Files), r.Files)
	}
}

// TestUnsupportedCompressionIsAGap: zstd is not in the standard library and no
// module may be added, so a .zst sibling is unreadable history and must be said
// out loud rather than skipped.
func TestUnsupportedCompressionIsAGap(t *testing.T) {
	r := mustRead(t, fixture(t, "rotate"))
	reasons := strings.Join(gapReasons(r, RuleSibling), " | ")
	if !strings.Contains(reasons, "pacman.log.4.zst") {
		t.Fatalf("no gap for the zstd sibling: %q", reasons)
	}
	if !strings.Contains(reasons, "zstd") {
		t.Errorf("gap does not name the format: %q", reasons)
	}
}

func TestPrimaryLogAbsentIsAGapNotAnError(t *testing.T) {
	dir := t.TempDir()
	r, err := Read(Config{Path: filepath.Join(dir, "pacman.log")})
	if err != nil {
		t.Fatalf("Read: %v", err)
	}
	if len(r.Entries) != 0 || len(r.Gaps) == 0 {
		t.Fatalf("want no entries and a gap, got %d entries %d gaps", len(r.Entries), len(r.Gaps))
	}
	if !r.Earliest.IsZero() {
		t.Errorf("Earliest = %s on an absent log, want zero", r.Earliest)
	}
}

// --- bounds: everything an attacker sizes ----------------------------------

// TestGzipBombIsBounded builds the bomb at test time rather than committing
// one. A 1 GiB expansion must not be read into memory.
func TestGzipBombIsBounded(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "pacman.log"),
		[]byte("[2026-05-01T09:00:00+0100] [ALPM] installed real (1-1)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	line := []byte("[2026-05-01T09:00:00+0100] [ALPM] installed bomb (1-1)\n")
	for i := 0; i < 400000; i++ { // ~21 MB expanded, ~40 KB compressed
		if _, err := zw.Write(line); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "pacman.log.1.gz"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Path: filepath.Join(dir, "pacman.log")}
	cfg.Limits = DefaultLimits()
	cfg.Limits.MaxFileBytes = 1 << 20
	r := mustRead(t, cfg)
	if got := gapReasons(r, RuleBound); len(got) == 0 {
		t.Fatalf("no bound gap for the oversized sibling; gaps = %v", gapReasons(r, ""))
	}
	// The bound truncates; it does not discard the file, and it does not
	// discard the readable primary log.
	var sawReal bool
	for _, e := range r.Entries {
		if e.Pkg == "real" {
			sawReal = true
		}
	}
	if !sawReal {
		t.Error("the bound on one sibling lost the primary log's entries")
	}
	for _, f := range r.Files {
		if f.Bytes > cfg.Limits.MaxFileBytes {
			t.Errorf("%s: read %d bytes, over the %d bound", f.Path, f.Bytes, cfg.Limits.MaxFileBytes)
		}
	}
}

func TestOverlongLineIsBoundedAndGapped(t *testing.T) {
	dir := t.TempDir()
	long := "[2026-05-01T09:00:00+0100] [ALPM] installed " + strings.Repeat("a", 200000) + " (1-1)\n"
	body := long + "[2026-05-01T09:00:01+0100] [ALPM] installed after (1-1)\n"
	if err := os.WriteFile(filepath.Join(dir, "pacman.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustRead(t, Config{Path: filepath.Join(dir, "pacman.log")})
	if len(r.Entries) != 1 || r.Entries[0].Pkg != "after" {
		t.Fatalf("entries = %+v; the overlong line must be dropped and the NEXT line still read",
			r.Entries)
	}
	if got := gapReasons(r, RuleBound); len(got) == 0 {
		t.Fatalf("no gap for the overlong line: %v", gapReasons(r, ""))
	}
}

func TestLineCountIsBounded(t *testing.T) {
	dir := t.TempDir()
	var b strings.Builder
	for i := 0; i < 100; i++ {
		b.WriteString("[2026-05-01T09:00:00+0100] [ALPM] installed p (1-1)\n")
	}
	if err := os.WriteFile(filepath.Join(dir, "pacman.log"), []byte(b.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	cfg := Config{Path: filepath.Join(dir, "pacman.log")}
	cfg.Limits = DefaultLimits()
	cfg.Limits.MaxLines = 10
	r := mustRead(t, cfg)
	if r.LinesRead != 10 {
		t.Errorf("LinesRead = %d, want 10", r.LinesRead)
	}
	if got := gapReasons(r, RuleBound); len(got) == 0 {
		t.Fatal("no gap for the line-count bound")
	}
}

func TestSiblingCountIsBounded(t *testing.T) {
	dir := t.TempDir()
	for i := 0; i <= 40; i++ {
		name := "pacman.log"
		if i > 0 {
			name = "pacman.log." + itoa(i)
		}
		if err := os.WriteFile(filepath.Join(dir, name),
			[]byte("[2026-05-01T09:00:00+0100] [ALPM] installed p"+itoa(i)+" (1-1)\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	cfg := Config{Path: filepath.Join(dir, "pacman.log")}
	cfg.Limits = DefaultLimits()
	cfg.Limits.MaxFiles = 4
	r := mustRead(t, cfg)
	if len(r.Files) != 4 {
		t.Errorf("read %d files, want 4", len(r.Files))
	}
	if got := gapReasons(r, RuleBound); len(got) == 0 {
		t.Fatal("no gap for the sibling-count bound")
	}
}

func itoa(i int) string {
	if i == 0 {
		return "0"
	}
	var b []byte
	for i > 0 {
		b = append([]byte{byte('0' + i%10)}, b...)
		i /= 10
	}
	return string(b)
}

// --- short coverage vs truncation: the substance of the task ---------------

// TestShortCoverageIsAGapNotAWallOfCriticals is the load-bearing assertion of
// this task. A log that starts after the baseline leaves every earlier package
// unexplained; emitting one critical per package would make the tool noise.
func TestShortCoverageIsAGapNotAWallOfCriticals(t *testing.T) {
	cfg := fixture(t, "shortcoverage")
	cfg.BaselineStart = time.Date(2025, 11, 11, 0, 0, 0, 0, time.UTC)
	r := mustRead(t, cfg)

	if len(r.Findings) != 0 {
		t.Fatalf("short coverage produced %d findings; it is a gap: %+v", len(r.Findings), r.Findings)
	}
	if r.MaxSeverityIsCritical() {
		t.Fatal("short coverage produced a critical")
	}
	reasons := gapReasons(r, RuleWindowNotCovered)
	if len(reasons) != 1 {
		t.Fatalf("want exactly one coverage gap, got %v (a per-package gap would be the same wall)",
			reasons)
	}
	if !strings.Contains(reasons[0], "2025-11-11") {
		t.Errorf("gap does not name the baseline start: %q", reasons[0])
	}
	if r.CoversWindow(cfg.BaselineStart) {
		t.Error("CoversWindow says the window is covered when the log starts six months later")
	}
	// The bucket P4 task 11 needs: per-instant, is this inside coverage?
	if r.Covers(time.Date(2025, 12, 1, 0, 0, 0, 0, time.UTC)) {
		t.Error("Covers said an instant before the log's first line is covered")
	}
	if !r.Covers(time.Date(2026, 5, 1, 9, 0, 2, 0, time.UTC).Add(-time.Hour)) {
		t.Error("Covers said an instant inside the log is not covered")
	}
}

// TestTruncationIsAFindingNotAGap: the manifest recorded an earliest timestamp,
// which is a signed claim that the log DID reach back that far. It now starts
// later, so lines were removed. That is evidence, and it is distinct from "the
// log never went back that far".
func TestTruncationIsAFindingNotAGap(t *testing.T) {
	cfg := fixture(t, "shortcoverage")
	cfg.RecordedEarliest = time.Date(2025, 11, 11, 0, 50, 40, 0, time.UTC)
	r := mustRead(t, cfg)

	var found bool
	for _, f := range r.Findings {
		if f.RuleID == RuleTruncated {
			found = true
			if f.Severity == 0 {
				t.Error("truncation rated info")
			}
			if f.Limits == "" {
				t.Error("truncation finding states no limits (INV-6)")
			}
			if !strings.Contains(strings.Join(f.Evidence, " "), "2025-11-11T00:50:40Z") {
				t.Errorf("evidence does not name the recorded earliest: %v", f.Evidence)
			}
		}
	}
	if !found {
		t.Fatalf("no %s finding; findings = %+v gaps = %v", RuleTruncated, r.Findings, gapReasons(r, ""))
	}
	// And the two conditions are independent: this call passed no BaselineStart,
	// so there must be no window gap to confuse it with.
	if got := gapReasons(r, RuleWindowNotCovered); len(got) != 0 {
		t.Errorf("truncation also emitted a window gap: %v", got)
	}
}

// TestShortCoverageWithoutRecordIsNotTruncation is the other half of the
// distinction: with no signed earliest timestamp there is no claim that the log
// ever reached further back, so calling it truncation would be an accusation
// built on nothing.
func TestShortCoverageWithoutRecordIsNotTruncation(t *testing.T) {
	cfg := fixture(t, "shortcoverage")
	cfg.BaselineStart = time.Date(2025, 11, 11, 0, 0, 0, 0, time.UTC)
	r := mustRead(t, cfg)
	for _, f := range r.Findings {
		if f.RuleID == RuleTruncated {
			t.Fatalf("truncation claimed with no recorded earliest timestamp: %+v", f)
		}
	}
	if !strings.Contains(strings.Join(r.Notes, " "), "no recorded earliest") {
		t.Errorf("Notes do not say truncation could not be checked: %v", r.Notes)
	}
}

func TestRecordedEarliestIntactIsSilent(t *testing.T) {
	cfg := fixture(t, "rotate")
	cfg.RecordedEarliest = time.Date(2025, 6, 1, 0, 0, 0, 0, time.UTC) // later than the log's head
	r := mustRead(t, cfg)
	for _, f := range r.Findings {
		if f.RuleID == RuleTruncated {
			t.Fatalf("truncation claimed for a log reaching FURTHER back than recorded: %+v", f)
		}
	}
}

// TestManifestEarliestSpansEveryCategory: the manifest field is the earliest
// pacman.log timestamp, not the earliest [ALPM] transaction. On the reference
// log the first line is [PACMAN]; anchoring on [ALPM] only would record a later
// instant and blunt the truncation detector by 18 seconds -- or, on a log whose
// head is all invocation records, by much more.
func TestManifestEarliestSpansEveryCategory(t *testing.T) {
	r := mustRead(t, fixture(t, "foreignroot"))
	want := time.Date(2025, 11, 11, 0, 50, 40, 0, time.UTC)
	if r.Earliest.Unix() != want.Unix() {
		t.Fatalf("Earliest = %s, want the [PACMAN] head line %s", r.Earliest, want)
	}
	if r.EarliestString() != "2025-11-11T00:50:40+0000" {
		t.Errorf("EarliestString = %q, want the offset preserved as written", r.EarliestString())
	}
}

// --- purity ----------------------------------------------------------------

func TestReadWritesNothing(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "pacman.log")
	if err := os.WriteFile(path, []byte("[2026-05-01T09:00:00+0100] [ALPM] installed p (1-1)\n"), 0o444); err != nil {
		t.Fatal(err)
	}
	before, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	mustRead(t, Config{Path: path})
	after, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if before.ModTime() != after.ModTime() || before.Size() != after.Size() {
		t.Error("Read modified the log (INV-5)")
	}
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("Read created files: %d entries in the directory", len(ents))
	}
}

func TestReadIsDeterministic(t *testing.T) {
	cfg := fixture(t, "foreignroot")
	a, b := mustRead(t, cfg), mustRead(t, cfg)
	if a.EarliestString() != b.EarliestString() || len(a.Entries) != len(b.Entries) ||
		len(a.Gaps) != len(b.Gaps) {
		t.Fatal("two reads of the same log disagree")
	}
	for i := range a.Entries {
		if a.Entries[i] != b.Entries[i] {
			t.Fatalf("entry %d differs across reads", i)
		}
	}
}

func TestOpsRecognised(t *testing.T) {
	dir := t.TempDir()
	body := strings.Join([]string{
		"[2026-05-01T09:00:00+0100] [ALPM] installed a (1-1)",
		"[2026-05-01T09:00:01+0100] [ALPM] removed b (2-1)",
		"[2026-05-01T09:00:02+0100] [ALPM] upgraded c (1-1 -> 1-2)",
		"[2026-05-01T09:00:03+0100] [ALPM] downgraded d (2-1 -> 1-1)",
		"[2026-05-01T09:00:04+0100] [ALPM] reinstalled e (3-1)",
		"[2026-05-01T09:00:05+0100] [ALPM] transaction started",
		"[2026-05-01T09:00:06+0100] [ALPM] running '20-systemd-sysusers.hook'...",
		"[2026-05-01T09:00:07+0100] [ALPM] warning: /etc/x installed as /etc/x.pacnew",
		"[2026-05-01T09:00:08+0100] [ALPM] error: could not extract /usr/x",
		"",
	}, "\n")
	if err := os.WriteFile(filepath.Join(dir, "pacman.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustRead(t, Config{Path: filepath.Join(dir, "pacman.log")})
	if r.Unparsed != 0 {
		t.Errorf("Unparsed = %d on a log of recognised messages: %v", r.Unparsed, gapReasons(r, RuleUnparsed))
	}
	got := map[string]Entry{}
	for _, e := range r.Entries {
		got[e.Pkg] = e
	}
	if len(got) != 5 {
		t.Fatalf("entries = %+v", r.Entries)
	}
	if e := got["c"]; e.Op != OpUpgraded || e.PrevVersion != "1-1" || e.Version != "1-2" {
		t.Errorf("upgraded parse = %+v", e)
	}
	if e := got["a"]; e.Op != OpInstalled || e.Version != "1-1" || e.PrevVersion != "" {
		t.Errorf("installed parse = %+v", e)
	}
	if e := got["d"]; e.Op != OpDowngraded || e.PrevVersion != "2-1" || e.Version != "1-1" {
		t.Errorf("downgraded parse = %+v", e)
	}
}

func TestLimitsAreStated(t *testing.T) {
	r := mustRead(t, fixture(t, "rotate"))
	if !strings.Contains(r.Limits, "pacman") {
		t.Fatalf("Limits = %q", r.Limits)
	}
	// INV-6: the log records what pacman did, not what a build did.
	if !strings.Contains(r.Limits, "build") {
		t.Errorf("Limits does not say the log is silent about builds: %q", r.Limits)
	}
}

// TestEntriesBeforeAnyInvocationAreMarkedInferred: a rotated file usually
// begins in the middle of history, with no invocation line to say which root
// its transactions belong to. They are attributed to the target root -- the only
// useful default -- but marked so a caller can see the attribution is an
// assumption rather than something the log said.
func TestEntriesBeforeAnyInvocationAreMarkedInferred(t *testing.T) {
	r := mustRead(t, fixture(t, "rotate"))
	for _, e := range r.Entries {
		if !e.RootInferred {
			t.Errorf("%s: RootInferred = false with no invocation line in %s", e.Pkg, e.File)
		}
	}
	// And the reverse: an invocation line makes it evidence.
	r2 := mustRead(t, fixture(t, "foreignroot"))
	for _, e := range r2.Entries {
		if e.RootInferred {
			t.Errorf("%s: RootInferred = true although an invocation line preceded it", e.Pkg)
		}
	}
}

// FuzzParseLine: the offline log is attacker-controlled, and a parser that
// panics on it turns a scan into a crash. The fuzzer asserts only what must
// always hold -- no panic, and a parsed line yields an orderable instant.
func FuzzParseLine(f *testing.F) {
	f.Add("[2026-05-01T09:00:00+0100] [ALPM] installed p (1-1)")
	f.Add("[2026-05-01T09:00:00+0100] [ALPM] upgraded p (1-1 -> 1-2)")
	f.Add("[2015-06-01 12:00] [PACMAN] Running 'pacman -Syu'")
	f.Add("[2026-05-01T09:00:00Z] [ALPM-SCRIPTLET] x")
	f.Add("[")
	f.Add("[][]")
	f.Add("[2026-05-01T09:00:00+0100] [PACMAN] Running 'pacman -r")
	f.Fuzz(func(t *testing.T, s string) {
		l, kind := parseLine(s)
		if kind != kindOK {
			return
		}
		if l.when.IsZero() {
			t.Fatalf("kindOK with a zero instant: %q", s)
		}
		if l.offset == "" {
			t.Fatalf("kindOK with no offset recorded: %q", s)
		}
		if l.category == CategoryPacman {
			if root, ok := invocationRoot(l.message); ok && root == "" {
				t.Fatalf("empty root from %q", s)
			}
		}
		if l.category == CategoryALPM {
			_, pkg, ver, _, isTx, _ := parseALPM(l.message)
			if isTx && (pkg == "" || ver == "") {
				t.Fatalf("transaction with empty name or version from %q", s)
			}
		}
	})
}

// TestImplausibleTimestampIsAGap is the regression the fuzzer produced. A line
// dated year 1 parses cleanly as RFC3339 yet yields an instant that IsZero()
// calls unset -- the sentinel this package uses for "no timestamp" -- so it must
// be refused before it can become Result.Earliest.
func TestImplausibleTimestampIsAGap(t *testing.T) {
	dir := t.TempDir()
	body := "[0001-01-01T00:00:00+0000] [ALPM] installed forged (1-1)\n" +
		"[2026-05-01T09:00:00+0100] [ALPM] installed real (1-1)\n" +
		"[2026-05-01T9:00:00+0100] [ALPM] installed lenient (1-1)\n"
	if err := os.WriteFile(filepath.Join(dir, "pacman.log"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
	r := mustRead(t, Config{Path: filepath.Join(dir, "pacman.log")})
	if len(r.Entries) != 1 || r.Entries[0].Pkg != "real" {
		t.Fatalf("entries = %+v; only the plausible, canonically stamped line is a transaction", r.Entries)
	}
	if r.Unparsed != 2 {
		t.Errorf("Unparsed = %d, want 2 (year 1, and the single-digit hour time.Parse would accept)",
			r.Unparsed)
	}
	if r.Earliest.IsZero() || r.Earliest.Year() != 2026 {
		t.Errorf("Earliest = %s; a forged year-1 line must not become the manifest's anchor", r.Earliest)
	}
}
