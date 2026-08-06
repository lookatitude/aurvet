// internal/baseline/drift_test.go
//
// Task 11. The bucket that matters most is the fourth, so it is tested first and
// hardest: a log that never covered an instant must NOT produce a wall of
// criticals, and the assertion is that the critical count is exactly zero.
package baseline

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
)

const driftFixtureDir = "../../testdata/baseline/drift"

func mustTime(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := ParseStamp(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

func driftNow(t *testing.T) time.Time { return mustTime(t, "2026-08-06T09:00:00+0200") }

// baseManifest is a two-package baseline made at a known instant, with a signed
// log window that reaches back before it.
func baseManifest(t *testing.T) Manifest {
	t.Helper()
	return manifestWithLog(t, LogInput{
		Earliest: "2025-11-11T00:50:40+0000", Latest: "2025-12-31T23:00:00+0100",
	})
}

func manifestWithLog(t *testing.T, log LogInput) Manifest {
	t.Helper()
	m, err := BuildManifest(ManifestInput{
		Host: "reference", Root: "/", CreatedAt: "2026-01-01T00:00:00+0100", Tier: "full",
		Packages: []PackageInput{
			{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)},
			{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		},
		Log: log,
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func observed(pkgs ...ObservedPackage) []ObservedPackage { return pkgs }

// fullCoverage is a log observation spanning the whole baseline window.
func fullCoverage(t *testing.T, txs ...LogTransaction) LogObservation {
	t.Helper()
	return LogObservation{
		Earliest:     mustTime(t, "2025-11-11T00:50:40+0000"),
		Latest:       mustTime(t, "2026-08-06T08:00:00+0200"),
		Transactions: txs,
	}
}

// -- bucket 4: a log-coverage shortfall is NOT a wall of criticals -------------

// The whole reason the fourth bucket exists. This baseline recorded no log window
// at all, so nothing signed says whether the log ever covered the changes; rating
// them on the log's silence would be an accusation derived from an absence
// (INV-3). Reduced severity, one gap, zero criticals.
func TestLogCoverageShortfallProducesNoCriticalsAtAll(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: manifestWithLog(t, LogInput{}), // no recorded window
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.2-1", MtreeSHA256: strings.Repeat("c", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("d", 64)},
			ObservedPackage{Name: "curl", Version: "8.11.0-1", MtreeSHA256: strings.Repeat("e", 64),
				InstallDate: mustTime(t, "2026-07-01T10:00:00+0200")},
		),
		Log: LogObservation{
			// Coverage begins after the baseline: whether it ever reached further
			// back cannot be judged, because the baseline recorded nothing to
			// compare against.
			Earliest: mustTime(t, "2026-06-01T00:00:00+0200"),
			Latest:   mustTime(t, "2026-08-05T00:00:00+0200"),
		},
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Counts[BucketLogCoverageGap]; got != 3 {
		t.Fatalf("log-coverage bucket holds %d items, want 3 (version, mtree, added): %+v",
			got, rep.Items)
	}
	if got := rep.Counts[BucketUnexplained]; got != 0 {
		t.Fatalf("%d items rated unexplained although nothing signed says the log covered them", got)
	}
	criticals := 0
	for _, f := range rep.Result.Findings {
		if f.Severity == finding.SevCritical {
			criticals++
		}
	}
	if criticals != 0 {
		t.Fatalf("%d critical(s) from a coverage shortfall; the bucket exists to prevent exactly this",
			criticals)
	}
	if len(rep.Result.Gaps) != 1 {
		t.Fatalf("want exactly ONE gap for the whole shortfall, not one per package, got %d: %+v",
			len(rep.Result.Gaps), rep.Result.Gaps)
	}
	if !strings.Contains(rep.Result.Gaps[0].Reason, "not evidence against") {
		t.Fatalf("the gap does not say what it is not: %q", rep.Result.Gaps[0].Reason)
	}
}

// The distinction the brief insists on: "the log never went back that far" is a
// GAP; "the log used to go back further" is EVIDENCE. They must not collapse, so
// the same shortfall against a baseline that DID record a window keeps its items
// unexplained and cites the truncation.
func TestTruncationIsEvidenceAndDoesNotExcuseDrift(t *testing.T) {
	short := LogObservation{
		Earliest: mustTime(t, "2026-06-01T00:00:00+0200"),
		Latest:   mustTime(t, "2026-08-05T00:00:00+0200"),
	}
	obs := observed(
		ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("z", 64)},
		ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
	)

	// No recorded window: reduced severity (the case above, one item).
	unjudgeable, err := Drift(DriftInput{
		Manifest: manifestWithLog(t, LogInput{}), Observed: obs, Log: short, Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if unjudgeable.Counts[BucketLogCoverageGap] != 1 || unjudgeable.Counts[BucketUnexplained] != 0 {
		t.Fatalf("unjudgeable shortfall bucketed wrong: %+v", unjudgeable.Counts)
	}
	if unjudgeable.Truncated {
		t.Fatal("truncation was claimed with nothing signed to compare against")
	}

	// A recorded window that reached further back: the shortfall is evidence.
	repTrunc, err := Drift(DriftInput{
		Manifest: baseManifest(t), Observed: obs, Log: short, Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !repTrunc.Truncated {
		t.Fatal("truncation was not detected against the baseline's signed log window")
	}
	if repTrunc.Counts[BucketUnexplained] != 1 || repTrunc.Counts[BucketLogCoverageGap] != 0 {
		t.Fatalf("truncation excused the drift: %+v", repTrunc.Counts)
	}
	if repTrunc.Result.MaxSeverity() != finding.SevCritical {
		t.Fatal("an mtree change whose explanation was removed from the log is not critical")
	}
	var cited bool
	for _, f := range repTrunc.Result.Findings {
		for _, e := range f.Evidence {
			if strings.Contains(strings.ToLower(e), "truncat") {
				cited = true
			}
		}
	}
	if !cited {
		t.Fatalf("the finding does not cite the truncation that removed its explanation: %+v",
			repTrunc.Result.Findings)
	}
}

// Both at once: the log has been truncated AND a package claims an install date
// before the signed window. Truncation must win, because that date comes from
// %INSTALLDATE% and root can rewrite it -- otherwise "delete the log, then backdate
// the package" turns a critical into a coverage gap in two commands.
func TestTruncationBeatsAnInstallDateClaimThatWouldDownRateIt(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t), // records earliest 2025-11-11
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
			ObservedPackage{Name: "planted", Version: "1-1", MtreeSHA256: strings.Repeat("9", 64),
				InstallDate: mustTime(t, "2025-06-01T00:00:00+0200")},
		),
		Log: LogObservation{
			Earliest: mustTime(t, "2026-06-01T00:00:00+0200"),
			Latest:   mustTime(t, "2026-08-05T00:00:00+0200"),
		},
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if !rep.Truncated {
		t.Fatal("precondition: truncation was not detected")
	}
	if rep.Counts[BucketLogCoverageGap] != 0 {
		t.Fatalf("a backdated install date bought a down-rating on a truncated log: %+v", rep.Items)
	}
	if rep.Counts[BucketUnexplained] != 1 || rep.Items[0].Package != "planted" {
		t.Fatalf("buckets: %+v items: %+v", rep.Counts, rep.Items)
	}
	if rep.Result.MaxSeverity() != finding.SevCritical {
		t.Fatal("the planted package is not critical")
	}
}

// A log read that stopped at a limit must NOT down-rate anything. Otherwise
// inflating the log is a way to turn every critical into a coverage gap, which is
// a downgrade attack with a two-line implementation.
func TestABoundedLogReadDoesNotDownRateAnything(t *testing.T) {
	log := fullCoverage(t)
	log.Bounded = true
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("f", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: log,
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 {
		t.Fatalf("a bounded read moved an item out of unexplained: %+v", rep.Counts)
	}
	if len(rep.Result.Gaps) == 0 {
		t.Fatal("a bounded read raised no coverage gap (INV-9)")
	}
}

// -- bucket 3: unexplained ----------------------------------------------------

func TestUnexplainedMtreeChangeIsCritical(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("f", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t),
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 {
		t.Fatalf("buckets: %+v items: %+v", rep.Counts, rep.Items)
	}
	if rep.Result.MaxSeverity() != finding.SevCritical {
		t.Fatalf("severity %s, want critical", rep.Result.MaxSeverity())
	}
	if len(rep.Result.Gaps) != 0 {
		t.Fatalf("a fully covered log still produced coverage gaps: %+v", rep.Result.Gaps)
	}
	for _, f := range rep.Result.Findings {
		if f.Limits == "" {
			t.Fatal("a drift finding states no limits (INV-6)")
		}
	}
}

// -- bucket 1: corroborated ---------------------------------------------------

func TestATransactionCorroboratesTheChangeItExplains(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.2-1", MtreeSHA256: strings.Repeat("c", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
			ObservedPackage{Name: "curl", Version: "8.11.0-1", MtreeSHA256: strings.Repeat("e", 64)},
		),
		Log: fullCoverage(t,
			LogTransaction{Time: mustTime(t, "2026-03-01T10:00:00+0100"), Op: "upgraded", Pkg: "zlib", Version: "1.3.2-1"},
			LogTransaction{Time: mustTime(t, "2026-04-02T10:00:00+0200"), Op: "installed", Pkg: "curl", Version: "8.11.0-1"},
		),
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketCorroborated] != 2 {
		t.Fatalf("buckets: %+v items: %+v", rep.Counts, rep.Items)
	}
	if rep.Counts[BucketUnexplained] != 0 {
		t.Fatalf("a corroborated change was also reported as unexplained: %+v", rep.Items)
	}
	if len(rep.Result.Findings) != 0 {
		t.Fatalf("corroborated drift produced findings: %+v", rep.Result.Findings)
	}
}

// A transaction that leaves a DIFFERENT version does not corroborate: the system
// is not in the state the log says it was left in.
func TestATransactionLeavingAnotherVersionDoesNotCorroborate(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.2-1", MtreeSHA256: strings.Repeat("c", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t,
			LogTransaction{Time: mustTime(t, "2026-03-01T10:00:00+0100"), Op: "upgraded", Pkg: "zlib", Version: "1.3.9-9"},
		),
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 {
		t.Fatalf("a transaction leaving a different version corroborated anyway: %+v", rep.Items)
	}
}

// A transaction dated BEFORE the baseline cannot explain a change made after it.
func TestATransactionBeforeTheBaselineDoesNotCorroborate(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.2-1", MtreeSHA256: strings.Repeat("c", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t,
			LogTransaction{Time: mustTime(t, "2025-12-01T10:00:00+0100"), Op: "upgraded", Pkg: "zlib", Version: "1.3.2-1"},
		),
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 {
		t.Fatalf("a pre-baseline transaction corroborated a post-baseline change: %+v", rep.Items)
	}
}

// -- bucket 2: adjudicated ----------------------------------------------------

func TestAnAdjudicationMovesDriftOutOfUnexplainedAndStaysVisible(t *testing.T) {
	in := DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("f", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t),
		Now: driftNow(t),
	}
	before, err := Drift(in)
	if err != nil {
		t.Fatal(err)
	}
	if before.Counts[BucketUnexplained] != 1 {
		t.Fatalf("precondition: %+v", before.Counts)
	}

	in.Adjudications = []DriftAdjudication{{
		RuleID: DriftRule, Subject: "zlib", Scope: "subject",
		Reason: "rebuilt locally from the same PKGBUILD after a toolchain bump; verified by hand",
	}}
	after, err := Drift(in)
	if err != nil {
		t.Fatal(err)
	}
	if after.Counts[BucketAdjudicated] != 1 || after.Counts[BucketUnexplained] != 0 {
		t.Fatalf("buckets: %+v", after.Counts)
	}
	if after.Result.MaxSeverity() == finding.SevCritical {
		t.Fatal("an adjudicated change is still critical")
	}
	// INV-6: the absence must be visible somewhere, with the reason.
	var seen bool
	for _, f := range after.Result.Findings {
		if strings.Contains(f.Summary, "adjudicated") &&
			strings.Contains(strings.Join(f.Evidence, " "), "toolchain") {
			seen = true
		}
	}
	if !seen {
		t.Fatalf("the adjudicated drift vanished from the report entirely: %+v", after.Result.Findings)
	}
}

// An adjudication with no reason is not an adjudication. It must not suppress, and
// it must be visible as a gap rather than ignored (INV-9).
func TestAnAdjudicationWithoutAReasonSuppressesNothing(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("f", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log:           fullCoverage(t),
		Adjudications: []DriftAdjudication{{RuleID: DriftRule, Subject: "zlib", Scope: "subject"}},
		Now:           driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketAdjudicated] != 0 || rep.Counts[BucketUnexplained] != 1 {
		t.Fatalf("a reasonless adjudication suppressed drift: %+v", rep.Counts)
	}
	if len(rep.Result.Gaps) == 0 {
		t.Fatal("a reasonless adjudication was ignored silently")
	}
}

// An adjudication that has expired suppresses nothing. Expiry is judged against
// the `now` passed in, never a clock read inside the classifier (INV-4).
func TestAnExpiredAdjudicationSuppressesNothing(t *testing.T) {
	in := DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("f", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t),
		Adjudications: []DriftAdjudication{{
			RuleID: DriftRule, Subject: "zlib", Scope: "subject",
			Reason:    "accepted for one week while the rebuild is investigated",
			ExpiresAt: "2026-02-01T00:00:00+0100",
		}},
		Now: driftNow(t),
	}
	rep, err := Drift(in)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 || rep.Counts[BucketAdjudicated] != 0 {
		t.Fatalf("an expired adjudication still suppressed: %+v", rep.Counts)
	}

	// The same input, evaluated before the expiry, does suppress -- which is what
	// makes the assertion above about EXPIRY and not about matching.
	in.Now = mustTime(t, "2026-01-15T00:00:00+0100")
	rep, err = Drift(in)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketAdjudicated] != 1 {
		t.Fatalf("the adjudication never matched at all, so the expiry test proves nothing: %+v",
			rep.Counts)
	}
}

// -- the four buckets must be told apart --------------------------------------

func TestTheFourBucketsArePairwiseDistinguishable(t *testing.T) {
	m, err := BuildManifest(ManifestInput{
		Host: "reference", Root: "/", CreatedAt: "2026-01-01T00:00:00+0100", Tier: "full",
		Packages: []PackageInput{
			{Name: "corrob", Version: "1-1", MtreeSHA256: strings.Repeat("1", 64)},
			{Name: "adjud", Version: "1-1", MtreeSHA256: strings.Repeat("2", 64)},
			{Name: "unexpl", Version: "1-1", MtreeSHA256: strings.Repeat("3", 64)},
		},
		Log: LogInput{Earliest: "2025-11-11T00:50:40+0000", Latest: "2025-12-31T23:00:00+0100"},
	})
	if err != nil {
		t.Fatal(err)
	}
	rep, err := Drift(DriftInput{
		Manifest: m,
		Observed: observed(
			ObservedPackage{Name: "corrob", Version: "2-1", MtreeSHA256: strings.Repeat("5", 64)},
			ObservedPackage{Name: "adjud", Version: "2-1", MtreeSHA256: strings.Repeat("6", 64)},
			ObservedPackage{Name: "unexpl", Version: "2-1", MtreeSHA256: strings.Repeat("7", 64)},
			// Added, and carrying an %INSTALLDATE% from before the log window the
			// baseline signed: the log never covered it, so it cannot be rated on
			// the log's silence.
			ObservedPackage{Name: "gapped", Version: "1-1", MtreeSHA256: strings.Repeat("8", 64),
				InstallDate: mustTime(t, "2025-06-01T00:00:00+0200")},
		),
		Log: fullCoverage(t,
			LogTransaction{Time: mustTime(t, "2026-03-01T10:00:00+0100"), Op: "upgraded", Pkg: "corrob", Version: "2-1"},
		),
		Adjudications: []DriftAdjudication{{
			RuleID: DriftRule, Subject: "adjud", Scope: "subject",
			Reason: "accepted: rebuilt against the new toolchain, diff reviewed",
		}},
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	byPkg := map[string]Bucket{}
	for _, it := range rep.Items {
		if prev, dup := byPkg[it.Package]; dup {
			t.Fatalf("%s landed in two buckets: %s and %s", it.Package, prev, it.Bucket)
		}
		byPkg[it.Package] = it.Bucket
	}
	want := map[string]Bucket{
		"corrob": BucketCorroborated,
		"adjud":  BucketAdjudicated,
		"unexpl": BucketUnexplained,
		"gapped": BucketLogCoverageGap,
	}
	for pkg, wantBucket := range want {
		if got := byPkg[pkg]; got != wantBucket {
			t.Errorf("%s bucketed %q, want %q", pkg, got, wantBucket)
		}
	}
	if len(rep.Items) != 4 {
		t.Fatalf("%d items for 4 changes: %+v", len(rep.Items), rep.Items)
	}
	// Distinguishable in the OUTPUT, not only in the struct: exactly one critical,
	// one gap, and the adjudicated one visible at info.
	criticals, infos := 0, 0
	for _, f := range rep.Result.Findings {
		switch f.Severity {
		case finding.SevCritical:
			criticals++
		case finding.SevInfo:
			infos++
		}
	}
	if criticals != 1 {
		t.Errorf("%d criticals, want exactly the unexplained one", criticals)
	}
	if infos < 2 {
		t.Errorf("%d info findings, want the adjudicated and the coverage-gapped ones", infos)
	}
	if len(rep.Result.Gaps) != 1 {
		t.Errorf("%d gaps, want one for the coverage shortfall: %+v", len(rep.Result.Gaps), rep.Result.Gaps)
	}
}

// -- the fixture the reference machine cannot provide -------------------------

// Measured on the reference machine: 0 of 1,410 packages predate the log window,
// so the log-coverage bucket is empty there. A committed fixture is the only way
// this path is exercised at all.
func TestLogCoverageFixture(t *testing.T) {
	path := filepath.Join(driftFixtureDir, "short-coverage.json")
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var fx driftFixture
	dec := json.NewDecoder(strings.NewReader(string(b)))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&fx); err != nil {
		t.Fatal(err)
	}
	rep, err := Drift(fx.input(t))
	if err != nil {
		t.Fatal(err)
	}
	if got := rep.Counts[BucketLogCoverageGap]; got != fx.WantLogCoverageGap {
		t.Fatalf("%s: log-coverage bucket %d, want %d (%+v)", path, got, fx.WantLogCoverageGap, rep.Items)
	}
	if got := rep.Counts[BucketUnexplained]; got != fx.WantUnexplained {
		t.Fatalf("%s: %d unexplained, want %d", path, got, fx.WantUnexplained)
	}
	// The coverage-gapped item must not be critical; the genuinely unexplained one
	// in the same fixture must be, or the fixture would prove only that everything
	// in it was down-rated.
	for _, it := range rep.Items {
		switch it.Bucket {
		case BucketLogCoverageGap:
			if it.Severity == finding.SevCritical {
				t.Fatalf("%s: %s was rated critical from a coverage shortfall", path, it.Package)
			}
		case BucketUnexplained:
			if it.Severity != finding.SevCritical {
				t.Fatalf("%s: %s is unexplained and not critical", path, it.Package)
			}
		}
	}
}

type driftFixture struct {
	Comment  string `json:"comment"`
	Manifest struct {
		CreatedAt string `json:"created_at"`
		Packages  []struct {
			Name        string `json:"name"`
			Version     string `json:"version"`
			MtreeSHA256 string `json:"mtree_sha256"`
		} `json:"packages"`
		LogEarliest string `json:"log_earliest"`
		LogLatest   string `json:"log_latest"`
	} `json:"manifest"`
	Observed []struct {
		Name        string `json:"name"`
		Version     string `json:"version"`
		MtreeSHA256 string `json:"mtree_sha256"`
		InstallDate string `json:"install_date"`
	} `json:"observed"`
	Log struct {
		Earliest string `json:"earliest"`
		Latest   string `json:"latest"`
	} `json:"log"`
	Now                string `json:"now"`
	WantLogCoverageGap int    `json:"want_log_coverage_gap"`
	WantUnexplained    int    `json:"want_unexplained"`
}

func (fx driftFixture) input(t *testing.T) DriftInput {
	t.Helper()
	var pkgs []PackageInput
	for _, p := range fx.Manifest.Packages {
		pkgs = append(pkgs, PackageInput{Name: p.Name, Version: p.Version, MtreeSHA256: p.MtreeSHA256})
	}
	m, err := BuildManifest(ManifestInput{
		Host: "fixture", Root: "/", CreatedAt: fx.Manifest.CreatedAt, Tier: "full",
		Packages: pkgs,
		Log:      LogInput{Earliest: fx.Manifest.LogEarliest, Latest: fx.Manifest.LogLatest},
	})
	if err != nil {
		t.Fatal(err)
	}
	var obs []ObservedPackage
	for _, p := range fx.Observed {
		o := ObservedPackage{Name: p.Name, Version: p.Version, MtreeSHA256: p.MtreeSHA256}
		if p.InstallDate != "" {
			o.InstallDate = mustTime(t, p.InstallDate)
		}
		obs = append(obs, o)
	}
	return DriftInput{
		Manifest: m,
		Observed: obs,
		Log: LogObservation{
			Earliest: mustTime(t, fx.Log.Earliest),
			Latest:   mustTime(t, fx.Log.Latest),
		},
		Now: mustTime(t, fx.Now),
	}
}

// -- refusals -----------------------------------------------------------------

func TestDriftRefusesWhatItCannotClassify(t *testing.T) {
	good := DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t),
		Now: driftNow(t),
	}
	rep, err := Drift(good)
	if err != nil {
		t.Fatalf("precondition: %v", err)
	}
	if len(rep.Items) != 0 {
		t.Fatalf("an unchanged system drifted: %+v", rep.Items)
	}

	noNow := good
	noNow.Now = time.Time{}
	if _, err := Drift(noNow); err == nil {
		t.Error("Drift accepted a zero `now`; expiry would then depend on the day it ran")
	}

	dup := good
	dup.Observed = append(append([]ObservedPackage(nil), good.Observed...), good.Observed[0])
	if _, err := Drift(dup); err == nil {
		t.Error("Drift accepted the same package observed twice")
	}

	noBaseline := good
	noBaseline.Manifest = Manifest{}
	if _, err := Drift(noBaseline); err == nil {
		t.Error("Drift accepted an empty manifest as a baseline to compare against")
	}
}

// An mtree that could not be read is not drift and must never read as agreement:
// it is a coverage gap for that package (INV-9).
func TestAnUnreadableMtreeIsAGapAndNotAComparison(t *testing.T) {
	rep, err := Drift(DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(
			ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeUnread: "permission denied"},
			ObservedPackage{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		),
		Log: fullCoverage(t),
		Now: driftNow(t),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rep.Items) != 0 {
		t.Fatalf("an unreadable mtree was classified as a change: %+v", rep.Items)
	}
	if len(rep.Result.Gaps) != 1 {
		t.Fatalf("want one gap for the unreadable mtree, got %+v", rep.Result.Gaps)
	}
	if rep.Result.MaxSeverity() == finding.SevCritical {
		t.Fatal("an unreadable mtree became an accusation")
	}
}

// A removal with no transaction is unexplained; with one, corroborated. Both
// directions, because a removal is the change most easily lost.
func TestRemovalIsClassifiedBothWays(t *testing.T) {
	base := DriftInput{
		Manifest: baseManifest(t),
		Observed: observed(ObservedPackage{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)}),
		Log:      fullCoverage(t),
		Now:      driftNow(t),
	}
	rep, err := Drift(base)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketUnexplained] != 1 || rep.Items[0].Kind != ChangeRemoved {
		t.Fatalf("an unexplained removal was not reported as one: %+v", rep.Items)
	}

	base.Log = fullCoverage(t,
		LogTransaction{Time: mustTime(t, "2026-02-01T10:00:00+0100"), Op: "removed", Pkg: "openssl", Version: "3.4.0-1"},
	)
	rep, err = Drift(base)
	if err != nil {
		t.Fatal(err)
	}
	if rep.Counts[BucketCorroborated] != 1 {
		t.Fatalf("a logged removal was not corroborated: %+v", rep.Items)
	}
}
