package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// spec §11's privilege policy: `scan` requires root and refuses unprivileged
// unless --allow-degraded is passed, which stamps the report and forces the
// incomplete exit.
//
// The behaviour these tests pin is not a preference. Before them, an
// unprivileged `aurvet scan` ran, said nothing about privilege, and exited 3 --
// on this machine 32 of its 72 coverage gaps were permission-denied, so exit 3
// was the outcome of EVERY unprivileged run. A code that always fires carries no
// information, and an operator who sees it on every run stops reading it. That
// is the state §11 was written to prevent.
// ---------------------------------------------------------------------------

// The policy is a pure function of the three inputs that decide it, so every
// combination can be asserted without standing up a scan. The table is
// exhaustive on purpose: the interesting cell is the one nobody thinks about,
// and here it was unprivileged + --offline-root.
func TestPrivilegePolicyTable(t *testing.T) {
	const nonRoot, root = 1000, 0
	cases := []struct {
		name          string
		euid          int
		offlineRoot   string
		allowDegraded bool
		wantRefuse    bool
		wantDegraded  bool
	}{
		{"root, live, no flag", root, "", false, false, false},
		{"root, live, flag", root, "", true, false, false},
		{"unprivileged, live, no flag", nonRoot, "", false, true, false},
		{"unprivileged, live, flag", nonRoot, "", true, false, true},
		{"unprivileged, offline root, no flag", nonRoot, "/mnt", false, false, false},
		{"unprivileged, offline root, flag", nonRoot, "/mnt", true, false, true},
		{"root, offline root, no flag", root, "/mnt", false, false, false},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := privilegePolicy(c.euid, c.offlineRoot, c.allowDegraded)
			if got.Refuse != c.wantRefuse {
				t.Errorf("Refuse = %v, want %v", got.Refuse, c.wantRefuse)
			}
			if got.Degraded != c.wantDegraded {
				t.Errorf("Degraded = %v, want %v", got.Degraded, c.wantDegraded)
			}
			if got.Refuse && len(got.Refusal) == 0 {
				t.Error("a refusal with no text: the operator is told no and not told why")
			}
			if got.Degraded && len(got.Stamp) == 0 {
				t.Error("a degraded run with no stamp: the report would not carry the fact that " +
					"bounds it")
			}
		})
	}
}

// The refusal must be a refusal -- exit 2, nothing scanned -- and it must name
// both ways forward. A refusal that does not say how to proceed is a wall.
func TestUnprivilegedLiveScanRefusesAndNamesBothWaysForward(t *testing.T) {
	euid := 1000
	var stdout, stderr strings.Builder
	code := runScan(scanOpts{euid: &euid}, &stdout, &stderr)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d (a refusal, not a degraded run)\nstdout: %s\nstderr: %s",
			code, exitUsage, stdout.String(), stderr.String())
	}
	if stdout.String() != "" {
		t.Errorf("the refusal wrote a report to stdout: %s", stdout.String())
	}
	for _, want := range []string{"sudo aurvet scan", "--allow-degraded"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, stderr.String())
		}
	}
	// It must say what is unavailable, not merely that something is.
	for _, want := range []string{"/etc/shadow", "unreadable", "directories"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("the refusal does not name what is unavailable (%q):\n%s", want, stderr.String())
		}
	}
}

// --allow-degraded stamps the report and forces the incomplete exit. The root
// here is one that exits 0 without the flag (TestScanIsCleanWhenContentsMatch...
// asserts exactly that), so the exit 3 below is the flag's doing and nothing
// else: "I could not look everywhere" is the finding.
func TestAllowDegradedStampsTheReportAndCannotExitZero(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "the packaged bytes\n")
	euid := 1000
	var stdout, stderr strings.Builder
	code := runScan(scanOpts{offlineRoot: root, allowDegraded: true, euid: &euid}, &stdout, &stderr)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: a degraded scan may never exit 0, even with zero gaps of its own"+
			"\nstdout:\n%s\nstderr:\n%s", code, exitIncomplete, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "DEGRADED") {
		t.Errorf("the report carries no degradation stamp:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "coverage: incomplete") {
		t.Errorf("the header still reports complete coverage on a degraded run:\n%s", stdout.String())
	}
}

// The stamp belongs where the verdict is: above the findings, on the same terms
// the replication banner earned its position. A report whose coverage is bounded
// by permissions cannot have that fact printed below 40 findings.
func TestTheDegradationStampPrecedesTheFindings(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered\n")
	euid := 1000
	var stdout, stderr strings.Builder
	if code := runScan(scanOpts{offlineRoot: root, allowDegraded: true, euid: &euid},
		&stdout, &stderr); code != exitIncomplete {
		t.Fatalf("exit = %d, want %d\n%s", code, exitIncomplete, stderr.String())
	}
	out := stdout.String()
	stamp := strings.Index(out, "DEGRADED")
	first := strings.Index(out, "\n[")
	if stamp < 0 {
		t.Fatalf("no stamp in:\n%s", out)
	}
	if first < 0 {
		t.Fatalf("no finding or gap in the output, so the ordering assertion is vacuous:\n%s", out)
	}
	if stamp > first {
		t.Errorf("the degradation stamp (%d) is printed below the first finding (%d):\n%s", stamp, first, out)
	}
}

// The forced incompleteness is a coverage gap, so -min-severity cannot gate it
// (INV-3: a floor is a reporting preference and must not overrule the contract).
func TestTheDegradationGapSurvivesTheHighestFloor(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	euid := 1000
	var stdout, stderr strings.Builder
	code := runScan(scanOpts{offlineRoot: root, allowDegraded: true, minSeverity: "critical", euid: &euid},
		&stdout, &stderr)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: -min-severity gated the degradation gap\n%s",
			code, exitIncomplete, stdout.String())
	}
}

// The gap is in the JSON document too, because a caller parsing stdout is
// exactly the reader who must not mistake a permission-bounded scan for a
// complete one.
func TestTheDegradationGapIsInTheJSONDocument(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	euid := 1000
	var stdout, stderr strings.Builder
	runScan(scanOpts{offlineRoot: root, allowDegraded: true, jsonOut: true, euid: &euid}, &stdout, &stderr)
	rep := decodeReport(t, stdout.String())
	found := false
	for _, g := range rep.CoverageGaps {
		if g.RuleID == rulePrivilegeCoverage {
			found = true
		}
	}
	if !found {
		t.Errorf("no %s gap in the JSON document: %+v", rulePrivilegeCoverage, rep.CoverageGaps)
	}
	if rep.CoverageComplete {
		t.Error("coverage_complete is true on a degraded scan")
	}
	// Nothing but JSON on stdout: the stamp goes to stderr under -json.
	if strings.Contains(stdout.String(), "DEGRADED SCAN") {
		t.Errorf("the human stamp was written into the JSON document:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "DEGRADED") {
		t.Errorf("under -json the stamp must still reach a human on stderr:\n%s", stderr.String())
	}
}

// An offline root is exempt, and this is the case worth stating: examining a
// mounted filesystem as an ordinary user is legitimate and common, the files
// there are readable exactly to the extent the mount and its ownership allow,
// and the whole existing suite scans offline roots to exit 0 unprivileged --
// which is what makes exit 3 informative there. The measurement behind the
// decision is in this lane's receipt: an unprivileged scan of a user-owned
// offline root produces ZERO permission-denied gaps, against 32 on the live
// system.
func TestAnOfflineRootIsExemptFromThePrivilegeRefusal(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	euid := 1000
	var stdout, stderr strings.Builder
	code := runScan(scanOpts{offlineRoot: root, euid: &euid}, &stdout, &stderr)
	if code == exitUsage {
		t.Fatalf("an unprivileged offline-root scan was refused:\n%s", stderr.String())
	}
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitClean,
			stdout.String(), stderr.String())
	}
	if strings.Contains(stdout.String(), "DEGRADED") {
		t.Errorf("an exempt run stamped itself degraded:\n%s", stdout.String())
	}
}

// The refusal reaches the CLI, not only runScan: the flag has to be wired.
func TestAllowDegradedIsWiredToTheCommandLine(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	code, stdout, stderr := scanOut(t, "scan", "-allow-degraded", "-offline-root", root)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitIncomplete, stdout, stderr)
	}
	if !strings.Contains(stdout, "DEGRADED") {
		t.Errorf("-allow-degraded is not wired: no stamp\n%s", stdout)
	}
}

// A degraded report is still persisted, and the gap goes with it: the stored
// report is what --since-last diffs against, and a stored report that dropped
// the degradation would make the next run's baseline claim coverage it never had.
func TestADegradedReportIsPersistedWithItsGap(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	state := t.TempDir()
	euid := 1000
	var stdout, stderr strings.Builder
	runScan(scanOpts{offlineRoot: root, allowDegraded: true, stateDir: state, euid: &euid}, &stdout, &stderr)
	var found bool
	err := filepath.WalkDir(state, func(p string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return err
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		if strings.Contains(string(b), rulePrivilegeCoverage) {
			found = true
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if !found {
		t.Errorf("no persisted report under %s carries the %s gap", state, rulePrivilegeCoverage)
	}
}
