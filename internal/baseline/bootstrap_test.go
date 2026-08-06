// internal/baseline/bootstrap_test.go
//
// Task 7. Four refusals, each proved to fire on its own, each carrying its own
// message. The happy path is last and is deliberately hard to reach.
package baseline

import (
	"errors"
	"strings"
	"testing"
	"time"
)

// okInput is the one input that is allowed to write: privileged, full tier, no
// unresolved criticals, and no gap that is not declared recordable.
func okInput(t *testing.T) BootstrapInput {
	t.Helper()
	return BootstrapInput{
		Euid:             0,
		Tier:             "full",
		Host:             "reference",
		Root:             "/",
		StateDir:         "/var/lib/aurvet",
		StateDirWritable: true,
		Gaps: []Gap{{
			RuleID:  "aur-provenance",
			Subject: "pkg:librewolf-fix-bin",
			Reason:  "no provenance snapshot exists for this package",
		}},
		Now: driftNow(t),
	}
}

func mustAllow(t *testing.T, in BootstrapInput) BootstrapDecision {
	t.Helper()
	d := Bootstrap(in)
	if !d.Allowed {
		t.Fatalf("precondition failed, bootstrap refused: %v", d.Err())
	}
	return d
}

// -- refusal 1: unresolved criticals ------------------------------------------

// The single worst outcome the tool can produce. A baseline that contains the
// compromise makes the compromise the reference point, and every later run then
// reports "no change".
func TestRefusesWhileAnUnresolvedCriticalExists(t *testing.T) {
	in := okInput(t)
	in.Criticals = []Critical{{
		RuleID: "integrity-digest-mismatch", SubjectKind: "package", Subject: "sudo",
		Fingerprint: "deadbeefdeadbeef",
		Summary:     "a packaged file's digest does not match the mtree",
	}}
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("a baseline was written over an unresolved critical")
	}
	r := findRefusal(t, d, RefusalCriticals)
	for _, want := range []string{"sudo", "integrity-digest-mismatch", "deadbeefdeadbeef", "adjudicate"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("the refusal does not mention %q, so it does not say what to do: %q", want, r.Message)
		}
	}
	if !errors.Is(d.Err(), ErrBootstrap) {
		t.Fatalf("Err does not wrap ErrBootstrap: %v", d.Err())
	}
}

// The other half of the same criterion: an adjudicated critical UNBLOCKS init, and
// its reason is recorded.
func TestAnAdjudicatedCriticalUnblocksInitAndAnUnadjudicatedOneDoesNot(t *testing.T) {
	crit := Critical{
		RuleID: "integrity-digest-mismatch", SubjectKind: "package", Subject: "sudo",
		Fingerprint: "deadbeefdeadbeef", Summary: "digest mismatch",
	}

	blocked := okInput(t)
	blocked.Criticals = []Critical{crit}
	if Bootstrap(blocked).Allowed {
		t.Fatal("an unadjudicated critical did not block init")
	}

	allowed := okInput(t)
	allowed.Adjudicated = []AdjudicatedCritical{{
		Critical:         crit,
		Reason:           "local %BACKUP% file edited by the administrator; verified by hand against upstream",
		Scope:            "subject",
		ExpiresAt:        "2026-12-01T00:00:00+0100",
		FingerprintEpoch: 1,
	}}
	d := mustAllow(t, allowed)
	if len(d.Adjudications) != 1 {
		t.Fatalf("the adjudication was not carried into the manifest input: %+v", d.Adjudications)
	}
	if d.Adjudications[0].Reason == "" || d.Adjudications[0].FingerprintEpoch != 1 {
		t.Fatalf("the recorded adjudication lost its reason or epoch: %+v", d.Adjudications[0])
	}
}

// An adjudication with no reason is not an adjudication. It must not unblock.
func TestAnAdjudicationWithoutARecordedReasonDoesNotUnblock(t *testing.T) {
	in := okInput(t)
	in.Adjudicated = []AdjudicatedCritical{{
		Critical: Critical{RuleID: "integrity-missing", SubjectKind: "package", Subject: "openssh",
			Fingerprint: "aaaa1111"},
		Scope: "subject",
	}}
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("a reasonless adjudication unblocked init")
	}
	r := findRefusal(t, d, RefusalCriticals)
	if !strings.Contains(r.Message, "reason") {
		t.Fatalf("the refusal does not name the missing reason: %q", r.Message)
	}
}

// A critical from a rule that declares no fingerprint epoch cannot be adjudicated
// at all, so demanding that it be adjudicated would deadlock the operator. The
// refusal must say so and name the edit.
func TestRefusesACriticalThatCannotBeAdjudicated(t *testing.T) {
	in := okInput(t)
	in.Criticals = []Critical{{
		RuleID: "some-new-rule", SubjectKind: "package", Subject: "zlib", Fingerprint: "bbbb2222",
	}}
	in.UndeclaredRules = []string{"some-new-rule"}
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("init proceeded over a critical nobody can adjudicate")
	}
	r := findRefusal(t, d, RefusalUndeclaredEpoch)
	for _, want := range []string{"some-new-rule", "epoch.go"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("the refusal does not name %q: %q", want, r.Message)
		}
	}
}

// -- refusal 2: unprivileged ---------------------------------------------------

func TestRefusesUnprivileged(t *testing.T) {
	in := okInput(t)
	in.Euid = 1000
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("an unprivileged run wrote a baseline")
	}
	r := findRefusal(t, d, RefusalUnprivileged)
	for _, want := range []string{"sudo", "1000"} {
		if !strings.Contains(r.Message, want) {
			t.Errorf("the refusal does not mention %q: %q", want, r.Message)
		}
	}
	if !strings.Contains(r.Message, "gap") {
		t.Errorf("the refusal does not say WHY unprivileged is wrong (gaps recorded as facts): %q",
			r.Message)
	}
}

// -- refusal 3: the tier -------------------------------------------------------

func TestRefusesATriageTierScanAsItsBasis(t *testing.T) {
	for _, tier := range []string{"triage", "meta"} {
		in := okInput(t)
		in.Tier = tier
		d := Bootstrap(in)
		if d.Allowed {
			t.Fatalf("%s tier was accepted as a baseline basis", tier)
		}
		r := findRefusal(t, d, RefusalTier)
		if !strings.Contains(r.Message, tier) || !strings.Contains(r.Message, "full") {
			t.Errorf("%s: the refusal does not name the tier or the remedy: %q", tier, r.Message)
		}
	}

	// An unknown tier is refused too: failing open on a tier name this build does
	// not recognise would sign whatever that tier happened not to look at.
	in := okInput(t)
	in.Tier = "quick"
	if Bootstrap(in).Allowed {
		t.Fatal("an unrecognised tier was accepted")
	}

	// And paranoid, which is deeper than full, is accepted.
	in = okInput(t)
	in.Tier = "paranoid"
	mustAllow(t, in)
}

// -- refusal 4: coverage that matters -----------------------------------------

// Gaps are blocking by DEFAULT. A gap rule this build has not explicitly declared
// recordable blocks, because failing open on an unknown gap means signing a
// baseline over whatever it was that could not be examined (INV-3).
func TestRefusesWhenCoverageIsIncompleteInAWayThatMatters(t *testing.T) {
	in := okInput(t)
	in.Gaps = append(in.Gaps, Gap{
		RuleID:  "integrity-coverage",
		Subject: "pkg:linux",
		Reason:  "the package's mtree could not be read",
	})
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("init proceeded with a blocking coverage gap")
	}
	r := findRefusal(t, d, RefusalCoverage)
	if !strings.Contains(r.Message, "integrity-coverage") {
		t.Fatalf("the refusal does not name the gap: %q", r.Message)
	}

	// Unknown rule: blocks, and says how to make it recordable deliberately.
	unknown := okInput(t)
	unknown.Gaps = []Gap{{RuleID: "brand-new-gap", Subject: "x", Reason: "y"}}
	d = Bootstrap(unknown)
	if d.Allowed {
		t.Fatal("an undeclared gap rule failed open")
	}
	if !strings.Contains(findRefusal(t, d, RefusalCoverage).Message, "brand-new-gap") {
		t.Fatal("the refusal does not name the undeclared gap rule")
	}

	// A declared-recordable gap does not block, and is carried into the manifest so
	// that what the baseline does not cover is inside the signed bytes.
	dec := mustAllow(t, okInput(t))
	if len(dec.RecordedGaps) != 1 || dec.RecordedGaps[0].RuleID != "aur-provenance" {
		t.Fatalf("the recordable gap was not carried into the manifest: %+v", dec.RecordedGaps)
	}
}

// db.lck: `scan` warns, `baseline init` refuses. Reading a database mid-transaction
// produces spurious findings, and these would get SIGNED.
func TestRefusesWhileAPacmanTransactionIsInFlight(t *testing.T) {
	in := okInput(t)
	in.DBLocked = true
	in.DBLockPath = "/var/lib/pacman/db.lck"
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("init proceeded during a pacman transaction")
	}
	r := findRefusal(t, d, RefusalDBLock)
	if !strings.Contains(r.Message, "db.lck") || !strings.Contains(strings.ToLower(r.Message), "signed") {
		t.Fatalf("the refusal does not name the lock or say why it matters: %q", r.Message)
	}
}

// INV-5 and the state directory: a baseline that cannot be persisted must not be
// signed, and an unwritable resolution is a configuration failure named as one.
func TestRefusesWhenTheStateDirectoryCannotBeWritten(t *testing.T) {
	in := okInput(t)
	in.StateDir = "/var/lib/aurvet"
	in.StateDirWritable = false
	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("init proceeded towards an unwritable state directory")
	}
	if !strings.Contains(findRefusal(t, d, RefusalStateDir).Message, "/var/lib/aurvet") {
		t.Fatal("the refusal does not name the directory")
	}
}

// -- all four at once ---------------------------------------------------------

// An operator on a real machine hits several at once. Every refusal must be
// reported, not just the first: fixing them one run at a time is how a bootstrap
// takes four attempts and teaches nobody anything.
func TestEveryRefusalIsReportedTogether(t *testing.T) {
	in := okInput(t)
	in.Euid = 1000
	in.Tier = "triage"
	in.Criticals = []Critical{{RuleID: "integrity-missing", SubjectKind: "package",
		Subject: "openssh", Fingerprint: "cccc3333"}}
	in.Gaps = append(in.Gaps, Gap{RuleID: "local-db", Subject: "x", Reason: "unreadable"})

	d := Bootstrap(in)
	if d.Allowed {
		t.Fatal("allowed")
	}
	want := []RefusalCode{RefusalCriticals, RefusalUnprivileged, RefusalTier, RefusalCoverage}
	for _, code := range want {
		findRefusal(t, d, code)
	}
	msg := d.Err().Error()
	for _, code := range want {
		if !strings.Contains(msg, string(code)) {
			t.Errorf("the aggregated error omits %s: %s", code, msg)
		}
	}
}

// -- the happy path, last -----------------------------------------------------

func TestAllowsOnlyWhenEverythingHolds(t *testing.T) {
	d := mustAllow(t, okInput(t))
	if len(d.Refusals) != 0 {
		t.Fatalf("allowed with refusals: %+v", d.Refusals)
	}
	if d.Err() != nil {
		t.Fatalf("allowed but Err is non-nil: %v", d.Err())
	}
	if len(d.Notes) == 0 {
		t.Fatal("a permitted bootstrap states nothing about its own limits (INV-6)")
	}
}

func TestBootstrapRefusesAMissingHostOrRoot(t *testing.T) {
	noHost := okInput(t)
	noHost.Host = ""
	if Bootstrap(noHost).Allowed {
		t.Error("a baseline with no host was allowed")
	}
	noRoot := okInput(t)
	noRoot.Root = ""
	if Bootstrap(noRoot).Allowed {
		t.Error("a baseline with no root was allowed")
	}
	noNow := okInput(t)
	noNow.Now = time.Time{}
	if Bootstrap(noNow).Allowed {
		t.Error("a baseline with no decision time was allowed")
	}
}

func findRefusal(t *testing.T, d BootstrapDecision, code RefusalCode) Refusal {
	t.Helper()
	for _, r := range d.Refusals {
		if r.Code == code {
			if strings.TrimSpace(r.Message) == "" {
				t.Fatalf("refusal %s carries no message", code)
			}
			return r
		}
	}
	t.Fatalf("no %s refusal in %+v", code, d.Refusals)
	return Refusal{}
}
