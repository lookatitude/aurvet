// internal/check/provenance_test.go
package check

import (
	"context"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/finding"
)

func pkg(name string) alpm.Package {
	return alpm.Package{Name: name, Base: name, Version: "1.0-1", Validation: "none"}
}

func findingFor(r finding.Result, ruleID string) (finding.Finding, bool) {
	for _, f := range r.Findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// Absent from the AUR AND carrying a malware tombstone is definitive.
func TestTombstonedPackageIsCritical(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"},
	}
	r := Provenance(context.Background(),
		[]alpm.Package{pkg("librewolf-fix-bin")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-tombstone")
	if !ok {
		t.Fatalf("no aur-tombstone finding; got %+v", r.Findings)
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "malware") {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

// D2 regression: a removal whose wording is administrative rather than
// malicious must NOT be critical. "removed due to rename" is the case.
func TestAdministrativeRemovalIsNotCritical(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"foo-bin": "history removed due to rename"},
	}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if r.MaxSeverity() == finding.SevCritical {
		t.Fatalf("administrative removal reported critical: %+v", r.Findings)
	}
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("expected aur-absent; got %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "rename") {
		t.Errorf("removal message not carried as evidence: %v", f.Evidence)
	}
}

// Absent with NO tombstone is only suspicious: it is the dropped-from-repo /
// renamed / never-published case (python-pkg_resources on the reference box).
func TestAbsentWithoutTombstoneIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{}, Tombstones: map[string]string{}}
	r := Provenance(context.Background(),
		[]alpm.Package{pkg("python-pkg_resources")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("no aur-absent finding; got %+v", r.Findings)
	}
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious", f.Severity)
	}
	if f.Limits == "" {
		t.Error("finding must state its limits (INV-6)")
	}
}

// Submitter != Maintainer is an observable takeover trace.
func TestSubmitterMismatchIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo-bin": {Name: "foo-bin", PackageBase: "foo-bin", Maintainer: "alice", Submitter: "bob"},
	}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-submitter-mismatch"); !ok {
		t.Fatalf("no submitter-mismatch finding; got %+v", r.Findings)
	}
}

// Orphaned packages are a takeover precondition.
func TestOrphanedIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo-bin": {Name: "foo-bin", PackageBase: "foo-bin", Maintainer: "", Submitter: "bob"},
	}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-orphaned"); !ok {
		t.Fatalf("no orphaned finding; got %+v", r.Findings)
	}
}

// CRITICAL BEHAVIOUR: an RPC failure must produce a coverage gap, never an
// "absent from the AUR" finding. Network failure must not be able to trigger
// the highest-severity rule.
func TestRPCFailureProducesGapNotAbsence(t *testing.T) {
	cl := aur.Fake{Err: errors.New("dial tcp: no route to host")}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-absent"); ok {
		t.Fatal("network failure produced an aur-absent finding")
	}
	if _, ok := findingFor(r, "aur-tombstone"); ok {
		t.Fatal("network failure produced a tombstone finding")
	}
	if r.Complete() {
		t.Fatal("network failure must leave coverage incomplete")
	}
}

// With network disabled the checks must report unavailable, not pass (INV-10).
func TestNetworkDisabledProducesGap(t *testing.T) {
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")},
		map[string]bool{}, aur.Fake{}, false)
	if len(r.Findings) != 0 {
		t.Errorf("findings = %+v, want none", r.Findings)
	}
	if r.Complete() {
		t.Fatal("disabled network must leave coverage incomplete")
	}
}

// Repo packages are not examined for AUR provenance at all.
func TestRepoPackagesAreSkipped(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{}}
	r := Provenance(context.Background(), []alpm.Package{pkg("zlib")},
		map[string]bool{"zlib": true}, cl, true)
	if len(r.Findings) != 0 || !r.Complete() {
		t.Errorf("repo package produced %+v gaps=%v", r.Findings, r.Gaps)
	}
}

// S1 — the security pass's headline false accusation, measured through the
// real aur.HTTP client against a faithful v5 RPC server. A SPLIT package whose
// pkgbase is not itself a package name is live in the AUR, but the RPC matches
// package NAMES only (internal/aur/http.go, F15: `by=pkgbase` is rejected), so
// asking by base returned resultcount=0 and every such package was reported
// "absent from the AUR" at SevSuspicious, with Complete() == true.
func TestLiveSplitPackageIsNotReportedAbsent(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		// Nothing here is NAMED foo-common; it exists only as a pkgbase.
		"foo":       {Name: "foo", PackageBase: "foo-common", Maintainer: "alice", Submitter: "alice"},
		"foo-utils": {Name: "foo-utils", PackageBase: "foo-common", Maintainer: "alice", Submitter: "alice"},
	}}
	pkgs := []alpm.Package{
		{Name: "foo", Base: "foo-common", Version: "2.1.0-1", Validation: "none"},
		{Name: "foo-utils", Base: "foo-common", Version: "2.1.0-1", Validation: "none"},
	}
	r := Provenance(context.Background(), pkgs, map[string]bool{}, cl, true)
	if f, ok := findingFor(r, "aur-absent"); ok {
		t.Fatalf("live split package accused of absence: %+v", f)
	}
	if !r.Complete() {
		t.Errorf("gaps = %+v, want none", r.Gaps)
	}
}

// S2 — the same defect in the false-assurance direction. %BASE% comes from the
// package's own .PKGINFO, so the builder controls it. A package the AUR has
// never published could name a healthy base, resolve through that base's
// record, and produce no finding, no gap, and no cgit lookup at all.
func TestBorrowedBaseDoesNotHideAnUnpublishedPackage(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"yay": {Name: "yay", PackageBase: "yay", Maintainer: "j", Submitter: "j"},
	}}
	evil := alpm.Package{Name: "nvidia-utils-patched", Base: "yay", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{evil}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("package published nowhere produced no finding; got %+v gaps=%+v", r.Findings, r.Gaps)
	}
	if f.Subject != "nvidia-utils-patched" {
		t.Errorf("subject = %q, want the package's own name", f.Subject)
	}
	// The borrowed base must be visible in the evidence, or a reader cannot
	// tell this apart from an ordinary unpublished package.
	if !strings.Contains(strings.Join(f.Evidence, " "), "pkgbase=yay") {
		t.Errorf("evidence does not name the declared base: %v", f.Evidence)
	}
}

// S6 — one AUR record must not be stamped onto a package it does not describe.
// Info cross-keys results on PackageBase as well as Name, so a record
// {Name: foo, PackageBase: bar} also lands under the key "bar"; an installed
// package named "bar" must not inherit foo's maintainer/submitter verdict.
func TestOneRecordIsNotStampedOntoAnotherPackage(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		// Keyed as Info's second pass would key it: under the PackageBase.
		"bar": {Name: "foo", PackageBase: "bar", Maintainer: "alice", Submitter: "bob"},
	}}
	victim := alpm.Package{Name: "bar", Base: "bar", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{victim}, map[string]bool{}, cl, true)
	if f, ok := findingFor(r, "aur-submitter-mismatch"); ok {
		t.Fatalf("another package's identity delta reported against bar: %+v", f)
	}
	// "bar" is genuinely not a package name in the AUR, so absence is correct.
	if _, ok := findingFor(r, "aur-absent"); !ok {
		t.Errorf("expected aur-absent for a name the AUR does not carry; got %+v", r.Findings)
	}
}

// The S1/S2 fix must not cost a true detection. A real tombstone still reaches
// SevCritical, including when it belongs to a split base — the tombstone lookup
// stays keyed on pkgbase even though presence moved to the package name.
func TestSplitBaseTombstoneIsStillCritical(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"librewolf-common": "history removed due to malware"},
	}
	p := alpm.Package{Name: "librewolf-fix-bin", Base: "librewolf-common", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{p}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-tombstone")
	if !ok {
		t.Fatalf("split-base tombstone missed; got %+v gaps=%+v", r.Findings, r.Gaps)
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
}

// T2 — the regression the S1/S2 fix introduced, and the reason the re-attack
// was not optional. AUR names are unique and are freed when a base is removed,
// so after `foo-evilbase` is deleted for malware a clean `foo` can be
// republished under base `foo`. A user still carrying the malware build has an
// installed package whose NAME resolves to the clean record while its declared
// %BASE% is the tombstoned one. Name-keyed presence made that read clean AND
// complete — no finding, no gap, cgit never consulted.
func TestRecycledNameStillReportsTombstonedDeclaredBase(t *testing.T) {
	cl := aur.Fake{
		Known: map[string]aur.Pkg{
			"foo": {Name: "foo", PackageBase: "foo", Maintainer: "alice", Submitter: "alice"},
		},
		Tombstones: map[string]string{"foo-evilbase": "history removed due to malware"},
	}
	installed := alpm.Package{Name: "foo", Base: "foo-evilbase", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{installed}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-tombstone")
	if !ok {
		t.Fatalf("tombstoned declared base went unreported; findings=%+v gaps=%+v", r.Findings, r.Gaps)
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "foo-evilbase") {
		t.Errorf("evidence does not name the declared base: %v", f.Evidence)
	}
}

// The T2 repair must not turn an ordinary upstream pkgbase RENAME into an
// accusation. The base disagrees, but there is no removal at all — the common,
// benign shape. Only a tombstone may speak here.
func TestBenignBaseRenameIsSilent(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo": {Name: "foo", PackageBase: "foo-newbase", Maintainer: "alice", Submitter: "alice"},
	}}
	installed := alpm.Package{Name: "foo", Base: "foo-oldbase", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{installed}, map[string]bool{}, cl, true)
	if len(r.Findings) != 0 {
		t.Errorf("benign pkgbase rename produced findings: %+v", r.Findings)
	}
	if !r.Complete() {
		t.Errorf("benign pkgbase rename produced gaps: %+v", r.Gaps)
	}
}

// A live split package's record agrees with its declared base, so the T2 path
// must not fire and must not cost an extra cgit request.
func TestAgreeingBaseIsNotProbed(t *testing.T) {
	cl := aur.Fake{
		Known: map[string]aur.Pkg{
			"foo": {Name: "foo", PackageBase: "foo-common", Maintainer: "alice", Submitter: "alice"},
		},
		// If the join probed an agreeing base it would find this and go critical.
		Tombstones: map[string]string{"foo-common": "history removed due to malware"},
	}
	installed := alpm.Package{Name: "foo", Base: "foo-common", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{installed}, map[string]bool{}, cl, true)
	if len(r.Findings) != 0 || !r.Complete() {
		t.Errorf("agreeing base was probed: findings=%+v gaps=%+v", r.Findings, r.Gaps)
	}
}

// A cgit failure on the declared base is "could not tell" — a Gap, never a
// finding in either direction (contract rule 1, on the T2 path too).
func TestDeclaredBaseTombstoneFailureIsAGap(t *testing.T) {
	cl := aur.Fake{
		Known: map[string]aur.Pkg{
			"foo": {Name: "foo", PackageBase: "foo", Maintainer: "alice", Submitter: "alice"},
		},
		TombstoneErr: map[string]error{"foo-otherbase": errors.New("cgit unreachable")},
	}
	installed := alpm.Package{Name: "foo", Base: "foo-otherbase", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{installed}, map[string]bool{}, cl, true)
	if len(r.Findings) != 0 {
		t.Errorf("a cgit failure produced findings: %+v", r.Findings)
	}
	if r.Complete() {
		t.Fatal("a cgit failure on the declared base must leave coverage incomplete")
	}
}

// T4 — the critical stands, but it must not claim the package itself was
// removed from an index it was never in. The removed subject is the declared
// pkgbase, and the finding has to say so or it is indistinguishable at triage
// from a genuine own-record tombstone.
func TestDeclaredBaseTombstoneNamesTheRightSubject(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"},
	}
	local := alpm.Package{Name: "my-internal-tool", Base: "librewolf-fix-bin", Version: "1-1", Validation: "none"}
	r := Provenance(context.Background(), []alpm.Package{local}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-tombstone")
	if !ok {
		t.Fatalf("no tombstone finding; got %+v", r.Findings)
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("severity = %v, want critical — the declared-base case is still definitive", f.Severity)
	}
	if !strings.Contains(f.Summary, "pkgbase") {
		t.Errorf("summary claims the package itself was removed: %q", f.Summary)
	}
	// The own-record case must keep its own, different wording.
	own := aur.Fake{Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"}}
	r2 := Provenance(context.Background(), []alpm.Package{pkg("librewolf-fix-bin")}, map[string]bool{}, own, true)
	f2, _ := findingFor(r2, "aur-tombstone")
	if f2.Summary == f.Summary {
		t.Errorf("declared-base and own-record tombstones render identically: %q", f.Summary)
	}
}

// T9 — with no recoverable message there is nothing to classify, so the
// summary must not assert that the reason was not malware-related.
func TestRemovalWithNoMessageDoesNotClaimNotMalware(t *testing.T) {
	cl := aur.Fake{Tombstones: map[string]string{"foo-bin": ""}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("expected aur-absent; got %+v", r.Findings)
	}
	if strings.Contains(f.Summary, "not malware-related") {
		t.Errorf("summary asserts an unestablished negative: %q", f.Summary)
	}
}

// S8 — a removal detected with no recoverable message must not render evidence
// asserting a commit message that does not exist.
func TestRemovalWithNoMessageDoesNotFabricateEvidence(t *testing.T) {
	cl := aur.Fake{Tombstones: map[string]string{"foo-bin": ""}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("expected aur-absent; got %+v", r.Findings)
	}
	for _, e := range f.Evidence {
		if strings.TrimSpace(e) == "cgit removal commit:" {
			t.Errorf("evidence asserts a commit message that does not exist: %v", f.Evidence)
		}
	}
}

// spec §4.1: a sync DB that could not be read makes every foreignness verdict
// in the run unreliable. Provenance cannot see that condition — the frozen
// signature carries the syncNames map, not the tar-entry count the structural
// rule needs — so the gap has to be constructible separately and merged by the
// caller. These two tests pin the primitive and, most importantly, pin that
// merging it actually costs the Result its Complete().
func TestSyncCoverageGapsMakeAResultIncomplete(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo-bin": {Name: "foo-bin", PackageBase: "foo-bin", Maintainer: "alice", Submitter: "alice"},
	}}
	// A clean sweep: the package resolves, nothing is wrong with it.
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if !r.Complete() {
		t.Fatalf("precondition: expected a complete Result, got gaps %+v", r.Gaps)
	}
	// Now the oracle that decided "foo-bin is foreign" turns out to have been
	// unreadable. The same verdicts must stop being presented as complete.
	r.Gaps = append(r.Gaps, SyncCoverageGaps([]string{"core.db"})...)
	if r.Complete() {
		t.Fatal("a run with an unreadable sync DB must not report complete coverage")
	}
	if r.Gaps[0].Subject != "core.db" || r.Gaps[0].Reason == "" {
		t.Errorf("gap = %+v, want core.db with a stated reason", r.Gaps[0])
	}
}

func TestSyncCoverageGapsEmptyIsNoGap(t *testing.T) {
	// Every sync DB read cleanly: no gaps, so a caller that merges
	// unconditionally does not manufacture one on a healthy system.
	if g := SyncCoverageGaps(nil); len(g) != 0 {
		t.Errorf("SyncCoverageGaps(nil) = %+v, want none", g)
	}
	if g := SyncCoverageGaps([]string{}); len(g) != 0 {
		t.Errorf("SyncCoverageGaps([]) = %+v, want none", g)
	}
}

// The plan's task-8 tests predate Tombstone's third outcome: (false, "", err)
// means "could not tell", and it is neither a removal nor a clean bill. Info
// answers (the base is simply not in the index) and the cgit lookup for that
// same base fails — the single most important test in this file, because the
// wrong answer here turns a transport hiccup into either a false accusation
// or false assurance.
func TestTombstoneErrorProducesGapNotAbsence(t *testing.T) {
	cl := aur.Fake{
		Known:        map[string]aur.Pkg{},
		TombstoneErr: map[string]error{"foo-bin": errors.New("dial tcp: connection reset")},
	}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-absent"); ok {
		t.Fatal("a Tombstone error produced an aur-absent finding")
	}
	if _, ok := findingFor(r, "aur-tombstone"); ok {
		t.Fatal("a Tombstone error produced an aur-tombstone finding")
	}
	found := false
	for _, g := range r.Gaps {
		if g.Subject == "foo-bin" {
			found = true
		}
	}
	if !found {
		t.Fatalf("no Gap naming foo-bin; got %+v", r.Gaps)
	}
	if r.Complete() {
		t.Fatal("a Tombstone error must leave coverage incomplete")
	}
}

// Tombstone's deliberate ambiguity error — a malware-bearing removal wording
// found inside a history that is NOT truncated, so Tombstone cannot tell a
// resurrected tombstoned base from an ordinary commit that mentions malware —
// must read as a Gap, not a critical. Do not "simplify" this by treating any
// malware-shaped Tombstone error text as a tombstone: the whole point of that
// error is that Tombstone itself could not decide.
func TestTombstoneAmbiguityIsAGapNotACritical(t *testing.T) {
	cl := aur.Fake{
		Known: map[string]aur.Pkg{},
		TombstoneErr: map[string]error{
			"yay": fmt.Errorf(
				"cgit log for %s: removal wording %q in a %d-commit history; "+
					"cannot distinguish a tombstone from an ordinary commit",
				"yay", "removed malware samples from the git history", 50),
		},
	}
	r := Provenance(context.Background(), []alpm.Package{pkg("yay")}, map[string]bool{}, cl, true)
	if r.MaxSeverity() == finding.SevCritical {
		t.Fatalf("Tombstone's ambiguity error reported critical: %+v", r.Findings)
	}
	if r.Complete() {
		t.Fatal("Tombstone's ambiguity error must leave coverage incomplete")
	}
}

// SevCritical must appear if and only if aur.IsMalwareRemoval(msg) is true —
// driven off the classifier itself, not a hardcoded expectation column, so
// this stays a structural invariant instead of a list of examples that can
// drift from internal/aur's own classification. Wordings are taken from
// internal/aur/acceptance_test.go so the two suites cannot disagree.
func TestCriticalRequiresMalwareTombstone(t *testing.T) {
	messages := []string{
		"history removed due to malware",
		"removed: trojan-dropper in the prebuilt binary",
		"history removed due to a malware-laden prebuilt binary",
		"removed: trojan-infected upstream tarball",
		"removed the backdoor-laced install hook",
		"removed: info-stealer in the vendored binary",
		"history removed due to rename",
		"history removed due to merge into security-misc",
		"removed due to rename to arch-security-tools",
		"removed due to rename to malware-analysis-toolkit",
		"history removed due to merge into clamav-unofficial-sigs-malware-expert",
	}
	for i, msg := range messages {
		base := fmt.Sprintf("pkg-%d", i)
		cl := aur.Fake{
			Known:      map[string]aur.Pkg{},
			Tombstones: map[string]string{base: msg},
		}
		r := Provenance(context.Background(), []alpm.Package{pkg(base)}, map[string]bool{}, cl, true)
		gotCritical := r.MaxSeverity() == finding.SevCritical
		wantCritical := aur.IsMalwareRemoval(msg)
		if gotCritical != wantCritical {
			t.Errorf("msg %q: critical = %v, want %v (IsMalwareRemoval)", msg, gotCritical, wantCritical)
		}
	}
}

// INV-6: every emitted Finding must state what it cannot prove.
func TestEveryFindingStatesItsLimits(t *testing.T) {
	scenarios := []struct {
		name string
		cl   aur.Fake
		pkgs []alpm.Package
	}{
		{"tombstoned", aur.Fake{Tombstones: map[string]string{"a": "history removed due to malware"}}, []alpm.Package{pkg("a")}},
		{"administrative", aur.Fake{Tombstones: map[string]string{"b": "history removed due to rename"}}, []alpm.Package{pkg("b")}},
		{"absent-no-tombstone", aur.Fake{}, []alpm.Package{pkg("c")}},
		{"orphaned", aur.Fake{Known: map[string]aur.Pkg{"d": {Name: "d", PackageBase: "d", Submitter: "bob"}}}, []alpm.Package{pkg("d")}},
		{"submitter-mismatch", aur.Fake{Known: map[string]aur.Pkg{"e": {Name: "e", PackageBase: "e", Maintainer: "alice", Submitter: "bob"}}}, []alpm.Package{pkg("e")}},
	}
	for _, s := range scenarios {
		r := Provenance(context.Background(), s.pkgs, map[string]bool{}, s.cl, true)
		if len(r.Findings) == 0 {
			t.Fatalf("%s: expected at least one finding, got none", s.name)
		}
		for _, f := range r.Findings {
			if f.Limits == "" {
				t.Errorf("%s: finding %+v has empty Limits", s.name, f)
			}
		}
	}
}

// A Gap must not swallow the rest of the sweep, and a finding must not hide
// a Gap: one foreign package whose tombstone lookup fails alongside another
// that is cleanly absent must each be reported on their own terms.
func TestGapDoesNotSuppressOtherPackages(t *testing.T) {
	cl := aur.Fake{
		Known:        map[string]aur.Pkg{},
		TombstoneErr: map[string]error{"broken-bin": errors.New("cgit unreachable")},
	}
	r := Provenance(context.Background(),
		[]alpm.Package{pkg("broken-bin"), pkg("clean-bin")}, map[string]bool{}, cl, true)

	f, ok := findingFor(r, "aur-absent")
	if !ok || f.Subject != "clean-bin" {
		t.Errorf("clean-bin: expected an aur-absent finding; got findings=%+v", r.Findings)
	}
	gapped := false
	for _, g := range r.Gaps {
		if g.Subject == "broken-bin" {
			gapped = true
		}
	}
	if !gapped {
		t.Errorf("broken-bin: expected a Gap; got %+v", r.Gaps)
	}
}

// The AUR is queried per base; findings are per package. Two alpm.Package
// values sharing a Base but not a Name must each get their own finding keyed
// by their own Name.
func TestPackagesSharingABaseAreEachReported(t *testing.T) {
	shared := alpm.Package{Name: "foo", Base: "foo-common", Version: "1.0-1", Validation: "none"}
	other := alpm.Package{Name: "foo-utils", Base: "foo-common", Version: "1.0-1", Validation: "none"}
	cl := aur.Fake{Known: map[string]aur.Pkg{}}
	r := Provenance(context.Background(), []alpm.Package{shared, other}, map[string]bool{}, cl, true)

	subjects := map[string]bool{}
	for _, f := range r.Findings {
		if f.RuleID == "aur-absent" {
			subjects[f.Subject] = true
		}
	}
	if !subjects["foo"] || !subjects["foo-utils"] {
		t.Errorf("expected an aur-absent finding for each of foo and foo-utils; got %+v", r.Findings)
	}
}
