// internal/finding/finding_test.go
package finding

import "testing"

// Fingerprints must be version-independent: with ~28 pacman transactions a
// day on the reference system, a version-bearing fingerprint would invalidate
// every suppression on every upgrade.
func TestFingerprintIsVersionIndependent(t *testing.T) {
	a := Fingerprint("aur-tombstone", "package", "foo-bin", "subject")
	b := Fingerprint("aur-tombstone", "package", "foo-bin", "subject")
	if a != b {
		t.Fatal("same inputs produced different fingerprints")
	}
	c := Fingerprint("aur-tombstone", "package", "bar-bin", "subject")
	if a == c {
		t.Error("different subjects produced the same fingerprint")
	}
	d := Fingerprint("aur-tombstone", "package", "foo-bin", "pin")
	if a == d {
		t.Error("different scopes produced the same fingerprint")
	}
}

// TestFingerprintFieldEncodingIsInjective pins F13: a NUL byte inside a field
// must not be indistinguishable from the old "\x00"-join separator. Before the
// length-prefix fix, these two different four-tuples hashed identically.
func TestFingerprintFieldEncodingIsInjective(t *testing.T) {
	a := Fingerprint("aur-tombstone", "package\x00librewolf-fix-bin", "subject", "x")
	b := Fingerprint("aur-tombstone", "package", "librewolf-fix-bin\x00subject", "x")
	if a == b {
		t.Fatal("field content that shifts a separator produced the same fingerprint as a different four-tuple")
	}

	// A second boundary-shift attempt: move a byte across the ruleID/subjectKind
	// boundary instead of subjectKind/subjectIdentity.
	c := Fingerprint("aur-tombstone\x00package", "subjectKind", "subject", "x")
	d := Fingerprint("aur-tombstone", "package\x00subjectKind", "subject", "x")
	if c == d {
		t.Fatal("shifting a byte across the ruleID/subjectKind boundary produced the same fingerprint")
	}
}

// TestFingerprintIsStableAcrossPackageVersions pins F14: subjectIdentity must
// be the package name, not name-version, or --since-last suppression breaks on
// every upgrade (~28 pacman transactions/day on the reference system).
func TestFingerprintIsStableAcrossPackageVersions(t *testing.T) {
	before := Fingerprint("aur-tombstone", "package", "librewolf-fix-bin", "subject")
	after := Fingerprint("aur-tombstone", "package", "librewolf-fix-bin", "subject")
	if before != after {
		t.Fatal("same rule and package name (version excluded from subjectIdentity) produced different fingerprints")
	}

	// The trap: a caller who folds the version into subjectIdentity anyway gets
	// a different fingerprint per upgrade. This is the caller's error, not a
	// bug in Fingerprint — Fingerprint cannot inspect its arguments to catch it.
	versioned := Fingerprint("aur-tombstone", "package", "librewolf-fix-bin-1.2.3-1", "subject")
	if before == versioned {
		t.Fatal("folding a version into subjectIdentity should change the fingerprint (documenting the caller trap)")
	}
}

// TestGapsOnlyResultIsIncompleteAtInfoSeverity pins F12: a Result whose Gaps
// are all that fired reports MaxSeverity() == SevInfo, identical to a clean
// sweep. This pairing is correct-but-dangerous: a caller must gate on
// Complete() as well as MaxSeverity() when deriving a summary or exit status,
// or a sweep where every check failed will read as clean.
func TestGapsOnlyResultIsIncompleteAtInfoSeverity(t *testing.T) {
	r := Result{Gaps: []Gap{{RuleID: "aur-tombstone", Subject: "librewolf-fix-bin", Reason: "aur unreachable"}}}
	if r.Complete() {
		t.Error("a gaps-only result must not be Complete")
	}
	if r.MaxSeverity() != SevInfo {
		t.Errorf("MaxSeverity = %v, want SevInfo (gaps contribute no severity)", r.MaxSeverity())
	}
}

func TestResultCompleteAndMaxSeverity(t *testing.T) {
	r := Result{}
	if !r.Complete() {
		t.Error("empty result should be complete")
	}
	if r.MaxSeverity() != SevInfo {
		t.Errorf("MaxSeverity = %v", r.MaxSeverity())
	}
	r.Gaps = append(r.Gaps, Gap{RuleID: "provenance", Subject: "foo-bin", Reason: "no cache clone"})
	if r.Complete() {
		t.Error("result with a gap must not be complete")
	}
	r.Findings = append(r.Findings,
		Finding{Severity: SevSuspicious}, Finding{Severity: SevCritical})
	if r.MaxSeverity() != SevCritical {
		t.Errorf("MaxSeverity = %v, want critical", r.MaxSeverity())
	}
}

func TestSeverityStrings(t *testing.T) {
	for sev, want := range map[Severity]string{
		SevInfo: "info", SevSuspicious: "suspicious", SevCritical: "critical",
	} {
		if got := sev.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", sev, got, want)
		}
	}
}

func TestSeverityStringIsTotalAndDoesNotDowngrade(t *testing.T) {
	if got := Severity(99).String(); got == "info" {
		t.Errorf("Severity(99).String() = %q; an unknown severity must not render as the least severe level", got)
	}
	if got := Severity(-1).String(); got == "" {
		t.Error("Severity(-1).String() returned empty; String must be total")
	}
}
