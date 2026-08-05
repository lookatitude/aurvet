// internal/check/integrity_test.go
package check

import (
	"io/fs"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/mtree"
)

const (
	digestA = "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa"
	digestB = "bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"
)

// obsMap is the shape tier.Verify hands to Integrity.
func obsMap(os ...Observed) map[string]Observed {
	m := map[string]Observed{}
	for _, o := range os {
		m[o.Path] = o
	}
	return m
}

func integrityFor(t *testing.T, res finding.Result, ruleID, subject string) finding.Finding {
	t.Helper()
	f, ok := findingForSubject(res, ruleID, subject)
	if !ok {
		t.Fatalf("no %s finding for %s: findings=%+v gaps=%+v", ruleID, subject, res.Findings, res.Gaps)
	}
	return f
}

func TestMatchingDigestProducesNothing(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 3, SHA256: digestA}}
	obs := obsMap(Observed{Path: "./usr/bin/foo", Kind: ObsHashed, SHA256: digestA, Size: 3, Mode: 0o755})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("clean file produced output: findings=%+v gaps=%+v", res.Findings, res.Gaps)
	}
}

func TestDigestMismatchIsSuspiciousAndNamesBothDigests(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 3, SHA256: digestA}}
	obs := obsMap(Observed{Path: "./usr/bin/foo", Kind: ObsHashed, SHA256: digestB, Size: 4, Mode: 0o755})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)

	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/bin/foo")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: %s", f.Severity, formatFinding(f))
	}
	ev := strings.Join(f.Evidence, " ")
	for _, want := range []string{"recorded sha256=" + digestA, "observed sha256=" + digestB, "package=foo"} {
		if !strings.Contains(ev, want) {
			t.Errorf("evidence missing %q: %v", want, f.Evidence)
		}
	}
	if f.Limits == "" {
		t.Error("INV-6: digest mismatch carries no Limits")
	}
	if strings.Contains(ev, "mtime-assisted") {
		t.Errorf("a fully hashed observation was marked mtime-assisted: %v", f.Evidence)
	}
}

// TestLinkTargetsAreComparedAsStrings is the measured regression pin: 4,145
// legitimate link targets on the reference system contain "..", so a check that
// resolved them would manufacture thousands of findings. The recorded string
// and the on-disk string are compared, and that is the whole check.
func TestLinkTargetsAreComparedAsStrings(t *testing.T) {
	const target = "../../../usr/lib/systemd/system/foo.service"
	entries := []mtree.Entry{{Path: "./etc/systemd/system/x.service", Type: "link", Link: target}}

	same := Integrity("foo", entries,
		obsMap(Observed{Path: "./etc/systemd/system/x.service", Kind: ObsLink, Link: target}),
		Exemptions{}, TierFull)
	if len(same.Findings) != 0 || len(same.Gaps) != 0 {
		t.Fatalf("a dot-dot link matching its record produced output (this is the 4,145-target "+
			"false-positive shape): findings=%+v gaps=%+v", same.Findings, same.Gaps)
	}

	moved := Integrity("foo", entries,
		obsMap(Observed{Path: "./etc/systemd/system/x.service", Kind: ObsLink, Link: "../../../tmp/evil.service"}),
		Exemptions{}, TierFull)
	f := integrityFor(t, moved, "integrity-link-target", "./etc/systemd/system/x.service")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: %s", f.Severity, formatFinding(f))
	}
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "recorded link="+target) || !strings.Contains(ev, "observed link=../../../tmp/evil.service") {
		t.Errorf("evidence does not name both targets: %v", f.Evidence)
	}
	if f.Limits == "" {
		t.Error("INV-6: link finding carries no Limits")
	}
}

// TestPlaceholderLinkIsNotDowngraded pins the lead's 2026-08-05 reversal: a
// record whose target is /dev/null gets no severity relief.
//
// This test replaces one that asserted the opposite. The shape is benign on
// ordinary systems -- on the reference system it was 2 of 4 total findings, both
// java-runtime-common paths relinked by archlinux-java -- but the downgrade was
// keyed on link=/dev/null, a field the package's own mtree writes, so a hostile
// package could have recorded the placeholder and shipped the link pointing
// anywhere to buy itself silence. Two benign paths on a full desktop is a job for
// adjudication and the P4 baseline diff, not for a rule that stops looking.
//
// The benign explanation must still be visible in the finding (INV-6), which is
// asserted rather than assumed.
func TestPlaceholderLinkIsNotDowngraded(t *testing.T) {
	placeholder := []mtree.Entry{{Path: "./usr/lib/jvm/default", Type: "link", Link: "/dev/null"}}
	res := Integrity("java-runtime-common", placeholder,
		obsMap(Observed{Path: "./usr/lib/jvm/default", Kind: ObsLink, Link: "java-26-openjdk"}),
		Exemptions{}, TierFull)
	f := integrityFor(t, res, "integrity-link-target", "./usr/lib/jvm/default")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("placeholder relink severity = %v, want suspicious -- a /dev/null record is a value the "+
			"package itself writes and must buy no severity relief: %s", f.Severity, formatFinding(f))
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "/dev/null placeholder") {
		t.Errorf("the placeholder is not named in the evidence: %v", f.Evidence)
	}
	if !strings.Contains(f.Limits, "Alternatives-style") {
		t.Errorf("Limits does not carry the benign explanation (INV-6): %q", f.Limits)
	}

	real := []mtree.Entry{{Path: "./usr/bin/x", Type: "link", Link: "../lib/x.real"}}
	res = Integrity("foo", real,
		obsMap(Observed{Path: "./usr/bin/x", Kind: ObsLink, Link: "/tmp/evil"}), Exemptions{}, TierFull)
	f = integrityFor(t, res, "integrity-link-target", "./usr/bin/x")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("a link recorded with a REAL target and now repointed must stay at the default floor; got %v: %s",
			f.Severity, formatFinding(f))
	}
}

// A recorded link with no link= value cannot be compared to anything: INV-9
// makes that a gap, not a silent pass.
func TestLinkWithNoRecordedTargetIsAGap(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/x", Type: "link"}}
	res := Integrity("foo", entries,
		obsMap(Observed{Path: "./usr/bin/x", Kind: ObsLink, Link: "y"}), Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", res.Findings)
	}
	if _, ok := gapForSubject(res, "integrity-link-target", "./usr/bin/x"); !ok {
		t.Errorf("no gap for a link record with no target: %+v", res.Gaps)
	}
}

func TestMissingFileIsInfoNeverCritical(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/share/doc/foo/README", Type: "file", SHA256: digestA}}
	res := Integrity("foo", entries,
		obsMap(Observed{Path: "./usr/share/doc/foo/README", Kind: ObsMissing}), Exemptions{}, TierFull)
	f := integrityFor(t, res, "integrity-missing", "./usr/share/doc/foo/README")
	if f.Severity != finding.SevInfo {
		t.Errorf("severity = %v, want info (deleted documentation and locales are ordinary): %s",
			f.Severity, formatFinding(f))
	}
}

func TestUnreadableFileIsAGap(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", SHA256: digestA}}
	res := Integrity("foo", entries, obsMap(Observed{
		Path: "./usr/bin/foo", Kind: ObsUnreadable,
		Err: &fs.PathError{Op: "openat", Path: "./usr/bin/foo", Err: fsx.ErrSymlink},
	}), Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("an unreadable file produced findings rather than a gap (INV-9): %+v", res.Findings)
	}
	g, ok := gapForSubject(res, "integrity-digest-mismatch", "./usr/bin/foo")
	if !ok {
		t.Fatalf("no gap for an unreadable file: %+v", res.Gaps)
	}
	if !strings.Contains(g.Reason, "symlink") {
		t.Errorf("gap does not carry the refusal: %+v", g)
	}
}

// A file that changed while it was being read is neither "matches" nor "does
// not match". Reporting it as a digest mismatch would accuse the package for
// the scan's own timing.
func TestMutationDuringScanIsAGapNotAMismatch(t *testing.T) {
	entries := []mtree.Entry{{Path: "./var/lib/x", Type: "file", SHA256: digestA}}
	res := Integrity("foo", entries, obsMap(Observed{
		Path: "./var/lib/x", Kind: ObsUnreadable,
		Err: &fs.PathError{Op: "fstat", Path: "./var/lib/x", Err: fsx.ErrMutatedDuringScan},
	}), Exemptions{}, TierFull)
	if _, ok := findingForSubject(res, "integrity-digest-mismatch", "./var/lib/x"); ok {
		t.Error("a mid-scan mutation was reported as a digest mismatch")
	}
	g, ok := gapForSubject(res, "integrity-digest-mismatch", "./var/lib/x")
	if !ok {
		t.Fatalf("no gap for a mid-scan mutation: %+v", res.Gaps)
	}
	if !strings.Contains(g.Reason, "mutated during scan") {
		t.Errorf("gap does not say what happened: %+v", g)
	}
}

// An entry whose only recorded digest is md5 is not verified here: INV-9 makes
// that a gap. 237 entries on the reference system carry md5digest.
func TestRecordWithoutSHA256IsAGap(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/lib/x.so", Type: "file", MD5: "d41d8cd98f00b204e9800998ecf8427e"}}
	res := Integrity("foo", entries,
		obsMap(Observed{Path: "./usr/lib/x.so", Kind: ObsHashed, SHA256: digestA}), Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", res.Findings)
	}
	g, ok := gapForSubject(res, "integrity-digest-mismatch", "./usr/lib/x.so")
	if !ok {
		t.Fatalf("no gap for a record with no sha256: %+v", res.Gaps)
	}
	if !strings.Contains(g.Reason, "sha256") {
		t.Errorf("gap does not name the missing digest: %+v", g)
	}
}

// INV-3: files verified by metadata alone were not examined, so the package
// cannot be reported clean for them. One gap per package, not per file --
// bounded noise, but never silence.
func TestMetadataOnlyCoverageIsGapped(t *testing.T) {
	entries := []mtree.Entry{
		{Path: "./a", Type: "file", Size: 1, SHA256: digestA},
		{Path: "./b", Type: "file", Size: 1, SHA256: digestA},
		{Path: "./c", Type: "file", Size: 1, SHA256: digestA},
	}
	obs := obsMap(
		Observed{Path: "./a", Kind: ObsMetadataOnly, Size: 1, MtimeAssisted: true},
		Observed{Path: "./b", Kind: ObsMetadataOnly, Size: 1, MtimeAssisted: true},
		Observed{Path: "./c", Kind: ObsHashed, SHA256: digestA, Size: 1},
	)
	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", res.Findings)
	}
	if len(res.Gaps) != 1 {
		t.Fatalf("want exactly one coverage gap for the package, got %+v", res.Gaps)
	}
	g := res.Gaps[0]
	if g.RuleID != "integrity-coverage" || g.Subject != "foo" {
		t.Errorf("coverage gap is not attributed to the package: %+v", g)
	}
	if !strings.Contains(g.Reason, "2 of 3") || !strings.Contains(g.Reason, "mtime-assisted") {
		t.Errorf("coverage gap does not quantify what was not hashed: %+v", g)
	}
}

// A metadata-only observation that DOES disagree with the record is reported,
// but never as an equal-strength finding: it carries the mtime-assisted marker
// (INV-6) because the bytes were never read.
func TestMetadataOnlyMismatchCarriesTheMtimeAssistedMarker(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Size: 10, SHA256: digestA}}
	res := Integrity("foo", entries, obsMap(Observed{
		Path: "./usr/bin/foo", Kind: ObsMetadataOnly, Size: 99, MtimeAssisted: true,
	}), Exemptions{}, TierTriage)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/bin/foo")
	ev := strings.Join(f.Evidence, " ")
	if !strings.Contains(ev, "mtime-assisted") {
		t.Errorf("a stat-derived finding is not marked mtime-assisted (INV-6): %v", f.Evidence)
	}
	if !strings.Contains(f.Limits, "never read") {
		t.Errorf("Limits does not say the contents were never hashed: %q", f.Limits)
	}
}

// An entry no observation covers must never read as clean.
func TestUnobservedEntryIsAGap(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", SHA256: digestA}}
	res := Integrity("foo", entries, map[string]Observed{}, Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("unexpected findings: %+v", res.Findings)
	}
	if _, ok := gapForSubject(res, "integrity-digest-mismatch", "./usr/bin/foo"); !ok {
		t.Fatalf("an unexamined entry produced no gap (INV-3): %+v", res.Gaps)
	}
}

func TestDirectoryEntriesAreNotChecked(t *testing.T) {
	entries := []mtree.Entry{{Path: "./usr/bin", Type: "dir", Mode: 0o755}}
	res := Integrity("foo", entries, map[string]Observed{}, Exemptions{}, TierFull)
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("a dir entry produced output: findings=%+v gaps=%+v", res.Findings, res.Gaps)
	}
}

func TestExemptPathIsSilentInFullAndInfoInParanoid(t *testing.T) {
	ex := DeriveExemptions([]Hook{{
		Name: "11-glibc-remove-ldconfig-cache.hook", When: "PreTransaction",
		Exec: "/usr/bin/rm --force /etc/ld.so.cache",
	}}, nil)
	entries := []mtree.Entry{{Path: "./etc/ld.so.cache", Type: "file", Mode: 0o644, SHA256: digestA}}

	full := Integrity("glibc", entries,
		obsMap(Observed{Path: "./etc/ld.so.cache", Kind: ObsExempt}), ex, TierFull)
	if len(full.Findings) != 0 || len(full.Gaps) != 0 {
		t.Fatalf("an exempt file produced output at tier full: findings=%+v gaps=%+v", full.Findings, full.Gaps)
	}

	par := Integrity("glibc", entries,
		obsMap(Observed{Path: "./etc/ld.so.cache", Kind: ObsHashed, SHA256: digestB}), ex, TierParanoid)
	f := integrityFor(t, par, "integrity-digest-mismatch", "./etc/ld.so.cache")
	if f.Severity != finding.SevInfo {
		t.Errorf("paranoid severity on an exempt path = %v, want info: %s", f.Severity, formatFinding(f))
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "11-glibc-remove-ldconfig-cache.hook") {
		t.Errorf("paranoid finding does not name the exemption it overrode: %v", f.Evidence)
	}
}

func TestUnownedSetuidIsReportedAndOwnedIsNot(t *testing.T) {
	res := UnownedSUID([]SUIDFile{
		{Path: "./usr/bin/sudo", Mode: 0o4755, Owner: "sudo"},
		{Path: "./usr/bin/wall", Mode: 0o2755, Owner: "util-linux"},
		{Path: "./opt/thing/helper", Mode: 0o4755},
		{Path: "./usr/local/bin/plain", Mode: 0o755},
	})
	if len(res.Findings) != 1 {
		t.Fatalf("want exactly one finding, got %+v", res.Findings)
	}
	f := res.Findings[0]
	if f.RuleID != "integrity-unowned-setuid" || f.Subject != "./opt/thing/helper" {
		t.Errorf("wrong subject: %s", formatFinding(f))
	}
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: %s", f.Severity, formatFinding(f))
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "mode=4755") {
		t.Errorf("evidence does not name the mode: %v", f.Evidence)
	}
	if f.Limits == "" {
		t.Error("INV-6: no Limits")
	}
}

// TestNoIntegrityRuleReachesCritical is the INV-8 structural pin for this
// lane. Every failure shape these checks can produce is fed in at once; none
// may reach SevCritical. A digest, a link target or a setuid bit cannot
// distinguish tampering from an administrator, a local rebuild or a hook whose
// output this lane failed to derive -- reaching critical on any of them would
// train the operator to ignore the tool, which is the failure this project
// cannot afford. Critical is reserved for the definitive rules (aur-tombstone).
func TestNoIntegrityRuleReachesCritical(t *testing.T) {
	entries := []mtree.Entry{
		{Path: "./usr/bin/foo", Type: "file", Mode: 0o4755, Size: 3, SHA256: digestA},
		{Path: "./usr/bin/bar", Type: "link", Link: "foo"},
		{Path: "./usr/share/doc/x", Type: "file", SHA256: digestA},
		{Path: "./etc/x.conf", Type: "file", Mode: 0o644, SHA256: digestA},
	}
	obs := obsMap(
		Observed{Path: "./usr/bin/foo", Kind: ObsHashed, SHA256: digestB, Mode: 0o4755},
		Observed{Path: "./usr/bin/bar", Kind: ObsLink, Link: "/tmp/elsewhere"},
		Observed{Path: "./usr/share/doc/x", Kind: ObsMissing},
		Observed{Path: "./etc/x.conf", Kind: ObsMetadataOnly, Size: 1, MtimeAssisted: true},
	)
	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	res.Findings = append(res.Findings, UnownedSUID([]SUIDFile{{Path: "./opt/x", Mode: 0o4755}}).Findings...)
	if len(res.Findings) < 4 {
		t.Fatalf("the fixture stopped exercising every rule (%d findings): %+v", len(res.Findings), res.Findings)
	}
	for _, f := range res.Findings {
		if f.Severity == finding.SevCritical {
			t.Errorf("integrity rule reached critical: %s", formatFinding(f))
		}
		if f.Limits == "" {
			t.Errorf("INV-6: finding with no Limits: %s", formatFinding(f))
		}
	}
}
