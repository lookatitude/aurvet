// internal/report/report_test.go
package report

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
)

// sample carries both a SevCritical finding AND a Gap — the case the
// exit-code precedence decision (Gap outranks finding) exists to cover.
func sample() finding.Result {
	return finding.Result{
		Findings: []finding.Finding{{
			RuleID: "aur-tombstone", SubjectKind: "package", Subject: "librewolf-fix-bin",
			Severity: finding.SevCritical, Summary: "removed from the AUR for malware",
			Evidence: []string{"cgit removal commit: history removed due to malware"},
			Limits:   "Does not confirm the payload is still present.",
		}},
		Gaps: []finding.Gap{{RuleID: "aur-provenance", Subject: "foo-bin", Reason: "no cache clone"}},
	}
}

// findingsOnly is sample() with the gap stripped: findings-only, coverage-complete.
func findingsOnly() finding.Result {
	r := sample()
	r.Gaps = nil
	return r
}

type errWriter struct{}

func (errWriter) Write(p []byte) (int, error) { return 0, errors.New("closed pipe") }

// --- Text ---

func TestTextHeaderHasCountsAndCoverage(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(), Summary{Total: 1409, Foreign: 39}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"critical", "librewolf-fix-bin", "coverage", "incomplete", "1 gap", "1409", "39"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestTextCoverageCompleteWhenNoGaps(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, findingsOnly(), Summary{}); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(b.String(), "incomplete") {
		t.Errorf("coverage-complete result rendered as incomplete:\n%s", b.String())
	}
	if !strings.Contains(b.String(), "coverage") {
		t.Errorf("coverage word missing from complete-coverage header:\n%s", b.String())
	}
}

func TestTextSortsBySeverityDescendingStable(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{
		{RuleID: "a", Subject: "pkg-a", Severity: finding.SevInfo, Summary: "a"},
		{RuleID: "b", Subject: "pkg-b", Severity: finding.SevCritical, Summary: "b"},
		{RuleID: "c", Subject: "pkg-c", Severity: finding.SevSuspicious, Summary: "c"},
		{RuleID: "d", Subject: "pkg-d", Severity: finding.SevCritical, Summary: "d"},
	}}
	var b bytes.Buffer
	if err := Text(&b, r, Summary{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	idxB, idxD, idxC, idxA := strings.Index(out, "pkg-b"), strings.Index(out, "pkg-d"), strings.Index(out, "pkg-c"), strings.Index(out, "pkg-a")
	if idxB < 0 || idxD < 0 || idxC < 0 || idxA < 0 {
		t.Fatalf("not all subjects rendered:\n%s", out)
	}
	// b and d are both SevCritical; stable sort must keep discovery order (b before d).
	if !(idxB < idxD && idxD < idxC && idxC < idxA) {
		t.Errorf("findings not sorted descending-severity, stable:\n%s", out)
	}
}

func TestTextEachFindingRendersLimits(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{
		{RuleID: "a", SubjectKind: "package", Subject: "pkg-a", Severity: finding.SevInfo, Summary: "a", Limits: "limit-a-unique"},
		{RuleID: "b", SubjectKind: "package", Subject: "pkg-b", Severity: finding.SevCritical, Summary: "b", Limits: "limit-b-unique"},
	}}
	var b bytes.Buffer
	if err := Text(&b, r, Summary{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, f := range r.Findings {
		if !strings.Contains(out, f.Limits) {
			t.Errorf("output missing Limits %q for subject %s:\n%s", f.Limits, f.Subject, out)
		}
	}
}

func TestTextRendersGaps(t *testing.T) {
	r := finding.Result{Gaps: []finding.Gap{
		{RuleID: "sync-coverage", Subject: "core.db", Reason: "sync database could not be read"},
	}}
	var b bytes.Buffer
	if err := Text(&b, r, Summary{}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"sync-coverage", "core.db", "sync database could not be read"} {
		if !strings.Contains(out, want) {
			t.Errorf("gap rendering missing %q:\n%s", want, out)
		}
	}
}

func TestTextReturnsWriteError(t *testing.T) {
	if err := Text(errWriter{}, sample(), Summary{}); err == nil {
		t.Error("expected error from a failing writer, got nil")
	}
}

func TestTextAndExplainHandleNilSlicesWithoutPanic(t *testing.T) {
	r := finding.Result{}
	var b bytes.Buffer
	if err := Text(&b, r, Summary{}); err != nil {
		t.Fatalf("Text errored on nil-slice Result: %v", err)
	}
	if err := Explain(&b, r, "nonexistent"); err == nil {
		t.Error("expected error for unknown id on empty Result")
	}
}

// --- FindingID cross-reference ---

func TestFindingIDCrossReference(t *testing.T) {
	r := sample()
	var textBuf, jsonBuf bytes.Buffer
	if err := Text(&textBuf, r, Summary{}); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&jsonBuf, r, Summary{}, finding.SevInfo); err != nil {
		t.Fatal(err)
	}
	textID := FindingID(r.Findings[0])
	if !strings.Contains(textBuf.String(), textID) {
		t.Fatalf("Text output missing id %s:\n%s", textID, textBuf.String())
	}

	var parsed map[string]any
	if err := json.Unmarshal(jsonBuf.Bytes(), &parsed); err != nil {
		t.Fatal(err)
	}
	findings, ok := parsed["findings"].([]any)
	if !ok || len(findings) != 1 {
		t.Fatalf("unexpected findings shape: %#v", parsed["findings"])
	}
	jsonID, _ := findings[0].(map[string]any)["id"].(string)
	if jsonID != textID {
		t.Fatalf("json id %s != text id %s", jsonID, textID)
	}

	for _, id := range []string{textID, jsonID} {
		var b bytes.Buffer
		if err := Explain(&b, r, id); err != nil {
			t.Fatalf("Explain(%s) failed to resolve a cross-referenced id: %v", id, err)
		}
	}
}

// --- ParseSeverity ---

func TestParseSeverityRoundTrips(t *testing.T) {
	for _, sev := range []finding.Severity{finding.SevInfo, finding.SevSuspicious, finding.SevCritical} {
		got, err := ParseSeverity(sev.String())
		if err != nil {
			t.Fatalf("ParseSeverity(%q): %v", sev.String(), err)
		}
		if got != sev {
			t.Errorf("ParseSeverity(%q) = %v, want %v", sev.String(), got, sev)
		}
	}
}

func TestParseSeverityCaseInsensitiveAndTrimmed(t *testing.T) {
	got, err := ParseSeverity("  CRITICAL \n")
	if err != nil {
		t.Fatal(err)
	}
	if got != finding.SevCritical {
		t.Errorf("got %v, want SevCritical", got)
	}
}

func TestParseSeverityRejectsUnknown(t *testing.T) {
	_, err := ParseSeverity("criticl")
	if err == nil {
		t.Fatal("expected error for a typo'd severity, got nil")
	}
	for _, want := range []string{"info", "suspicious", "critical"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("error %q does not name accepted value %q", err, want)
		}
	}
}

// --- ExitCode ---

func TestExitCodeCleanComplete(t *testing.T) {
	if got := ExitCode(finding.Result{}, finding.SevSuspicious); got != exitClean {
		t.Errorf("got %d, want %d", got, exitClean)
	}
}

func TestExitCodeZeroFindingsOneGap(t *testing.T) {
	r := finding.Result{Gaps: []finding.Gap{{RuleID: "r", Subject: "s", Reason: "x"}}}
	if got := ExitCode(r, finding.SevSuspicious); got != exitIncomplete {
		t.Errorf("got %d, want %d", got, exitIncomplete)
	}
}

func TestExitCodeFindingsAtFloorNoGaps(t *testing.T) {
	if got := ExitCode(findingsOnly(), finding.SevSuspicious); got != exitFindings {
		t.Errorf("got %d, want %d", got, exitFindings)
	}
}

func TestExitCodeFindingsBelowFloorNoGaps(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{{Severity: finding.SevInfo}}}
	if got := ExitCode(r, finding.SevSuspicious); got != exitClean {
		t.Errorf("got %d, want %d", got, exitClean)
	}
}

func TestExitCodeFindingsBelowFloorPlusGap(t *testing.T) {
	r := finding.Result{
		Findings: []finding.Finding{{Severity: finding.SevInfo}},
		Gaps:     []finding.Gap{{RuleID: "r", Subject: "s", Reason: "x"}},
	}
	if got := ExitCode(r, finding.SevSuspicious); got != exitIncomplete {
		t.Errorf("got %d, want %d", got, exitIncomplete)
	}
}

// TestGapOutranksFindings pins the precedence decision: sample() carries both
// a SevCritical finding and a Gap. The plan's own reference test asserted 1
// here, contradicting the lead's decision that 3 outranks 1 — this is the
// corrected version of that test.
func TestGapOutranksFindings(t *testing.T) {
	if got := ExitCode(sample(), finding.SevSuspicious); got != exitIncomplete {
		t.Errorf("got %d, want %d — a gap must outrank a finding at/above the floor", got, exitIncomplete)
	}
}

func TestExitCodeTableDriven(t *testing.T) {
	type findingCase struct {
		name string
		sev  *finding.Severity
	}
	floors := []finding.Severity{finding.SevInfo, finding.SevSuspicious, finding.SevCritical}

	for _, floor := range floors {
		floor := floor
		var cases []findingCase
		cases = append(cases, findingCase{"none", nil})
		if floor > finding.SevInfo {
			below := floor - 1
			cases = append(cases, findingCase{"belowFloor", &below})
		}
		at := floor
		cases = append(cases, findingCase{"atFloor", &at})
		if floor < finding.SevCritical {
			above := floor + 1
			cases = append(cases, findingCase{"aboveFloor", &above})
		}

		for _, fc := range cases {
			fc := fc
			for _, gapCount := range []int{0, 1} {
				gapCount := gapCount
				name := fmt.Sprintf("floor=%s/finding=%s/gaps=%d", floor, fc.name, gapCount)
				t.Run(name, func(t *testing.T) {
					var r finding.Result
					if fc.sev != nil {
						r.Findings = []finding.Finding{{Severity: *fc.sev}}
					}
					if gapCount > 0 {
						r.Gaps = []finding.Gap{{RuleID: "r", Subject: "s", Reason: "x"}}
					}

					want := exitClean
					switch {
					case gapCount > 0:
						want = exitIncomplete
					case fc.name == "atFloor" || fc.name == "aboveFloor":
						want = exitFindings
					}

					got := ExitCode(r, floor)
					if got == exitClean && len(r.Gaps) > 0 {
						t.Fatalf("ExitCode returned 0 with a gap present — this must never happen")
					}
					if got != want {
						t.Errorf("ExitCode(...) = %d, want %d", got, want)
					}
				})
			}
		}
	}
}

// TestExitCodeNotDerivableFromMaxSeverityAlone documents why ExitCode must
// read Complete() and cannot be reconstructed from MaxSeverity(): a gap-only
// Result and a genuinely clean Result report the identical MaxSeverity.
func TestExitCodeNotDerivableFromMaxSeverityAlone(t *testing.T) {
	gapOnly := finding.Result{Gaps: []finding.Gap{{RuleID: "r", Subject: "s", Reason: "x"}}}
	clean := finding.Result{}

	if gapOnly.MaxSeverity() != clean.MaxSeverity() {
		t.Fatalf("test setup invalid: MaxSeverity differs (%v vs %v)", gapOnly.MaxSeverity(), clean.MaxSeverity())
	}
	if got := ExitCode(gapOnly, finding.SevInfo); got != exitIncomplete {
		t.Errorf("ExitCode(gapOnly) = %d, want %d — indistinguishable from clean by MaxSeverity alone", got, exitIncomplete)
	}
}

// --- JSON ---

func TestJSONCarriesSchemaVersion(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(), Summary{Total: 1409, Foreign: 39}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] != float64(1) {
		t.Errorf("schema_version = %v, want 1", got["schema_version"])
	}
}

func TestJSONExitCodeMatchesExitCode(t *testing.T) {
	r := sample()
	min := finding.SevSuspicious
	var b bytes.Buffer
	if err := JSON(&b, r, Summary{}, min); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	want := float64(ExitCode(r, min))
	if got["exit_code"] != want {
		t.Errorf("exit_code = %v, want %v", got["exit_code"], want)
	}
}

func TestJSONIncludesMinSeverity(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, finding.Result{}, Summary{}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"min_severity": "suspicious"`) {
		t.Errorf("min_severity missing or wrong:\n%s", b.String())
	}
}

func TestJSONIncludesSummaryCounts(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, finding.Result{}, Summary{Total: 42, Foreign: 7}, finding.SevInfo); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["total_packages"] != float64(42) || got["foreign_packages"] != float64(7) {
		t.Errorf("summary counts wrong: %v", got)
	}
}

func TestJSONEmptySlicesNotNull(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, finding.Result{}, Summary{}, finding.SevInfo); err != nil {
		t.Fatal(err)
	}
	raw := b.String()
	if !strings.Contains(raw, `"findings": []`) {
		t.Errorf("findings not rendered as empty array:\n%s", raw)
	}
	if !strings.Contains(raw, `"coverage_gaps": []`) {
		t.Errorf("coverage_gaps not rendered as empty array:\n%s", raw)
	}
}

func TestJSONSeverityAsTextToken(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(), Summary{}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"severity": "critical"`) {
		t.Errorf("severity not rendered as text token:\n%s", b.String())
	}
}

func TestJSONFindingFields(t *testing.T) {
	r := sample()
	var b bytes.Buffer
	if err := JSON(&b, r, Summary{}, finding.SevInfo); err != nil {
		t.Fatal(err)
	}
	var got struct {
		Findings []struct {
			ID          string   `json:"id"`
			RuleID      string   `json:"rule_id"`
			SubjectKind string   `json:"subject_kind"`
			Subject     string   `json:"subject"`
			Severity    string   `json:"severity"`
			Summary     string   `json:"summary"`
			Evidence    []string `json:"evidence"`
			Limits      string   `json:"limits"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if len(got.Findings) != 1 {
		t.Fatalf("got %d findings, want 1", len(got.Findings))
	}
	f, want := got.Findings[0], r.Findings[0]
	if f.ID != FindingID(want) || f.RuleID != want.RuleID || f.SubjectKind != want.SubjectKind ||
		f.Subject != want.Subject || f.Severity != want.Severity.String() || f.Summary != want.Summary ||
		f.Limits != want.Limits {
		t.Errorf("finding fields mismatch: got %+v, want subset of %+v", f, want)
	}
	if len(f.Evidence) != len(want.Evidence) {
		t.Errorf("evidence mismatch: got %v want %v", f.Evidence, want.Evidence)
	}
}

func TestJSONFindingEvidenceEmptyNotNull(t *testing.T) {
	r := finding.Result{Findings: []finding.Finding{{
		RuleID: "r", SubjectKind: "package", Subject: "s", Severity: finding.SevInfo, Summary: "sum",
	}}}
	var b bytes.Buffer
	if err := JSON(&b, r, Summary{}, finding.SevInfo); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), `"evidence": []`) {
		t.Errorf("evidence not rendered as empty array:\n%s", b.String())
	}
}

func TestJSONDeterministic(t *testing.T) {
	r := sample()
	var b1, b2 bytes.Buffer
	if err := JSON(&b1, r, Summary{Total: 10, Foreign: 2}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if err := JSON(&b2, r, Summary{Total: 10, Foreign: 2}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(b1.Bytes(), b2.Bytes()) {
		t.Errorf("JSON output not deterministic:\n%s\nvs\n%s", b1.String(), b2.String())
	}
}

// --- Explain ---

func TestExplainStatesLimits(t *testing.T) {
	r := sample()
	id := FindingID(r.Findings[0])
	var b bytes.Buffer
	if err := Explain(&b, r, id); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Does not confirm") {
		t.Errorf("explain omitted limits:\n%s", b.String())
	}
}

func TestExplainIncludesInvestigationCommands(t *testing.T) {
	r := sample()
	id := FindingID(r.Findings[0])
	var b bytes.Buffer
	if err := Explain(&b, r, id); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"pacman -Qi librewolf-fix-bin", "pacman -Qlq librewolf-fix-bin"} {
		if !strings.Contains(out, want) {
			t.Errorf("explain missing investigation command %q:\n%s", want, out)
		}
	}
}

func TestExplainUnknownIDNamesID(t *testing.T) {
	err := Explain(io.Discard, sample(), "does-not-exist")
	if err == nil {
		t.Fatal("expected error")
	}
	if !strings.Contains(err.Error(), "does-not-exist") {
		t.Errorf("error does not name the id: %v", err)
	}
}

// TestExplainUnknownIDStatesFindingAndGapCounts: a gap-explain surface is out
// of scope for P1-A, but the error must not read as "no such finding" when a
// scan gapped everything it was asked to check — it must state how much was
// present.
func TestExplainUnknownIDStatesFindingAndGapCounts(t *testing.T) {
	r := finding.Result{
		Findings: []finding.Finding{{RuleID: "a", Subject: "x"}, {RuleID: "b", Subject: "y"}},
		Gaps: []finding.Gap{
			{RuleID: "g1", Subject: "z", Reason: "r"},
			{RuleID: "g2", Subject: "w", Reason: "r"},
			{RuleID: "g3", Subject: "v", Reason: "r"},
		},
	}
	err := Explain(io.Discard, r, "does-not-exist")
	if err == nil {
		t.Fatal("expected error")
	}
	msg := err.Error()
	if !strings.Contains(msg, "2") || !strings.Contains(msg, "3") {
		t.Errorf("error does not state finding/gap counts (want 2 findings, 3 gaps): %v", msg)
	}
}

func TestExplainReturnsWriteError(t *testing.T) {
	r := sample()
	id := FindingID(r.Findings[0])
	if err := Explain(errWriter{}, r, id); err == nil {
		t.Error("expected error from a failing writer, got nil")
	}
}
