// internal/report/since_test.go
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
)

// critical is the SevCritical finding sample() carries, on its own.
func critical() finding.Result {
	return finding.Result{Findings: findingsOnly().Findings}
}

// TestSinceLastIsADisplayFilterNeverASeverityFilter is the reason View exists.
//
// Setup: a critical finding that was ALREADY present in the previous scan, so
// --since-last suppresses it from the listing. The exit code must still be 1 —
// a finding you saw yesterday is still a finding today. If this ever returns 0,
// --since-last has become a way to make malware stop being reported by looking
// at it twice, and the flag is worse than useless.
func TestSinceLastIsADisplayFilterNeverASeverityFilter(t *testing.T) {
	prev := critical()
	cur := critical()

	v := SinceLastView(prev, true, cur)

	if len(v.Display.Findings) != 0 {
		t.Fatalf("expected the already-seen finding to be suppressed from the display set, got %+v", v.Display.Findings)
	}
	if len(v.Verdict.Findings) != 1 {
		t.Fatalf("the verdict must keep the full finding set, got %+v", v.Verdict.Findings)
	}
	if got := ExitCode(v.Verdict, finding.SevSuspicious); got != exitFindings {
		t.Errorf("ExitCode(verdict) = %d, want %d: --since-last must not change the exit code", got, exitFindings)
	}
	// The defect, stated as the thing we must never do.
	if got := ExitCode(v.Display, finding.SevSuspicious); got != exitClean {
		t.Fatalf("test premise broken: the display set was supposed to be empty, ExitCode(display) = %d", got)
	}
}

// TestSinceLastKeepsGapsSoCoverageStaysIncomplete: gaps are not findings and
// are never diffed. A package that could not be checked yesterday is still
// unchecked today, so the second --since-last run must still exit 3.
func TestSinceLastKeepsGapsSoCoverageStaysIncomplete(t *testing.T) {
	prev := sample()
	cur := sample()

	v := SinceLastView(prev, true, cur)

	if len(v.Display.Gaps) != len(cur.Gaps) {
		t.Errorf("display gaps = %d, want %d: gaps must survive the diff", len(v.Display.Gaps), len(cur.Gaps))
	}
	if v.Verdict.Complete() {
		t.Fatal("verdict reported complete coverage despite a gap")
	}
	if got := ExitCode(v.Verdict, finding.SevSuspicious); got != exitIncomplete {
		t.Errorf("ExitCode = %d, want %d: a seen-before gap is still a gap", got, exitIncomplete)
	}
}

// TestSinceLastWithNoBaselineShowsEverything: a first run has nothing to
// compare against, and must not print an empty list that reads as "clean".
func TestSinceLastWithNoBaselineShowsEverything(t *testing.T) {
	cur := sample()
	v := SinceLastView(finding.Result{}, false, cur)

	if len(v.Display.Findings) != len(cur.Findings) {
		t.Errorf("display findings = %d, want all %d", len(v.Display.Findings), len(cur.Findings))
	}
	if v.Since == nil || v.Since.HadBaseline {
		t.Fatalf("Since.HadBaseline should be false, got %+v", v.Since)
	}

	var buf bytes.Buffer
	if err := TextView(&buf, v, Summary{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "no previous report") {
		t.Errorf("a baseline-less run must say so; got:\n%s", buf.String())
	}
}

// TestTextViewHeaderCountsTheFullResultNotTheDisplaySet: the header count is
// the operator's at-a-glance verdict. Printing the suppressed count there
// would say "0 finding(s)" about a host with a critical on it.
func TestTextViewHeaderCountsTheFullResultNotTheDisplaySet(t *testing.T) {
	v := SinceLastView(critical(), true, critical())

	var buf bytes.Buffer
	if err := TextView(&buf, v, Summary{Total: 1410, Foreign: 39}); err != nil {
		t.Fatal(err)
	}
	out := buf.String()
	if !strings.Contains(out, "1 finding(s)") {
		t.Errorf("header must count the full result (1 finding), got:\n%s", out)
	}
	if !strings.Contains(out, "0 new") {
		t.Errorf("header must report 0 new, got:\n%s", out)
	}
	if !strings.Contains(out, "1 finding(s) still present, not re-listed") {
		t.Errorf("the suppressed count must be stated explicitly, got:\n%s", out)
	}
}

// TestTextViewListsResolvedFindings: resolved findings are absent from the
// current result by definition, so the ordinary listing can never show them.
func TestTextViewListsResolvedFindings(t *testing.T) {
	v := SinceLastView(critical(), true, finding.Result{})

	var buf bytes.Buffer
	if err := TextView(&buf, v, Summary{}); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "resolved: [critical] librewolf-fix-bin") {
		t.Errorf("resolved finding not rendered:\n%s", buf.String())
	}
}

// TestJSONViewExitCodeComesFromTheVerdict is the JSON half of the display-vs-
// severity-filter rule. exit_code is a document field; if it were computed
// from the suppressed display set it would contradict the process's own exit
// status, and automation branching on the document would draw the opposite
// conclusion from automation branching on $?.
func TestJSONViewExitCodeComesFromTheVerdict(t *testing.T) {
	v := SinceLastView(critical(), true, critical())

	var buf bytes.Buffer
	if err := JSONView(&buf, v, Summary{}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	var doc struct {
		ExitCode  int                   `json:"exit_code"`
		Findings  []struct{ ID string } `json:"findings"`
		SinceLast *struct {
			HadBaseline   bool `json:"had_baseline"`
			TotalFindings int  `json:"total_findings"`
			New           int  `json:"new"`
			Suppressed    int  `json:"suppressed"`
		} `json:"since_last"`
	}
	if err := json.Unmarshal(buf.Bytes(), &doc); err != nil {
		t.Fatalf("unmarshal: %v\n%s", err, buf.String())
	}
	if doc.ExitCode != exitFindings {
		t.Errorf("exit_code = %d, want %d (must come from the full result)", doc.ExitCode, exitFindings)
	}
	if len(doc.Findings) != 0 {
		t.Errorf("findings should be the suppressed display set, got %d", len(doc.Findings))
	}
	if doc.SinceLast == nil {
		t.Fatal("since_last block missing")
	}
	if doc.SinceLast.TotalFindings != 1 || doc.SinceLast.New != 0 || doc.SinceLast.Suppressed != 1 {
		t.Errorf("since_last = %+v, want total=1 new=0 suppressed=1", *doc.SinceLast)
	}
}

// TestJSONWithoutSinceLastOmitsTheBlock: a run that did not ask for
// --since-last must emit exactly what it emitted before this feature existed,
// so no existing consumer is broken and schema_version need not move.
func TestJSONWithoutSinceLastOmitsTheBlock(t *testing.T) {
	var buf bytes.Buffer
	if err := JSON(&buf, sample(), Summary{}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(buf.String(), "since_last") {
		t.Errorf("since_last must be omitted when the flag was not used:\n%s", buf.String())
	}
}

// TestJSONViewCarriesTheSameInformationAsText: the two renders must not drift.
// Every number the text header states about the diff has to be recoverable
// from the JSON document.
func TestJSONViewCarriesTheSameInformationAsText(t *testing.T) {
	prev := finding.Result{Findings: []finding.Finding{
		critical().Findings[0],
		{RuleID: "aur-orphaned", SubjectKind: "package", Subject: "gone-bin", Severity: finding.SevSuspicious, Summary: "orphaned"},
	}}
	cur := finding.Result{Findings: []finding.Finding{
		critical().Findings[0],
		{RuleID: "aur-orphaned", SubjectKind: "package", Subject: "new-bin", Severity: finding.SevSuspicious, Summary: "orphaned"},
	}}
	v := SinceLastView(prev, true, cur)

	var text, js bytes.Buffer
	if err := TextView(&text, v, Summary{}); err != nil {
		t.Fatal(err)
	}
	if err := JSONView(&js, v, Summary{}, finding.SevSuspicious); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(text.String(), "1 new, 1 resolved") {
		t.Fatalf("text render: want '1 new, 1 resolved', got:\n%s", text.String())
	}
	var doc struct {
		SinceLast struct {
			New      int `json:"new"`
			Resolved []struct {
				Subject string `json:"subject"`
			} `json:"resolved"`
		} `json:"since_last"`
	}
	if err := json.Unmarshal(js.Bytes(), &doc); err != nil {
		t.Fatal(err)
	}
	if doc.SinceLast.New != 1 {
		t.Errorf("json new = %d, want 1", doc.SinceLast.New)
	}
	if len(doc.SinceLast.Resolved) != 1 || doc.SinceLast.Resolved[0].Subject != "gone-bin" {
		t.Errorf("json resolved = %+v, want one entry for gone-bin", doc.SinceLast.Resolved)
	}
	if !strings.Contains(text.String(), "gone-bin") {
		t.Errorf("text render dropped the resolved finding JSON reports:\n%s", text.String())
	}
}
