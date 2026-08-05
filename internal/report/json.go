// internal/report/json.go
package report

import (
	"encoding/json"
	"io"

	"github.com/lookatitude/aurvet/internal/finding"
)

const schemaVersion = 1

type jsonFinding struct {
	ID          string   `json:"id"`
	RuleID      string   `json:"rule_id"`
	SubjectKind string   `json:"subject_kind"`
	Subject     string   `json:"subject"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence"`
	Limits      string   `json:"limits"`
}

type jsonGap struct {
	RuleID  string `json:"rule_id"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// jsonSinceLast mirrors, field for field, what TextView's since-last header
// prints. The contract is that --json and the text render carry the SAME
// information: a consumer that only ever parses JSON must be able to tell that
// findings were suppressed, how many, and which ones went away.
//
// It is a pointer with omitempty in jsonReport, so a run without --since-last
// emits byte-identical output to before this field existed. That is why adding
// it does not bump schema_version: existing consumers see no change.
type jsonSinceLast struct {
	// HadBaseline false means no comparison happened at all — distinct from a
	// comparison that found nothing new.
	HadBaseline bool `json:"had_baseline"`
	// TotalFindings is the FULL count, which is what exit_code reflects.
	// Without it a consumer reading len(findings) would conclude the host is
	// clean on the run that suppressed everything.
	TotalFindings int           `json:"total_findings"`
	New           int           `json:"new"`
	Suppressed    int           `json:"suppressed"`
	Resolved      []jsonFinding `json:"resolved"`
}

type jsonReport struct {
	SchemaVersion    int            `json:"schema_version"`
	TotalPackages    int            `json:"total_packages"`
	ForeignPackages  int            `json:"foreign_packages"`
	CoverageComplete bool           `json:"coverage_complete"`
	MinSeverity      string         `json:"min_severity"`
	ExitCode         int            `json:"exit_code"`
	Findings         []jsonFinding  `json:"findings"`
	CoverageGaps     []jsonGap      `json:"coverage_gaps"`
	SinceLast        *jsonSinceLast `json:"since_last,omitempty"`
}

func encodeFindings(fs []finding.Finding) []jsonFinding {
	out := make([]jsonFinding, 0, len(fs))
	for _, f := range fs {
		evidence := make([]string, 0, len(f.Evidence))
		evidence = append(evidence, f.Evidence...)
		out = append(out, jsonFinding{
			ID:          FindingID(f),
			RuleID:      f.RuleID,
			SubjectKind: f.SubjectKind,
			Subject:     f.Subject,
			Severity:    f.Severity.String(),
			Summary:     f.Summary,
			Evidence:    evidence,
			Limits:      f.Limits,
		})
	}
	return out
}

// JSON renders the versioned schema (spec §14). min is the floor the run
// used: a JSON consumer cannot interpret exit_code without knowing it, and
// exit_code itself is computed by calling ExitCode so the document and the
// process's actual exit status can never disagree.
func JSON(w io.Writer, r finding.Result, s Summary, min finding.Severity) error {
	return JSONView(w, FullView(r), s, min)
}

// JSONView is JSON over a View. coverage_complete and exit_code are computed
// from v.Verdict, NEVER from v.Display.
//
// This is the same rule TextView follows, and it matters more here: exit_code
// is a document field, and a JSON report claiming exit_code 0 while the process
// exits 1 is a contradiction a machine consumer cannot recover from. Under
// --since-last, Display can be empty while Verdict holds a critical — feeding
// Display to ExitCode would turn a display filter into a severity filter in the
// one surface built for automation.
func JSONView(w io.Writer, v View, s Summary, min finding.Severity) error {
	gaps := make([]jsonGap, 0, len(v.Verdict.Gaps))
	for _, g := range v.Verdict.Gaps {
		gaps = append(gaps, jsonGap{RuleID: g.RuleID, Subject: g.Subject, Reason: g.Reason})
	}

	out := jsonReport{
		SchemaVersion:    schemaVersion,
		TotalPackages:    s.Total,
		ForeignPackages:  s.Foreign,
		CoverageComplete: v.Verdict.Complete(),
		MinSeverity:      min.String(),
		ExitCode:         ExitCode(v.Verdict, min),
		Findings:         encodeFindings(v.Display.Findings),
		CoverageGaps:     gaps,
	}
	if v.Since != nil {
		out.SinceLast = &jsonSinceLast{
			HadBaseline:   v.Since.HadBaseline,
			TotalFindings: len(v.Verdict.Findings),
			New:           len(v.Since.Added),
			Suppressed:    len(v.Verdict.Findings) - len(v.Display.Findings),
			Resolved:      encodeFindings(v.Since.Resolved),
		}
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
