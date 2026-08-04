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

type jsonReport struct {
	SchemaVersion    int           `json:"schema_version"`
	TotalPackages    int           `json:"total_packages"`
	ForeignPackages  int           `json:"foreign_packages"`
	CoverageComplete bool          `json:"coverage_complete"`
	MinSeverity      string        `json:"min_severity"`
	ExitCode         int           `json:"exit_code"`
	Findings         []jsonFinding `json:"findings"`
	CoverageGaps     []jsonGap     `json:"coverage_gaps"`
}

// JSON renders the versioned schema (spec §14). min is the floor the run
// used: a JSON consumer cannot interpret exit_code without knowing it, and
// exit_code itself is computed by calling ExitCode so the document and the
// process's actual exit status can never disagree.
func JSON(w io.Writer, r finding.Result, s Summary, min finding.Severity) error {
	findings := make([]jsonFinding, 0, len(r.Findings))
	for _, f := range r.Findings {
		evidence := make([]string, 0, len(f.Evidence))
		evidence = append(evidence, f.Evidence...)
		findings = append(findings, jsonFinding{
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

	gaps := make([]jsonGap, 0, len(r.Gaps))
	for _, g := range r.Gaps {
		gaps = append(gaps, jsonGap{RuleID: g.RuleID, Subject: g.Subject, Reason: g.Reason})
	}

	out := jsonReport{
		SchemaVersion:    schemaVersion,
		TotalPackages:    s.Total,
		ForeignPackages:  s.Foreign,
		CoverageComplete: r.Complete(),
		MinSeverity:      min.String(),
		ExitCode:         ExitCode(r, min),
		Findings:         findings,
		CoverageGaps:     gaps,
	}

	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
