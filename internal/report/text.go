// internal/report/text.go
package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/lookatitude/aurvet/internal/finding"
)

// Summary carries the sweep-wide counts that finding.Result itself does not
// track (it only holds foreign-package outcomes, not the full inventory).
type Summary struct {
	Total   int
	Foreign int
}

// FindingID is the fingerprint rendered in output and accepted by `explain`.
// It exists so Text, JSON and Explain cannot drift: an id printed by one and
// not resolvable by another is a broken cross-reference in a security tool.
// Scope is "subject" (spec §12): this rule x this package, surviving upgrades.
//
// Subject is a package name (never name-version) everywhere in
// internal/check, which is what keeps the fingerprint version-independent
// per spec §12.
func FindingID(f finding.Finding) string {
	return finding.Fingerprint(f.RuleID, f.SubjectKind, f.Subject, "subject")
}

// Text renders the quiet default output: one header line carrying counts and
// coverage (spec §14), findings sorted by descending severity, and gaps — a
// gap is never silence (INV-3/INV-10).
func Text(w io.Writer, r finding.Result, s Summary) error {
	coverage := "coverage: complete"
	if !r.Complete() {
		coverage = fmt.Sprintf("coverage: incomplete (%d gap(s))", len(r.Gaps))
	}
	if _, err := fmt.Fprintf(w, "%d foreign / %d total packages · %d finding(s) · %s\n",
		s.Foreign, s.Total, len(r.Findings), coverage); err != nil {
		return err
	}

	findings := make([]finding.Finding, len(r.Findings))
	copy(findings, r.Findings)
	sort.SliceStable(findings, func(i, j int) bool {
		return findings[i].Severity > findings[j].Severity
	})

	for _, f := range findings {
		if _, err := fmt.Fprintf(w, "\n[%s] %s: %s (%s)\n", f.Severity, f.Subject, f.Summary, FindingID(f)); err != nil {
			return err
		}
		for _, e := range f.Evidence {
			if _, err := fmt.Fprintf(w, "    evidence: %s\n", e); err != nil {
				return err
			}
		}
		if _, err := fmt.Fprintf(w, "    limits:   %s\n", f.Limits); err != nil {
			return err
		}
	}

	for _, g := range r.Gaps {
		if _, err := fmt.Fprintf(w, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason); err != nil {
			return err
		}
	}
	return nil
}

// Explain prints the rationale for one finding: its evidence, what it cannot
// prove (INV-6), and copy-pasteable investigation commands (spec §12).
//
// An unknown id is an error naming the id, never a silent empty success —
// cmd/aurvet maps that to exit 2. A gap-explain surface is out of scope for
// P1-A; the error states how many findings and gaps were present so a user
// is not told "no such finding" by a scan that gapped everything it checked.
func Explain(w io.Writer, r finding.Result, id string) error {
	for _, f := range r.Findings {
		if FindingID(f) != id {
			continue
		}
		return explainFinding(w, f)
	}
	return fmt.Errorf("no finding with id %q (%d finding(s), %d gap(s) present)", id, len(r.Findings), len(r.Gaps))
}

func explainFinding(w io.Writer, f finding.Finding) error {
	if _, err := fmt.Fprintf(w, "id:       %s\nrule:     %s\nseverity: %s\nsubject:  %s\nsummary:  %s\n\n",
		FindingID(f), f.RuleID, f.Severity, f.Subject, f.Summary); err != nil {
		return err
	}
	if _, err := fmt.Fprintln(w, "evidence:"); err != nil {
		return err
	}
	for _, e := range f.Evidence {
		if _, err := fmt.Fprintf(w, "  - %s\n", e); err != nil {
			return err
		}
	}
	if _, err := fmt.Fprintf(w, "\nwhat this does NOT prove:\n  %s\n", f.Limits); err != nil {
		return err
	}
	if _, err := fmt.Fprintf(w, "\ninvestigate:\n  pacman -Qi %s\n  pacman -Qlq %s\n", f.Subject, f.Subject); err != nil {
		return err
	}
	return nil
}
