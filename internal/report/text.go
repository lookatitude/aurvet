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
	return TextView(w, FullView(r), s)
}

// TextView is Text over a View. The header's finding count and coverage verdict
// come from v.Verdict — the FULL result — while only the listed findings come
// from v.Display. Under --since-last that is the difference between "0
// finding(s)" (a lie: they are suppressed, not gone) and "14 finding(s), 0 new
// since the last scan".
func TextView(w io.Writer, v View, s Summary) error {
	coverage := "coverage: complete"
	if !v.Verdict.Complete() {
		coverage = fmt.Sprintf("coverage: incomplete (%d gap(s))", len(v.Verdict.Gaps))
	}
	if _, err := fmt.Fprintf(w, "%d foreign / %d total packages · %d finding(s) · %s\n",
		s.Foreign, s.Total, len(v.Verdict.Findings), coverage); err != nil {
		return err
	}

	if err := writeSinceHeader(w, v); err != nil {
		return err
	}

	findings := make([]finding.Finding, len(v.Display.Findings))
	copy(findings, v.Display.Findings)
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

	// Gaps come from Verdict, never from Display. A package that could not be
	// checked yesterday is still unchecked today, so --since-last must not
	// diff gaps away — they are what holds the exit code at 3.
	for _, g := range v.Verdict.Gaps {
		if _, err := fmt.Fprintf(w, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason); err != nil {
			return err
		}
	}
	return nil
}

// writeSinceHeader renders the --since-last summary line and the resolved
// findings, which are the one thing the ordinary listing cannot show: they are
// absent from the current result by definition.
//
// The suppressed count is stated explicitly. "0 new" on its own reads as "you
// are clean" to a tired operator at 2am; "0 new (14 finding(s) still present,
// not re-listed)" cannot.
func writeSinceHeader(w io.Writer, v View) error {
	if v.Since == nil {
		return nil
	}
	if !v.Since.HadBaseline {
		_, err := fmt.Fprintln(w, "since last scan: no previous report to compare against; showing all findings")
		return err
	}
	suppressed := len(v.Verdict.Findings) - len(v.Since.Added)
	if _, err := fmt.Fprintf(w, "since last scan: %d new, %d resolved (%d finding(s) still present, not re-listed)\n",
		len(v.Since.Added), len(v.Since.Resolved), suppressed); err != nil {
		return err
	}
	for _, f := range v.Since.Resolved {
		if _, err := fmt.Fprintf(w, "  resolved: [%s] %s — %s\n", f.Severity, f.Subject, f.Summary); err != nil {
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
