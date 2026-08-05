// internal/report/since.go
package report

import "github.com/lookatitude/aurvet/internal/finding"

// SinceLast is the --since-last bookkeeping: what changed relative to the
// previous run, and whether there even was a previous run.
//
// HadBaseline false is not an error and not an empty diff — it means the diff
// did not happen at all (first run, or a state directory that could not be
// read). Renders must say so out loud rather than printing "0 new", which a
// reader would take as "nothing changed" when the truth is "nothing was
// compared".
type SinceLast struct {
	HadBaseline bool
	Added       []finding.Finding
	Resolved    []finding.Finding
}

// View separates what a render SHOWS from what the run REPORTS.
//
// This type exists to make one defect impossible to write. --since-last is a
// DISPLAY FILTER, NEVER A SEVERITY FILTER: a finding you saw yesterday is
// still a finding today, so the exit code, the coverage verdict and the
// headline finding count must all come from Verdict — the full, unfiltered
// result — while only the listing is narrowed to Display.
//
// Collapsing the two back into one finding.Result is exactly how --since-last
// silently becomes "exit 0 because I already told you about the malware",
// which is worse than not shipping the flag at all. Keeping them as separate
// fields means a caller has to choose one deliberately, and every render in
// this package takes the View rather than a bare Result so the choice is made
// in one place.
type View struct {
	// Verdict is the full result. Exit code and coverage come from here.
	Verdict finding.Result
	// Display is the subset actually listed. Its Gaps always mirror
	// Verdict.Gaps: a gap is not a finding and is never diffed away — an
	// unchecked package is still unchecked on the second run.
	Display finding.Result
	// Since is nil unless --since-last was requested.
	Since *SinceLast
}

// FullView is the ordinary, unfiltered view: display and verdict are the same
// result.
func FullView(r finding.Result) View {
	return View{Verdict: r, Display: r}
}

// SinceLastView builds the --since-last view of cur against the previous run's
// baseline. Verdict is always the FULL cur — never the diff.
//
// With no baseline the display falls back to the complete finding list: the
// safe direction is showing too much, because a first run that printed nothing
// would read as "this host is clean".
func SinceLastView(prev finding.Result, hadBaseline bool, cur finding.Result) View {
	if !hadBaseline {
		v := FullView(cur)
		v.Since = &SinceLast{HadBaseline: false}
		return v
	}
	added, resolved := Diff(prev, cur)
	return View{
		Verdict: cur,
		Display: finding.Result{Findings: added, Gaps: cur.Gaps},
		Since:   &SinceLast{HadBaseline: true, Added: added, Resolved: resolved},
	}
}
