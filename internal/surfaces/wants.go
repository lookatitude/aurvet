// internal/surfaces/wants.go
//
// The `*.wants` triage rule. THREE behaviours, not one -- and the task is most
// often got wrong by implementing only the first:
//
//  1. resolve symlink targets. `systemctl enable` writes a symlink into
//     /etc/systemd/system/<target>.wants/, and the LINK is unowned while the
//     unit it points at is packaged. Measured on the reference system
//     (2026-08-05): 14 of the 15 links there are exactly this. A rule that does
//     not resolve reports all 14.
//  2. exclude directories. The `<target>.wants/` directories are created by
//     `systemctl enable` too, so no package owns them either -- 9 more false
//     positives on the reference system for a rule that treats "unowned path"
//     as "subject".
//  3. alert only on a target that is UNRESOLVABLE OR NOT PACKAGE-OWNED.
//
// Measured decomposition on the reference system's /etc/systemd/system: 24
// unowned paths = 9 `*.target.wants` directories + 14 benign enablement symlinks
// whose target is package-owned + 1 link to a hand-written unit. Treat the
// totals as a point-in-time snapshot -- they drift with enablement state and the
// installed set. The GATE is the invariant, not the totals: exactly ONE subject.
// A rule producing 15 has skipped behaviour 3; one producing 24 has skipped 2
// and 3 both.
//
// Resolution goes through internal/own, which resolves symlinks itself and
// distinguishes "nobody owns this" from "I could not tell" -- the second is a
// coverage gap (INV-9), never a finding. filepath.EvalSymlinks would resolve
// against the RUNNING filesystem and walk straight out of an --offline-root
// tree; os.Readlink would read a path this process never confined. Neither is
// used here.
package surfaces

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
)

// Rule and gap identifiers for the enablement-link surface.
const (
	RuleWantsUnowned  = "wants-link-unowned-target"
	RuleWantsCoverage = "wants-coverage"
)

// wantsSuffixes are the enablement-directory suffixes. `.requires` has identical
// semantics to `.wants` (a stronger dependency, the same symlink shape) and
// identical abuse potential. There are none on the reference system, so covering
// it costs nothing there and closes a blind spot elsewhere.
var wantsSuffixes = []string{".wants", ".requires"}

// wantsLimit is the rule-specific half of the honesty requirement; it is
// concatenated with unitLimitCorrelation so the reader of a single finding gets
// the whole ceiling (INV-6).
const wantsLimit = "An enablement link to an unowned unit is what `systemctl enable` produces for any " +
	"hand-written unit, which is ordinary administration: this rule cannot distinguish a hand-written " +
	"local unit from a planted one. It also does not distinguish a link to an unowned file from a " +
	"DANGLING link -- both are reported, because both mean systemd would be asked to start something no " +
	"package accounts for. "

// WantsEntry is one examined path under an enablement directory.
type WantsEntry struct {
	// Path is the entry's path relative to the scanned root.
	Path string

	// Link is the symlink's own text, verbatim, when the entry is a symlink.
	// Kept unresolved as evidence: it is what an operator would see.
	Link string

	// Target is Link interpreted relative to the SCANNED root -- an absolute
	// target is re-rooted there, not at the running filesystem's "/". Empty when
	// the entry is not a link or the target escapes the root.
	Target string

	// Pkg is the owning package when State is own.Owned.
	Pkg string

	// State is the oracle's verdict on the entry, resolved THROUGH the link.
	State own.State

	// Err is the resolution failure behind own.Unresolved.
	Err error
}

// WantsSurvey is the rule's whole output, including what it examined and chose
// not to report. The excluded buckets are returned rather than dropped for two
// reasons: an operator can see that silence meant "looked and found nothing"
// rather than "looked at nothing", and each bucket's count fails for a different
// and diagnosable reason when a behaviour stops firing.
type WantsSurvey struct {
	// Dirs are the directories examined and excluded by behaviour 2 -- the
	// enablement directories themselves and any directory inside them.
	Dirs []string

	// OwnedTargets are the entries excluded by behaviour 3 because the target
	// resolved to a packaged file. This is the false-positive population.
	OwnedTargets []WantsEntry

	// Subjects are the reported entries: target unowned, or dangling.
	Subjects []WantsEntry

	// Unresolved are the entries whose ownership could not be determined. They
	// are coverage gaps, not findings.
	Unresolved []WantsEntry

	// Examined counts every path this rule looked at, including the excluded
	// ones.
	Examined int
}

// SurveyWants applies the three behaviours to every enablement directory found
// one level below each of dirs.
//
// It is a pure function of (root, owners, dirs): no ambient path, no dependence
// on the process working directory, no write of any kind (INV-4, INV-5). Gaps
// are returned separately so a caller cannot mistake an unreadable directory for
// an empty one.
func SurveyWants(src fsx.Source, owners *own.Owners, dirs []string) (WantsSurvey, []finding.Gap) {
	var (
		s    WantsSurvey
		gaps []finding.Gap
	)
	if src.Zero() || owners == nil {
		return s, []finding.Gap{{
			RuleID:  RuleWantsCoverage,
			Subject: "systemd enablement directories",
			Reason: "no scanned tree or no ownership index was supplied, so no enablement link could be " +
				"resolved",
		}}
	}

	for _, dir := range dirs {
		ents, err := src.ReadDir(dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleWantsCoverage,
					Subject: dir,
					Reason: fmt.Sprintf("unit directory could not be listed (%v); any enablement links "+
						"below it were not examined", err),
				})
			}
			continue
		}
		for _, ent := range ents {
			if !hasWantsSuffix(ent.Name) {
				continue
			}
			wdir := path.Join(dir, ent.Name)

			// The enablement directory is classified by exactly the same rule as
			// its contents, rather than quietly skipped for being a container.
			// That is deliberate: on every system that has run `systemctl
			// enable` these directories are unowned paths (9 of the reference
			// system's 24), and they must be excluded BECAUSE THEY ARE
			// DIRECTORIES -- behaviour 2 -- not because of where the loop
			// happens to meet them. Skipping them structurally would make the
			// exclusion untestable and the rule's silence accidental.
			gaps = s.classify(src, owners, wdir, ent, gaps)
			if !ent.IsDir() {
				// A *.wants that is not a directory -- a symlink to one, say --
				// is a path whose CONTENTS cannot be enumerated here without
				// following it. Its own ownership was just classified; the fact
				// that its contents went unread is a coverage gap, because an
				// enablement directory moved out of the way is a good place to
				// keep links nobody reads.
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleWantsCoverage,
					Subject: wdir,
					Reason: "enablement path is not a directory (it may be a symlink to one); the links " +
						"inside it were not enumerated",
				})
				continue
			}

			wents, err := src.ReadDir(wdir)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleWantsCoverage,
					Subject: wdir,
					Reason: fmt.Sprintf("enablement directory could not be listed (%v); it may hold any "+
						"number of links to units this scan never saw", err),
				})
				continue
			}
			for _, we := range wents {
				gaps = s.classify(src, owners, path.Join(wdir, we.Name), we, gaps)
			}
		}
	}
	return s, gaps
}

// classify applies behaviours 2 and 3 to one examined path and files it in the
// bucket its verdict belongs to. One code path for the enablement directory and
// for its contents, so there is exactly one place where "is this a subject?" is
// decided.
func (s *WantsSurvey) classify(src fsx.Source, owners *own.Owners, rel string, ent fsx.Ent, gaps []finding.Gap) []finding.Gap {
	s.Examined++

	// Behaviour 2. Note that a SYMLINK to a directory is reported as a symlink
	// by the directory read and is therefore NOT excluded here: excluding it
	// would require following the link, and a link is exactly what this rule
	// resolves deliberately rather than incidentally.
	if ent.IsDir() {
		s.Dirs = append(s.Dirs, rel)
		return gaps
	}

	e := WantsEntry{Path: rel}
	if ent.IsSymlink() {
		link, lerr := src.ReadLink(rel)
		if lerr != nil {
			// The link exists and its own target could not be read. That is an
			// inability, not a fact about ownership.
			e.State = own.Unresolved
			e.Err = lerr
			s.Unresolved = append(s.Unresolved, e)
			return append(gaps, finding.Gap{
				RuleID:  RuleWantsCoverage,
				Subject: rel,
				Reason: fmt.Sprintf("enablement link's target could not be read (%v); whether it points "+
					"at a packaged unit is unknown", lerr),
			})
		}
		e.Link = link
		e.Target = resolveLinkPath(path.Dir(rel), link)
	}

	// Behaviours 1 and 3 in one lookup. own.Resolve walks the path component by
	// component through the confined reader, so the leaf symlink is resolved here
	// and an absolute target is re-rooted at the SCANNED root -- not at this
	// machine's "/".
	pkg, st, err := owners.Resolve(rel)
	e.Pkg, e.State, e.Err = pkg, st, err
	switch st {
	case own.Owned:
		s.OwnedTargets = append(s.OwnedTargets, e)
	case own.Unresolved:
		s.Unresolved = append(s.Unresolved, e)
		gaps = append(gaps, finding.Gap{
			RuleID:  RuleWantsCoverage,
			Subject: rel,
			Reason: fmt.Sprintf("ownership of the enablement link's target could not be determined (%v); "+
				"it is reported as unknown rather than as unowned", err),
		})
	default:
		s.Subjects = append(s.Subjects, e)
	}
	return gaps
}

func hasWantsSuffix(name string) bool {
	for _, sfx := range wantsSuffixes {
		if strings.HasSuffix(name, sfx) {
			return true
		}
	}
	return false
}

// Findings renders the subjects. Suspicious, never critical: cruft's one true
// positive is a hand-written backup unit, and rating this critical would fail
// the INV-8 gate on a legitimate root. Correlation is what earns critical, and
// correlation lives in another package.
func (s WantsSurvey) Findings() []finding.Finding {
	out := make([]finding.Finding, 0, len(s.Subjects))
	for _, e := range s.Subjects {
		evidence := []string{
			fmt.Sprintf("%s is a %s under an enablement directory", e.Path, entryKind(e)),
		}
		if e.Link != "" {
			evidence = append(evidence, fmt.Sprintf("link target as written: %s", e.Link))
			if e.Target != "" {
				evidence = append(evidence,
					fmt.Sprintf("target resolved against the scanned root: %s", e.Target))
			} else {
				evidence = append(evidence,
					"the target does not resolve within the scanned root")
			}
		}
		evidence = append(evidence, "no installed package owns the target")
		out = append(out, finding.Finding{
			RuleID:      RuleWantsUnowned,
			SubjectKind: "systemd-enablement-link",
			Subject:     e.Path,
			Severity:    finding.SevSuspicious,
			Summary: fmt.Sprintf("%s enables a unit that no installed package owns",
				path.Base(path.Dir(e.Path))),
			Evidence: evidence,
			Limits:   wantsLimit + unitLimitCorrelation,
		})
	}
	return out
}

func entryKind(e WantsEntry) string {
	if e.Link != "" {
		return "symlink"
	}
	return "file"
}
