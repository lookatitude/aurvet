// internal/gate/vcsdelta.go
//
// VCS delta review (P2 task 11).
//
// # Why this exists at all
//
// The approval store keys on pkgbase + recipe digest, which is the right key
// for a recipe and the wrong one for a -git package. Such a recipe declares
// source=('foo::git+https://…') once and never changes; the code it builds
// changes on every upstream push. Approve it once and the approval is a
// permanent blank cheque over unbounded future commits -- the sharpest hole in
// a naive approval store, and the reason task 10 alone is not enough.
//
// So for a VCS source the reviewed unit is not only the recipe: it is the
// commit range since the position recorded when the recipe was last approved or
// snapshotted.
//
// # reached is not a detail
//
// internal/vcs.LogSince returns (commits, reached, err) and the second value
// carries a fact the first cannot:
//
//	empty slice + reached == true   -> already up to date
//	commits     + reached == true   -> this is the range to review
//	           reached == false     -> the recorded commit was NOT found
//
// Those are different facts and rendering them the same way is a lie. The third
// is the interesting one: a force-push that removes the commit you approved is
// exactly what a hostile upstream does, and it must never display as "no
// changes".
//
// This file refines the third case rather than reporting it flat, because
// reached == false has two causes and only one of them is an accusation:
//
//   - the walk exhausted the history without finding the anchor -> the anchor
//     is not in this history (force-push, swapped upstream, truncated clone).
//     DeltaAnchorAbsent, a suspicious finding that says which of the three it
//     cannot distinguish (INV-6).
//   - the walk hit its own bound first -> nothing is proven either way.
//     DeltaUndetermined, a coverage gap. Reporting this as a force-push would
//     be a false accusation built on the reviewer's own cap, and INV-8 is the
//     standing objection to exactly that.
//
// Nothing here executes git (D-1, INV-2): every read goes through
// internal/vcs, which parses objects with compress/zlib.
package gate

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/vcs"
)

// Rule identifiers for the delta review. Findings and gaps are kept apart on
// purpose: new commits and a vanished anchor are things this tool observed,
// while a bounded walk or an unreadable clone are things it could not.
const (
	// RuleVCSNewCommits is the commit range an operator must review before a
	// -git package is rebuilt.
	RuleVCSNewCommits = "vcs-delta-new-commits"

	// RuleVCSAnchorAbsent is the recorded commit not being in this history.
	RuleVCSAnchorAbsent = "vcs-delta-anchor-absent"

	// RuleVCSRemoteChanged is the clone's origin URL differing from the one
	// recorded at approval time -- a change the recipe digest cannot see,
	// because the recipe is not what was edited.
	RuleVCSRemoteChanged = "vcs-delta-remote-changed"

	// RuleVCSNoAnchor is a VCS package with no recorded position to measure
	// from (INV-10: no evidence, so no verdict).
	RuleVCSNoAnchor = "vcs-delta-no-anchor"

	// RuleVCSBadAnchor is a recorded position that is not a commit hash.
	RuleVCSBadAnchor = "vcs-delta-anchor-malformed"

	// RuleVCSTruncated is a walk that hit its bound before reaching the anchor.
	RuleVCSTruncated = "vcs-delta-truncated"

	// RuleVCSIncomplete is a history that could not be followed to the end --
	// a missing object, the normal shape of a shallow clone.
	RuleVCSIncomplete = "vcs-delta-history-incomplete"

	// RuleVCSUnreadable is a clone this tool could not read at all.
	RuleVCSUnreadable = "vcs-delta-unreadable"

	// RuleVCSNoRemote is a clone whose origin URL could not be determined, so
	// the recorded remote cannot be compared.
	RuleVCSNoRemote = "vcs-delta-no-remote"
)

// SubjectVCS is the subject kind for delta gaps and findings. The subject
// itself is the pkgbase: the operator acts on packages, not on directories.
const SubjectVCS = "vcs-source"

// DefaultMaxCommits bounds a rendered range. It is a review budget, not a
// safety bound (internal/vcs has its own): nobody reviews 10,000 commits, and
// a range longer than this is itself the thing to report.
const DefaultMaxCommits = 200

// Anchor is the upstream position a review decision was taken at: the commit
// that was built and reviewed, and the remote it came from.
//
// It is recorded by the snapshot (spec §7, "the upstream commit actually
// built") and carried on an Approval so a later run can still measure a range
// after the cache -- 88 GB of it -- has been cleaned.
type Anchor struct {
	// Commit is the upstream commit reviewed, as a 40-character hex sha.
	Commit string `json:"commit"`

	// Remote is the origin URL recorded at that time. Empty means it was not
	// recorded, which is an absence of evidence and not a match.
	Remote string `json:"remote,omitempty"`
}

// DeltaStatus is the outcome of a delta review. Six values, none of which may
// be collapsed into another without losing the distinction the operator acts
// on.
type DeltaStatus string

const (
	// DeltaUpToDate: the anchor is HEAD. The only status with nothing to
	// review, and the only one that may be rendered as such.
	DeltaUpToDate DeltaStatus = "up-to-date"

	// DeltaAhead: the anchor is in this history and there are commits since.
	DeltaAhead DeltaStatus = "new-commits"

	// DeltaAnchorAbsent: the history was exhausted without finding the anchor.
	DeltaAnchorAbsent DeltaStatus = "anchor-absent"

	// DeltaUndetermined: the walk stopped at a bound, or the history could not
	// be followed. Neither up to date nor proven diverged.
	DeltaUndetermined DeltaStatus = "undetermined"

	// DeltaUnanchored: no recorded position, so no range can be computed.
	DeltaUnanchored DeltaStatus = "no-anchor"

	// DeltaUnreadable: the clone could not be read.
	DeltaUnreadable DeltaStatus = "unreadable"
)

// Request parameterises one delta review. Pure input: no ambient paths, no
// environment (INV-4).
type Request struct {
	// PkgBase is the subject the result is attributed to.
	PkgBase string

	// Dir is the clone to read. It is attacker-controlled and is never
	// executed against.
	Dir string

	// Anchor is the recorded position. A zero Anchor is the unanchored case.
	Anchor Anchor

	// Max bounds the rendered range. Zero means DefaultMaxCommits.
	Max int

	// Limits tightens internal/vcs's bounds. Zero means its defaults.
	Limits vcs.Limits
}

// Delta is the reviewed range.
type Delta struct {
	PkgBase string
	Dir     string
	Status  DeltaStatus

	// Anchor is the position the range was measured from, echoed so output
	// can name it even when it was not found.
	Anchor Anchor

	// Head is the clone's current commit, when it could be read.
	Head string

	// Remote is the clone's current origin URL, when it could be read.
	Remote string

	// RemoteChanged reports that Remote differs from Anchor.Remote. It is only
	// ever true when both are known.
	RemoteChanged bool

	// Commits is the range, newest first. NOTE the ordering limit internal/vcs
	// documents: this is committer-date order, not git's topological order, so
	// where a history contains merges the sequence can differ from `git log`
	// even though the set is the same. Render it as "the commits in this
	// range", never as "the order they were applied".
	Commits []vcs.Commit

	// Reached is vcs.LogSince's second return, kept verbatim so a caller can
	// re-derive the distinction rather than trust this package's summary.
	Reached bool

	// Truncated reports that the walk stopped at Max.
	Truncated bool

	// Gaps is everything that could not be determined (INV-9).
	Gaps []finding.Gap
}

// ReviewDelta reads the clone and reports the range since the anchor.
//
// It never returns an error: every failure is a status plus a gap, because a
// clone this tool could not read says nothing about whether the package is
// safe, and an error return invites a caller to log it and continue as though
// the check had passed.
func ReviewDelta(req Request) Delta {
	d := Delta{PkgBase: req.PkgBase, Dir: req.Dir, Anchor: req.Anchor}

	max := req.Max
	if max <= 0 {
		max = DefaultMaxCommits
	}

	r, err := vcs.Open(req.Dir, req.Limits)
	if err != nil {
		d.Status = DeltaUnreadable
		d.gap(RuleVCSUnreadable, fmt.Sprintf("cannot read the clone at %s: %v", req.Dir, err))
		return d
	}
	defer r.Close()

	if head, err := r.Head(); err == nil {
		d.Head = head
	} else {
		d.Status = DeltaUnreadable
		d.gap(RuleVCSUnreadable, fmt.Sprintf("cannot resolve HEAD in %s: %v", req.Dir, err))
		d.Gaps = append(d.Gaps, r.Gaps()...)
		return d
	}

	switch remote, err := r.Remote(); {
	case err == nil:
		d.Remote = remote
		d.RemoteChanged = req.Anchor.Remote != "" && remote != req.Anchor.Remote
	case req.Anchor.Remote != "":
		// A recorded remote that cannot be compared is a gap, not a match.
		d.gap(RuleVCSNoRemote, fmt.Sprintf("origin URL unreadable (%v), so the recorded remote %q could not be compared", err, req.Anchor.Remote))
	}

	switch {
	case req.Anchor.Commit == "":
		d.Status = DeltaUnanchored
		d.gap(RuleVCSNoAnchor, "no recorded upstream commit for this package, so the commits built since the last review cannot be listed; capture a snapshot to anchor future reviews")
		d.Gaps = append(d.Gaps, r.Gaps()...)
		return d
	case !isCommitHash(req.Anchor.Commit):
		d.Status = DeltaUnreadable
		d.gap(RuleVCSBadAnchor, fmt.Sprintf("recorded position %q is not a 40-character commit hash, so no range can be measured from it", safeQuote(req.Anchor.Commit)))
		d.Gaps = append(d.Gaps, r.Gaps()...)
		return d
	}

	commits, reached, err := r.LogSince("", req.Anchor.Commit, max)
	d.Commits = commits
	d.Reached = reached
	d.Gaps = append(d.Gaps, r.Gaps()...)

	switch {
	case errors.Is(err, vcs.ErrIncomplete):
		// The commits that WERE read are kept: refusing the facts in hand
		// because the history could not be followed further is the wrong trade.
		d.Status = DeltaUndetermined
		d.gap(RuleVCSIncomplete, fmt.Sprintf("history could not be followed to the recorded commit (%v); %d commit(s) were read and the range may be incomplete", err, len(commits)))
		return d
	case err != nil:
		d.Status = DeltaUnreadable
		d.gap(RuleVCSUnreadable, fmt.Sprintf("cannot read the history of %s: %v", req.Dir, err))
		return d
	}

	// The bound is reported whether or not the anchor was reached. Measured
	// live (yay, Max=20): a walk can reach its anchor AND fill its bound,
	// because the traversal is date-ordered over a merged history, so the
	// rendered list is a floor on what changed rather than the whole of it.
	d.Truncated = len(commits) >= max

	switch {
	case reached && len(commits) == 0:
		d.Status = DeltaUpToDate
	case reached:
		d.Status = DeltaAhead
		if d.Truncated {
			d.gap(RuleVCSTruncated, fmt.Sprintf("the range was rendered up to the %d-commit review bound; the recorded commit was reached, but commits beyond the bound are not listed", max))
		}
	case d.Truncated:
		// The bound stopped the walk, not the history. This proves nothing
		// about the anchor and must not be reported as if it did.
		d.Status = DeltaUndetermined
		d.gap(RuleVCSTruncated, fmt.Sprintf("stopped after %d commits without reaching the recorded commit %s; the range is longer than the review bound and the anchor is neither confirmed present nor shown absent", max, short(req.Anchor.Commit)))
	default:
		d.Status = DeltaAnchorAbsent
	}
	if req.Anchor.Commit == d.Head {
		// LogSince already answers this, but stating it here keeps the
		// invariant local: an anchor that IS head is up to date, whatever the
		// walk did.
		d.Status = DeltaUpToDate
		d.Reached = true
	}
	return d
}

func (d *Delta) gap(rule, reason string) {
	subject := d.PkgBase
	if subject == "" {
		subject = d.Dir
	}
	d.Gaps = append(d.Gaps, finding.Gap{RuleID: rule, Subject: subject, Reason: reason})
}

// Result renders the delta as findings plus gaps.
//
// New commits are SevInfo: an upstream that moved is not evidence of anything
// by itself, and inflating it to suspicious is how a tool trains its user to
// ignore it (INV-8). A vanished anchor and a changed remote are suspicious,
// because both mean the thing that was reviewed is not the thing that is there.
func (d Delta) Result() finding.Result {
	res := finding.Result{Gaps: d.Gaps}

	switch d.Status {
	case DeltaAhead:
		res.Findings = append(res.Findings, finding.Finding{
			RuleID:      RuleVCSNewCommits,
			SubjectKind: SubjectVCS,
			Subject:     d.PkgBase,
			Severity:    finding.SevInfo,
			Summary: fmt.Sprintf("%d new upstream commit(s) since the reviewed position %s; the recipe is unchanged, the source is not",
				len(d.Commits), short(d.Anchor.Commit)),
			Evidence: d.commitLines(),
			Limits: "lists the commits in the range, not their effect: the tool has not read the diffs, and the order shown is committer date, not git's topological order. " +
				"A recipe approval does not cover these commits.",
		})
	case DeltaAnchorAbsent:
		res.Findings = append(res.Findings, finding.Finding{
			RuleID:      RuleVCSAnchorAbsent,
			SubjectKind: SubjectVCS,
			Subject:     d.PkgBase,
			Severity:    finding.SevSuspicious,
			Summary: fmt.Sprintf("the reviewed commit %s is not in this repository's history; what was approved is not what is here",
				short(d.Anchor.Commit)),
			Evidence: append([]string{
				"recorded commit: " + d.Anchor.Commit,
				"current HEAD:    " + d.Head,
			}, d.commitLines()...),
			Limits: "cannot distinguish an upstream force-push from a different upstream, a re-clone, or a history this tool could not read in full; " +
				"it establishes only that the commit recorded at review time was not found.",
		})
	}

	if d.RemoteChanged {
		res.Findings = append(res.Findings, finding.Finding{
			RuleID:      RuleVCSRemoteChanged,
			SubjectKind: SubjectVCS,
			Subject:     d.PkgBase,
			Severity:    finding.SevSuspicious,
			Summary:     "the clone's origin URL differs from the one recorded at review time",
			Evidence: []string{
				"recorded: " + d.Anchor.Remote,
				"current:  " + d.Remote,
			},
			Limits: "reports the URL the repository configuration states, verbatim and unresolved; it does not establish that the two URLs serve different code, " +
				"only that the recipe digest cannot see this change.",
		})
	}
	return res
}

// Lines renders the delta for terminal review: the status first, then the
// range. Each status has its own sentence, because the whole point of this file
// is that they are different facts.
func (d Delta) Lines() []string {
	head := short(d.Head)
	anchor := short(d.Anchor.Commit)

	var out []string
	switch d.Status {
	case DeltaUpToDate:
		if d.RemoteChanged {
			out = append(out, fmt.Sprintf("%s: no new upstream commits since %s, but the origin URL changed", d.PkgBase, anchor))
		} else {
			out = append(out, fmt.Sprintf("%s: up to date with the reviewed commit %s", d.PkgBase, anchor))
		}
	case DeltaAhead:
		out = append(out, fmt.Sprintf("%s: %d new upstream commit(s) since the reviewed commit %s (now %s)",
			d.PkgBase, len(d.Commits), anchor, head))
	case DeltaAnchorAbsent:
		out = append(out, fmt.Sprintf("%s: the reviewed commit %s IS NOT IN THIS HISTORY (force-push, a different upstream, or a clone this tool could not read in full); HEAD is %s",
			d.PkgBase, anchor, head))
	case DeltaUndetermined:
		out = append(out, fmt.Sprintf("%s: could not determine the range since %s -- the walk stopped before reaching it; HEAD is %s",
			d.PkgBase, anchor, head))
	case DeltaUnanchored:
		out = append(out, fmt.Sprintf("%s: no reviewed commit was ever recorded, so the upstream delta is unknown; HEAD is %s", d.PkgBase, head))
	case DeltaUnreadable:
		out = append(out, fmt.Sprintf("%s: the clone could not be read, so the upstream delta is unknown", d.PkgBase))
	}

	if d.RemoteChanged {
		out = append(out, fmt.Sprintf("  remote changed: %s -> %s", d.Anchor.Remote, d.Remote))
	}
	out = append(out, indent(d.commitLines())...)
	if d.Truncated {
		out = append(out, fmt.Sprintf("  ... bounded at %d commits; the range is longer", len(d.Commits)))
	}
	for _, g := range d.Gaps {
		out = append(out, fmt.Sprintf("  gap [%s]: %s", g.RuleID, g.Reason))
	}
	return out
}

func indent(lines []string) []string {
	out := make([]string, 0, len(lines))
	for _, l := range lines {
		out = append(out, "  "+l)
	}
	return out
}

// commitLines renders one line per commit: hash, date, author, subject. The
// subject is what a reviewer scans, and it is attacker-controlled text, so it
// is bounded and stripped of anything that could rewrite the terminal.
func (d Delta) commitLines() []string {
	out := make([]string, 0, len(d.Commits))
	for _, c := range d.Commits {
		out = append(out, fmt.Sprintf("%s %s %s  %s",
			short(c.Hash),
			c.Author.When.Format("2006-01-02"),
			sanitise(c.Author.Email, 40),
			sanitise(c.Subject, 72)))
	}
	return out
}

// sanitise bounds untrusted text and removes control bytes. A commit subject
// carrying an ANSI escape could otherwise redraw a review prompt.
func sanitise(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}

func short(sha string) string {
	if len(sha) >= 12 {
		return sha[:12]
	}
	if sha == "" {
		return "(none)"
	}
	return sha
}

func isCommitHash(s string) bool {
	if len(s) != 40 {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= '0' && c <= '9', c >= 'a' && c <= 'f', c >= 'A' && c <= 'F':
		default:
			return false
		}
	}
	return true
}

// --- which sources are VCS sources -----------------------------------------

// vcsProtocols are the VCS types makepkg understands. Only git is readable by
// this project: internal/vcs parses git objects, and there is no equivalent
// reader for the other four (D-1 scoped the read narrowly on purpose).
var vcsProtocols = []string{"git", "hg", "svn", "bzr", "fossil"}

// VCSKind reports the VCS type a source entry names, and whether this tool can
// read that type's history.
//
// It follows makepkg's own rule and nothing else: a source is a VCS checkout
// when it carries a proto+ prefix (git+https://…) or a bare VCS scheme
// (git://…), after any rename:: prefix is removed. A .git SUFFIX is not a VCS
// marker -- https://host/y.git is a plain fetch of a file called y.git, and
// makepkg treats it as one.
//
// Getting this wrong is consequential in both directions: over-matching points
// the delta review at a tarball, and under-matching leaves a -git package
// reviewed once and never again, which is the hole this file exists to close.
// An unreadable kind (hg, svn, bzr, fossil) is reported rather than ignored, so
// the caller raises a coverage gap instead of silently reviewing nothing.
func VCSKind(entry string) (kind string, readable bool) {
	s := entry
	if i := strings.Index(s, "::"); i >= 0 {
		s = s[i+2:]
	}
	lower := strings.ToLower(s)
	for _, p := range vcsProtocols {
		if strings.HasPrefix(lower, p+"+") {
			return p, p == "git"
		}
		if strings.HasPrefix(lower, p+"://") {
			return p, p == "git"
		}
	}
	return "", false
}
