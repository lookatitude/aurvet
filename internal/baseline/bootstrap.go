// internal/baseline/bootstrap.go
//
// Bootstrap refusal (P4 task 7): the decision about whether `baseline init` is
// allowed to sign anything at all.
//
// # Why this is a separate, pure function
//
// Every condition below is a reason NOT to write, and each one has to be
// checkable and testable on its own. Bootstrap therefore takes measured facts and
// returns a decision; it opens nothing, signs nothing and reads no clock (INV-4).
// The caller performs the scan, applies the adjudications, resolves the state
// directory and then asks.
//
// # The four refusals, and why each exists
//
//  1. UNRESOLVED CRITICALS. Signing a baseline that already contains a compromise
//     makes the compromise the reference point: every later run compares against
//     it and reports "no change". This is the single worst outcome the whole tool
//     can produce, and it is the reason this refusal exists. Each critical must be
//     adjudicated, with a recorded reason, before init proceeds.
//
//  2. UNPRIVILEGED. An unprivileged scan cannot read everything, so it records
//     gaps as though they were facts about the system. A baseline built from that
//     view commits to an absence caused by permissions.
//
//  3. TRIAGE TIER. A triage scan does not verify file contents, so a baseline
//     built on it commits to metadata that was never checked. Signing a shallow
//     scan blesses whatever it failed to look at.
//
//  4. COVERAGE THAT MATTERS. A baseline is the one artefact that must not be built
//     from a partial view, and INV-3 puts exit 3 above exit 1. Gaps are therefore
//     BLOCKING BY DEFAULT: only a gap rule explicitly declared recordable here --
//     with the reason it is honestly recordable -- may travel into the signed
//     document instead of stopping the write. An unknown gap rule blocks, because
//     failing open on a gap nobody has thought about is how a baseline comes to
//     cover something it never examined.
//
// Two more refusals exist for the same reason and are not "extra": db.lck (task
// 12 -- a database mid-transaction produces spurious findings, and here they would
// be SIGNED) and an unwritable state directory (a baseline that cannot be
// persisted must not be signed).
//
// # Every refusal is reported, not just the first
//
// An operator on a real machine hits several at once. Fixing them one run at a
// time takes four attempts and teaches nothing, so Bootstrap collects them all and
// Err aggregates them with the remedy for each.
package baseline

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"
)

// ErrBootstrap wraps every bootstrap refusal, so a caller can branch on the class
// while still printing the specific remedies.
var ErrBootstrap = errors.New("baseline: refusing to write a baseline")

// The tiers a baseline may be built from. They mirror internal/check's tier names;
// the strings are compared rather than the type imported, so that this package
// keeps its one-way dependency and an unknown name FAILS CLOSED rather than
// resolving to some default.
const (
	TierFull     = "full"
	TierParanoid = "paranoid"
)

// RefusalCode names one reason. It is in the message and in the aggregated error
// so that a wrapper can grep for a specific refusal without parsing prose.
type RefusalCode string

const (
	RefusalCriticals       RefusalCode = "unresolved-criticals"
	RefusalUndeclaredEpoch RefusalCode = "critical-cannot-be-adjudicated"
	RefusalUnprivileged    RefusalCode = "unprivileged"
	RefusalTier            RefusalCode = "insufficient-tier"
	RefusalCoverage        RefusalCode = "coverage-incomplete"
	RefusalDBLock          RefusalCode = "pacman-transaction-in-flight"
	RefusalStateDir        RefusalCode = "state-directory-unwritable"
	RefusalInput           RefusalCode = "input-incomplete"
)

// Refusal is one reason not to write, with what to do about it.
type Refusal struct {
	Code    RefusalCode
	Message string
}

// Critical is one unresolved critical finding, projected to plain data.
//
// It is not finding.Finding: this package must stay free of the higher layers it
// would otherwise pull in, and a projection makes explicit which fields the
// decision actually depends on.
type Critical struct {
	RuleID      string
	SubjectKind string
	Subject     string
	Fingerprint string
	Summary     string
}

// AdjudicatedCritical is a critical the operator has decided about. The reason is
// mandatory: an adjudication with no reason cannot be re-evaluated by anyone,
// including its author, and must not unblock a signature.
type AdjudicatedCritical struct {
	Critical

	Reason           string
	Scope            string
	ExpiresAt        string
	FingerprintEpoch int
}

// BootstrapInput is the measured state the decision is made from.
type BootstrapInput struct {
	// Euid is the effective uid of the running process.
	Euid int

	// Tier is the verification tier the scan actually ran at.
	Tier string

	Host string
	Root string

	// StateDir is where the baseline would be written; StateDirWritable is the
	// caller's verdict on whether it can be. The caller owns that check because it
	// is the only layer that knows how the path was resolved -- in particular
	// config.SourceFallbackUnwritable, which resolves to a root-owned directory for
	// an unprivileged run.
	StateDir         string
	StateDirWritable bool

	// Criticals are the criticals that SURVIVED adjudication.
	Criticals []Critical

	// Adjudicated are the criticals an adjudication covered, carried so their
	// reasons travel into the signed manifest.
	Adjudicated []AdjudicatedCritical

	// UndeclaredRules are rule ids with no fingerprint epoch declared, from
	// adjudicate.Registry.Undeclared. A critical from such a rule cannot be
	// adjudicated at all, so demanding that it be adjudicated would deadlock.
	UndeclaredRules []string

	// Gaps are every coverage gap the scan produced.
	Gaps []Gap

	DBLocked   bool
	DBLockPath string

	// Now is the decision time (INV-4).
	Now time.Time
}

// BootstrapDecision is the answer.
type BootstrapDecision struct {
	Allowed bool

	Refusals []Refusal

	// Adjudications are the adjudication records to carry into the manifest, in
	// canonical form. Populated only when Allowed.
	Adjudications []AdjudicationInput

	// RecordedGaps are the gaps that may travel into the signed document because
	// each is declared recordable. Populated only when Allowed.
	RecordedGaps []Gap

	// Notes are what this bootstrap does NOT establish (INV-6). Never empty on the
	// allowed path: a baseline that says nothing about its own limits invites being
	// read as a proof of cleanliness.
	Notes []string
}

// Err aggregates the refusals into one error, or returns nil.
func (d BootstrapDecision) Err() error {
	if d.Allowed || len(d.Refusals) == 0 {
		return nil
	}
	var b strings.Builder
	fmt.Fprintf(&b, "%d reason(s):", len(d.Refusals))
	for _, r := range d.Refusals {
		fmt.Fprintf(&b, "\n  [%s] %s", r.Code, r.Message)
	}
	return fmt.Errorf("%w: %s", ErrBootstrap, b.String())
}

// recordableGaps are the gap rules a baseline may honestly carry, each with the
// reason it is recordable rather than blocking.
//
// The table is an allowlist, and that direction is the whole design: an
// unrecognised gap BLOCKS. The alternative -- a blocklist -- means every gap rule
// added anywhere in the tree is silently recordable in a signed baseline until
// someone remembers to classify it, which is exactly the failure INV-3 describes.
//
// The test for whether a gap belongs here is: does the SIGNED DOCUMENT still say
// what it does not cover? A missing provenance snapshot is recordable, because the
// manifest records that absence per package and a later run can see it. An
// unreadable package database is not, because the manifest would then simply be
// missing packages, with nothing in it to say so.
var recordableGaps = map[string]string{
	"aur-provenance": "the manifest records provenance per pkgbase, so a package with none is " +
		"visibly absent from the provenance list rather than silently assumed captured",
	"aur-absent": "an AUR package that no longer exists upstream is a fact about the host, " +
		"recorded as a finding in its own right",
	"aur-orphaned": "maintainer state is a fact about upstream, not a limit on what was examined here",
	// Measured on the reference machine: 3 of its foreign packages carry no
	// submitter in the AUR's own record, so this gap is present on every run and
	// blocking on it would make a baseline unreachable for a reason no local fix can
	// address. It is recordable because the identity comparison is not something a
	// baseline commits to at all -- the manifest records the provenance snapshot
	// digest, and a missing submitter is upstream data that does not exist, not
	// something this host failed to examine.
	"aur-submitter-mismatch": "the maintainer/submitter comparison is not part of what a baseline " +
		"records; an absent submitter is missing upstream data, not unexamined local state",
	"baseline.mtree-unread": "the manifest carries the stated reason per package, so the gap is " +
		"inside the signed bytes and a later run compares against a documented absence",
	"baseline.log-window-unknown": "the manifest records that no log window was established, which " +
		"is what makes later truncation undetectable-and-known rather than undetectable-and-unseen",
	"baseline.log-bounded": "the manifest records that log reading stopped at a limit",
	"pacmanlog-other-root": "transactions naming another root describe a different filesystem; the " +
		"manifest's root field says which one this baseline is about",
	"pacmanlog-rotated-sibling": "an unreadable rotated sibling shortens log coverage, which the " +
		"manifest's log window states",
	"pacmanlog-window-not-covered": "log coverage shorter than the baseline window is the case task " +
		"11's fourth bucket exists for: recorded, and rated as coverage rather than as evidence",
	"pacmanlog-unparsed-line": "an unparseable line is counted and reported; the log window it " +
		"belongs to is still recorded",
	"pacmanlog-truncated": "truncation is a finding in its own right and is recorded as such",
	"chain-no-anchor": "the first entry cannot have been pushed before it is written, so demanding " +
		"an anchor at init would make init impossible",
}

// Bootstrap decides whether `baseline init` may write.
func Bootstrap(in BootstrapInput) BootstrapDecision {
	var d BootstrapDecision

	// Input completeness first: a decision made from a half-filled input is not a
	// decision, and every field below is one the signed document needs.
	var missing []string
	if strings.TrimSpace(in.Host) == "" {
		missing = append(missing, "host")
	}
	if strings.TrimSpace(in.Root) == "" {
		missing = append(missing, "root")
	}
	if in.Now.IsZero() {
		missing = append(missing, "now")
	}
	if len(missing) > 0 {
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalInput,
			Message: fmt.Sprintf("the bootstrap input is missing %s; a manifest cannot be assembled "+
				"without it, and guessing would put an invented value inside the signed bytes",
				strings.Join(missing, ", ")),
		})
	}

	// 1. Unresolved criticals, and the two ways an adjudication fails to resolve one.
	if len(in.Criticals) > 0 {
		var lines []string
		for _, c := range in.Criticals {
			lines = append(lines, fmt.Sprintf("    %s %s:%s (%s) %s",
				c.RuleID, c.SubjectKind, c.Subject, c.Fingerprint, c.Summary))
		}
		sort.Strings(lines)
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalCriticals,
			Message: fmt.Sprintf("%d unresolved critical finding(s). Signing a baseline over a "+
				"critical makes it the reference point: every later run compares against it and "+
				"reports 'no change', which is the worst outcome this tool can produce. Adjudicate "+
				"each one with a recorded reason (`aurvet adjudicate <fingerprint> --reason ...`) or "+
				"fix it, then run init again:\n%s",
				len(in.Criticals), strings.Join(lines, "\n")),
		})
	}
	var reasonless []string
	for _, a := range in.Adjudicated {
		if strings.TrimSpace(a.Reason) == "" {
			reasonless = append(reasonless, fmt.Sprintf("%s %s (%s)", a.RuleID, a.Subject, a.Fingerprint))
		}
	}
	if len(reasonless) > 0 {
		sort.Strings(reasonless)
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalCriticals,
			Message: "an adjudication with no recorded reason is indistinguishable from an " +
				"attacker's, so it does not resolve anything: " + strings.Join(reasonless, ", ") +
				". Re-record each with a reason a different person could re-evaluate",
		})
	}
	if undeclared := undeclaredCriticalRules(in); len(undeclared) > 0 {
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalUndeclaredEpoch,
			Message: fmt.Sprintf("critical finding(s) from rule(s) that declare no fingerprint "+
				"epoch: %s. Such a finding cannot be adjudicated at all, so init would demand an "+
				"adjudication and then refuse to make one. Declare the rule in "+
				"internal/adjudicate/epoch.go (and add its entry to "+
				"testdata/adjudicate/epochs.golden.json) before bootstrapping",
				strings.Join(undeclared, ", ")),
		})
	}

	// 2. Privilege.
	if in.Euid != 0 {
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalUnprivileged,
			Message: fmt.Sprintf("running as euid %d. An unprivileged scan cannot read everything, "+
				"so it records a gap wherever permission was refused -- and a baseline built from "+
				"that view commits to an absence caused by permissions rather than to the system. "+
				"Re-run as root (`sudo aurvet baseline init`); privileges are dropped to "+
				"CAP_DAC_READ_SEARCH for the scan itself", in.Euid),
		})
	}

	// 3. Tier.
	switch in.Tier {
	case TierFull, TierParanoid:
	default:
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalTier,
			Message: fmt.Sprintf("the scan ran at tier %q. A baseline must stand on a scan that "+
				"verified file contents; signing a shallower one blesses whatever it did not look "+
				"at. Re-run with --tier %s (or %s)", in.Tier, TierFull, TierParanoid),
		})
	}

	// 4. Coverage.
	blocking, recordable := splitGaps(in.Gaps)
	if len(blocking) > 0 {
		var lines []string
		for _, g := range blocking {
			lines = append(lines, fmt.Sprintf("    %s %s: %s", g.RuleID, g.Subject, g.Reason))
		}
		sort.Strings(lines)
		if len(lines) > 20 {
			extra := len(lines) - 20
			lines = append(lines[:20], fmt.Sprintf("    ... and %d more", extra))
		}
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalCoverage,
			Message: fmt.Sprintf("%d coverage gap(s) that a signed baseline cannot honestly carry. "+
				"A baseline is the one artefact that must not be built from a partial view, so a gap "+
				"is blocking unless it is declared recordable in internal/baseline/bootstrap.go's "+
				"recordableGaps table -- an unrecognised gap rule blocks by design. Fix the cause, or "+
				"declare the rule recordable deliberately and say why:\n%s",
				len(blocking), strings.Join(lines, "\n")),
		})
	}

	// db.lck.
	if in.DBLocked {
		path := in.DBLockPath
		if path == "" {
			path = "db.lck"
		}
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalDBLock,
			Message: fmt.Sprintf("%s exists, so a pacman transaction is in flight. A scan taken "+
				"during one can see a package half-installed, and here those spurious findings would "+
				"be SIGNED into the trust chain permanently. Wait for the transaction to finish and "+
				"run init again", path),
		})
	}

	// The state directory.
	if !in.StateDirWritable {
		d.Refusals = append(d.Refusals, Refusal{
			Code: RefusalStateDir,
			Message: fmt.Sprintf("the state directory %s is not writable by this run, so the "+
				"baseline could be signed and then not stored. Nothing is signed until there is "+
				"somewhere to put it", displayPath(in.StateDir)),
		})
	}

	if len(d.Refusals) > 0 {
		return d
	}

	d.Allowed = true
	d.RecordedGaps = recordable
	for _, a := range in.Adjudicated {
		d.Adjudications = append(d.Adjudications, AdjudicationInput{
			Fingerprint:      a.Fingerprint,
			Scope:            a.Scope,
			Reason:           a.Reason,
			ExpiresAt:        a.ExpiresAt,
			FingerprintEpoch: a.FingerprintEpoch,
		})
	}
	sort.Slice(d.Adjudications, func(i, j int) bool {
		return d.Adjudications[i].Fingerprint < d.Adjudications[j].Fingerprint
	})

	d.Notes = append(d.Notes,
		"this baseline is a record of what the system looked like, not a proof that it was clean: a "+
			"host already compromised now has the attacker's state as its reference point, and every "+
			"later run will report it as unchanged",
		fmt.Sprintf("%d coverage gap(s) are recorded inside the signed document; each is a limit on "+
			"what this baseline covers", len(recordable)),
	)
	if len(d.Adjudications) > 0 {
		d.Notes = append(d.Notes, fmt.Sprintf("%d critical finding(s) were adjudicated rather than "+
			"fixed, and their reasons are inside the signed document", len(d.Adjudications)))
	}
	return d
}

// undeclaredCriticalRules is the intersection of the criticals' rules with the
// rules that declare no epoch. Only criticals matter here: a rule with no epoch
// that produces nothing critical cannot block a bootstrap.
func undeclaredCriticalRules(in BootstrapInput) []string {
	if len(in.UndeclaredRules) == 0 || len(in.Criticals) == 0 {
		return nil
	}
	undeclared := make(map[string]bool, len(in.UndeclaredRules))
	for _, r := range in.UndeclaredRules {
		undeclared[r] = true
	}
	seen := map[string]bool{}
	var out []string
	for _, c := range in.Criticals {
		if undeclared[c.RuleID] && !seen[c.RuleID] {
			seen[c.RuleID] = true
			out = append(out, c.RuleID)
		}
	}
	sort.Strings(out)
	return out
}

// splitGaps partitions gaps into blocking and recordable. Unknown rules are
// blocking: see recordableGaps.
func splitGaps(gaps []Gap) (blocking, recordable []Gap) {
	for _, g := range gaps {
		if _, ok := recordableGaps[g.RuleID]; ok {
			recordable = append(recordable, g)
			continue
		}
		blocking = append(blocking, g)
	}
	return blocking, recordable
}

// RecordableGapRules lists, sorted, the gap rules a baseline may carry. Exported
// so a caller can render the table rather than restating it.
func RecordableGapRules() []string {
	out := make([]string, 0, len(recordableGaps))
	for k := range recordableGaps {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// RecordableGapReason is why a rule is recordable, "" when it is not.
func RecordableGapReason(ruleID string) string { return recordableGaps[ruleID] }

func displayPath(p string) string {
	if strings.TrimSpace(p) == "" {
		return "(unresolved)"
	}
	return p
}
