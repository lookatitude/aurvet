// internal/baseline/drift.go
//
// Drift classification (P4 task 11): what changed since the signed baseline, and
// which of four buckets each change belongs in.
//
//	corroborated       a pacman transaction inside the log's coverage explains it
//	adjudicated        an operator recorded a reason for it, and it has not expired
//	unexplained        nothing explains it -- CRITICAL, and the point of the tool
//	log-coverage gap   the log never covered the instant that would explain it --
//	                   REDUCED severity plus one coverage gap, never a critical
//
// # Why the fourth bucket exists, and what it is not
//
// Without it, a log that does not reach back far enough turns every change into an
// accusation, and a wall of criticals produced by ordinary log retention teaches
// an operator to ignore the tool -- which costs more than the detection was worth.
// So a change whose explanation could not have been in the log is bucketed as
// coverage, at reduced severity, with ONE gap for the whole shortfall rather than
// one per package.
//
// But "the log never went back that far" and "the log used to go back further" are
// different facts and must not collapse into one bucket:
//
//   - never went back that far -- the baseline's own SIGNED log window says the
//     log did not cover that instant. That is bucket four.
//   - used to go back further -- the log now begins later than the baseline
//     recorded. That is TRUNCATION: evidence, not a gap. The items it would have
//     explained stay UNEXPLAINED and cite the truncation, because the alternative
//     is that deleting the log is a way to downgrade every finding it would have
//     supported.
//
// The same reasoning bounds the whole bucket. Down-rating happens only on the
// authority of the signed baseline (or of an admitted absence of one), never on
// the authority of the log as it stands now -- otherwise every path into bucket
// four is a downgrade attack: truncate the log, or inflate it until the reader
// gives up (Bounded), and criticals become coverage gaps. Bounded therefore raises
// a gap and down-rates nothing.
//
// # Purity
//
// Everything here is a pure function of its input. `now` is a parameter (INV-4):
// adjudication expiry must not depend on the day the classifier ran, or two hosts
// auditing one chain disagree and nothing about expiry is testable.
package baseline

import (
	"errors"
	"fmt"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
)

// ErrDrift reports input that cannot be classified at all. Every case is a
// refusal to produce a verdict from something ambiguous.
var ErrDrift = errors.New("baseline: drift is not classifiable")

// DriftRule is the rule id every drift finding carries. One rule, subject =
// package name, so a suppression written for one package survives its upgrades
// and does not silence the others.
//
// NOTE (cross-phase): a finding can only be adjudicated through
// internal/adjudicate if its rule declares a fingerprint epoch there. This rule
// now does (epoch 1), which is what makes a drift critical adjudicable at all --
// without it the operator is told to adjudicate and then refused permission to.
// Changing what drift MATCHES ON must bump that epoch, not just this file:
// internal/adjudicate's golden history is the thing that fails, deliberately.
// DriftAdjudication below stays the seam for callers that hold adjudications as
// plain data, because baseline must not import adjudicate.
const DriftRule = "baseline-drift"

// DriftCoverageRule is the rule id of the single coverage gap raised for a log
// shortfall, and of the per-package gap raised for an unreadable mtree.
const (
	DriftCoverageRule = "baseline-drift-coverage"
	DriftMtreeRule    = "baseline-drift-mtree-unread"
)

// SubjectKindPackage is the subject kind drift findings use.
const SubjectKindPackage = "package"

// DriftLimitsText is what a drift verdict cannot tell you, whatever it says
// (INV-6). It is rendered with every finding this file produces.
const DriftLimitsText = "drift is measured against a baseline that was SIGNED, not verified: a host " +
	"already compromised when the baseline was made recorded the attacker's state as the reference, " +
	"and this comparison then reports it as unchanged. Corroboration by pacman.log means a " +
	"transaction with that shape was logged, not that it was legitimate -- root can write the log, " +
	"and a package's build ran arbitrary code before pacman recorded anything. An mtree digest " +
	"change localises to a package, never to a file: read that package's mtree to find out which. " +
	"A change bucketed as a log-coverage gap on the strength of an install date is down-rated on " +
	"%INSTALLDATE%, which root can rewrite -- that bucket is a statement about what the log could " +
	"have shown, not a judgement that the change was benign."

// -- buckets ------------------------------------------------------------------

// Bucket is one of the four classifications. A string rather than an integer so
// that it is legible in output and in a test failure without a lookup table.
type Bucket string

const (
	BucketCorroborated   Bucket = "corroborated"
	BucketAdjudicated    Bucket = "adjudicated"
	BucketUnexplained    Bucket = "unexplained"
	BucketLogCoverageGap Bucket = "log-coverage-gap"
)

// ChangeKind is what changed about a package.
type ChangeKind string

const (
	ChangeAdded   ChangeKind = "added"
	ChangeRemoved ChangeKind = "removed"
	ChangeVersion ChangeKind = "version"
	ChangeMtree   ChangeKind = "mtree"
)

// -- input --------------------------------------------------------------------

// ObservedPackage is one package as it is NOW. It mirrors PackageInput plus the
// install date, which is the instant used to decide whether the log could have
// covered this package at all.
type ObservedPackage struct {
	Name        string
	Version     string
	MtreeSHA256 string

	// MtreeUnread is the stated reason the digest is absent. An absent digest with
	// no reason is refused: it would otherwise read as agreement with the
	// baseline, which is the one comparison outcome that must never be inferred
	// from missing data.
	MtreeUnread string

	// InstallDate is %INSTALLDATE% when known. Zero means unknown, which is not
	// an error: the window is used instead.
	InstallDate time.Time
}

// LogTransaction is one pacman transaction, projected from internal/pacmanlog.
// It is redeclared here rather than imported so that internal/baseline keeps its
// one-way dependency on nothing but internal/finding, and so the shape of what
// drift consumes cannot change under it when pacmanlog grows a field.
type LogTransaction struct {
	Time    time.Time
	Op      string // installed, removed, upgraded, downgraded, reinstalled
	Pkg     string
	Version string
}

// LogObservation is what pacman.log covers NOW, and what it says happened.
type LogObservation struct {
	// Earliest and Latest bound what the log covers now. Zero Earliest means no
	// timestamped line was read at all.
	Earliest time.Time
	Latest   time.Time

	// Bounded records that reading stopped at a limit. It raises a gap and
	// down-rates nothing: see the file comment.
	Bounded bool

	Transactions []LogTransaction
}

// DriftAdjudication is one recorded decision about drift, as plain data.
//
// It is the caller's projection of an adjudicate.Record: internal/adjudicate
// imports this package, so this package cannot import it back. Reason is
// mandatory here as it is there -- a suppression with no reason is
// indistinguishable from an attacker's -- and an empty one suppresses nothing and
// raises a gap.
type DriftAdjudication struct {
	RuleID  string
	Subject string
	Scope   string // pin, subject, rule
	Reason  string

	// ExpiresAt is RFC3339 with an explicit offset. Empty means "no expiry
	// recorded", which is accepted here only because the caller's own store
	// refuses it; it is reported in the item's evidence either way.
	ExpiresAt string
}

// DriftInput is everything the classification needs.
type DriftInput struct {
	// Manifest is the verified baseline. It must have been authenticated by the
	// caller: nothing here checks a signature, and a manifest that was not
	// verified is an attacker's opinion about what the system used to look like.
	Manifest Manifest

	Observed      []ObservedPackage
	Log           LogObservation
	Adjudications []DriftAdjudication

	// Now is the instant expiry is judged against (INV-4).
	Now time.Time
}

// -- output -------------------------------------------------------------------

// DriftItem is one change and its classification.
type DriftItem struct {
	Kind    ChangeKind
	Package string
	Bucket  Bucket

	// From and To are the values that changed: versions for ChangeVersion, mtree
	// digests for ChangeMtree, and the version present on one side only for
	// ChangeAdded and ChangeRemoved.
	From string
	To   string

	// Version is the package version this item is about: the observed one, or the
	// baseline one for a removal. It is what a corroborating transaction for an
	// mtree change must have left in place.
	Version string

	Severity finding.Severity
	Detail   string
	Evidence []string
}

// DriftReport is the whole classification.
type DriftReport struct {
	Items  []DriftItem
	Counts map[Bucket]int

	// Result is the findings and gaps this classification contributes.
	Result finding.Result

	// Truncated reports that the log now begins later than the baseline recorded.
	// This is evidence in its own right, not a gap.
	Truncated bool

	// WindowCovered reports whether the log reaches back to the baseline instant.
	WindowCovered bool

	// Notes state what this classification did not determine.
	Notes []string
}

// -- classification -----------------------------------------------------------

// Drift compares the observed system against the signed baseline and classifies
// every difference into exactly one bucket.
//
// Precedence is corroborated, then adjudicated, then coverage, then unexplained.
// Corroboration outranks adjudication deliberately: a change the log explains
// needs no judgement, and consuming the operator's adjudication on it would leave
// them believing they had suppressed something they had not.
func Drift(in DriftInput) (DriftReport, error) {
	rep := DriftReport{Counts: map[Bucket]int{}}

	if in.Now.IsZero() {
		return rep, fmt.Errorf("%w: no `now` was supplied, so adjudication expiry would depend on "+
			"the day this ran", ErrDrift)
	}
	created, err := ParseStamp(in.Manifest.CreatedAt)
	if err != nil {
		return rep, fmt.Errorf("%w: the baseline's created_at is unusable, so there is no window to "+
			"compare against: %v", ErrDrift, err)
	}
	if in.Manifest.Schema != ManifestSchema {
		return rep, fmt.Errorf("%w: manifest schema %d, this build understands %d",
			ErrDrift, in.Manifest.Schema, ManifestSchema)
	}

	obs := make(map[string]ObservedPackage, len(in.Observed))
	for _, p := range in.Observed {
		if p.Name == "" {
			return rep, fmt.Errorf("%w: an observed package has no name", ErrDrift)
		}
		if _, dup := obs[p.Name]; dup {
			return rep, fmt.Errorf("%w: package %q was observed twice; two current states for one "+
				"package cannot both be compared", ErrDrift, p.Name)
		}
		if p.MtreeSHA256 == "" && p.MtreeUnread == "" {
			return rep, fmt.Errorf("%w: package %q has no mtree digest and no reason; an unread "+
				"mtree is a gap, never a blank that reads as agreement", ErrDrift, p.Name)
		}
		obs[p.Name] = p
	}

	// Truncation and window coverage, both judged against the baseline's own
	// signed record. See the file comment for why the authority matters.
	recorded, haveRecorded := time.Time{}, false
	if in.Manifest.Log.Earliest != "" {
		if t, err := ParseStamp(in.Manifest.Log.Earliest); err == nil {
			recorded, haveRecorded = t, true
		}
	}
	switch {
	case !haveRecorded:
		rep.Notes = append(rep.Notes, "the baseline recorded no pacman.log window, so whether the log "+
			"has since been truncated cannot be judged at all; changes the log does not cover are "+
			"treated as coverage gaps rather than findings")
	case in.Log.Earliest.IsZero():
		rep.Truncated = true
		rep.Notes = append(rep.Notes, "no timestamped log line was read, although the baseline recorded "+
			"a log window: the entire log is missing, which is truncation in the limit")
	case in.Log.Earliest.After(recorded):
		rep.Truncated = true
	}
	rep.WindowCovered = !in.Log.Earliest.IsZero() && !in.Log.Earliest.After(created)

	// Changes, in a deterministic order.
	var items []DriftItem
	for _, base := range in.Manifest.Packages {
		cur, present := obs[base.Name]
		if !present {
			items = append(items, DriftItem{
				Kind: ChangeRemoved, Package: base.Name, From: base.Version,
				Version: base.Version,
			})
			continue
		}
		if cur.MtreeUnread != "" {
			rep.Result.Gaps = append(rep.Result.Gaps, finding.Gap{
				RuleID:  DriftMtreeRule,
				Subject: "pkg:" + base.Name,
				Reason: cur.MtreeUnread + "; the baseline's digest for this package could not be " +
					"compared, so this package is unexamined rather than unchanged",
			})
			continue
		}
		if cur.Version != base.Version {
			items = append(items, DriftItem{
				Kind: ChangeVersion, Package: base.Name, From: base.Version, To: cur.Version,
				Version: cur.Version,
			})
			continue
		}
		if base.MtreeSHA256 != "" && cur.MtreeSHA256 != base.MtreeSHA256 {
			items = append(items, DriftItem{
				Kind: ChangeMtree, Package: base.Name,
				From: base.MtreeSHA256, To: cur.MtreeSHA256,
				Version: cur.Version,
			})
		}
	}
	baseNames := make(map[string]bool, len(in.Manifest.Packages))
	for _, p := range in.Manifest.Packages {
		baseNames[p.Name] = true
	}
	for _, p := range in.Observed {
		if baseNames[p.Name] {
			continue
		}
		if p.MtreeUnread != "" {
			rep.Result.Gaps = append(rep.Result.Gaps, finding.Gap{
				RuleID:  DriftMtreeRule,
				Subject: "pkg:" + p.Name,
				Reason: p.MtreeUnread + "; this package is not in the baseline and its mtree could " +
					"not be read either, so nothing about it was examined",
			})
			continue
		}
		items = append(items, DriftItem{Kind: ChangeAdded, Package: p.Name, To: p.Version,
			Version: p.Version})
	}
	sort.SliceStable(items, func(i, j int) bool {
		if items[i].Package != items[j].Package {
			return items[i].Package < items[j].Package
		}
		return items[i].Kind < items[j].Kind
	})

	adj, adjGaps := indexAdjudications(in.Adjudications, in.Now)
	rep.Result.Gaps = append(rep.Result.Gaps, adjGaps...)

	shortfall := 0
	for _, it := range items {
		classified := classify(it, in, obs, created, recorded, haveRecorded, rep.Truncated, adj)
		if classified.Bucket == BucketLogCoverageGap {
			shortfall++
		}
		rep.Counts[classified.Bucket]++
		rep.Items = append(rep.Items, classified)
		if f, ok := driftFinding(classified); ok {
			rep.Result.Findings = append(rep.Result.Findings, f)
		}
	}

	if shortfall > 0 {
		rep.Result.Gaps = append(rep.Result.Gaps, finding.Gap{
			RuleID:  DriftCoverageRule,
			Subject: "pacman-log",
			Reason: fmt.Sprintf("%d change(s) could not have been explained by pacman.log: its "+
				"coverage does not include the instant that would have, so their absence from the log "+
				"is a coverage gap and not evidence against them. Ordinary log retention produces "+
				"exactly this", shortfall),
		})
	}
	if in.Log.Bounded {
		rep.Result.Gaps = append(rep.Result.Gaps, finding.Gap{
			RuleID:  DriftCoverageRule,
			Subject: "pacman-log",
			Reason: "reading pacman.log stopped at a limit, so a transaction that would have " +
				"corroborated a change may exist in the part that was not read. Nothing was " +
				"down-rated on that basis: a log a caller cannot finish reading must not be a way " +
				"to turn findings into coverage gaps",
		})
	}
	if !in.Log.Latest.IsZero() && in.Log.Latest.Before(in.Now) {
		rep.Notes = append(rep.Notes, fmt.Sprintf("the log's last line is %s, %s before this run: "+
			"whether it covers the most recent changes was not judged",
			in.Log.Latest.Format(TimeLayoutOffset), in.Now.Sub(in.Log.Latest).Round(time.Minute)))
	}
	return rep, nil
}

// TimeLayoutOffset is the timestamp spelling used in drift notes: the same
// explicit-offset layout pacman.log writes, so a note and a log line can be
// compared by eye.
const TimeLayoutOffset = "2006-01-02T15:04:05-0700"

// classify decides one item's bucket. Compiled logic, in one function, so the
// precedence is readable in one place.
func classify(it DriftItem, in DriftInput, obs map[string]ObservedPackage,
	created, recorded time.Time, haveRecorded, truncated bool,
	adj map[string]DriftAdjudication) DriftItem {

	// 1. corroborated.
	if tx, ok := corroborate(it, in.Log.Transactions, created); ok {
		it.Bucket = BucketCorroborated
		it.Severity = finding.SevInfo
		it.Detail = fmt.Sprintf("a %s transaction at %s explains it", tx.Op,
			tx.Time.Format(TimeLayoutOffset))
		it.Evidence = append(it.Evidence, fmt.Sprintf("pacman.log: %s %s %s at %s",
			tx.Op, tx.Pkg, tx.Version, tx.Time.Format(TimeLayoutOffset)))
		return it
	}

	// 2. adjudicated.
	if rec, ok := adj[it.Package]; ok {
		it.Bucket = BucketAdjudicated
		it.Severity = finding.SevInfo
		it.Detail = fmt.Sprintf("adjudicated (%s scope): %s", rec.Scope, rec.Reason)
		it.Evidence = append(it.Evidence,
			"adjudicated reason: "+rec.Reason,
			"scope: "+rec.Scope+", expires: "+expiryText(rec.ExpiresAt))
		return it
	}

	// 3. the log never covered the instant that would have explained it. Only the
	// baseline's own signed window, or an admitted absence of one, may put an item
	// here -- never the state of the log as it is now (see the file comment).
	if reason, ok := coverageShortfall(it, in, obs, created, recorded, haveRecorded, truncated); ok {
		it.Bucket = BucketLogCoverageGap
		it.Severity = finding.SevInfo
		it.Detail = reason
		it.Evidence = append(it.Evidence, reason,
			"this is a coverage gap for this package, not evidence against it")
		return it
	}

	// 4. unexplained.
	it.Bucket = BucketUnexplained
	it.Severity = finding.SevCritical
	it.Detail = "no pacman transaction inside the log's coverage explains it, and no adjudication " +
		"covers it"
	it.Evidence = append(it.Evidence, fmt.Sprintf("baseline recorded %s, observed %s",
		valueOrNone(it.From), valueOrNone(it.To)))
	if truncated {
		it.Evidence = append(it.Evidence, "pacman.log has been TRUNCATED since the baseline was "+
			"signed: it now begins later than the baseline recorded, so a transaction that would "+
			"have explained this change may have been removed. That is evidence, not an excuse: a "+
			"log that can be deleted must not become a way to down-rate what it would have shown")
	}
	if !in.Log.Earliest.IsZero() {
		it.Evidence = append(it.Evidence, fmt.Sprintf("log coverage searched: %s .. %s (%d transaction(s))",
			in.Log.Earliest.Format(TimeLayoutOffset), in.Log.Latest.Format(TimeLayoutOffset),
			len(in.Log.Transactions)))
	}
	return it
}

// corroborate looks for a transaction that explains the change. The match is by
// shape, not by string equality on a summary: op, package, resulting version, and
// an instant at or after the baseline.
//
// A transaction BEFORE the baseline cannot explain a change made after it, and one
// leaving a different version does not corroborate at all -- the system is then
// not in the state the log says it was left in, which is itself the finding.
func corroborate(it DriftItem, txs []LogTransaction, created time.Time) (LogTransaction, bool) {
	var best LogTransaction
	found := false
	for _, tx := range txs {
		if tx.Pkg != it.Package || tx.Time.Before(created) {
			continue
		}
		if !opExplains(it.Kind, tx.Op) {
			continue
		}
		switch it.Kind {
		case ChangeAdded, ChangeVersion:
			// The resulting version must be the one that is actually installed.
			if tx.Version != "" && tx.Version != it.To {
				continue
			}
		case ChangeMtree:
			// The version did not change, so a transaction that explains it must
			// have left that same version in place.
			if tx.Version != "" && it.Version != "" && tx.Version != it.Version {
				continue
			}
		case ChangeRemoved:
			// Nothing further: a removal has no resulting version to check.
		}
		if !found || tx.Time.After(best.Time) {
			best, found = tx, true
		}
	}
	return best, found
}

func opExplains(kind ChangeKind, op string) bool {
	switch kind {
	case ChangeAdded:
		return op == "installed" || op == "reinstalled" || op == "upgraded"
	case ChangeRemoved:
		return op == "removed"
	case ChangeVersion:
		return op == "upgraded" || op == "downgraded" || op == "installed" || op == "reinstalled"
	case ChangeMtree:
		return op == "reinstalled" || op == "upgraded" || op == "downgraded" || op == "installed"
	}
	return false
}

// coverageShortfall reports whether the log could not have covered the instant
// that would explain this item.
func coverageShortfall(it DriftItem, in DriftInput, obs map[string]ObservedPackage,
	created, recorded time.Time, haveRecorded, truncated bool) (string, bool) {

	// Truncation is evidence, never an excuse: an item whose explanation may have
	// been deleted stays unexplained, INCLUDING one whose install date claims to
	// predate the signed window. That claim comes from %INSTALLDATE% in the local
	// database, which root can rewrite -- so on a host whose log has demonstrably
	// been shortened, an attacker-writable date is not permitted to buy a
	// down-rating. This guard is the only thing standing between "the log was
	// deleted" and "and therefore nothing it would have shown counts".
	if truncated {
		return "", false
	}

	// The instant that would explain this item: the package's own install date
	// when known, otherwise the baseline window as a whole.
	if p, ok := obs[it.Package]; ok && !p.InstallDate.IsZero() {
		if haveRecorded && p.InstallDate.Before(recorded) {
			return fmt.Sprintf("this package records an install date of %s, before the earliest "+
				"pacman.log line the baseline recorded (%s), so the log never covered its install. "+
				"That date comes from %%INSTALLDATE%% in the local database, which root can rewrite, "+
				"so this down-rating rests on data the host itself controls",
				p.InstallDate.Format(TimeLayoutOffset), recorded.Format(TimeLayoutOffset)), true
		}
		if !in.Log.Earliest.IsZero() && p.InstallDate.Before(in.Log.Earliest) && !haveRecorded {
			return fmt.Sprintf("this package records an install date of %s, before the log's "+
				"earliest line (%s), and the baseline recorded no window to judge truncation against",
				p.InstallDate.Format(TimeLayoutOffset), in.Log.Earliest.Format(TimeLayoutOffset)), true
		}
	}

	// No signed window at all: nothing says the log ever covered the baseline
	// window, so a change the log does not explain cannot be rated on its silence.
	if !haveRecorded && (in.Log.Earliest.IsZero() || in.Log.Earliest.After(created)) {
		if in.Log.Earliest.IsZero() {
			return "no timestamped pacman.log line was read and the baseline recorded no log " +
				"window, so nothing establishes that the log ever covered this change", true
		}
		return fmt.Sprintf("log coverage begins %s, after the baseline was made (%s), and the "+
			"baseline recorded no window to judge truncation against, so the shortfall cannot be "+
			"told apart from a log that never reached back",
			in.Log.Earliest.Format(TimeLayoutOffset), created.Format(TimeLayoutOffset)), true
	}
	return "", false
}

// indexAdjudications builds the per-package lookup, and reports every record that
// cannot be used. A record that fails here suppresses nothing and becomes a gap:
// an adjudication a caller cannot rely on must not silently look like one that
// worked (INV-9).
func indexAdjudications(recs []DriftAdjudication, now time.Time) (map[string]DriftAdjudication, []finding.Gap) {
	out := map[string]DriftAdjudication{}
	var gaps []finding.Gap
	for i, r := range recs {
		where := fmt.Sprintf("adjudication %d", i)
		if r.Subject != "" {
			where = "adjudication for " + r.Subject
		}
		switch {
		case r.RuleID != "" && r.RuleID != DriftRule:
			gaps = append(gaps, finding.Gap{
				RuleID:  DriftCoverageRule,
				Subject: where,
				Reason: fmt.Sprintf("names rule %q, not %q, so it does not apply to drift and "+
					"suppresses nothing here", r.RuleID, DriftRule),
			})
		case strings.TrimSpace(r.Reason) == "":
			gaps = append(gaps, finding.Gap{
				RuleID:  DriftCoverageRule,
				Subject: where,
				Reason: "has no recorded reason, so it suppresses nothing: a suppression without a " +
					"reason is indistinguishable from an attacker's",
			})
		case r.Scope != "pin" && r.Scope != "subject" && r.Scope != "rule":
			gaps = append(gaps, finding.Gap{
				RuleID:  DriftCoverageRule,
				Subject: where,
				Reason: fmt.Sprintf("has scope %q, which is not pin, subject or rule, so it "+
					"suppresses nothing", r.Scope),
			})
		case r.Scope != "rule" && strings.TrimSpace(r.Subject) == "":
			gaps = append(gaps, finding.Gap{
				RuleID:  DriftCoverageRule,
				Subject: where,
				Reason:  "names no subject, so there is nothing for it to apply to",
			})
		case r.ExpiresAt != "" && !expired(r.ExpiresAt, now):
			out[r.Subject] = r
		case r.ExpiresAt == "":
			out[r.Subject] = r
		default:
			gaps = append(gaps, finding.Gap{
				RuleID:  DriftCoverageRule,
				Subject: where,
				Reason: fmt.Sprintf("expired on %s, so it suppresses nothing until re-adjudicated",
					r.ExpiresAt),
			})
		}
	}
	return out, gaps
}

// expired reports whether an expiry has passed at now. An unparseable expiry
// counts as expired: a date this build cannot read must not extend a suppression.
func expired(expiresAt string, now time.Time) bool {
	t, err := ParseStamp(expiresAt)
	if err != nil {
		return true
	}
	return !now.Before(t)
}

func expiryText(s string) string {
	if s == "" {
		return "none recorded"
	}
	return s
}

// driftFinding renders one item. Corroborated items produce no finding at all --
// ordinary system evolution is not a detection -- while adjudicated and
// coverage-gapped ones produce an INFO finding, so their absence from the critical
// list is visible rather than silent (INV-6).
func driftFinding(it DriftItem) (finding.Finding, bool) {
	if it.Bucket == BucketCorroborated {
		return finding.Finding{}, false
	}
	summary := fmt.Sprintf("%s %s since the baseline", it.Package, it.Kind)
	switch it.Bucket {
	case BucketAdjudicated:
		summary = fmt.Sprintf("%s %s since the baseline (adjudicated)", it.Package, it.Kind)
	case BucketLogCoverageGap:
		summary = fmt.Sprintf("%s %s since the baseline, and pacman.log could not have explained it",
			it.Package, it.Kind)
	}
	return finding.Finding{
		RuleID:      DriftRule,
		SubjectKind: SubjectKindPackage,
		Subject:     it.Package,
		Severity:    it.Severity,
		Summary:     summary,
		Evidence:    append([]string{"classification: " + string(it.Bucket) + " — " + it.Detail}, it.Evidence...),
		Limits:      DriftLimitsText,
	}, true
}

func valueOrNone(s string) string {
	if s == "" {
		return "(absent)"
	}
	return s
}
