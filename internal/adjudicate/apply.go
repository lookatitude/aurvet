// internal/adjudicate/apply.go
//
// Applying a set of adjudications to a scan result.
//
// Six outcomes, one per way a suppression can fail to be what it claims. The
// spread is the feature: "it did not suppress" is not one fact, and an operator
// who cannot tell "the rule changed" from "the finding was fixed" from "this
// record is corrupt" cannot act on any of them.
package adjudicate

import (
	"fmt"
	"sort"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

// State is what one record did on one run.
type State string

const (
	// StateActive suppressed at least one finding.
	StateActive State = "active"

	// StateStale is bound to matching semantics that have moved: the judgement
	// is preserved, it suppresses nothing, and it must be re-adjudicated. This
	// is the whole point of task 8 -- the alternatives are silently persisting
	// (hides something nobody assessed) and silently vanishing (loses the
	// operator's recorded judgement).
	StateStale State = "stale"

	// StateExpired is past its expiry date. It suppresses nothing.
	StateExpired State = "expired"

	// StateSpent is a pin whose subject still has a finding but whose evidence
	// changed. The finding reappears once, which is the pin's contract.
	StateSpent State = "spent"

	// StateDead matched nothing at all: either the finding was fixed (delete the
	// record) or the rule's semantics moved without an epoch bump (re-adjudicate
	// it). Reported either way, because silence is how a suppression file rots
	// into a liability.
	StateDead State = "dead"

	// StateInvalid failed Validate. It suppresses nothing and raises a coverage
	// gap (INV-9).
	StateInvalid State = "invalid"
)

// Suppresses reports whether findings were actually hidden in this state. Only
// one state suppresses; the method exists so no caller has to re-derive that
// from a switch and get it wrong in one branch.
func (s State) Suppresses() bool { return s == StateActive }

// Status is one record's outcome. The Record is carried whole, so a report can
// print the reason and the scope of something that no longer applies -- a stale
// or expired judgement is still the operator's judgement.
type Status struct {
	Record  Record
	State   State
	Detail  string   // always populated when State != StateActive
	Matched []string // FindingIDs suppressed, or that WOULD have been suppressed
}

// Suppression pairs a hidden finding with the record that hid it. INV-6: a
// suppressed finding's absence must be visible somewhere, so the severity and
// the reason both survive the trip.
type Suppression struct {
	Finding finding.Finding
	Record  Record
}

// Outcome is the result of applying a set.
type Outcome struct {
	// Kept is what the run still reports. Gaps are the input gaps plus one per
	// unusable adjudication record -- never fewer, because no adjudication can
	// remove a gap (INV-3).
	Kept finding.Result

	// Suppressed is every finding hidden, with why.
	Suppressed []Suppression

	// Statuses covers every record in the set, whatever it did. A record that
	// reports nothing is indistinguishable from a record that was deleted, and
	// those are different facts.
	Statuses []Status
}

// ByState returns the statuses in one state, in report order.
func (o Outcome) ByState(s State) []Status {
	var out []Status
	for _, st := range o.Statuses {
		if st.State == s {
			out = append(out, st)
		}
	}
	return out
}

// NeedsAttention returns every record that did not do what it claims: stale,
// expired, spent, dead and invalid. This is the list `scan` and `doctor` print;
// an adjudication set nobody prunes becomes a set nobody understands.
func (o Outcome) NeedsAttention() []Status {
	var out []Status
	for _, st := range o.Statuses {
		if st.State != StateActive {
			out = append(out, st)
		}
	}
	return out
}

// RuleScoped returns the ACTIVE rule-scope suppressions, for echoing in the run
// header. A whole check being off is a standing property of the host and has to
// be visible on every run, not only on the run that switched it off.
func (o Outcome) RuleScoped() []Record {
	var out []Record
	for _, st := range o.Statuses {
		if st.State == StateActive && st.Record.Scope == ScopeRule {
			out = append(out, st.Record)
		}
	}
	return out
}

// Set is a loaded collection of adjudications plus whatever could not be loaded.
//
// The zero value suppresses nothing, which is the right default for a caller
// whose load failed. Faults are carried rather than returned as an error so that
// a partial load cannot be mistaken for an empty one: a Set with faults raises
// gaps in every Outcome it produces.
type Set struct {
	Records []Record
	Faults  []Fault
	Source  string

	// SignedBy is the key that signed the store, when it was read through
	// ParseSignedStore and verified. nil means the records' authenticity was
	// established somewhere else, or not at all -- so a caller that requires a
	// signature must check this rather than assume the load path.
	SignedBy *baseline.PublicKey
}

// Fault is something in the adjudication store that could not be used. INV-9: an
// adjudication record you cannot parse is a coverage gap, never silence -- and
// specifically never an active suppression.
type Fault struct {
	Where  string // "record 3", "signature", "file"
	Reason string
}

// Apply evaluates a set against a result using the built-in epoch registry.
func Apply(set Set, res finding.Result, now time.Time) Outcome {
	return ApplyWith(BuiltIn(), set, res, now)
}

// ApplyWith evaluates a set against a result at time now.
//
// now is a parameter, not time.Now() (INV-4): the same inputs must give the same
// answer on any day, or nothing about expiry is testable and two hosts auditing
// one chain can disagree.
//
// Precedence between failure states is deliberate and is ordered by what the
// operator must do first:
//
//  1. invalid   -- the record cannot be read, so nothing else about it is known.
//  2. stale     -- the semantics moved; re-adjudicating is required regardless
//     of the expiry date, so this outranks expiry.
//  3. expired   -- the judgement lapsed.
//  4. spent     -- a pin whose evidence changed.
//  5. active or dead, by whether anything matched.
//
// Gaps pass through untouched. An adjudication can hide a FINDING; it can never
// hide the fact that something was not examined (INV-3).
func ApplyWith(reg Registry, set Set, res finding.Result, now time.Time) Outcome {
	out := Outcome{Kept: finding.Result{
		Findings: make([]finding.Finding, 0, len(res.Findings)),
		Gaps:     append([]finding.Gap(nil), res.Gaps...),
	}}

	source := set.Source
	if source == "" {
		source = "adjudications"
	}
	for _, f := range set.Faults {
		out.Kept.Gaps = append(out.Kept.Gaps, finding.Gap{
			RuleID:  "adjudicate-store",
			Subject: source + ": " + f.Where,
			Reason: f.Reason + "; it suppresses nothing, so any finding it covered is " +
				"reported in full",
		})
	}

	// suppressedBy is keyed by finding index rather than by identity: two
	// findings can share a rule and subject and differ only in evidence, and a
	// pin must not hide the one it was not written for.
	suppressedBy := make(map[int]Record, len(res.Findings))

	for i, rec := range set.Records {
		st := evaluate(reg, rec, res.Findings, now)
		switch {
		case st.State == StateInvalid:
			out.Kept.Gaps = append(out.Kept.Gaps, finding.Gap{
				RuleID:  "adjudicate-store",
				Subject: fmt.Sprintf("%s: record %d", source, i),
				Reason: st.Detail + "; it suppresses nothing, so any finding it covered is " +
					"reported in full",
			})
		case st.State == StateActive:
			for _, idx := range st.indices {
				if _, taken := suppressedBy[idx]; !taken {
					suppressedBy[idx] = rec
				}
			}
		}
		out.Statuses = append(out.Statuses, st.Status)
	}

	for i, f := range res.Findings {
		if rec, ok := suppressedBy[i]; ok {
			out.Suppressed = append(out.Suppressed, Suppression{Finding: f, Record: rec})
			continue
		}
		out.Kept.Findings = append(out.Kept.Findings, f)
	}

	sort.SliceStable(out.Statuses, func(i, j int) bool {
		a, b := out.Statuses[i], out.Statuses[j]
		if a.State != b.State {
			return a.State < b.State
		}
		if a.Record.Scope.Breadth() != b.Record.Scope.Breadth() {
			return a.Record.Scope.Breadth() < b.Record.Scope.Breadth()
		}
		return a.Record.Fingerprint < b.Record.Fingerprint
	})
	return out
}

// evaluated is a Status plus the finding indices it applies to, which stay
// internal: an index into one run's finding slice means nothing outside it.
type evaluated struct {
	Status
	indices []int
}

func evaluate(reg Registry, rec Record, findings []finding.Finding, now time.Time) evaluated {
	if err := rec.Validate(); err != nil {
		return evaluated{Status: Status{Record: rec, State: StateInvalid, Detail: err.Error()}}
	}

	// What it WOULD have covered, computed before the epoch and expiry checks so
	// a stale or expired record can report what it is no longer suppressing.
	var idx []int
	var ids []string
	spent := false
	for i, f := range findings {
		matched, evidenceOK := rec.Matches(f)
		if !matched {
			continue
		}
		if !evidenceOK {
			spent = true
			continue
		}
		idx = append(idx, i)
		ids = append(ids, findingID(f))
	}
	st := Status{Record: rec, Matched: ids}

	if current, why := rec.Current(reg); !current {
		st.State = StateStale
		st.Detail = why + " — stale, re-adjudicate: the judgement is kept but suppresses nothing"
		return evaluated{Status: st}
	}
	exp, err := rec.Expiry()
	if err != nil { // unreachable after Validate, kept so a future edit fails closed
		st.State = StateInvalid
		st.Detail = err.Error()
		return evaluated{Status: st}
	}
	if !now.Before(exp) {
		st.State = StateExpired
		st.Detail = fmt.Sprintf("expired on %s (%s scope); it suppresses nothing until "+
			"re-adjudicated", rec.ExpiresAt, rec.Scope)
		return evaluated{Status: st}
	}
	if len(idx) > 0 {
		st.State = StateActive
		st.Detail = ""
		return evaluated{Status: st, indices: idx}
	}
	if spent {
		st.State = StateSpent
		st.Detail = "the pinned evidence changed, so the pin is spent and the finding is " +
			"reported once; re-adjudicate it if the new evidence is also acceptable"
		return evaluated{Status: st}
	}
	st.State = StateDead
	st.Detail = "matched nothing on this run: either the finding was fixed, in which case delete " +
		"this record, or the rule's semantics moved, in which case re-adjudicate it"
	return evaluated{Status: st}
}

// findingID names a finding for a human reading a status line. It is not the
// fingerprint and must not be used as a key for anything durable -- it exists so
// a stale record can say WHAT it is no longer suppressing.
func findingID(f finding.Finding) string {
	return fmt.Sprintf("%s %s:%s", f.RuleID, f.SubjectKind, f.Subject)
}
