// internal/triage/apply.go
//
// Applying a set of triage records to a scan result.
//
// The state spread mirrors internal/adjudicate's, and deliberately so: an
// operator who has learned that "stale" means one thing for a signed judgement
// must not find it meaning something else for a triage record. What differs is
// StateAnnotated, which exists because one of the three verbs suppresses
// nothing, and a `note` reported in the same column as an `ack` would be exactly
// the silent-suppression confusion the verb was introduced to avoid.
package triage

import (
	"fmt"
	"sort"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/finding"
)

// State is what one record did on one run.
type State string

const (
	// StateActive is an ack or a snooze that hid at least one finding.
	StateActive State = "active"

	// StateAnnotated is a NOTE whose finding is present. It suppressed nothing,
	// which is the verb's whole contract, and it is a healthy state rather than
	// something needing attention.
	StateAnnotated State = "annotated"

	// StateStale is bound to matching semantics that have moved: preserved,
	// reported, suppressing nothing, re-triage required.
	StateStale State = "stale"

	// StateExpired is past its expiry. It suppresses nothing.
	StateExpired State = "expired"

	// StateSpent is a pin whose subject still has a finding but whose evidence
	// changed. The finding reappears once, which is the pin's contract.
	StateSpent State = "spent"

	// StateDead matched nothing at all. §12: "dead suppressions that match
	// nothing are reported for removal" -- a record whose finding stopped
	// occurring is clutter, and clutter is what hides the next one.
	StateDead State = "dead"

	// StateInvalid failed Validate. It suppresses nothing and raises a coverage
	// gap (INV-9).
	StateInvalid State = "invalid"
)

// Suppresses reports whether findings were actually hidden in this state. Only
// StateActive hides anything; the method exists so no caller re-derives that
// from a switch and gets StateAnnotated wrong.
func (s State) Suppresses() bool { return s == StateActive }

// NeedsRemoval reports the states §12 calls dead suppressions: a record that
// will never do anything again unless the world changes back.
func (s State) NeedsRemoval() bool { return s == StateDead || s == StateExpired }

// Status is one record's outcome. The Record is carried whole so a report can
// print the note and the scope of something that no longer applies.
type Status struct {
	Record  Record
	State   State
	Detail  string   // always populated when State is neither active nor annotated
	Caveat  string   // the unbound-epoch caveat, when there is one
	Matched []string // finding ids covered, or that WOULD have been covered
}

// Suppression pairs a hidden finding with the record that hid it (INV-6: the
// absence has to be visible somewhere, with the severity intact).
type Suppression struct {
	Finding finding.Finding
	Record  Record
}

// Annotation pairs a still-reported finding with the note attached to it. It is
// a separate type from Suppression on purpose: collapsing the two would be the
// first step towards a note that suppresses.
type Annotation struct {
	Finding finding.Finding
	Record  Record
}

// Outcome is the result of applying a set.
type Outcome struct {
	// Kept is what the run still reports. Gaps are the input gaps plus one per
	// unusable record -- never fewer, because no triage record can remove a gap.
	Kept finding.Result

	// Suppressed is every finding hidden, with the record that hid it.
	Suppressed []Suppression

	// Annotated is every finding a note is attached to. These findings are in
	// Kept as well: a note does not remove anything.
	Annotated []Annotation

	// Statuses covers every record in the set, whatever it did.
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

// NeedsAttention returns every record that is neither doing its job nor
// harmlessly annotating: stale, expired, spent, dead and invalid.
func (o Outcome) NeedsAttention() []Status {
	var out []Status
	for _, st := range o.Statuses {
		if st.State != StateActive && st.State != StateAnnotated {
			out = append(out, st)
		}
	}
	return out
}

// Set is a loaded collection of triage records plus whatever could not be
// loaded. The zero value suppresses nothing, which is the right default for a
// caller whose load failed.
//
// There is no SignedBy field, and its absence is the type telling the truth:
// this store carries no signature, and a field that could be nil-checked would
// invite a caller to write `if set.SignedBy != nil` and believe the answer.
type Set struct {
	Records []Record
	Faults  []Fault
	Source  string
}

// Fault is something in the store that could not be used (INV-9).
type Fault struct {
	Where  string
	Reason string
}

// Apply evaluates a set against a result using the built-in epoch registry.
func Apply(set Set, res finding.Result, now time.Time) Outcome {
	return ApplyWith(adjudicate.BuiltIn(), set, res, now)
}

// ApplyWith evaluates a set against a result at time now.
//
// now is a parameter, not time.Now() (INV-4): the same inputs must give the same
// answer on any day, or nothing about expiry is testable.
//
// Precedence between failure states, ordered by what the operator must do first:
//
//  1. invalid -- the record cannot be read, so nothing else about it is known.
//  2. stale   -- the semantics moved; re-triage regardless of the expiry date.
//  3. expired -- the record lapsed.
//  4. spent   -- a pin whose evidence changed.
//  5. active / annotated / dead, by verb and by whether anything matched.
//
// GAPS PASS THROUGH UNTOUCHED. A triage record can hide a FINDING; nothing here
// can hide the fact that something was not examined (INV-3).
func ApplyWith(reg adjudicate.Registry, set Set, res finding.Result, now time.Time) Outcome {
	out := Outcome{Kept: finding.Result{
		Findings: make([]finding.Finding, 0, len(res.Findings)),
		Gaps:     append([]finding.Gap(nil), res.Gaps...),
	}}

	source := set.Source
	if source == "" {
		source = "triage"
	}
	for _, f := range set.Faults {
		out.Kept.Gaps = append(out.Kept.Gaps, finding.Gap{
			RuleID:  "triage-store",
			Subject: source + ": " + f.Where,
			Reason: f.Reason + "; it suppresses nothing, so any finding it covered is " +
				"reported in full",
		})
	}

	// Keyed by finding INDEX rather than identity: two findings can share a rule
	// and subject and differ only in evidence, and a pin must not hide the one it
	// was not written for.
	suppressedBy := make(map[int]Record, len(res.Findings))
	notedBy := make(map[int][]Record, len(res.Findings))

	for i, rec := range set.Records {
		st := evaluate(reg, rec, res.Findings, now)
		switch {
		case st.State == StateInvalid:
			out.Kept.Gaps = append(out.Kept.Gaps, finding.Gap{
				RuleID:  "triage-store",
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
		case st.State == StateAnnotated:
			for _, idx := range st.indices {
				notedBy[idx] = append(notedBy[idx], rec)
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
		for _, rec := range notedBy[i] {
			out.Annotated = append(out.Annotated, Annotation{Finding: f, Record: rec})
		}
	}

	sort.SliceStable(out.Statuses, func(i, j int) bool {
		a, b := out.Statuses[i], out.Statuses[j]
		if a.State != b.State {
			return a.State < b.State
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

func evaluate(reg adjudicate.Registry, rec Record, findings []finding.Finding, now time.Time) evaluated {
	if err := rec.Validate(); err != nil {
		return evaluated{Status: Status{Record: rec, State: StateInvalid, Detail: err.Error()}}
	}

	// What it WOULD cover, computed before the epoch and expiry checks so a stale
	// or expired record can report what it is no longer suppressing.
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

	current, why := rec.Current(reg)
	if !current {
		st.State = StateStale
		st.Detail = why + " — stale, re-triage: the record is kept but suppresses nothing"
		return evaluated{Status: st}
	}
	st.Caveat = why // non-empty exactly when the record carries no epoch binding

	exp, err := rec.Expiry()
	if err != nil { // unreachable after Validate; kept so a future edit fails closed
		st.State = StateInvalid
		st.Detail = err.Error()
		return evaluated{Status: st}
	}
	if !now.Before(exp) {
		st.State = StateExpired
		st.Detail = fmt.Sprintf("expired on %s; it suppresses nothing. `%s` lasts %d day(s) by "+
			"default -- record it again if it is still true", rec.ExpiresAt, rec.Verb,
			int(rec.Verb.DefaultExpiry().Hours()/24))
		return evaluated{Status: st}
	}
	if len(idx) > 0 {
		if rec.Verb == VerbNote {
			st.State = StateAnnotated
			st.Detail = "a note SUPPRESSES NOTHING: the finding below is still reported in full"
			return evaluated{Status: st, indices: idx}
		}
		st.State = StateActive
		if rec.Verb == VerbSnooze {
			st.Detail = fmt.Sprintf("snoozed until %s, when it comes back", rec.ExpiresAt)
		}
		return evaluated{Status: st, indices: idx}
	}
	if spent {
		st.State = StateSpent
		st.Detail = "the pinned evidence changed, so the record is spent and the finding is " +
			"reported once; triage it again if the new evidence is also expected"
		return evaluated{Status: st}
	}
	st.State = StateDead
	st.Detail = "matched nothing on this run: either the finding stopped occurring, in which case " +
		"delete this record with `aurvet triage drop <fingerprint>`, or the rule's semantics moved"
	return evaluated{Status: st}
}

// findingID names a finding for a human reading a status line. It is not the
// report's finding id and must not be used as a durable key -- it exists so a
// stale record can say WHAT it is no longer covering.
func findingID(f finding.Finding) string {
	return fmt.Sprintf("%s %s:%s", f.RuleID, f.SubjectKind, f.Subject)
}
