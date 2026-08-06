// internal/triage/triage.go

// Package triage is the MIDDLE of spec §12's three weights: a lightweight,
// local, unsigned, expiring record that says "I have seen this".
//
// # Why a middle weight exists at all
//
// §12, verbatim: "Three weights, not two -- the reviewed design had no middle
// ground, so users would over-suppress or ignore output." The heavy weight,
// internal/adjudicate, needs an ed25519 key, a signature, a reason of substance
// and a place in the store that gates `baseline init`. That price is correct for
// a judgement that unblocks the strongest refusal in the tool, and wrong for an
// operator with one noisy `info` finding about their own hand-written systemd
// unit. Offered only the heavy weight, that operator ignores the output -- which
// is the failure this package exists to prevent.
//
// # The property this package must never break
//
// A TRIAGE RECORD CANNOT UNBLOCK `baseline init`. Not by design, not by
// accident, and not through a shared code path.
//
// Structurally: nothing in internal/baseline, internal/chain or
// internal/adjudicate imports this package, cmd/aurvet's baselineWrite never
// loads this store, and TestNothingThatGatesBootstrapImportsTriage in this
// package enforces both directions. The dependency arrow points the other way --
// triage imports adjudicate for the SCOPE and EPOCH vocabulary, so §12's three
// scopes have one definition rather than a fourth invented here.
//
// The reasoning is not squeamishness about layering. Signed adjudications are
// reserved for bootstrap BECAUSE bootstrap is the strongest gate in the tool; a
// keyless, unsigned, reason-optional record that could satisfy it would make the
// middle weight a bypass of the top one, and the cheapest suppression in the
// product would be the one with the widest blast radius.
//
// # What each verb does, and the differences are visible in output
//
//   - ack    -- "I have seen this and it is expected." Suppresses. Expires.
//   - snooze -- "not now." Suppresses for a SHORTER period, and every rendering
//     of it says when it comes back.
//   - note   -- annotates and suppresses NOTHING. This is the verb an
//     investigation reaches for, and a `note` that quietly hid
//     something would be the worst of the three.
//
// # Everything here fails closed
//
//   - An unreadable or invalid record suppresses nothing and is reported as a
//     coverage gap (INV-9).
//   - A record past its expiry suppresses nothing. There is no unbounded form:
//     see Verb.MaxExpiry.
//   - A record bound to matching semantics that have moved reads STALE:
//     preserved, reported, suppressing nothing -- the same third option
//     internal/adjudicate takes, for the same reason.
//   - GAPS ARE NEVER SUPPRESSIBLE. A gap is "I did not look"; no
//     acknowledgement turns unexamined into examined (INV-3).
//   - Every suppressed finding is carried out in Outcome.Suppressed with its
//     severity intact, so a report can state what it is not showing (INV-6).
//
// Nothing here reads the clock (INV-4): `now` is a parameter. Nothing here
// writes (that is store.go) or executes (INV-2).
package triage

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/finding"
)

// ErrRecord reports a malformed or unusable triage record.
var ErrRecord = errors.New("triage: invalid triage record")

// MaxNoteRunes bounds the free text so a record stays a record. There is no
// MINIMUM: a note of substance is the point of `note`, but `ack` and `snooze`
// are deliberately cheap, and demanding twelve considered characters before an
// operator may dismiss an `info` finding about their own unit would reinvent the
// friction §12 introduced this layer to remove. The bound on being wrong is the
// expiry, not the prose.
const MaxNoteRunes = 2000

// Verb is which of the three weights-within-the-weight this record is.
type Verb string

const (
	// VerbAck suppresses: "I have seen this and it is expected."
	VerbAck Verb = "ack"

	// VerbSnooze suppresses for a shorter period: "not now."
	VerbSnooze Verb = "snooze"

	// VerbNote suppresses NOTHING. It annotates.
	VerbNote Verb = "note"
)

// Verbs lists the three in the order they are documented.
func Verbs() []Verb { return []Verb{VerbAck, VerbSnooze, VerbNote} }

// Valid reports whether v is one of the three.
func (v Verb) Valid() bool {
	switch v {
	case VerbAck, VerbSnooze, VerbNote:
		return true
	}
	return false
}

// Suppresses reports whether this verb hides findings from the default view. It
// is a method rather than a comparison at each call site so that no caller can
// get `note` wrong in one branch.
func (v Verb) Suppresses() bool { return v == VerbAck || v == VerbSnooze }

// DefaultExpiry is how long the record lasts unless a shorter one is asked for.
//
// Every value here is SHORTER than internal/adjudicate's 180 days, and that
// ordering is a requirement rather than a preference: triage is the lighter
// weight, so a triage record must not outlive a signed judgement about the same
// finding. Snooze is shortest because "not now" is a statement about today.
func (v Verb) DefaultExpiry() time.Duration {
	switch v {
	case VerbSnooze:
		return 7 * 24 * time.Hour
	default:
		return 30 * 24 * time.Hour
	}
}

// MaxExpiry caps the record. There is no non-expiring triage record, for a
// sharper version of adjudicate's reason: this record carries no signature, no
// key and not necessarily any stated reason, so a permanent one would be an
// anonymous, unattributable, unreviewable blindfold that nothing ever forces
// anyone to look behind.
func (v Verb) MaxExpiry() time.Duration {
	switch v {
	case VerbSnooze:
		return 30 * 24 * time.Hour
	default:
		return 90 * 24 * time.Hour
	}
}

// Describe spells out what the verb does, for output that is read rather than
// parsed.
func (v Verb) Describe() string {
	switch v {
	case VerbAck:
		return "ack: seen and expected -- hidden from the default view until it expires"
	case VerbSnooze:
		return "snooze: not now -- hidden until it expires, then it comes back"
	case VerbNote:
		return "note: annotation only -- IT SUPPRESSES NOTHING and the finding still reports"
	default:
		return "unknown verb: suppresses nothing"
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Record is one triage entry.
//
// It deliberately carries no `by` and no signature. Who typed it is not
// establishable without a key, and a `by` field an operator types is a field an
// operator can type anything into -- recording it would dress an unattributable
// record up as an attributable one, which is the confusion this whole layer must
// not create.
type Record struct {
	// Fingerprint is adjudicate.FingerprintFor over (rule, subject kind, subject
	// identity, scope). It is recomputed and checked by Validate, so a record
	// cannot claim one fingerprint while naming a different subject.
	Fingerprint string `json:"fingerprint"`

	Verb Verb `json:"verb"`

	RuleID      string           `json:"rule_id"`
	SubjectKind string           `json:"subject_kind"`
	Subject     string           `json:"subject"`
	Scope       adjudicate.Scope `json:"scope"`

	// EvidenceDigest is set for ScopePin only, and required there.
	EvidenceDigest string `json:"evidence_digest"`

	// FingerprintEpoch and SemanticsDigest bind the record to the matching
	// semantics it was made against, exactly as an adjudication is bound.
	//
	// ZERO AND EMPTY ARE LEGAL HERE, AND THAT IS A DECIDED DIFFERENCE FROM
	// adjudicate. A rule that declares no epoch cannot be adjudicated at all --
	// adjudicate.New refuses, naming the file to edit -- because a signed
	// judgement that cannot be told apart later from one made against changed
	// semantics is worse than no judgement. Applying that refusal here would be
	// the fifth appearance of a deadlock this project has already hit four
	// times: an operator told to quieten a finding and then refused permission
	// to quieten it, with the next step being a source-code edit.
	//
	// A keyless record is not blocked on an epoch declaration. The cost of being
	// wrong is bounded by the expiry above -- 90 days at the very most -- and
	// every rendering of an unbound record says, in words, that it cannot be
	// told stale. Bound records behave exactly as adjudications do.
	FingerprintEpoch int    `json:"fingerprint_epoch"`
	SemanticsDigest  string `json:"semantics_digest"`

	// Note is free text. Mandatory for VerbNote, which exists to carry it;
	// optional for the other two.
	Note string `json:"note"`

	// At and ExpiresAt are RFC3339 with an EXPLICIT offset. A local timestamp
	// with no offset is ambiguous by an hour twice a year, and an expiry that is
	// ambiguous is an expiry that can be argued with.
	At        string `json:"at"`
	ExpiresAt string `json:"expires_at"`
}

// EpochBound reports whether this record can be told stale when the rule's
// matching semantics move.
func (r Record) EpochBound() bool { return r.FingerprintEpoch > 0 && r.SemanticsDigest != "" }

// Request is what a caller asks for; New turns it into a Record.
type Request struct {
	Finding finding.Finding
	Verb    Verb

	// Scope is pin or subject. RULE SCOPE IS REFUSED HERE, and the refusal is
	// the argument the lane brief asked for.
	//
	// §12 gives rule scope a --force because it turns a check off for every
	// package and path on the host, and requires it echoed in every subsequent
	// run header. That is a standing property of the machine, not a remark about
	// one finding. Allowing an unsigned, keyless, note-optional record to
	// establish it would make the WIDEST suppression in the product the CHEAPEST
	// one to create -- the exact inversion this middle weight exists to prevent,
	// since the whole reason it exists is that an expensive-only suppression
	// path drives people to suppress in bulk.
	//
	// The counter-argument, stated because it is not silly: a rule-scope triage
	// record expires in at most 90 days, so the blast radius is time-bounded,
	// and an operator drowning in one noisy rule during an investigation has a
	// real need. It loses on the run header. A rule-scope suppression has to be
	// visible on every later run to be safe, and a record with no author, no
	// signature and no required reason cannot answer the question that header
	// provokes -- "who turned this off, and why?". `aurvet adjudicate -scope
	// rule -force-rule-scope` can, so that is where it stays.
	Scope adjudicate.Scope

	Note string
	Now  time.Time

	// Expiry is how long the record lasts. Zero means Verb.DefaultExpiry.
	Expiry time.Duration

	// EvidenceDigest overrides the digest computed from Finding.Evidence. Pins
	// only; normally left empty.
	EvidenceDigest string
}

// New builds a validated Record.
//
// reg supplies the epoch binding where the rule declares one. An UNDECLARED rule
// is not an error here (see Record.FingerprintEpoch): the record is written
// unbound and says so.
func New(reg adjudicate.Registry, req Request) (Record, error) {
	if !req.Verb.Valid() {
		return Record{}, fmt.Errorf("%w: %q is not one of ack, snooze, note",
			ErrRecord, string(req.Verb))
	}
	switch req.Scope {
	case adjudicate.ScopePin, adjudicate.ScopeSubject:
	case adjudicate.ScopeRule:
		return Record{}, fmt.Errorf("%w: triage does not offer rule scope. Turning a check off for "+
			"every package and path on this host is a standing property of the machine, it is echoed "+
			"in every later run header, and an unsigned record with no author cannot answer the "+
			"question that header provokes. Use `aurvet adjudicate <fingerprint> -scope rule "+
			"-force-rule-scope -reason ...`", ErrRecord)
	default:
		return Record{}, fmt.Errorf("%w: %q is not one of pin, subject", ErrRecord, string(req.Scope))
	}
	if req.Now.IsZero() {
		return Record{}, fmt.Errorf("%w: no decision time was supplied", ErrRecord)
	}
	expiry := req.Expiry
	if expiry == 0 {
		expiry = req.Verb.DefaultExpiry()
	}
	if expiry <= 0 {
		return Record{}, fmt.Errorf("%w: an expiry of %v is not a duration a record can last, and "+
			"there is no non-expiring triage record", ErrRecord, req.Expiry)
	}
	if max := req.Verb.MaxExpiry(); expiry > max {
		return Record{}, fmt.Errorf("%w: %v exceeds the %v maximum for `%s`; triage is the LIGHTER "+
			"weight, so it expires sooner than a signed adjudication, never later",
			ErrRecord, expiry, max, req.Verb)
	}

	ev := req.EvidenceDigest
	if req.Scope == adjudicate.ScopePin && ev == "" {
		var err error
		if ev, err = adjudicate.EvidenceDigest(req.Finding); err != nil {
			return Record{}, err
		}
	}
	if req.Scope != adjudicate.ScopePin {
		ev = ""
	}

	rec := Record{
		Fingerprint: adjudicate.FingerprintFor(req.Finding.RuleID, req.Finding.SubjectKind,
			req.Finding.Subject, req.Scope),
		Verb:           req.Verb,
		RuleID:         req.Finding.RuleID,
		SubjectKind:    req.Finding.SubjectKind,
		Subject:        req.Finding.Subject,
		Scope:          req.Scope,
		EvidenceDigest: ev,
		Note:           strings.TrimSpace(req.Note),
		At:             req.Now.Format(time.RFC3339),
		ExpiresAt:      req.Now.Add(expiry).Format(time.RFC3339),
	}
	if sem, ok := reg.Lookup(req.Finding.RuleID); ok {
		digest, err := sem.Digest()
		if err != nil {
			return Record{}, err
		}
		rec.FingerprintEpoch, rec.SemanticsDigest = sem.Epoch, digest
	}
	if err := rec.Validate(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Validate checks everything about a record that can be checked without knowing
// the current epoch or the current time. It runs on construction AND on every
// record read from disk: a record on disk has been outside this package's
// control, and a record that fails here suppresses nothing.
func (r Record) Validate() error {
	if !r.Verb.Valid() {
		return fmt.Errorf("%w: %q is not one of ack, snooze, note", ErrRecord, string(r.Verb))
	}
	switch r.Scope {
	case adjudicate.ScopePin, adjudicate.ScopeSubject:
	case adjudicate.ScopeRule:
		return fmt.Errorf("%w: a rule-scope triage record; triage does not offer rule scope and this "+
			"record would turn a whole check off with no signature and no author", ErrRecord)
	default:
		return fmt.Errorf("%w: %q is not one of pin, subject", ErrRecord, string(r.Scope))
	}
	if r.RuleID == "" {
		return fmt.Errorf("%w: no rule id", ErrRecord)
	}
	if r.SubjectKind == "" || r.Subject == "" {
		return fmt.Errorf("%w: a triage record needs a subject", ErrRecord)
	}
	if r.Verb == VerbNote && strings.TrimSpace(r.Note) == "" {
		return fmt.Errorf("%w: `note` exists to record the note; an empty one annotates nothing and "+
			"suppresses nothing, so it is a file entry with no effect at all", ErrRecord)
	}
	if len([]rune(r.Note)) > MaxNoteRunes {
		return fmt.Errorf("%w: the note is longer than %d characters", ErrRecord, MaxNoteRunes)
	}
	if r.Note != strings.TrimSpace(r.Note) {
		return fmt.Errorf("%w: the note has leading or trailing whitespace, which would give one "+
			"note two spellings", ErrRecord)
	}
	if r.Scope == adjudicate.ScopePin {
		if !hex64.MatchString(r.EvidenceDigest) {
			return fmt.Errorf("%w: a pin binds an evidence digest; %q is not a sha256 hex digest",
				ErrRecord, r.EvidenceDigest)
		}
	} else if r.EvidenceDigest != "" {
		return fmt.Errorf("%w: only a pin binds evidence", ErrRecord)
	}
	// The epoch binding is OPTIONAL but must be coherent: half a binding is a
	// record that claims to be checkable and is not.
	if (r.FingerprintEpoch > 0) != (r.SemanticsDigest != "") {
		return fmt.Errorf("%w: fingerprint_epoch %d with semantics_digest %q is half an epoch "+
			"binding; a record is bound to matching semantics or it is not",
			ErrRecord, r.FingerprintEpoch, r.SemanticsDigest)
	}
	if r.FingerprintEpoch < 0 {
		return fmt.Errorf("%w: fingerprint_epoch %d; epochs start at 1", ErrRecord, r.FingerprintEpoch)
	}
	if r.SemanticsDigest != "" && !hex64.MatchString(r.SemanticsDigest) {
		return fmt.Errorf("%w: semantics_digest %q is not a sha256 hex digest",
			ErrRecord, r.SemanticsDigest)
	}
	want := adjudicate.FingerprintFor(r.RuleID, r.SubjectKind, r.Subject, r.Scope)
	if want != r.Fingerprint {
		return fmt.Errorf("%w: fingerprint %q does not cover this record's own fields (want %q); "+
			"the record claims to be about something other than what it names",
			ErrRecord, r.Fingerprint, want)
	}
	at, err := parseStamp(r.At, "at")
	if err != nil {
		return err
	}
	exp, err := parseStamp(r.ExpiresAt, "expires_at")
	if err != nil {
		return err
	}
	if !exp.After(at) {
		return fmt.Errorf("%w: expires_at %s is not after at %s", ErrRecord, r.ExpiresAt, r.At)
	}
	if max := r.Verb.MaxExpiry(); exp.Sub(at) > max {
		return fmt.Errorf("%w: %s..%s is longer than the %v maximum for `%s`; there is no "+
			"non-expiring triage record", ErrRecord, r.At, r.ExpiresAt, max, r.Verb)
	}
	return nil
}

// Expiry returns the moment the record lapses.
func (r Record) Expiry() (time.Time, error) { return parseStamp(r.ExpiresAt, "expires_at") }

// Matches reports whether this record covers f, ignoring epoch and expiry --
// those are Apply's decisions. evidenceMatched is meaningful for pins only.
func (r Record) Matches(f finding.Finding) (matched, evidenceMatched bool) {
	if r.RuleID != f.RuleID || r.SubjectKind != f.SubjectKind || r.Subject != f.Subject {
		return false, false
	}
	if r.Scope != adjudicate.ScopePin {
		return true, true
	}
	got, err := adjudicate.EvidenceDigest(f)
	if err != nil {
		// Evidence that cannot be canonically encoded cannot be compared, so the
		// pin does not apply. Fail closed.
		return true, false
	}
	return true, got == r.EvidenceDigest
}

// Current reports whether the record is still bound to the matching semantics in
// force, and why not when it is not.
//
// An UNBOUND record is current: there was never a binding to break. The second
// return value is then the caveat every rendering prints, because "current"
// earned that way is a weaker statement than "current" earned by a digest match,
// and a reader must be able to tell them apart.
func (r Record) Current(reg adjudicate.Registry) (bool, string) {
	if !r.EpochBound() {
		return true, fmt.Sprintf("not bound to a fingerprint epoch: rule %q declared none when this "+
			"record was written, so if its matching semantics move this record will NOT read stale. "+
			"It expires on %s regardless", r.RuleID, r.ExpiresAt)
	}
	sem, ok := reg.Lookup(r.RuleID)
	if !ok {
		return false, fmt.Sprintf("rule %q declares no fingerprint epoch in this build, so the "+
			"semantics this record was made against cannot be confirmed", r.RuleID)
	}
	digest, err := sem.Digest()
	if err != nil {
		return false, fmt.Sprintf("rule %q has an unusable epoch declaration: %v", r.RuleID, err)
	}
	switch {
	case sem.Epoch != r.FingerprintEpoch:
		return false, fmt.Sprintf("triaged at fingerprint epoch %d; rule %q is now at epoch %d",
			r.FingerprintEpoch, r.RuleID, sem.Epoch)
	case digest != r.SemanticsDigest:
		return false, fmt.Sprintf("rule %q still reports epoch %d but its matching inputs changed "+
			"(%s, was %s), so the epoch bump was missed", r.RuleID, sem.Epoch,
			short(digest), short(r.SemanticsDigest))
	}
	return true, ""
}

func short(d string) string {
	if len(d) > 12 {
		return d[:12]
	}
	return d
}

// parseStamp requires RFC3339 with an explicit offset. "Z" counts: it is an
// explicit offset of zero. A bare local time does not.
func parseStamp(s, field string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: %s is empty; a triage record without a %s cannot be "+
			"aged out, and there is no non-expiring triage record", ErrRecord, field, field)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s %q is not RFC3339 with an explicit offset: %v",
			ErrRecord, field, s, err)
	}
	return t, nil
}

// sortRecords orders records for storage and reporting: notes last, because a
// reader meets what is HIDDEN before what is merely annotated; then by scope
// breadth, then by fingerprint. The order is total and derived only from the
// records, so two hosts holding the same set produce the same bytes.
func sortRecords(recs []Record) {
	rank := map[Verb]int{VerbSnooze: 0, VerbAck: 1, VerbNote: 2}
	sort.Slice(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
		if rank[a.Verb] != rank[b.Verb] {
			return rank[a.Verb] < rank[b.Verb]
		}
		if a.Scope.Breadth() != b.Scope.Breadth() {
			return a.Scope.Breadth() < b.Scope.Breadth()
		}
		if a.Fingerprint != b.Fingerprint {
			return a.Fingerprint < b.Fingerprint
		}
		if a.EvidenceDigest != b.EvidenceDigest {
			return a.EvidenceDigest < b.EvidenceDigest
		}
		return a.At < b.At
	})
}
