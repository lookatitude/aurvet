// internal/adjudicate/adjudicate.go

// Package adjudicate is the signed adjudication lifecycle: three scopes, a
// mandatory reason, a bounded expiry, and epoch binding (P4 tasks 8 and 9).
//
// # What an adjudication is, and what it is not
//
// An adjudication is a RECORDED, SIGNED, EXPIRING SECURITY DECISION: "I looked
// at this finding, here is why it is acceptable, and here is when that judgement
// has to be made again." It is reserved for `baseline init`, where a first
// baseline has to convert every unresolved critical into a dated, auditable
// assumption before anything can be signed (spec §11).
//
// It is NOT the triage layer. Triage (internal/report, `scan --since-last`) is
// lightweight, local, unsigned and needs no keys: "I have seen this, do not show
// it to me again today." The two are kept apart on purpose, and structurally --
// this package does not import internal/report, and a test enforces that -- so
// that a casual dismissal can never acquire the weight of a signed judgement by
// travelling along a shared code path. The reverse matters too: adjudication is
// expensive to create BY DESIGN, and if it were the only tool, operators would
// suppress in bulk to get a quiet report, which is the outcome all of this
// exists to avoid.
//
// # Everything here fails closed
//
//   - An unreadable or invalid record suppresses NOTHING and is reported as a
//     coverage gap (INV-9). Absence of a suppression is safe; a suppression
//     nobody can read is not.
//   - A record whose epoch or semantics digest no longer matches the live
//     registry reads STALE: preserved, reported, suppressing nothing.
//   - A record past its expiry stops suppressing and says so.
//   - Gaps are never suppressible. Adjudicating away "I could not examine this"
//     would turn unexamined into clean, which is INV-3.
//   - Every suppressed finding is carried out in Outcome.Suppressed with its
//     severity intact, so a report can state what it is not showing (INV-6). A
//     report that silently omits suppressed findings lies by omission.
//
// Nothing here reads the clock (INV-4): `now` is a parameter, because a
// suppression whose effect depends on the day it is evaluated is neither
// reproducible nor testable. Nothing here writes (INV-5) or executes (INV-2).
package adjudicate

import (
	"errors"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
	"unicode"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

// ErrRecord reports a malformed or unusable adjudication record.
var ErrRecord = errors.New("adjudicate: invalid adjudication record")

const (
	// DefaultExpiry is the 180 days a suppression lasts unless a shorter one is
	// asked for. Suppressions expire so that the default outcome of NEGLECT is
	// re-examination rather than permanent blindness.
	DefaultExpiry = 180 * 24 * time.Hour

	// MaxExpiry caps an adjudication at a year. There is no non-expiring
	// suppression in this format: see Request.Expiry.
	MaxExpiry = 365 * 24 * time.Hour

	// MinReasonRunes is the shortest reason that can plausibly be re-evaluated
	// by someone else. "ok", "wontfix" and "n/a" are not reasons; they are a
	// record of somebody wanting the output to be quiet.
	MinReasonRunes = 12

	// MaxReasonRunes bounds the reason so a record stays a record.
	MaxReasonRunes = 2000
)

// Scope is the blast radius of one adjudication. The three are ordered, and the
// order is the point: they must not be interchangeable, and a reader a year
// later must be able to see the breadth without reasoning about it.
type Scope string

const (
	// ScopePin suppresses THIS EXACT EVIDENCE. Any change to the evidence spends
	// the pin and the finding reappears once (spec §12).
	ScopePin Scope = "pin"

	// ScopeSubject suppresses this rule for this one package or path, and
	// survives upgrades because the subject identity is version-independent.
	ScopeSubject Scope = "subject"

	// ScopeRule turns a check off EVERYWHERE. It requires an explicit force and
	// is echoed in every subsequent run header, because a whole check being off
	// is a standing property of the host, not a detail of one finding.
	ScopeRule Scope = "rule"
)

// Breadth ranks the scopes 1..3 by how much they hide. 0 means "not a scope".
func (s Scope) Breadth() int {
	switch s {
	case ScopePin:
		return 1
	case ScopeSubject:
		return 2
	case ScopeRule:
		return 3
	default:
		return 0
	}
}

// Valid reports whether s is one of the three scopes.
func (s Scope) Valid() bool { return s.Breadth() != 0 }

// Describe spells the breadth out in words, for output that is read rather than
// parsed. A one-word scope name in a list is exactly how a rule-wide suppression
// gets mistaken for a narrow one.
func (s Scope) Describe() string {
	switch s {
	case ScopePin:
		return "pin: this exact evidence only; spent by any change to it"
	case ScopeSubject:
		return "subject: this rule for this one package or path, across upgrades"
	case ScopeRule:
		return "rule: THIS CHECK IS OFF EVERYWHERE, for every package and path"
	default:
		return "unknown scope: suppresses nothing"
	}
}

var hex64 = regexp.MustCompile(`^[0-9a-f]{64}$`)

// Record is one adjudication.
//
// The json tags are the on-disk spelling and are also what the canonical
// serialisation sorts by, so field order in this struct is not load-bearing --
// moving a field cannot invalidate a signature. Renaming a tag can, and would be
// a format change.
type Record struct {
	// Fingerprint is finding.Fingerprint over (rule, subject kind, subject
	// identity, scope class). It is recomputed and checked by Validate, so a
	// record cannot claim one fingerprint while naming a different subject.
	Fingerprint string `json:"fingerprint"`

	RuleID      string `json:"rule_id"`
	SubjectKind string `json:"subject_kind"`
	Subject     string `json:"subject"`
	Scope       Scope  `json:"scope"`

	// EvidenceDigest is set for ScopePin only, and required there.
	EvidenceDigest string `json:"evidence_digest"`

	// FingerprintEpoch and SemanticsDigest bind the judgement to the matching
	// semantics it was made against. See epoch.go.
	FingerprintEpoch int    `json:"fingerprint_epoch"`
	SemanticsDigest  string `json:"semantics_digest"`

	// Reason is mandatory and cannot be defaulted. A suppression whose reason
	// is empty cannot be re-evaluated by anyone, including its author.
	Reason string `json:"reason"`

	// By names who decided. Not an authorisation claim -- the signature is that
	// -- but a person to ask.
	By string `json:"by"`

	// At and ExpiresAt are RFC3339 with an EXPLICIT offset. A local timestamp
	// with no offset is ambiguous by an hour twice a year, and an expiry that is
	// ambiguous is an expiry that can be argued with.
	At        string `json:"at"`
	ExpiresAt string `json:"expires_at"`

	// Forced records the explicit force a rule-scope adjudication needs. It is
	// stored rather than implied so the record itself shows the decision was
	// deliberate.
	Forced bool `json:"forced"`
}

// FingerprintFor computes the fingerprint a record of this scope must carry. A
// rule-scope record has no subject at all, so pin, subject and rule scopes over
// the same finding yield three DIFFERENT fingerprints and a record cannot be
// relabelled into a wider scope without invalidating itself.
func FingerprintFor(ruleID, subjectKind, subject string, scope Scope) string {
	if scope == ScopeRule {
		subjectKind, subject = "", ""
	}
	return finding.Fingerprint(ruleID, subjectKind, subject, string(scope))
}

// EvidenceDigest is the hex sha256 over a finding's evidence lines, canonically
// encoded. It is what a pin binds to.
func EvidenceDigest(f finding.Finding) (string, error) {
	ev := f.Evidence
	if ev == nil {
		ev = []string{}
	}
	d, err := baseline.Digest(struct {
		Evidence []string `json:"evidence"`
	}{Evidence: ev})
	if err != nil {
		return "", err
	}
	return baseline.Hex(d[:]), nil
}

// Request is what a caller asks for; New turns it into a Record.
type Request struct {
	// Finding is the finding being adjudicated. Its RuleID must declare an
	// epoch in the registry.
	Finding finding.Finding

	Scope  Scope
	Reason string
	By     string

	// Now is the decision time (INV-4: passed in, never read from the clock).
	Now time.Time

	// Expiry is how long the judgement lasts. Zero means DefaultExpiry.
	//
	// There is no value meaning "never". That is a deliberate omission: a
	// permanent suppression is indistinguishable, a year later, from a check
	// that was never written, and the operator who would need to know is the one
	// who did not write it. A standing exception is re-adjudicated annually at
	// worst, which is cheap, or it is not actually justified.
	Expiry time.Duration

	// EvidenceDigest overrides the digest computed from Finding.Evidence. Pins
	// only; normally left empty.
	EvidenceDigest string

	// Forced must be true for ScopeRule.
	Forced bool
}

// New builds a validated Record.
//
// It refuses a finding whose rule declares no epoch. That refusal is the honest
// answer: without a declaration there is nothing to bind the judgement to, so
// the record could never be told apart from one made against semantics that have
// since moved. The error names the file to edit.
func New(reg Registry, req Request) (Record, error) {
	if !req.Scope.Valid() {
		return Record{}, fmt.Errorf("%w: %q is not one of pin, subject, rule",
			ErrRecord, string(req.Scope))
	}
	if req.Now.IsZero() {
		return Record{}, fmt.Errorf("%w: no decision time was supplied", ErrRecord)
	}
	sem, ok := reg.Lookup(req.Finding.RuleID)
	if !ok {
		return Record{}, fmt.Errorf("%w: rule %q declares no fingerprint epoch, so a judgement "+
			"about it could not be told apart later from one made against semantics that have "+
			"changed; declare it in internal/adjudicate/epoch.go first",
			ErrEpoch, req.Finding.RuleID)
	}
	digest, err := sem.Digest()
	if err != nil {
		return Record{}, err
	}
	expiry := req.Expiry
	if expiry == 0 {
		expiry = DefaultExpiry
	}
	if expiry <= 0 {
		return Record{}, fmt.Errorf("%w: an expiry of %v is not a duration a judgement can last",
			ErrRecord, req.Expiry)
	}
	if expiry > MaxExpiry {
		return Record{}, fmt.Errorf("%w: %v exceeds the %v maximum; there is no non-expiring "+
			"suppression in this format", ErrRecord, expiry, MaxExpiry)
	}
	ev := req.EvidenceDigest
	if req.Scope == ScopePin && ev == "" {
		if ev, err = EvidenceDigest(req.Finding); err != nil {
			return Record{}, err
		}
	}
	if req.Scope != ScopePin {
		ev = ""
	}
	kind, subject := req.Finding.SubjectKind, req.Finding.Subject
	if req.Scope == ScopeRule {
		kind, subject = "", ""
	}
	rec := Record{
		Fingerprint:      FingerprintFor(req.Finding.RuleID, kind, subject, req.Scope),
		RuleID:           req.Finding.RuleID,
		SubjectKind:      kind,
		Subject:          subject,
		Scope:            req.Scope,
		EvidenceDigest:   ev,
		FingerprintEpoch: sem.Epoch,
		SemanticsDigest:  digest,
		Reason:           strings.TrimSpace(req.Reason),
		By:               strings.TrimSpace(req.By),
		At:               req.Now.Format(time.RFC3339),
		ExpiresAt:        req.Now.Add(expiry).Format(time.RFC3339),
		Forced:           req.Forced,
	}
	if err := rec.Validate(); err != nil {
		return Record{}, err
	}
	return rec, nil
}

// Validate checks everything about a record that can be checked without knowing
// the current epoch or the current time.
//
// It is run on construction AND on every record read from disk, because a record
// on disk has been outside this package's control. A record that fails here
// suppresses nothing (see Apply) -- an unusable suppression is a coverage gap,
// never an active one.
func (r Record) Validate() error {
	if !r.Scope.Valid() {
		return fmt.Errorf("%w: %q is not one of pin, subject, rule", ErrRecord, string(r.Scope))
	}
	if r.RuleID == "" {
		return fmt.Errorf("%w: no rule id", ErrRecord)
	}
	if err := validReason(r.Reason); err != nil {
		return err
	}
	if r.By == "" {
		return fmt.Errorf("%w: no adjudicator recorded", ErrRecord)
	}
	if r.FingerprintEpoch < 1 {
		return fmt.Errorf("%w: fingerprint_epoch %d; epochs start at 1",
			ErrRecord, r.FingerprintEpoch)
	}
	if !hex64.MatchString(r.SemanticsDigest) {
		return fmt.Errorf("%w: semantics_digest %q is not a sha256 hex digest",
			ErrRecord, r.SemanticsDigest)
	}
	switch r.Scope {
	case ScopeRule:
		// A rule-scope record that names a subject reads as narrower than it is,
		// to a human skimming a list and to any tool that groups by subject.
		if r.SubjectKind != "" || r.Subject != "" {
			return fmt.Errorf("%w: a rule-scope adjudication names subject %q/%q; rule scope "+
				"suppresses the check EVERYWHERE and must not read as narrower",
				ErrRecord, r.SubjectKind, r.Subject)
		}
		if !r.Forced {
			return fmt.Errorf("%w: a rule-scope adjudication turns a whole check off and requires "+
				"an explicit force", ErrRecord)
		}
		if r.EvidenceDigest != "" {
			return fmt.Errorf("%w: only a pin binds evidence", ErrRecord)
		}
	case ScopeSubject:
		if r.Subject == "" || r.SubjectKind == "" {
			return fmt.Errorf("%w: a subject-scope adjudication needs a subject", ErrRecord)
		}
		if r.EvidenceDigest != "" {
			return fmt.Errorf("%w: only a pin binds evidence", ErrRecord)
		}
	case ScopePin:
		if r.Subject == "" || r.SubjectKind == "" {
			return fmt.Errorf("%w: a pin needs a subject", ErrRecord)
		}
		if !hex64.MatchString(r.EvidenceDigest) {
			return fmt.Errorf("%w: a pin binds an evidence digest; %q is not a sha256 hex digest",
				ErrRecord, r.EvidenceDigest)
		}
	}
	if want := FingerprintFor(r.RuleID, r.SubjectKind, r.Subject, r.Scope); want != r.Fingerprint {
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
	if exp.Sub(at) > MaxExpiry {
		return fmt.Errorf("%w: %s..%s is longer than the %v maximum; there is no non-expiring "+
			"suppression in this format", ErrRecord, r.At, r.ExpiresAt, MaxExpiry)
	}
	return nil
}

// Expiry returns the moment the judgement lapses.
func (r Record) Expiry() (time.Time, error) { return parseStamp(r.ExpiresAt, "expires_at") }

// Matches reports whether this record covers f, ignoring epoch and expiry --
// those are Apply's decisions. evidenceMatched is meaningful for pins only: a
// pin whose fingerprint matches but whose evidence does not is SPENT, which is a
// different outcome from a pin that matched nothing.
func (r Record) Matches(f finding.Finding) (matched, evidenceMatched bool) {
	if r.RuleID != f.RuleID {
		return false, false
	}
	switch r.Scope {
	case ScopeRule:
		return true, true
	case ScopeSubject:
		return r.SubjectKind == f.SubjectKind && r.Subject == f.Subject, true
	case ScopePin:
		if r.SubjectKind != f.SubjectKind || r.Subject != f.Subject {
			return false, false
		}
		got, err := EvidenceDigest(f)
		if err != nil {
			// An evidence set that cannot be canonically encoded cannot be
			// compared, so the pin does not apply. Fail closed.
			return true, false
		}
		return true, got == r.EvidenceDigest
	default:
		return false, false
	}
}

// Current reports whether the record is still bound to the matching semantics in
// force. The reason it is not is returned for the operator, since "stale" on its
// own is not actionable.
func (r Record) Current(reg Registry) (bool, string) {
	sem, ok := reg.Lookup(r.RuleID)
	if !ok {
		return false, fmt.Sprintf("rule %q declares no fingerprint epoch in this build, so the "+
			"semantics this judgement was made against cannot be confirmed", r.RuleID)
	}
	digest, err := sem.Digest()
	if err != nil {
		return false, fmt.Sprintf("rule %q has an unusable epoch declaration: %v", r.RuleID, err)
	}
	switch {
	case sem.Epoch != r.FingerprintEpoch:
		return false, fmt.Sprintf("adjudicated at fingerprint epoch %d; rule %q is now at epoch %d",
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

// validReason enforces the mandatory reason. It is checked in runes of actual
// content, so whitespace, a tab, a non-breaking space or a lone "ok" are all
// refused: the point is that a third party can re-evaluate the decision.
func validReason(reason string) error {
	trimmed := strings.TrimSpace(reason)
	if trimmed == "" {
		return fmt.Errorf("%w: a suppression with no reason cannot be re-evaluated by anyone, "+
			"including whoever wrote it", ErrRecord)
	}
	if trimmed != reason {
		return fmt.Errorf("%w: reason has leading or trailing whitespace, which would give one "+
			"reason two spellings inside a signed document", ErrRecord)
	}
	content := 0
	for _, r := range trimmed {
		if !unicode.IsSpace(r) {
			content++
		}
	}
	if content < MinReasonRunes {
		return fmt.Errorf("%w: reason %q carries %d characters of content; at least %d are "+
			"required, because a reason too short to re-evaluate is the same as none",
			ErrRecord, trimmed, content, MinReasonRunes)
	}
	if content > MaxReasonRunes {
		return fmt.Errorf("%w: reason is longer than %d characters", ErrRecord, MaxReasonRunes)
	}
	return nil
}

// parseStamp requires RFC3339 with an explicit offset. "Z" counts: it is an
// explicit offset of zero. A bare local time does not.
func parseStamp(s, field string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: %s is empty; an adjudication without a %s cannot be "+
			"aged out, and there is no non-expiring suppression in this format",
			ErrRecord, field, field)
	}
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return time.Time{}, fmt.Errorf("%w: %s %q is not RFC3339 with an explicit offset: %v",
			ErrRecord, field, s, err)
	}
	return t, nil
}

// sortRecords orders records for storage and for reporting: widest scope last so
// a reader meets the narrow suppressions first, then by fingerprint, which is
// unique per (rule, subject, scope). The order is total and derived only from
// the records, so two hosts holding the same set produce the same bytes.
func sortRecords(recs []Record) {
	sort.Slice(recs, func(i, j int) bool {
		a, b := recs[i], recs[j]
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
