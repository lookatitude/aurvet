// internal/adjudicate/adjudicate_test.go
//
// Attack-first. Every test in the first half asserts that something REFUSES to
// suppress; the round trips come afterwards. A suppression layer whose tests
// only prove that suppression works is untested, because the failure mode that
// matters is a suppression that hides a finding nobody assessed.
package adjudicate

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

const fixtures = "../../testdata/adjudicate"

var (
	// now and the stamps derived from it are FIXED. INV-4: expiry is evaluated
	// against a timestamp passed in, so the same inputs must give the same
	// answer on every day this suite ever runs.
	now  = time.Date(2026, 8, 6, 12, 0, 0, 0, time.FixedZone("+02:00", 2*3600))
	reg  = BuiltIn()
	find = finding.Finding{
		RuleID:      "integrity-digest-mismatch",
		SubjectKind: "path",
		Subject:     "usr/bin/curl",
		Severity:    finding.SevCritical,
		Summary:     "digest differs from the package record",
		Evidence:    []string{"recorded=aa", "observed=bb"},
	}
	other = finding.Finding{
		RuleID:      "integrity-digest-mismatch",
		SubjectKind: "path",
		Subject:     "usr/bin/ssh",
		Severity:    finding.SevCritical,
		Summary:     "digest differs from the package record",
		Evidence:    []string{"recorded=cc", "observed=dd"},
	}
	gap = finding.Gap{RuleID: "integrity-coverage", Subject: "librewolf", Reason: "mtree unreadable"}
)

func mustRecord(t *testing.T, req Request) Record {
	t.Helper()
	r, err := New(reg, req)
	if err != nil {
		t.Fatalf("New: %v", err)
	}
	return r
}

func baseReq(f finding.Finding, scope Scope) Request {
	req := Request{
		Finding: f,
		Scope:   scope,
		Reason:  "vendored curl replaced by a local rebuild, tracked in ticket OPS-441",
		By:      "operator@host",
		Now:     now,
	}
	if scope == ScopePin {
		d, err := EvidenceDigest(f)
		if err != nil {
			panic(err)
		}
		req.EvidenceDigest = d
	}
	if scope == ScopeRule {
		req.Forced = true
	}
	return req
}

func in(t *testing.T, r finding.Result, f finding.Finding) bool {
	t.Helper()
	for _, g := range r.Findings {
		if g.RuleID == f.RuleID && g.Subject == f.Subject {
			return true
		}
	}
	return false
}

func statusOf(t *testing.T, o Outcome, fp string) Status {
	t.Helper()
	for _, s := range o.Statuses {
		if s.Record.Fingerprint == fp {
			return s
		}
	}
	t.Fatalf("no status reported for %s: a record that vanished from the report is invisible", fp)
	return Status{}
}

// -- attacks: things that must not suppress ---------------------------------

// An empty or whitespace-only reason is the whole failure mode of a suppression
// file nobody can re-evaluate. It must be impossible to construct, not merely
// discouraged.
func TestEmptyReasonIsRefused(t *testing.T) {
	for _, reason := range []string{"", " ", "\t\n ", "  ", "n/a", "ok"} {
		req := baseReq(find, ScopeSubject)
		req.Reason = reason
		if _, err := New(reg, req); err == nil {
			t.Fatalf("reason %q was accepted", reason)
		}
	}
}

// The reason cannot be smuggled past Validate either: a record hand-edited on
// disk to carry an empty reason must be invalid, and an invalid record must
// suppress nothing while remaining visible as a gap (INV-9).
func TestHandEditedEmptyReasonSuppressesNothing(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	rec.Reason = "   "
	o := Apply(Set{Records: []Record{rec}, Source: "test"},
		finding.Result{Findings: []finding.Finding{find}}, now)
	if len(o.Suppressed) != 0 {
		t.Fatal("a record with an empty reason suppressed a finding")
	}
	if !in(t, o.Kept, find) {
		t.Fatal("the finding disappeared")
	}
	if st := statusOf(t, o, rec.Fingerprint); st.State != StateInvalid {
		t.Fatalf("state = %s, want %s", st.State, StateInvalid)
	}
	if len(o.Kept.Gaps) == 0 {
		t.Fatal("an unusable adjudication record is a coverage gap, not silence (INV-9)")
	}
}

// Expiry: past 180 days the suppression stops suppressing AND says so. A
// suppression that quietly outlives its reason is the thing expiry exists to
// prevent.
func TestExpiredSuppressionDoesNotSuppressAndSaysSo(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	later := now.Add(DefaultExpiry).Add(time.Second)
	o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find}}, later)
	if len(o.Suppressed) != 0 {
		t.Fatal("an expired suppression still suppressed")
	}
	if !in(t, o.Kept, find) {
		t.Fatal("the finding did not come back after expiry")
	}
	st := statusOf(t, o, rec.Fingerprint)
	if st.State != StateExpired {
		t.Fatalf("state = %s, want %s", st.State, StateExpired)
	}
	if !strings.Contains(st.Detail, "expired") {
		t.Fatalf("detail does not say it expired: %q", st.Detail)
	}
	// One second before expiry it is still active, so the boundary is not
	// accidentally a day out.
	just := now.Add(DefaultExpiry).Add(-time.Second)
	if o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find}}, just); len(o.Suppressed) != 1 {
		t.Fatal("the suppression expired early")
	}
}

// A non-expiring suppression is not expressible. Zero means "use the default",
// and an out-of-range or hand-cleared expiry is refused rather than treated as
// forever.
func TestNonExpiringSuppressionIsNotExpressible(t *testing.T) {
	req := baseReq(find, ScopeSubject)
	req.Expiry = -time.Hour
	if _, err := New(reg, req); err == nil {
		t.Fatal("a negative expiry was accepted")
	}
	req.Expiry = MaxExpiry + time.Hour
	if _, err := New(reg, req); err == nil {
		t.Fatal("an expiry beyond the maximum was accepted")
	}
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	for _, bad := range []string{"", "never", "2027-01-01", "2027-01-01T00:00:00"} {
		mutated := rec
		mutated.ExpiresAt = bad
		if err := mutated.Validate(); err == nil {
			t.Fatalf("expires_at %q was accepted", bad)
		}
		o := Apply(Set{Records: []Record{mutated}}, finding.Result{Findings: []finding.Finding{find}}, now)
		if len(o.Suppressed) != 0 {
			t.Fatalf("expires_at %q suppressed a finding", bad)
		}
	}
}

// A rule-scope record is the widest thing in the format and must not be
// constructible by accident, nor readable as anything narrower.
func TestRuleScopeRequiresForceAndCarriesNoSubject(t *testing.T) {
	req := baseReq(find, ScopeRule)
	req.Forced = false
	if _, err := New(reg, req); err == nil {
		t.Fatal("a rule-scope adjudication was accepted without an explicit force")
	}
	rec := mustRecord(t, baseReq(find, ScopeRule))
	if rec.Subject != "" || rec.SubjectKind != "" {
		t.Fatalf("a rule-scope record kept a subject (%q/%q); it would read as narrower than it is",
			rec.SubjectKind, rec.Subject)
	}
	// Hand-adding a subject back must invalidate it rather than narrow it.
	mutated := rec
	mutated.Subject = "usr/bin/curl"
	if err := mutated.Validate(); err == nil {
		t.Fatal("a rule-scope record with a subject validated")
	}
	// And a valid one is echoed for the run header.
	o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find, other}}, now)
	if len(o.Suppressed) != 2 {
		t.Fatalf("rule scope suppressed %d of 2 findings", len(o.Suppressed))
	}
	if len(o.RuleScoped()) != 1 {
		t.Fatal("an active rule-scope suppression was not echoed for the run header")
	}
}

// The scopes are ordered by blast radius and must not be interchangeable: a
// subject-scope record cannot be relabelled as a rule-scope one and keep
// working, because the fingerprint binds the scope class.
func TestScopesAreNotInterchangeable(t *testing.T) {
	if ScopePin.Breadth() >= ScopeSubject.Breadth() || ScopeSubject.Breadth() >= ScopeRule.Breadth() {
		t.Fatal("scope breadth is not strictly ordered pin < subject < rule")
	}
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	mutated := rec
	mutated.Scope = ScopeRule
	if err := mutated.Validate(); err == nil {
		t.Fatal("a subject-scope record relabelled as rule-scope validated")
	}
	o := Apply(Set{Records: []Record{mutated}}, finding.Result{Findings: []finding.Finding{find, other}}, now)
	if len(o.Suppressed) != 0 {
		t.Fatal("a relabelled record widened its own blast radius")
	}
}

// A pin binds the exact evidence. When the evidence changes the pin is spent:
// the finding reappears exactly once and the pin is reported, rather than
// following the subject silently.
func TestPinDoesNotFollowChangedEvidence(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopePin))
	changed := find
	changed.Evidence = []string{"recorded=aa", "observed=ee"}
	o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{changed}}, now)
	if len(o.Suppressed) != 0 {
		t.Fatal("a pin suppressed a finding whose evidence had changed")
	}
	st := statusOf(t, o, rec.Fingerprint)
	if st.State != StateSpent {
		t.Fatalf("state = %s, want %s", st.State, StateSpent)
	}
	// The same pin over unchanged evidence still works, so the failure above is
	// about the evidence and not about pins in general.
	if o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find}}, now); len(o.Suppressed) != 1 {
		t.Fatal("a pin failed to suppress its own unchanged finding")
	}
}

// A fingerprint that does not match the fields beside it is a forged narrowing:
// the record claims to be about one thing and names another.
func TestFingerprintMustMatchItsFields(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	mutated := rec
	mutated.Subject = "usr/bin/ssh"
	if err := mutated.Validate(); err == nil {
		t.Fatal("a record whose fingerprint does not cover its subject validated")
	}
	mutated = rec
	mutated.Fingerprint = strings.Repeat("0", len(rec.Fingerprint))
	if err := mutated.Validate(); err == nil {
		t.Fatal("a record with an unrelated fingerprint validated")
	}
}

// Gaps are never suppressible. Adjudicating a coverage gap away would turn
// "not examined" into "clean", which is INV-3 exactly.
func TestGapsAreNeverSuppressed(t *testing.T) {
	req := baseReq(find, ScopeRule)
	req.Finding = finding.Finding{RuleID: "integrity-coverage", SubjectKind: "package", Subject: "librewolf"}
	req.Forced = true
	rec := mustRecord(t, req)
	o := Apply(Set{Records: []Record{rec}},
		finding.Result{Findings: []finding.Finding{find}, Gaps: []finding.Gap{gap}}, now)
	found := false
	for _, g := range o.Kept.Gaps {
		if g.RuleID == gap.RuleID && g.Subject == gap.Subject {
			found = true
		}
	}
	if !found {
		t.Fatal("an adjudication removed a coverage gap (INV-3)")
	}
	if o.Kept.Complete() {
		t.Fatal("the result reads complete despite an unexamined package")
	}
}

// -- the epoch, end to end --------------------------------------------------

// The task's reason for existing: three outcomes must be distinguishable, and
// the middle one must be reachable.
func TestEpochBumpMakesSuppressionStaleNotGoneAndNotActive(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	res := finding.Result{Findings: []finding.Finding{find}}

	// 1. active — the epoch and the semantics digest agree with the registry.
	active := Apply(Set{Records: []Record{rec}}, res, now)
	if len(active.Suppressed) != 1 || in(t, active.Kept, find) {
		t.Fatal("the freshly made adjudication did not suppress its finding")
	}
	if st := statusOf(t, active, rec.Fingerprint); st.State != StateActive {
		t.Fatalf("state = %s, want %s", st.State, StateActive)
	}

	// 2. stale — matching semantics moved. The judgement is preserved, it no
	// longer suppresses, and the operator is told why.
	bumped := bumpEpoch(t, reg, find.RuleID)
	stale := ApplyWith(bumped, Set{Records: []Record{rec}}, res, now)
	if len(stale.Suppressed) != 0 {
		t.Fatal("a suppression bound to a superseded epoch kept suppressing (silently persisting)")
	}
	if !in(t, stale.Kept, find) {
		t.Fatal("the finding did not reappear after the epoch bump")
	}
	st := statusOf(t, stale, rec.Fingerprint)
	if st.State != StateStale {
		t.Fatalf("state = %s, want %s (silently vanishing is the other wrong answer)", st.State, StateStale)
	}
	if !strings.Contains(st.Detail, "re-adjudicate") {
		t.Fatalf("detail does not tell the operator to re-adjudicate: %q", st.Detail)
	}
	if st.Record.Reason != rec.Reason {
		t.Fatal("the recorded judgement was lost rather than preserved")
	}

	// 3. gone — the record was deleted. Nothing is reported about it at all,
	// which is what makes it distinguishable from stale.
	gone := ApplyWith(bumped, Set{}, res, now)
	if len(gone.Statuses) != 0 {
		t.Fatal("a deleted record still reported a status")
	}
	if !in(t, gone.Kept, find) {
		t.Fatal("the finding is missing with no record at all")
	}

	// All three are distinguishable by the tuple (suppressed, reported).
	type shape struct {
		suppressed, reported int
	}
	got := []shape{
		{len(active.Suppressed), len(active.Statuses)},
		{len(stale.Suppressed), len(stale.Statuses)},
		{len(gone.Suppressed), len(gone.Statuses)},
	}
	if got[0] == got[1] || got[1] == got[2] || got[0] == got[2] {
		t.Fatalf("the three epoch outcomes are not distinguishable: %+v", got)
	}
}

// The semantics digest is the enforcement, not the epoch number: an author who
// changes matching inputs and FORGETS to bump the epoch still cannot keep an
// old suppression alive.
func TestChangedSemanticsWithoutAnEpochBumpIsStillStale(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	changed := mutateInputs(t, reg, find.RuleID) // same epoch, different inputs
	o := ApplyWith(changed, Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find}}, now)
	if len(o.Suppressed) != 0 {
		t.Fatal("changing matching inputs without bumping the epoch kept the suppression alive")
	}
	if st := statusOf(t, o, rec.Fingerprint); st.State != StateStale {
		t.Fatalf("state = %s, want %s", st.State, StateStale)
	}
}

// A rule the registry does not know about cannot be adjudicated at all, and a
// record naming one reads as stale rather than as an active suppression: an
// epoch we cannot compare against is an unknown, and an unknown must not
// suppress.
func TestUndeclaredRuleFailsClosed(t *testing.T) {
	req := baseReq(find, ScopeSubject)
	req.Finding.RuleID = "rule-that-declares-no-epoch"
	if _, err := New(reg, req); err == nil {
		t.Fatal("a finding from a rule with no declared epoch was adjudicated")
	}
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	empty, err := NewRegistry()
	if err != nil {
		t.Fatal(err)
	}
	o := ApplyWith(empty, Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find}}, now)
	if len(o.Suppressed) != 0 {
		t.Fatal("a record for an undeclared rule suppressed a finding")
	}
	if st := statusOf(t, o, rec.Fingerprint); st.State != StateStale {
		t.Fatalf("state = %s, want %s", st.State, StateStale)
	}
}

// -- dead suppressions -------------------------------------------------------

func TestDeadSuppressionIsReported(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	// The finding it was written for is gone: fixed, or a rule that moved.
	o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{other}}, now)
	st := statusOf(t, o, rec.Fingerprint)
	if st.State != StateDead {
		t.Fatalf("state = %s, want %s", st.State, StateDead)
	}
	if len(o.ByState(StateDead)) != 1 {
		t.Fatal("the dead suppression was not reported for removal")
	}
	if !strings.Contains(st.Detail, "matched nothing") {
		t.Fatalf("detail does not say it matched nothing: %q", st.Detail)
	}
	if len(o.NeedsAttention()) != 1 {
		t.Fatal("a dead suppression does not need attention?")
	}
}

// -- INV-6: a suppressed finding's absence is visible ------------------------

func TestSuppressedFindingsAreVisibleAndKeepTheirSeverity(t *testing.T) {
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	o := Apply(Set{Records: []Record{rec}}, finding.Result{Findings: []finding.Finding{find, other}}, now)
	if len(o.Suppressed) != 1 {
		t.Fatalf("Suppressed has %d entries, want 1", len(o.Suppressed))
	}
	s := o.Suppressed[0]
	if s.Finding.Severity != finding.SevCritical {
		t.Fatal("a suppressed finding lost its severity, so nothing downstream can report what was hidden")
	}
	if s.Record.Reason == "" || s.Record.Scope == "" {
		t.Fatal("the suppression does not carry why or how widely it applied")
	}
	if o.Kept.MaxSeverity() != finding.SevCritical {
		t.Fatal("expected the OTHER critical to still be in Kept")
	}
}

// -- store: fail closed ------------------------------------------------------

func TestUnparseableStoreSuppressesNothing(t *testing.T) {
	entries, err := os.ReadDir(filepath.Join(fixtures, "broken"))
	if err != nil {
		t.Fatal(err)
	}
	if len(entries) == 0 {
		t.Fatal("no broken-store fixtures")
	}
	for _, e := range entries {
		name := e.Name()
		t.Run(name, func(t *testing.T) {
			raw, err := os.ReadFile(filepath.Join(fixtures, "broken", name))
			if err != nil {
				t.Fatal(err)
			}
			set := ParseStore(name, raw)
			if len(set.Records) != 0 {
				t.Fatalf("%s yielded %d records", name, len(set.Records))
			}
			if len(set.Faults) == 0 {
				t.Fatalf("%s parsed as an empty store with no fault reported", name)
			}
			o := Apply(set, finding.Result{Findings: []finding.Finding{find}}, now)
			if len(o.Suppressed) != 0 {
				t.Fatalf("%s suppressed a finding", name)
			}
			if len(o.Kept.Gaps) == 0 {
				t.Fatalf("%s produced neither suppression nor gap: it read as silence (INV-9)", name)
			}
		})
	}
}

func TestOversizedStoreIsRefused(t *testing.T) {
	set := ParseStore("huge", make([]byte, MaxStoreBytes+1))
	if len(set.Records) != 0 || len(set.Faults) == 0 {
		t.Fatal("an oversized store was not refused")
	}
}

// A signature is verified over the RAW bytes before anything parses them, and a
// store whose signature does not verify suppresses nothing.
func TestSignedStoreRejectsTamperedBytes(t *testing.T) {
	priv, pub := testKey(t)
	rec := mustRecord(t, baseReq(find, ScopeSubject))
	raw, err := MarshalStore([]Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := SignStore(priv, raw)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*baseline.PublicKey{pub}

	set := ParseSignedStore("store", raw, sig, trusted)
	if len(set.Faults) != 0 || len(set.Records) != 1 {
		t.Fatalf("a validly signed store was refused: %+v", set.Faults)
	}
	if o := Apply(set, finding.Result{Findings: []finding.Finding{find}}, now); len(o.Suppressed) != 1 {
		t.Fatal("a validly signed store did not suppress")
	}

	// Flip every single byte in turn: none may verify.
	for i := 0; i < len(raw); i++ {
		for _, bit := range []byte{0x01, 0x80} {
			bad := append([]byte(nil), raw...)
			bad[i] ^= bit
			if s := ParseSignedStore("store", bad, sig, trusted); len(s.Records) != 0 {
				t.Fatalf("byte %d flipped by %#x still yielded records", i, bit)
			}
		}
	}
	// Wrong namespace: an adjudication store signature must not be replayable
	// from another document type, and vice versa.
	wrongNS, err := baseline.Sign(priv, baseline.NamespaceManifest, raw)
	if err != nil {
		t.Fatal(err)
	}
	if s := ParseSignedStore("store", raw, wrongNS, trusted); len(s.Records) != 0 {
		t.Fatal("a manifest-namespace signature was accepted over an adjudication store")
	}
	// Untrusted key.
	if s := ParseSignedStore("store", raw, sig, nil); len(s.Records) != 0 {
		t.Fatal("a store signed by an untrusted key was accepted")
	}
	// Absent signature.
	if s := ParseSignedStore("store", raw, nil, trusted); len(s.Records) != 0 {
		t.Fatal("an unsigned store was accepted on the signed path")
	}
}

// Round trip through the canonical form must be byte-stable and order-
// independent: the store is a signed document, so two spellings of one set
// would be two digests.
func TestStoreRoundTripIsCanonicalAndOrderIndependent(t *testing.T) {
	a := mustRecord(t, baseReq(find, ScopeSubject))
	b := mustRecord(t, baseReq(other, ScopeSubject))
	one, err := MarshalStore([]Record{a, b})
	if err != nil {
		t.Fatal(err)
	}
	two, err := MarshalStore([]Record{b, a})
	if err != nil {
		t.Fatal(err)
	}
	if string(one) != string(two) {
		t.Fatal("record order changed the canonical bytes")
	}
	if canon, err := baseline.Canonical(one); err != nil || string(canon) != string(one) {
		t.Fatalf("MarshalStore output is not canonical: %v", err)
	}
	set := ParseStore("store", one)
	if len(set.Faults) != 0 || len(set.Records) != 2 {
		t.Fatalf("round trip lost records: %+v", set)
	}
}

// -- distinctness from triage ------------------------------------------------

// Adjudication must not become a heavier spelling of triage, and triage must
// not acquire the weight of a signed judgement. The cheapest durable guard is
// structural: this package does not import the triage layer, so no code path
// can promote one into the other by accident.
func TestAdjudicationDoesNotDependOnTheTriageLayer(t *testing.T) {
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatal(err)
	}
	for name, pkg := range pkgs {
		for path, f := range pkg.Files {
			if strings.HasSuffix(path, "_test.go") {
				continue
			}
			for _, imp := range f.Imports {
				if strings.Contains(imp.Path.Value, "internal/report") {
					t.Fatalf("%s (%s) imports the triage layer: %s", path, name, imp.Path.Value)
				}
			}
		}
	}
}

// -- helpers ----------------------------------------------------------------

// testKey loads the throwaway key committed under testdata/baseline. It is not
// a release key and nothing here generates one: real signing keys are a human
// action, held offline, and never appear in this tree.
func testKey(t *testing.T) (*baseline.PrivateKey, *baseline.PublicKey) {
	t.Helper()
	privPEM, err := os.ReadFile("../../testdata/baseline/testkey")
	if err != nil {
		t.Fatal(err)
	}
	k, err := baseline.ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatal(err)
	}
	return k, k.PublicKey()
}

// bumpEpoch returns a registry identical to r except that ruleID's epoch is one
// higher — what a rule author does when matching semantics change.
func bumpEpoch(t *testing.T, r Registry, ruleID string) Registry {
	t.Helper()
	decls := r.All()
	for i := range decls {
		if decls[i].RuleID == ruleID {
			decls[i].Epoch++
			decls[i].Inputs = append(append([]string(nil), decls[i].Inputs...), "a new matching input")
		}
	}
	out, err := NewRegistry(decls...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

// mutateInputs changes ruleID's matching inputs and deliberately does NOT bump
// its epoch, which is the mistake the semantics digest has to catch.
func mutateInputs(t *testing.T, r Registry, ruleID string) Registry {
	t.Helper()
	decls := r.All()
	for i := range decls {
		if decls[i].RuleID == ruleID {
			decls[i].Inputs = append(append([]string(nil), decls[i].Inputs...), "an undeclared new input")
		}
	}
	out, err := NewRegistry(decls...)
	if err != nil {
		t.Fatal(err)
	}
	return out
}
