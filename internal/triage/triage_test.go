// internal/triage/triage_test.go
//
// The attacks first. Every test in the first half is a way a lightweight record
// could acquire weight it has not earned -- outliving its expiry, surviving a
// semantics change, hiding a coverage gap, disabling a whole check, or being
// mistaken for the signed judgement that gates `baseline init`.
package triage

import (
	"go/parser"
	"go/token"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/finding"
)

func now(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-08-06T09:00:00+02:00")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// theFinding's rule declares a fingerprint epoch, so records about it are bound.
// The undeclared case has its own test.
func theFinding() finding.Finding {
	return finding.Finding{
		RuleID: "surface-profiled-unowned", SubjectKind: "file",
		Subject:  "etc/profile.d/local-path.sh",
		Severity: finding.SevInfo,
		Summary:  "file in a shell-startup drop-in directory is owned by no installed package",
		Evidence: []string{"no installed package records this path, resolving symlinks"},
		Limits:   "a hand-written snippet is ordinary administration",
	}
}

func mustNew(t *testing.T, req Request) Record {
	t.Helper()
	rec, err := New(adjudicate.BuiltIn(), req)
	if err != nil {
		t.Fatalf("New(%s/%s): %v", req.Verb, req.Scope, err)
	}
	return rec
}

func req(v Verb, f finding.Finding, at time.Time) Request {
	return Request{Finding: f, Verb: v, Scope: adjudicate.ScopeSubject, Now: at, Note: "seen"}
}

// -- attack 1: a triage record that turns a whole check off -------------------

// Rule scope is echoed in every later run header (spec §12) and needs a --force
// under `adjudicate`. An unsigned record with no author cannot answer the
// question that header provokes, so the widest suppression must not also be the
// cheapest one to create.
func TestTriageRefusesRuleScope(t *testing.T) {
	r := req(VerbAck, theFinding(), now(t))
	r.Scope = adjudicate.ScopeRule
	if _, err := New(adjudicate.BuiltIn(), r); err == nil {
		t.Fatal("New accepted rule scope for a triage record")
	} else if !strings.Contains(err.Error(), "aurvet adjudicate") {
		t.Fatalf("the refusal does not name the command that CAN do this: %v", err)
	}

	// And a record hand-written into the file cannot smuggle it past Validate.
	rec := mustNew(t, req(VerbAck, theFinding(), now(t)))
	rec.Scope = adjudicate.ScopeRule
	rec.Fingerprint = adjudicate.FingerprintFor(rec.RuleID, "", "", adjudicate.ScopeRule)
	if err := rec.Validate(); err == nil {
		t.Fatal("Validate accepted a hand-written rule-scope triage record")
	}
}

// -- attack 2: a record that never expires ------------------------------------

func TestThereIsNoNonExpiringTriageRecord(t *testing.T) {
	at := now(t)
	for _, tc := range []struct {
		name   string
		verb   Verb
		expiry time.Duration
	}{
		{"negative", VerbAck, -time.Hour},
		{"ack beyond 90 days", VerbAck, 91 * 24 * time.Hour},
		{"snooze beyond 30 days", VerbSnooze, 31 * 24 * time.Hour},
		{"a decade", VerbNote, 3650 * 24 * time.Hour},
	} {
		r := req(tc.verb, theFinding(), at)
		r.Expiry = tc.expiry
		if _, err := New(adjudicate.BuiltIn(), r); err == nil {
			t.Errorf("%s: New accepted an expiry of %v", tc.name, tc.expiry)
		}
	}

	// The on-disk direction: stretching expires_at by hand makes the record
	// INVALID, which suppresses nothing and raises a gap. A record cannot buy
	// permanence by being written rather than recorded.
	rec := mustNew(t, req(VerbAck, theFinding(), at))
	rec.ExpiresAt = at.AddDate(10, 0, 0).Format(time.RFC3339)
	if err := rec.Validate(); err == nil {
		t.Fatal("Validate accepted a ten-year window on disk")
	}
	out := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{rec}},
		finding.Result{Findings: []finding.Finding{theFinding()}}, at)
	if len(out.Suppressed) != 0 {
		t.Fatalf("a record with a stretched expiry suppressed %d finding(s)", len(out.Suppressed))
	}
	if len(out.Kept.Gaps) != 1 {
		t.Fatalf("an invalid record raised %d gap(s), want 1 (INV-9)", len(out.Kept.Gaps))
	}
}

// Every triage window must be shorter than a signed adjudication's default. The
// lighter weight must not outlive the heavier one, or the price of the heavier
// one buys nothing.
func TestEveryTriageWindowIsShorterThanASignedAdjudication(t *testing.T) {
	for _, v := range Verbs() {
		if v.DefaultExpiry() >= adjudicate.DefaultExpiry {
			t.Errorf("%s defaults to %v, which is not shorter than an adjudication's %v",
				v, v.DefaultExpiry(), adjudicate.DefaultExpiry)
		}
		if v.MaxExpiry() >= adjudicate.DefaultExpiry {
			t.Errorf("%s allows up to %v, which is not shorter than an adjudication's default %v",
				v, v.MaxExpiry(), adjudicate.DefaultExpiry)
		}
		if v.DefaultExpiry() > v.MaxExpiry() {
			t.Errorf("%s defaults to more than its own maximum", v)
		}
	}
	if VerbSnooze.MaxExpiry() >= VerbAck.MaxExpiry() {
		t.Error("snooze is supposed to be the SHORTER suppression; it is not")
	}
}

// -- attack 3: a note that suppresses -----------------------------------------

// The worst of the three would be a `note` that quietly hid something: it is the
// verb an operator reaches for mid-investigation, precisely because they want to
// keep seeing the finding.
func TestANoteSuppressesNothing(t *testing.T) {
	at := now(t)
	f := theFinding()
	res := finding.Result{Findings: []finding.Finding{f}}

	n := req(VerbNote, f, at)
	n.Note = "correlating with the deploy on the 3rd; leave visible"
	out := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{mustNew(t, n)}}, res, at)

	if len(out.Suppressed) != 0 {
		t.Fatalf("a note suppressed %d finding(s)", len(out.Suppressed))
	}
	if len(out.Kept.Findings) != 1 {
		t.Fatalf("the noted finding is not reported: %d kept", len(out.Kept.Findings))
	}
	if len(out.Annotated) != 1 || out.Annotated[0].Record.Note != n.Note {
		t.Fatalf("the note is not attached to the finding: %+v", out.Annotated)
	}
	st := out.ByState(StateAnnotated)
	if len(st) != 1 {
		t.Fatalf("the note is not reported as annotated: %+v", out.Statuses)
	}
	if !strings.Contains(st[0].Detail, "SUPPRESSES NOTHING") {
		t.Fatalf("the annotated state does not say it suppresses nothing: %q", st[0].Detail)
	}
	if StateAnnotated.Suppresses() {
		t.Fatal("StateAnnotated.Suppresses() is true")
	}
	if VerbNote.Suppresses() {
		t.Fatal("VerbNote.Suppresses() is true")
	}

	// An empty note is refused: `note` exists to carry the note, and an empty one
	// is a file entry with no effect that an operator would believe in.
	empty := req(VerbNote, f, at)
	empty.Note = "   "
	if _, err := New(adjudicate.BuiltIn(), empty); err == nil {
		t.Fatal("New accepted a note with no note")
	}

	// ack and snooze, on the same finding, DO hide it -- so the difference is a
	// property of the verb and not of this fixture.
	for _, v := range []Verb{VerbAck, VerbSnooze} {
		o := ApplyWith(adjudicate.BuiltIn(),
			Set{Records: []Record{mustNew(t, req(v, f, at))}}, res, at)
		if len(o.Suppressed) != 1 || len(o.Kept.Findings) != 0 {
			t.Fatalf("%s did not suppress: %d suppressed, %d kept", v,
				len(o.Suppressed), len(o.Kept.Findings))
		}
	}
}

// -- attack 4: outliving the expiry -------------------------------------------

func TestAnExpiredRecordSuppressesNothingAndSaysWhen(t *testing.T) {
	at := now(t)
	f := theFinding()
	rec := mustNew(t, req(VerbSnooze, f, at))
	res := finding.Result{Findings: []finding.Finding{f}}

	// One second before it lapses it is still hiding the finding.
	just := at.Add(VerbSnooze.DefaultExpiry() - time.Second)
	if o := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{rec}}, res, just); len(o.Suppressed) != 1 {
		t.Fatalf("a snooze stopped suppressing before its expiry")
	}
	// At the expiry it does not.
	o := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{rec}}, res,
		at.Add(VerbSnooze.DefaultExpiry()))
	if len(o.Suppressed) != 0 || len(o.Kept.Findings) != 1 {
		t.Fatalf("an expired snooze still suppresses: %d suppressed", len(o.Suppressed))
	}
	st := o.ByState(StateExpired)
	if len(st) != 1 || !strings.Contains(st[0].Detail, rec.ExpiresAt) {
		t.Fatalf("the expired record does not report when it lapsed: %+v", o.Statuses)
	}
	if !StateExpired.NeedsRemoval() {
		t.Fatal("an expired record is not reported for removal")
	}
}

// -- attack 5: surviving a change in what the rule matches --------------------

func TestAStaleRecordSuppressesNothingAndIsPreserved(t *testing.T) {
	at := now(t)
	f := theFinding()
	rec := mustNew(t, req(VerbAck, f, at))
	rec.Note = "checked against the deploy runbook"
	// The rule's declared matching inputs moved under the record. Editing the
	// record's own bound digest is the same comparison from the other side and
	// does not need a second registry.
	rec.SemanticsDigest = strings.Repeat("9", 64)

	o := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{rec}},
		finding.Result{Findings: []finding.Finding{f}}, at)
	if len(o.Suppressed) != 0 {
		t.Fatalf("a stale record still suppresses %d finding(s)", len(o.Suppressed))
	}
	st := o.ByState(StateStale)
	if len(st) != 1 {
		t.Fatalf("the record is not reported stale: %+v", o.Statuses)
	}
	if !strings.Contains(st[0].Detail, "re-triage") {
		t.Fatalf("the stale detail does not say what to do: %q", st[0].Detail)
	}
	if st[0].Record.Note != rec.Note {
		t.Fatal("a stale record lost the operator's note; it must be preserved verbatim")
	}

	// An epoch BUMP is the other half of the same mechanism.
	bumped, err := adjudicate.NewRegistry(adjudicate.Semantics{
		RuleID: f.RuleID, Epoch: 99, Inputs: []string{"profile.d directory set"},
	})
	if err != nil {
		t.Fatal(err)
	}
	fresh := mustNew(t, req(VerbAck, f, at))
	o2 := ApplyWith(bumped, Set{Records: []Record{fresh}},
		finding.Result{Findings: []finding.Finding{f}}, at)
	if len(o2.ByState(StateStale)) != 1 || len(o2.Suppressed) != 0 {
		t.Fatalf("an epoch bump did not make the record stale: %+v", o2.Statuses)
	}
}

// A rule with no declared epoch is TRIAGEABLE -- deliberately, and unlike an
// adjudication. What it must not do is pretend to a binding it does not have.
func TestAnUndeclaredRuleIsTriageableAndSaysItCannotGoStale(t *testing.T) {
	at := now(t)
	f := theFinding()
	f.RuleID = "some-rule-nobody-declared"

	rec, err := New(adjudicate.BuiltIn(), req(VerbAck, f, at))
	if err != nil {
		t.Fatalf("a keyless record was refused for want of an epoch declaration, which is the "+
			"deadlock this project has already hit four times: %v", err)
	}
	if rec.EpochBound() {
		t.Fatal("a record about an undeclared rule claims an epoch binding")
	}
	o := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{rec}},
		finding.Result{Findings: []finding.Finding{f}}, at)
	if len(o.Suppressed) != 1 {
		t.Fatalf("an unbound record did not suppress: %+v", o.Statuses)
	}
	if c := o.Statuses[0].Caveat; !strings.Contains(c, "NOT read stale") {
		t.Fatalf("the unbound record does not warn that it cannot go stale: %q", c)
	}

	// Half a binding is a lie about checkability and is refused.
	half := mustNew(t, req(VerbAck, theFinding(), at))
	half.SemanticsDigest = ""
	if err := half.Validate(); err == nil {
		t.Fatal("Validate accepted an epoch number with no semantics digest")
	}
}

// -- attack 6: hiding a coverage gap ------------------------------------------

// A gap is "I did not look". No acknowledgement turns unexamined into examined
// (INV-3), and there is no code path here that could -- gaps are copied through
// and never consulted against a record.
func TestNoTriageRecordCanSuppressACoverageGap(t *testing.T) {
	at := now(t)
	f := theFinding()
	gaps := []finding.Gap{
		{RuleID: f.RuleID, Subject: f.Subject, Reason: "the directory could not be listed"},
		{RuleID: "integrity-coverage", Subject: "files", Reason: "nothing was hashed"},
	}
	res := finding.Result{Findings: []finding.Finding{f}, Gaps: gaps}

	for _, v := range Verbs() {
		o := ApplyWith(adjudicate.BuiltIn(),
			Set{Records: []Record{mustNew(t, req(v, f, at))}}, res, at)
		if len(o.Kept.Gaps) != len(gaps) {
			t.Fatalf("%s changed the gap count from %d to %d", v, len(gaps), len(o.Kept.Gaps))
		}
		for i := range gaps {
			if o.Kept.Gaps[i] != gaps[i] {
				t.Fatalf("%s altered gap %d: %+v", v, i, o.Kept.Gaps[i])
			}
		}
	}
}

// -- attack 7: an unreadable store that reads as an empty one -----------------

func TestAnUnusableStoreSuppressesNothingAndIsReported(t *testing.T) {
	for _, tc := range []struct {
		name string
		raw  string
	}{
		{"empty file", ""},
		{"truncated", `{"schema_version":1,"records":[`},
		{"unknown schema", `{"records":[],"schema_version":99}`},
		{"duplicate keys", `{"records":[],"records":[],"schema_version":1}`},
		{"unknown field", `{"records":[],"schema_version":1,"trusted":true}`},
		{"no records", `{"records":[],"schema_version":1}`},
	} {
		set := Parse("triage.json", []byte(tc.raw))
		if len(set.Records) != 0 {
			t.Errorf("%s: yielded %d record(s)", tc.name, len(set.Records))
		}
		if len(set.Faults) == 0 {
			t.Errorf("%s: parsed silently; an unusable store must be reported (INV-9)", tc.name)
		}
		o := ApplyWith(adjudicate.BuiltIn(), set,
			finding.Result{Findings: []finding.Finding{theFinding()}}, now(t))
		if len(o.Kept.Gaps) == 0 {
			t.Errorf("%s: raised no coverage gap", tc.name)
		}
		if len(o.Suppressed) != 0 {
			t.Errorf("%s: suppressed something anyway", tc.name)
		}
	}

	// Oversize is refused BEFORE parsing, not after.
	big := Parse("triage.json", make([]byte, MaxStoreBytes+1))
	if len(big.Faults) != 1 || !strings.Contains(big.Faults[0].Reason, "not parsed at all") {
		t.Fatalf("an oversize store was not refused before parsing: %+v", big.Faults)
	}

	// One bad record among good ones voids only itself: otherwise anyone who can
	// append a single malformed line disables every legitimate record.
	at := now(t)
	good := mustNew(t, req(VerbAck, theFinding(), at))
	raw, err := Marshal([]Record{good})
	if err != nil {
		t.Fatal(err)
	}
	injected := strings.Replace(string(raw), `"records":[`,
		`"records":[{"at":"","evidence_digest":"","expires_at":"","fingerprint":"",`+
			`"fingerprint_epoch":0,"note":"","rule_id":"","scope":"subject","subject":"",`+
			`"subject_kind":"","verb":"ack"},`, 1)
	set := Parse("triage.json", []byte(injected))
	if len(set.Records) != 1 || len(set.Faults) != 1 {
		t.Fatalf("one bad record among good ones: %d kept, %d faults", len(set.Records), len(set.Faults))
	}
}

// -- attack 8: a record that outlives what it was about -----------------------

// §12: "dead suppressions that match nothing are reported for removal." A record
// whose finding stopped occurring is clutter, and clutter hides the next one.
func TestDeadAndSpentRecordsAreReportedForRemoval(t *testing.T) {
	at := now(t)
	f := theFinding()

	dead := ApplyWith(adjudicate.BuiltIn(),
		Set{Records: []Record{mustNew(t, req(VerbAck, f, at))}}, finding.Result{}, at)
	st := dead.ByState(StateDead)
	if len(st) != 1 {
		t.Fatalf("a record matching nothing is not reported dead: %+v", dead.Statuses)
	}
	if !strings.Contains(st[0].Detail, "triage drop") {
		t.Fatalf("the dead record does not name the command that removes it: %q", st[0].Detail)
	}
	if !StateDead.NeedsRemoval() || len(dead.NeedsAttention()) != 1 {
		t.Fatal("a dead record does not need attention")
	}

	// A pin whose evidence moved is SPENT, which is a different fact from dead:
	// the subject still has a finding, and it reports once.
	pinReq := req(VerbAck, f, at)
	pinReq.Scope = adjudicate.ScopePin
	pin := mustNew(t, pinReq)
	changed := f
	changed.Evidence = []string{"something else entirely"}
	spent := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{pin}},
		finding.Result{Findings: []finding.Finding{changed}}, at)
	if len(spent.ByState(StateSpent)) != 1 || len(spent.Suppressed) != 0 {
		t.Fatalf("a pin whose evidence changed still suppresses: %+v", spent.Statuses)
	}
	// And it still covers the unchanged evidence.
	held := ApplyWith(adjudicate.BuiltIn(), Set{Records: []Record{pin}},
		finding.Result{Findings: []finding.Finding{f}}, at)
	if len(held.Suppressed) != 1 {
		t.Fatal("a pin stopped covering the exact evidence it was written for")
	}
}

// -- the structural property: triage cannot reach the bootstrap gate ----------

// This is the one that matters most. Signed adjudications are reserved for
// `baseline init` BECAUSE bootstrap is the strongest gate in the tool; a
// keyless, unsigned record that could satisfy it would turn the middle weight
// into a bypass of the top one.
//
// The end-to-end proof -- triage every critical, watch `baseline init` refuse
// with the same count -- lives in cmd/aurvet. This is the structural half: the
// packages that decide whether a baseline may be written cannot even see this
// one, so no future edit can wire them together by accident.
func TestNothingThatGatesBootstrapImportsTriage(t *testing.T) {
	const self = "github.com/lookatitude/aurvet/internal/triage"
	for _, dir := range []string{
		"../baseline", "../chain", "../adjudicate", "../check", "../report",
	} {
		for _, path := range goFilesIn(t, dir) {
			for _, imp := range importsOf(t, path) {
				if imp == self {
					t.Errorf("%s imports internal/triage. A lightweight, unsigned, keyless record "+
						"must never be reachable from the code that decides whether a baseline may "+
						"be signed", path)
				}
			}
		}
	}

	// cmd/aurvet is one package, so an import guard cannot separate `baseline`
	// from `triage` there. The file is checked instead: baselineWrite is what
	// refuses, and it must not so much as mention this store.
	src, err := os.ReadFile("../../cmd/aurvet/baseline.go")
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(src), "triage.") {
		t.Error("cmd/aurvet/baseline.go references the triage package; `baseline init`'s refusal " +
			"must be decided from the SIGNED adjudication store alone")
	}
}

func goFilesIn(t *testing.T, dir string) []string {
	t.Helper()
	entries, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("read %s: %v", dir, err)
	}
	var out []string
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".go") {
			continue
		}
		out = append(out, filepath.Join(dir, e.Name()))
	}
	if len(out) == 0 {
		t.Fatalf("%s: no Go files found; this guard would be vacuous", dir)
	}
	return out
}

func importsOf(t *testing.T, path string) []string {
	t.Helper()
	fset := token.NewFileSet()
	f, err := parser.ParseFile(fset, path, nil, parser.ImportsOnly|parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", path, err)
	}
	var out []string
	for _, imp := range f.Imports {
		out = append(out, strings.Trim(imp.Path.Value, `"`))
	}
	return out
}

// -- the happy path, last -----------------------------------------------------

func TestStoreRoundTripsAndIsCanonical(t *testing.T) {
	at := now(t)
	f := theFinding()
	other := f
	other.Subject = "etc/profile.d/other.sh"

	n := req(VerbNote, other, at)
	n.Note = "asked the platform team"
	recs := []Record{mustNew(t, req(VerbAck, f, at)), mustNew(t, n)}

	raw, err := Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	// Order in must not decide bytes out: two hosts with the same decisions
	// produce the same file.
	swapped, err := Marshal([]Record{recs[1], recs[0]})
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != string(swapped) {
		t.Fatal("the store's bytes depend on the order records were appended in")
	}

	set := Parse("triage.json", raw)
	if len(set.Faults) != 0 || len(set.Records) != 2 {
		t.Fatalf("round trip: %d records, faults %+v", len(set.Records), set.Faults)
	}

	dir := t.TempDir()
	if err := Save(dir, recs); err != nil {
		t.Fatal(err)
	}
	st, err := os.Stat(filepath.Join(dir, FileName))
	if err != nil {
		t.Fatal(err)
	}
	if st.Mode().Perm() != 0o600 {
		t.Fatalf("the triage store is mode %v, want 0600", st.Mode().Perm())
	}
	if got := Load(dir); len(got.Records) != 2 || len(got.Faults) != 0 {
		t.Fatalf("Load: %d records, faults %+v", len(got.Records), got.Faults)
	}

	// Saving an empty set REMOVES the file: an empty document would be reported
	// as a fault forever by an operator who was only tidying up.
	if err := Save(dir, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(dir, FileName)); !os.IsNotExist(err) {
		t.Fatal("Save(nil) left a store behind")
	}
	if got := Load(dir); len(got.Records) != 0 || len(got.Faults) != 0 {
		t.Fatalf("an absent store is not the healthy empty set: %+v", got)
	}
}
