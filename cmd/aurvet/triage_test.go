// cmd/aurvet/triage_test.go
//
// `triage` end to end.
//
// The first test is the one that matters and it is an attack: triage every
// critical on a host, then watch `baseline init` refuse anyway, with the same
// count and for the same reasons. If that ever passes, the lightweight layer has
// become a bypass of the strongest gate in the tool and the middle weight has
// destroyed the top one.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/triage"
)

// triOpts is the invocation that WOULD be allowed. Each refusal test breaks
// exactly one thing about it.
//
// No key, no signer and no trust set: a triage record needs none, and an
// invocation here that supplied one would hide a regression in which it did.
func triOpts(t *testing.T, state string, ev scanEvidence, args ...string) triageOpts {
	t.Helper()
	return triageOpts{
		baselineOpts: baselineOpts{
			args:     args,
			stateDir: state,
			now:      baselineNow(t),
			euid:     rootEuid(),
			scan:     func(baselineEnv) (scanEvidence, error) { return ev, nil },
		},
	}
}

func run3(t *testing.T, opts triageOpts) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runTriage(opts, &out, &errb)
	return code, out.String(), errb.String()
}

func triageStorePath(state string) string { return filepath.Join(state, triage.FileName) }

func assertNoTriageStore(t *testing.T, state, why string) {
	t.Helper()
	if _, err := os.Stat(triageStorePath(state)); !os.IsNotExist(err) {
		t.Fatalf("%s: %s exists after a refusal", why, triageStorePath(state))
	}
}

// -- THE attack: a keyless record must not satisfy the bootstrap gate ---------

func TestTriagingEveryCriticalDoesNotUnblockBaselineInit(t *testing.T) {
	// Three criticals, one per rule shape an operator meets, so the assertion is
	// about the mechanism and not about one lucky finding.
	crits := []finding.Finding{
		{
			RuleID: "integrity-digest-mismatch", SubjectKind: "package", Subject: "sudo",
			Severity: finding.SevCritical, Summary: "a packaged file's digest does not match",
			Evidence: []string{"recorded aaa, observed bbb"}, Limits: "may be a local edit",
		},
		{
			RuleID: "correlated-cluster", SubjectKind: "path", Subject: "etc/systemd/system/x.service",
			Severity: finding.SevCritical, Summary: "3 persistence facts correlate",
			Evidence: []string{"unit-execstart, enablement-link, hook"}, Limits: "weak alone",
		},
		{
			RuleID: "aur-tombstone", SubjectKind: "package", Subject: "evil-bin",
			Severity: finding.SevCritical, Summary: "installed but absent from the AUR",
			Evidence: []string{"no RPC record"}, Limits: "deletion is not proof",
		},
	}
	ev := fakeEvidence(t)
	ev.Result.Findings = append(ev.Result.Findings, crits...)
	state := stateWithTrust(t)

	// 1. init refuses, and we record exactly what it said.
	var b1, e1 bytes.Buffer
	before := runBaseline(initOpts(t, state, ev), &b1, &e1)
	if before != exitFindings {
		t.Fatalf("init with 3 unadjudicated criticals = %d, want %d\n%s", before, exitFindings, e1.String())
	}
	for _, c := range crits {
		if !strings.Contains(e1.String(), report.FindingID(c)) {
			t.Fatalf("the refusal does not name %s:\n%s", c.RuleID, e1.String())
		}
	}

	// 2. triage all three, with every verb, at the widest scope triage allows.
	verbs := []string{"ack", "snooze", "note"}
	for i, c := range crits {
		o := triOpts(t, state, ev, verbs[i], report.FindingID(c))
		o.scope = "subject"
		o.note = "seen, expected, do not show me this again"
		code, stdout, stderr := run3(t, o)
		if code != exitClean {
			t.Fatalf("triage %s = %d, want %d\n%s", verbs[i], code, exitClean, stderr)
		}
		if !strings.Contains(stdout, "not a signed judgement") {
			t.Fatalf("the confirmation does not say the record is unsigned:\n%s", stdout)
		}
	}
	set := triage.Load(state)
	if len(set.Records) != 3 || len(set.Faults) != 0 {
		t.Fatalf("the triage store holds %d record(s), faults %+v", len(set.Records), set.Faults)
	}

	// 3. init refuses AGAIN, with the same count and the same fingerprints.
	var b2, e2 bytes.Buffer
	after := runBaseline(initOpts(t, state, ev), &b2, &e2)
	if after != before {
		t.Fatalf("`baseline init` exited %d after every critical was triaged, and %d before. A "+
			"local, unsigned, keyless record has just unblocked the strongest gate in the tool.\n%s",
			after, before, e2.String())
	}
	for _, c := range crits {
		if !strings.Contains(e2.String(), report.FindingID(c)) {
			t.Errorf("after triage, `baseline init` no longer names the critical %s (%s). It is "+
				"being counted as resolved by something that never signed anything.\n%s",
				c.RuleID, report.FindingID(c), e2.String())
		}
	}
	if got, want := countUnresolved(e2.String()), countUnresolved(e1.String()); got != want || want == 0 {
		t.Fatalf("the refusal counts %d unresolved criticals after triage and %d before", got, want)
	}
	// And no chain was written.
	if _, err := os.Stat(filepath.Join(state, chainSubdir, "chain.jsonl")); err == nil {
		t.Fatal("a chain exists after a refusal")
	}

	// 4. The signed store is what does unblock it -- so the refusal above is a
	// property of the STORE and not of these findings being unadjudicable.
	adj := adjOpts(t, state, ev, report.FindingID(crits[0]))
	if code, _, ae := runAdjudicateCapture(t, adj); code != exitClean {
		t.Fatalf("adjudicate = %d: %s", code, ae)
	}
	var b3, e3 bytes.Buffer
	if code := runBaseline(initOpts(t, state, ev), &b3, &e3); code != exitFindings {
		t.Fatalf("init after ONE adjudication = %d, want %d (two criticals remain)\n%s",
			code, exitFindings, e3.String())
	}
	if strings.Contains(e3.String(), report.FindingID(crits[0])) {
		t.Fatalf("the adjudicated critical is still counted:\n%s", e3.String())
	}
}

// countUnresolved counts the fingerprints the refusal lists, by counting the
// occurrences of the phrase the bootstrap refusal uses per critical.
func countUnresolved(msg string) int {
	return strings.Count(msg, "aurvet adjudicate ")
}

func runAdjudicateCapture(t *testing.T, opts adjudicateOpts) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := runAdjudicate(opts, &out, &errb)
	return code, out.String(), errb.String()
}

// -- the three verbs are not synonyms -----------------------------------------

func TestTheThreeVerbsDifferAndTheOutputSaysHow(t *testing.T) {
	f := theTriageFinding()
	ev := evidenceWith(t, f)
	fp := report.FindingID(f)

	for _, tc := range []struct {
		verb      string
		wantIn    []string
		suppress  bool
		expiresIn time.Duration
	}{
		{"ack", []string{"seen and expected", "hidden from the default view"}, true, 30 * 24 * time.Hour},
		{"snooze", []string{"not now", "then it comes back"}, true, 7 * 24 * time.Hour},
		{"note", []string{"SUPPRESSES NOTHING", "still reports"}, false, 30 * 24 * time.Hour},
	} {
		t.Run(tc.verb, func(t *testing.T) {
			state := t.TempDir()
			o := triOpts(t, state, ev, tc.verb, fp)
			o.note = "checked against the runbook on the 3rd"
			code, stdout, stderr := run3(t, o)
			if code != exitClean {
				t.Fatalf("%s = %d, want %d\n%s", tc.verb, code, exitClean, stderr)
			}
			for _, want := range tc.wantIn {
				if !strings.Contains(stdout, want) {
					t.Errorf("`triage %s` output does not say %q:\n%s", tc.verb, want, stdout)
				}
			}
			want := baselineNow(t).Add(tc.expiresIn).Format(time.RFC3339)
			if !strings.Contains(stdout, want) {
				t.Errorf("`triage %s` does not expire at %s:\n%s", tc.verb, want, stdout)
			}

			// The effect, measured through the same code `scan` uses.
			out := triage.ApplyWith(adjudicate.BuiltIn(), triage.Load(state), ev.Result, baselineNow(t))
			if got := len(out.Suppressed) > 0; got != tc.suppress {
				t.Fatalf("`triage %s` suppressed=%v, want %v", tc.verb, got, tc.suppress)
			}
			if tc.verb == "note" && len(out.Annotated) != 1 {
				t.Fatalf("`triage note` did not annotate anything: %+v", out.Statuses)
			}
		})
	}
}

// `triage note` without a note is refused: the note is the verb.
func TestTriageNoteRequiresTheNote(t *testing.T) {
	f := theTriageFinding()
	state := t.TempDir()
	code, _, stderr := run3(t, triOpts(t, state, evidenceWith(t, f), "note", report.FindingID(f)))
	if code != exitUsage {
		t.Fatalf("`triage note` with no -reason = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "that is `triage ack`") {
		t.Fatalf("the refusal does not name the verb the operator probably wanted:\n%s", stderr)
	}
	assertNoTriageStore(t, state, "note with no note")
}

// -- a coverage gap is not triageable -----------------------------------------

func TestNoTriageVerbCanTouchACoverageGap(t *testing.T) {
	ev := fakeEvidence(t)
	ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
		RuleID: "integrity-coverage", Subject: "usr/bin/sudo", Reason: "the file could not be read",
	})
	state := t.TempDir()

	// A gap has no id, so the id an operator might construct for it resolves to
	// nothing. The refusal has to say WHY rather than "no such finding".
	gapID := finding.Fingerprint("integrity-coverage", "file", "usr/bin/sudo", "subject")
	for _, verb := range []string{"ack", "snooze", "note"} {
		o := triOpts(t, state, ev, verb, gapID)
		o.note = "the file is on an unreadable mount"
		code, _, stderr := run3(t, o)
		if code != exitUsage {
			t.Fatalf("`triage %s` on a gap = %d, want %d", verb, code, exitUsage)
		}
		if !strings.Contains(stderr, "no acknowledgement turns unexamined into examined") {
			t.Fatalf("the refusal does not explain that a gap is not triageable:\n%s", stderr)
		}
		assertNoTriageStore(t, state, "gap "+verb)
	}

	// And a record about a FINDING leaves every gap in place, which is the half a
	// usage error cannot prove.
	f := theTriageFinding()
	ev2 := evidenceWith(t, f)
	ev2.Result.Gaps = ev.Result.Gaps
	o := triOpts(t, state, ev2, "ack", report.FindingID(f))
	if code, _, se := run3(t, o); code != exitClean {
		t.Fatalf("triage ack = %d: %s", code, se)
	}
	out := triage.ApplyWith(adjudicate.BuiltIn(), triage.Load(state), ev2.Result, baselineNow(t))
	if len(out.Kept.Gaps) != len(ev2.Result.Gaps) {
		t.Fatalf("triage changed the gap count from %d to %d",
			len(ev2.Result.Gaps), len(out.Kept.Gaps))
	}
}

// -- rule scope, expiry, offline root -----------------------------------------

func TestTriageRefusesRuleScopeAndNamesTheCommandThatCanDoIt(t *testing.T) {
	f := theTriageFinding()
	state := t.TempDir()
	o := triOpts(t, state, evidenceWith(t, f), "ack", report.FindingID(f))
	o.scope = "rule"
	code, _, stderr := run3(t, o)
	if code != exitUsage {
		t.Fatalf("rule scope = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(stderr, "aurvet adjudicate") || !strings.Contains(stderr, "force-rule-scope") {
		t.Fatalf("the refusal does not name the signed route:\n%s", stderr)
	}
	assertNoTriageStore(t, state, "rule scope")
}

func TestTriageRefusesAnExpiryBeyondTheVerbsMaximum(t *testing.T) {
	f := theTriageFinding()
	fp := report.FindingID(f)
	ev := evidenceWith(t, f)
	for _, tc := range []struct {
		verb string
		days int
	}{
		{"ack", 91}, {"note", 365}, {"snooze", 31}, {"ack", -1},
	} {
		state := t.TempDir()
		o := triOpts(t, state, ev, tc.verb, fp)
		o.note = "a note of substance for the note verb"
		o.expiryDays = tc.days
		code, _, stderr := run3(t, o)
		if code != exitUsage {
			t.Fatalf("`triage %s -expiry-days %d` = %d, want %d\n%s",
				tc.verb, tc.days, code, exitUsage, stderr)
		}
		assertNoTriageStore(t, state, "expiry")
	}
	// A shorter window is accepted and is what lands in the record.
	state := t.TempDir()
	o := triOpts(t, state, ev, "ack", fp)
	o.expiryDays = 3
	code, stdout, stderr := run3(t, o)
	if code != exitClean {
		t.Fatalf("-expiry-days 3 = %d\n%s", code, stderr)
	}
	if want := baselineNow(t).Add(3 * 24 * time.Hour).Format(time.RFC3339); !strings.Contains(stdout, want) {
		t.Fatalf("the recorded expiry is not %s:\n%s", want, stdout)
	}
}

func TestTriageWritingVerbsRefuseUnderAnOfflineRootAndListDoesNot(t *testing.T) {
	f := theTriageFinding()
	ev := evidenceWith(t, f)
	state := t.TempDir()
	for _, args := range [][]string{
		{"ack", report.FindingID(f)}, {"snooze", report.FindingID(f)},
		{"note", report.FindingID(f)}, {"drop", report.FindingID(f)},
	} {
		o := triOpts(t, state, ev, args...)
		o.offlineRoot = cleanRoot
		o.note = "a note of substance for the note verb"
		code, _, stderr := run3(t, o)
		if code != exitUsage {
			t.Fatalf("`triage %s` under --offline-root = %d, want %d\n%s",
				args[0], code, exitUsage, stderr)
		}
		if !strings.Contains(stderr, "INV-5") {
			t.Fatalf("the refusal does not cite the invariant:\n%s", stderr)
		}
		assertNoTriageStore(t, state, "offline "+args[0])
	}
	// list only reads, so it is allowed.
	o := triOpts(t, state, ev, "list")
	o.offlineRoot = cleanRoot
	if code, _, se := run3(t, o); code != exitClean {
		t.Fatalf("`triage list` under --offline-root = %d, want %d\n%s", code, exitClean, se)
	}
}

// -- list: dead records, stale records, and what is hidden --------------------

// §12: dead suppressions that match nothing are reported for removal. A report
// that names a record an operator cannot remove trains them to ignore it, so the
// removal command is printed with the fingerprint filled in.
func TestTriageListReportsDeadRecordsForRemovalAndDropRemovesThem(t *testing.T) {
	f := theTriageFinding()
	ev := evidenceWith(t, f)
	state := t.TempDir()
	if code, _, se := run3(t, triOpts(t, state, ev, "ack", report.FindingID(f))); code != exitClean {
		t.Fatalf("ack = %d: %s", code, se)
	}

	// The finding stops occurring: the record now matches nothing.
	gone := fakeEvidence(t)
	code, stdout, _ := run3(t, triOpts(t, state, gone, "list"))
	if code != exitFindings {
		t.Fatalf("`triage list` with a dead record = %d, want %d\n%s", code, exitFindings, stdout)
	}
	if !strings.Contains(stdout, "[dead]") {
		t.Fatalf("the dead record is not reported as dead:\n%s", stdout)
	}
	if !strings.Contains(stdout, "will never do anything again") {
		t.Fatalf("dead records are not reported for removal:\n%s", stdout)
	}
	set := triage.Load(state)
	if len(set.Records) != 1 {
		t.Fatalf("expected one record, got %d", len(set.Records))
	}
	fp := set.Records[0].Fingerprint
	if !strings.Contains(stdout, "aurvet triage drop "+fp) {
		t.Fatalf("the removal line does not carry the fingerprint to drop:\n%s", stdout)
	}

	// And dropping it works, by the fingerprint the listing printed.
	dcode, dout, derr := run3(t, triOpts(t, state, gone, "drop", fp))
	if dcode != exitClean {
		t.Fatalf("drop = %d, want %d\n%s", dcode, exitClean, derr)
	}
	if !strings.Contains(dout, "reported in full from the next run on") {
		t.Fatalf("drop does not say what happens next:\n%s", dout)
	}
	assertNoTriageStore(t, state, "drop to empty")

	// Dropping something that is not there is a usage error naming how to look.
	if code, _, se := run3(t, triOpts(t, state, gone, "drop", fp)); code != exitUsage {
		t.Fatalf("drop of an absent record = %d, want %d", code, exitUsage)
	} else if !strings.Contains(se, "aurvet triage list") {
		t.Fatalf("the refusal does not say how to find the right fingerprint:\n%s", se)
	}
}

// A record bound to matching semantics that have moved must read stale, be
// preserved verbatim and suppress nothing -- exactly as an adjudication does.
func TestTriageListShowsAStaleRecordAfterTheSemanticsMove(t *testing.T) {
	f := theTriageFinding()
	ev := evidenceWith(t, f)
	state := t.TempDir()
	o := triOpts(t, state, ev, "ack", report.FindingID(f))
	o.note = "the profile.d snippet is ours; deploy 2026-07"
	if code, _, se := run3(t, o); code != exitClean {
		t.Fatalf("ack = %d: %s", code, se)
	}
	// Before: active and hiding the finding.
	if code, stdout, _ := run3(t, triOpts(t, state, ev, "list")); code != exitClean {
		t.Fatalf("list = %d, want %d\n%s", code, exitClean, stdout)
	} else if !strings.Contains(stdout, "[active]") || !strings.Contains(stdout, "currently hidden") {
		t.Fatalf("the record is not reported as hiding anything:\n%s", stdout)
	}

	// The rule's declared matching inputs move under the record. Rewriting the
	// record's own bound digest is the same comparison from the other side.
	staleTriageOnDisk(t, state)

	code, stdout, _ := run3(t, triOpts(t, state, ev, "list"))
	if code != exitFindings {
		t.Fatalf("`triage list` with a stale record = %d, want %d\n%s", code, exitFindings, stdout)
	}
	for _, want := range []string{"[stale]", "re-triage", "deploy 2026-07"} {
		if !strings.Contains(stdout, want) {
			t.Errorf("the stale listing does not contain %q:\n%s", want, stdout)
		}
	}
	if strings.Contains(stdout, "currently hidden") {
		t.Fatalf("a stale record is still hiding something:\n%s", stdout)
	}
}

func staleTriageOnDisk(t *testing.T, state string) {
	t.Helper()
	set := triage.Load(state)
	if len(set.Records) != 1 {
		t.Fatalf("expected one record, got %d (faults %+v)", len(set.Records), set.Faults)
	}
	recs := set.Records
	recs[0].SemanticsDigest = strings.Repeat("9", 64)
	raw, err := triage.Marshal(recs)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(triageStorePath(state), raw, 0o600); err != nil {
		t.Fatal(err)
	}
}

// A store nobody can read must not be rewritten into an empty one, and it must
// not read as "nothing triaged" either.
func TestTriageRefusesToRewriteAStoreItCannotRead(t *testing.T) {
	f := theTriageFinding()
	ev := evidenceWith(t, f)
	state := t.TempDir()
	if code, _, se := run3(t, triOpts(t, state, ev, "ack", report.FindingID(f))); code != exitClean {
		t.Fatalf("ack = %d: %s", code, se)
	}
	before, err := os.ReadFile(triageStorePath(state))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(triageStorePath(state), []byte(`{"schema_version":1,"records":[`), 0o600); err != nil {
		t.Fatal(err)
	}

	code, _, stderr := run3(t, triOpts(t, state, ev, "snooze", report.FindingID(f)))
	if code != exitIncomplete {
		t.Fatalf("writing over an unreadable store = %d, want %d\n%s", code, exitIncomplete, stderr)
	}
	if !strings.Contains(stderr, "refusing to rewrite") {
		t.Fatalf("the refusal does not say it declined:\n%s", stderr)
	}

	// list reports it as unusable and exits 3, not 0.
	lcode, lout, _ := run3(t, triOpts(t, state, ev, "list"))
	if lcode != exitIncomplete {
		t.Fatalf("`triage list` over an unreadable store = %d, want %d\n%s", lcode, exitIncomplete, lout)
	}
	if !strings.Contains(lout, "UNUSABLE") {
		t.Fatalf("the listing does not report the store as unusable:\n%s", lout)
	}
	_ = before
}

func TestTriageListWithNoStoreIsCleanAndSaysSo(t *testing.T) {
	state := t.TempDir()
	code, stdout, stderr := run3(t, triOpts(t, state, fakeEvidence(t), "list"))
	if code != exitClean {
		t.Fatalf("list with no store = %d, want %d\n%s", code, exitClean, stderr)
	}
	if !strings.Contains(stdout, "correct default") {
		t.Fatalf("an empty triage set is not reported as the healthy state:\n%s", stdout)
	}
}

// -- unknown fingerprint, unknown verb ----------------------------------------

func TestTriageRefusesAFingerprintNoFindingCarriesAndSaysWhereIdsComeFrom(t *testing.T) {
	state := t.TempDir()
	code, _, stderr := run3(t, triOpts(t, state, fakeEvidence(t), "ack", strings.Repeat("f", 32)))
	if code != exitUsage {
		t.Fatalf("unknown fingerprint = %d, want %d", code, exitUsage)
	}
	for _, want := range []string{"aurvet explain", "aurvet scan -json", "INV-3"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q:\n%s", want, stderr)
		}
	}
	if code, _, se := run3(t, triOpts(t, state, fakeEvidence(t), "postpone", "x")); code != exitUsage {
		t.Fatalf("an unknown verb = %d, want %d\n%s", code, exitUsage, se)
	}
}

// -- json ---------------------------------------------------------------------

// A machine reader must be able to tell a triage record from an adjudication,
// and the fields that say so are explicit rather than inferable from absence.
func TestTriageJSONSaysItIsUnsignedAndUnblocksNothing(t *testing.T) {
	f := theTriageFinding()
	state := t.TempDir()
	o := triOpts(t, state, evidenceWith(t, f), "ack", report.FindingID(f))
	o.jsonOut = true
	code, stdout, stderr := run3(t, o)
	if code != exitClean {
		t.Fatalf("triage -json = %d\n%s", code, stderr)
	}
	var doc map[string]any
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout)
	}
	for _, k := range []string{"signed", "unblocks_baseline"} {
		if doc[k] != false {
			t.Errorf("%s = %v, want false", k, doc[k])
		}
	}
	if doc["suppresses"] != true || doc["verb"] != "ack" {
		t.Errorf("the record does not describe itself: %v", doc)
	}
}

// -- scan applies triage to the LISTING and nothing else ----------------------

// §12's "suppresses from the default view" is a display filter. A local unsigned
// file that could change an exit code would be the blindfold the whole
// lifecycle is arranged to prevent, so this is asserted through the same
// function `scan` calls.
func TestTriageNarrowsTheListingAndNeverTheVerdict(t *testing.T) {
	f := theTriageFinding()
	f.Severity = finding.SevCritical
	res := finding.Result{Findings: []finding.Finding{f}}
	state := t.TempDir()
	ev := scanEvidence{Tier: "full", Result: res}
	if code, _, se := run3(t, triOpts(t, state, ev, "ack", report.FindingID(f))); code != exitClean {
		t.Fatalf("ack = %d: %s", code, se)
	}

	got, view, out := applyTriage(state, res, report.FullView(res), baselineNow(t))
	if len(view.Display.Findings) != 0 {
		t.Fatalf("the triaged finding is still listed: %d", len(view.Display.Findings))
	}
	if len(view.Verdict.Findings) != 1 {
		t.Fatalf("the VERDICT lost the finding: %d", len(view.Verdict.Findings))
	}
	if report.ExitCode(got, finding.SevCritical) != exitFindings {
		t.Fatal("a local unsigned triage record changed the exit code of a scan with a critical")
	}
	if len(out.Suppressed) != 1 {
		t.Fatalf("the outcome does not report what it hid: %+v", out)
	}

	// And the banner says it, above the findings, because a report that silently
	// omits suppressed findings lies by omission (INV-6).
	var banner bytes.Buffer
	writeTriageBanner(&banner, out)
	if !strings.Contains(banner.String(), "are NOT listed below") ||
		!strings.Contains(banner.String(), "UNSIGNED") {
		t.Fatalf("the scan banner does not announce the suppression:\n%s", banner.String())
	}
}

// theTriageFinding is an `info` finding on a hand-written file: exactly the case
// §12 says an operator would otherwise ignore the tool over.
func theTriageFinding() finding.Finding {
	return finding.Finding{
		RuleID: "surface-profiled-unowned", SubjectKind: "file",
		Subject:  "etc/profile.d/local-path.sh",
		Severity: finding.SevInfo,
		Summary:  "file in a shell-startup drop-in directory is owned by no installed package",
		Evidence: []string{"no installed package records this path, resolving symlinks"},
		Limits:   "a hand-written snippet is ordinary administration",
	}
}
