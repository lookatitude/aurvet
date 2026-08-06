// cmd/aurvet/adjudicate_test.go
//
// `adjudicate` end to end. The refusals come first: every one of them is a way
// an operator could otherwise acquire a suppression without having made a
// judgement, and the last test in the refusal block is the one that matters most
// -- a recorded adjudication really does unblock `baseline init`, and an
// unrecorded one really does not.
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
	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/chain"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/report"
)

// theCritical is the finding every test in this file adjudicates. Its rule
// declares a fingerprint epoch, so it is adjudicable; the undeclared case has
// its own test.
func theCritical() finding.Finding {
	return finding.Finding{
		RuleID: "integrity-digest-mismatch", SubjectKind: "package", Subject: "sudo",
		Severity: finding.SevCritical,
		Summary:  "a packaged file's digest does not match the mtree",
		Evidence: []string{"recorded aaa, observed bbb"},
		Limits:   "may be a legitimate local edit",
	}
}

// adjOpts is the invocation that WOULD be allowed. Each refusal test breaks
// exactly one thing about it.
//
// offlineRoot is empty, unlike the baseline tests: `adjudicate` refuses to write
// under an offline root at all, so the permitted path cannot use one. Nothing
// under / is touched -- the scan is seamed and the state directory is a temp dir.
func adjOpts(t *testing.T, state string, ev scanEvidence, fp string) adjudicateOpts {
	t.Helper()
	return adjudicateOpts{
		baselineOpts: baselineOpts{
			keyPath:  testKeyPath,
			args:     []string{fp},
			stateDir: state,
			now:      baselineNow(t),
			euid:     rootEuid(),
			scan:     func(baselineEnv) (scanEvidence, error) { return ev, nil },
		},
		reason: "the file is a local %BACKUP% edit; verified by hand against upstream",
	}
}

func evidenceWith(t *testing.T, f finding.Finding) scanEvidence {
	t.Helper()
	ev := fakeEvidence(t)
	ev.Result.Findings = append(ev.Result.Findings, f)
	return ev
}

func storeFiles(state string) (string, string) {
	p := filepath.Join(state, adjudicationsFile)
	return p, p + ".sig"
}

func assertNoStore(t *testing.T, state, why string) {
	t.Helper()
	doc, sig := storeFiles(state)
	for _, p := range []string{doc, sig} {
		if _, err := os.Stat(p); !os.IsNotExist(err) {
			t.Fatalf("%s: %s exists after a refusal", why, p)
		}
	}
}

// -- attack 1: a suppression with no stated reason ----------------------------

// The reason is the whole mechanism. Without it an adjudication is an operator
// clicking "ignore", and nothing about the decision can be re-evaluated later --
// not by a reviewer, not by the person who made it.
func TestAdjudicateRefusesAReasonlessJudgement(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)
	opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
	opts.reason = ""

	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitUsage {
		t.Fatalf("reasonless adjudicate = %d, want %d\nstdout: %s\nstderr: %s",
			code, exitUsage, out.String(), errb.String())
	}
	if !strings.Contains(errb.String(), "-reason is required") {
		t.Fatalf("the refusal does not name the flag:\n%s", errb.String())
	}
	assertNoStore(t, state, "reasonless")

	// Whitespace is not a reason either, and neither is a token short enough to
	// be typed reflexively. The rule lives in internal/adjudicate; what is
	// asserted here is that the command does not route around it.
	for _, bad := range []string{"   ", "ok", "wontfix"} {
		o := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
		o.reason = bad
		var so, se bytes.Buffer
		if code := runAdjudicate(o, &so, &se); code != exitUsage {
			t.Fatalf("reason %q = %d, want %d\n%s", bad, code, exitUsage, se.String())
		}
		assertNoStore(t, state, "reason "+bad)
	}
}

// -- attack 2: a rule with no declared epoch ----------------------------------

// A finding whose rule declares no fingerprint epoch CANNOT be adjudicated, by
// design: there would be nothing to bind the judgement to, so later it could not
// be told apart from one made against semantics that have since moved.
//
// The refusal is correct. What this test pins is that it is ACTIONABLE -- it
// names the file to edit and the golden file beside it -- because this exact
// deadlock has been hit three times in this project, and "no" with no next step
// is what made it survive.
func TestAdjudicateRefusesAnUndeclaredRuleAndNamesTheFileToEdit(t *testing.T) {
	crit := theCritical()
	crit.RuleID = "some-rule-nobody-declared"
	state := stateWithTrust(t)

	var out, errb bytes.Buffer
	code := runAdjudicate(adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit)), &out, &errb)
	if code != exitUsage {
		t.Fatalf("undeclared rule = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	msg := errb.String()
	for _, want := range []string{
		"declares no fingerprint epoch",
		"internal/adjudicate/epoch.go",
		"testdata/adjudicate/epochs.golden.json",
		"some-rule-nobody-declared",
	} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, msg)
		}
	}
	assertNoStore(t, state, "undeclared rule")
}

// -- attack 3: widening the scope quietly -------------------------------------

// -scope rule turns a check off for every package and path on the host. It needs
// an explicit force, and the record stores that the force was given.
func TestAdjudicateRefusesRuleScopeWithoutTheExplicitForce(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)
	opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
	opts.scope = "rule"

	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitUsage {
		t.Fatalf("rule scope without force = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), "force-rule-scope") {
		t.Fatalf("the refusal does not name the force flag:\n%s", errb.String())
	}
	assertNoStore(t, state, "unforced rule scope")

	// With the force it is accepted -- and the standing consequence is printed.
	opts.forceRuleScope = true
	var o2, e2 bytes.Buffer
	if code := runAdjudicate(opts, &o2, &e2); code != exitClean {
		t.Fatalf("forced rule scope = %d, want %d\n%s", code, exitClean, e2.String())
	}
	if !strings.Contains(o2.String(), "OFF EVERYWHERE") {
		t.Fatalf("a rule-scope adjudication does not say what it did:\n%s", o2.String())
	}
}

// -- attack 4: adjudicating something that is not there -----------------------

func TestAdjudicateRefusesAFingerprintNoFindingCarries(t *testing.T) {
	state := stateWithTrust(t)
	opts := adjOpts(t, state, fakeEvidence(t), strings.Repeat("f", 32))

	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitUsage {
		t.Fatalf("unknown fingerprint = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	// And it says why a gap has no id: the operator most likely tried to
	// adjudicate a coverage gap, which is forbidden (INV-3), not missing.
	if !strings.Contains(errb.String(), "no judgement can turn unexamined into clean") {
		t.Fatalf("the refusal does not explain that gaps are not adjudicable:\n%s", errb.String())
	}
	assertNoStore(t, state, "unknown fingerprint")
}

// -- attack 5: recording a judgement about someone else's filesystem ----------

func TestAdjudicateRefusesToWriteUnderAnOfflineRoot(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)
	opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
	opts.offlineRoot = cleanRoot

	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitUsage {
		t.Fatalf("adjudicate under --offline-root = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), "INV-5") {
		t.Fatalf("the refusal does not cite the invariant:\n%s", errb.String())
	}
	assertNoStore(t, state, "offline root")

	// revoke writes too, and refuses on the same terms.
	rev := opts
	rev.args = []string{"revoke", report.FindingID(crit)}
	var o2, e2 bytes.Buffer
	if code := runAdjudicate(rev, &o2, &e2); code != exitUsage {
		t.Fatalf("revoke under --offline-root = %d, want %d\n%s", code, exitUsage, e2.String())
	}
}

// -- attack 6: signing with a key the host does not trust ---------------------

// A store signed by an untrusted key does not verify on the next run, and a
// store that does not verify suppresses NOTHING. Writing one would leave the
// operator believing they had recorded a judgement that never applies.
func TestAdjudicateRefusesASigningKeyThatIsNotTrusted(t *testing.T) {
	crit := theCritical()
	state := t.TempDir() // no trusted-keys file

	var out, errb bytes.Buffer
	code := runAdjudicate(adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit)), &out, &errb)
	if code != exitUsage {
		t.Fatalf("untrusted key = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), trustedKeysFile) || !strings.Contains(errb.String(), "SHA256:") {
		t.Fatalf("the refusal does not name the file or print the fingerprint to check:\n%s", errb.String())
	}
	assertNoStore(t, state, "untrusted key")
}

// -- attack 7: a rewrite that silently discards what it could not read --------

// The store is present but its signature does not verify. loadAdjudications
// correctly reports that as a fault and yields no records -- so a rewrite would
// re-sign an empty store and every judgement in the file would be gone, with a
// perfectly valid signature over the result.
func TestAdjudicateRefusesToRewriteAStoreItCannotRead(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)

	// One good record first.
	if code := runAdjudicate(adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit)),
		&bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("the first adjudication did not record")
	}
	doc, sig := storeFiles(state)
	before, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}

	// Corrupt the signature: one byte is enough.
	sb, err := os.ReadFile(sig)
	if err != nil {
		t.Fatal(err)
	}
	sb[len(sb)/2] ^= 0x01
	if err := os.WriteFile(sig, sb, 0o600); err != nil {
		t.Fatal(err)
	}

	second := theCritical()
	second.Subject = "openssl"
	var out, errb bytes.Buffer
	code := runAdjudicate(adjOpts(t, state, evidenceWith(t, second), report.FindingID(second)), &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("adjudicate over an unreadable store = %d, want %d\n%s", code, exitIncomplete, errb.String())
	}
	if !strings.Contains(errb.String(), "refusing to rewrite") {
		t.Fatalf("the refusal does not say it declined to rewrite:\n%s", errb.String())
	}
	after, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(before, after) {
		t.Fatal("a refused adjudication rewrote the store anyway")
	}
}

// -- the deliverable: a recorded reason unblocks init, an absent one does not --

func TestARecordedAdjudicationUnblocksBaselineInitAndAnUnrecordedOneDoesNot(t *testing.T) {
	crit := theCritical()
	fp := report.FindingID(crit)
	ev := evidenceWith(t, crit)
	state := stateWithTrust(t)

	// 1. init refuses, and its refusal names the command that gets past it.
	var io1, ie1 bytes.Buffer
	if code := runBaseline(initOpts(t, state, ev), &io1, &ie1); code != exitFindings {
		t.Fatalf("init with an unadjudicated critical = %d, want %d\n%s", code, exitFindings, ie1.String())
	}
	if !strings.Contains(ie1.String(), "aurvet adjudicate") {
		t.Fatalf("the refusal does not name the adjudicate command:\n%s", ie1.String())
	}

	// 2. adjudicate it, with the fingerprint the refusal printed.
	if !strings.Contains(ie1.String(), fp) {
		t.Fatalf("the refusal does not print the fingerprint %s an operator must pass to "+
			"`aurvet adjudicate`:\n%s", fp, ie1.String())
	}
	var ao, ae bytes.Buffer
	if code := runAdjudicate(adjOpts(t, state, ev, fp), &ao, &ae); code != exitClean {
		t.Fatalf("adjudicate = %d, want %d\nstdout: %s\nstderr: %s",
			code, exitClean, ao.String(), ae.String())
	}
	if !strings.Contains(ao.String(), "expires") {
		t.Fatalf("the confirmation does not state an expiry:\n%s", ao.String())
	}

	// 3. init now proceeds -- and the reason is inside the SIGNED manifest, not
	// merely in a log line somebody could have piped to /dev/null.
	var io2, ie2 bytes.Buffer
	if code := runBaseline(initOpts(t, state, ev), &io2, &ie2); code != exitClean {
		t.Fatalf("init after adjudication = %d, want %d\nstdout: %s\nstderr: %s",
			code, exitClean, io2.String(), ie2.String())
	}
	trusted := trustFromFile(t, state)
	store := chain.Open(filepath.Join(state, chainSubdir))
	recs, err := store.Load(trusted)
	if err != nil || len(recs) != 1 {
		t.Fatalf("chain: %v (%d records)", err, len(recs))
	}
	pay, err := store.LoadPayload(recs[0].Entry.Payload.SHA256, baseline.NamespaceManifest, trusted)
	if err != nil || pay.State != chain.PayloadPresent {
		t.Fatalf("payload: %v %s", err, pay.Reason)
	}
	if !bytes.Contains(pay.Raw, []byte("verified by hand against upstream")) {
		t.Fatalf("the reason recorded by `aurvet adjudicate` is not inside the signed manifest:\n%s",
			pay.Raw)
	}

	// 4. and revoking it puts the refusal back. A suppression that could not be
	// withdrawn would be a one-way door.
	rev := adjOpts(t, state, ev, fp)
	rev.args = []string{"revoke", fp}
	var ro, re bytes.Buffer
	if code := runAdjudicate(rev, &ro, &re); code != exitClean {
		t.Fatalf("revoke = %d, want %d\n%s", code, exitClean, re.String())
	}
	if !strings.Contains(ro.String(), "reported in full") {
		t.Fatalf("revoke does not say what happens next:\n%s", ro.String())
	}
	// The store is GONE rather than an empty signed document: an empty store is
	// reported as a fault on every later run, which is a coverage gap the
	// operator manufactured by tidying up.
	assertNoStore(t, state, "revoke to empty")

	appendAfter := initOpts(t, state, ev)
	appendAfter.args = []string{"append"}
	appendAfter.now = baselineNow(t).Add(time.Hour)
	var no, ne bytes.Buffer
	if code := runBaseline(appendAfter, &no, &ne); code != exitFindings {
		t.Fatalf("append after revoke = %d, want %d (the critical is unresolved again)\n%s",
			code, exitFindings, ne.String())
	}
}

// -- list ---------------------------------------------------------------------

// The listing must distinguish what is suppressing from what has quietly stopped
// suppressing. A stale record is the dangerous case: the file is intact, the
// finding is back, and nothing else in the tool says why.
func TestAdjudicateListShowsWhatIsSuppressedAndWhatWentStale(t *testing.T) {
	crit := theCritical()
	ev := evidenceWith(t, crit)
	state := stateWithTrust(t)
	if code := runAdjudicate(adjOpts(t, state, ev, report.FindingID(crit)),
		&bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("adjudicate failed")
	}

	list := adjOpts(t, state, ev, "")
	list.args = []string{"list"}
	var out, errb bytes.Buffer
	if code := runAdjudicate(list, &out, &errb); code != exitClean {
		t.Fatalf("list = %d, want %d\nstdout: %s\nstderr: %s", code, exitClean, out.String(), errb.String())
	}
	got := out.String()
	for _, want := range []string{
		"[active]", "integrity-digest-mismatch", "package:sudo",
		"verified by hand against upstream", "currently suppressed", "critical",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("list output does not contain %q:\n%s", want, got)
		}
	}

	// Now move the rule's semantics: the record's stored semantics digest no
	// longer matches, so it must read STALE, be preserved verbatim, and suppress
	// nothing. The registry is not mutable from here, so the record's own bound
	// digest is edited instead -- which is the same comparison from the other
	// side and does not require a second registry.
	staleRecordOnDisk(t, state)

	var so, se bytes.Buffer
	code := runAdjudicate(list, &so, &se)
	if code != exitFindings {
		t.Fatalf("list with a stale record = %d, want %d (it needs attention)\nstdout: %s",
			code, exitFindings, so.String())
	}
	stale := so.String()
	if !strings.Contains(stale, "[stale]") || !strings.Contains(stale, "re-adjudicate") {
		t.Fatalf("list does not report the record as stale and needing re-adjudication:\n%s", stale)
	}
	if !strings.Contains(stale, "verified by hand against upstream") {
		t.Fatalf("a stale record lost the operator's recorded reason:\n%s", stale)
	}
	if strings.Contains(stale, "currently suppressed") {
		t.Fatalf("a stale record is still suppressing something:\n%s", stale)
	}
}

// staleRecordOnDisk rewrites the stored semantics digest so the record is bound
// to matching semantics that no longer exist, then re-signs the store. It is the
// on-disk equivalent of an epoch bump landing in a new release.
func staleRecordOnDisk(t *testing.T, state string) {
	t.Helper()
	doc, sigPath := storeFiles(state)
	raw, err := os.ReadFile(doc)
	if err != nil {
		t.Fatal(err)
	}
	var envelope struct {
		SchemaVersion int                 `json:"schema_version"`
		Records       []adjudicate.Record `json:"records"`
	}
	if err := json.Unmarshal(raw, &envelope); err != nil {
		t.Fatal(err)
	}
	if len(envelope.Records) != 1 {
		t.Fatalf("expected one record, got %d", len(envelope.Records))
	}
	envelope.Records[0].SemanticsDigest = strings.Repeat("9", 64)
	out, err := adjudicate.MarshalStore(envelope.Records)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := adjudicate.SignStore(testSigningKey(t), out)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(doc, out, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatal(err)
	}
}

// An empty store is not an error and is not a listing of nothing-in-particular:
// suppressing nothing is the correct default and the command says so.
func TestAdjudicateListWithNoStoreIsCleanAndSaysSo(t *testing.T) {
	state := stateWithTrust(t)
	opts := adjOpts(t, state, fakeEvidence(t), "")
	opts.args = []string{"list"}
	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitClean {
		t.Fatalf("list with no store = %d, want %d\n%s", code, exitClean, errb.String())
	}
	if !strings.Contains(out.String(), "correct default") {
		t.Fatalf("an empty suppression set is not reported as the healthy state:\n%s", out.String())
	}
}

// -- expiry -------------------------------------------------------------------

// There is no non-expiring suppression. The command may not offer one, and it
// may not offer one by arithmetic either.
func TestAdjudicateRefusesAnExpiryBeyondTheMaximum(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)
	for _, days := range []int{366, 3650, -1} {
		opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
		opts.expiryDays = days
		var out, errb bytes.Buffer
		if code := runAdjudicate(opts, &out, &errb); code != exitUsage {
			t.Fatalf("-expiry-days %d = %d, want %d\n%s", days, code, exitUsage, errb.String())
		}
		assertNoStore(t, state, "expiry")
	}

	// A shorter one is accepted and is what lands in the record.
	opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
	opts.expiryDays = 30
	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitClean {
		t.Fatalf("-expiry-days 30 = %d, want %d\n%s", code, exitClean, errb.String())
	}
	want := baselineNow(t).Add(30 * 24 * time.Hour).Format(time.RFC3339)
	if !strings.Contains(out.String(), want) {
		t.Fatalf("the recorded expiry is not the one asked for (%s):\n%s", want, out.String())
	}
}

// -- json ---------------------------------------------------------------------

func TestAdjudicateJSONCarriesTheReasonAndTheEpoch(t *testing.T) {
	crit := theCritical()
	state := stateWithTrust(t)
	opts := adjOpts(t, state, evidenceWith(t, crit), report.FindingID(crit))
	opts.jsonOut = true

	var out, errb bytes.Buffer
	if code := runAdjudicate(opts, &out, &errb); code != exitClean {
		t.Fatalf("adjudicate -json = %d, want %d\n%s", code, exitClean, errb.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out.String())
	}
	if doc["reason"] != opts.reason {
		t.Errorf("reason = %v, want %q", doc["reason"], opts.reason)
	}
	if doc["fingerprint_epoch"] == nil || doc["semantics_digest"] == nil {
		t.Errorf("the JSON record does not carry the epoch binding: %v", doc)
	}
}
