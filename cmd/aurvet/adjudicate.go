// cmd/aurvet/adjudicate.go
//
// The `adjudicate` subcommand: record, list, revoke.
//
// # Why this file exists
//
// `baseline init` refuses to write while an unresolved critical finding exists,
// and its refusal tells the operator, verbatim, to run
// `aurvet adjudicate <fingerprint> --reason ...`. Until this file landed there
// was no such subcommand: the tool's own instruction for getting past its most
// important refusal named a command that did not exist, and the signed store at
// <state>/adjudications.json was read by internal/adjudicate and written by
// nothing but a test.
//
// # What is deliberate here
//
//   - The reason is RECORDED, not printed. It travels into the signed
//     adjudication store and, through baseline.Bootstrap, into the signed
//     manifest. A reasonless adjudication cannot be constructed at all --
//     adjudicate.New refuses it -- so nothing can be unblocked by one.
//
//   - The SAME scan `baseline init` runs is run here, through the same
//     runBaselineScan seam. Any other scan and the two could disagree about
//     which findings exist, so an adjudication would be recorded against a
//     finding init never sees, and init would keep refusing while the operator
//     did exactly what it asked.
//
//   - A rule that declares no fingerprint epoch cannot be adjudicated, by
//     design (internal/adjudicate/epoch.go). That refusal names the file and
//     spells out the edit, because this deadlock -- a critical the operator is
//     told to adjudicate and then refused permission to adjudicate -- has
//     already been hit three times in this project.
//
//   - Nothing is written under --offline-root (INV-5), and no signing key is
//     ever generated (INV-7 is satisfied by a key the operator holds).
package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/report"
)

// adjudicateOpts is `adjudicate`'s input. It embeds baselineOpts because the two
// commands need the same environment -- state directory, trust set, signer, the
// scan seam -- and resolving it twice in two ways is how they would come to
// disagree about which findings exist.
type adjudicateOpts struct {
	baselineOpts

	// reason is mandatory and is checked by adjudicate.New, not here: one
	// implementation of "is this a reason" belongs in the package that stores it.
	reason string

	// scope is pin, subject or rule. The default is pin, the narrowest: a
	// default that hid more than the operator asked for would be a default that
	// hides the next finding too.
	scope string

	// expiryDays is 0 for the 180-day default. There is no value meaning never.
	expiryDays int

	// forceRuleScope is the explicit force a rule-scope adjudication requires.
	// It is spelled in full rather than as a bare -force so that it can never
	// grow into "ignore whatever refused", which on a security tool is the one
	// flag that must not exist.
	forceRuleScope bool
}

// adjudicateLockFile guards the read-modify-write of the signed store. Two
// concurrent `adjudicate` runs would otherwise each read the store, each add its
// own record, and the loser's judgement would vanish -- silently, because the
// winner's store is perfectly valid and signed.
const adjudicateLockFile = ".adjudications.lock"

func runAdjudicate(opts adjudicateOpts, stdout, stderr io.Writer) int {
	if len(opts.args) == 0 {
		adjudicateUsage(stderr)
		return exitUsage
	}
	env, err := resolveBaselineEnv(opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	switch opts.args[0] {
	case "list":
		if len(opts.args) != 1 {
			fmt.Fprintln(stderr, "usage: aurvet adjudicate list")
			return exitUsage
		}
		return adjudicateList(env, opts, stdout, stderr)

	case "revoke":
		if len(opts.args) != 2 {
			fmt.Fprintln(stderr, "usage: aurvet adjudicate revoke <fingerprint> "+
				"-key <file>|-signer <fingerprint>")
			return exitUsage
		}
		return adjudicateRevoke(env, opts, opts.args[1], stdout, stderr)

	default:
		if len(opts.args) != 1 {
			adjudicateUsage(stderr)
			return exitUsage
		}
		return adjudicateRecord(env, opts, opts.args[0], stdout, stderr)
	}
}

func adjudicateUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aurvet adjudicate <fingerprint> -reason <why> [-scope pin|subject|rule] "+
		"[-expiry-days n] [-force-rule-scope] -key <file>|-signer <fingerprint>")
	fmt.Fprintln(w, "       aurvet adjudicate list")
	fmt.Fprintln(w, "       aurvet adjudicate revoke <fingerprint> -key <file>|-signer <fingerprint>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  Records a signed, expiring judgement about ONE finding: \"I looked at this, here")
	fmt.Fprintln(w, "  is why it is acceptable, and here is when that has to be decided again\". The")
	fmt.Fprintln(w, "  reason is mandatory and is stored inside the signed document, not printed and")
	fmt.Fprintln(w, "  forgotten.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  scopes (widest last -- they are not interchangeable):")
	for _, s := range []adjudicate.Scope{adjudicate.ScopePin, adjudicate.ScopeSubject, adjudicate.ScopeRule} {
		fmt.Fprintf(w, "    %-8s %s\n", s, s.Describe())
	}
	fmt.Fprintf(w, "\n  expiry defaults to %d days and may not exceed %d. There is no non-expiring\n",
		int(adjudicate.DefaultExpiry.Hours()/24), int(adjudicate.MaxExpiry.Hours()/24))
	fmt.Fprintln(w, "  suppression: a permanent one is indistinguishable, a year later, from a check")
	fmt.Fprintln(w, "  that was never written.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  A coverage GAP can never be adjudicated (INV-3): adjudicating \"I could not")
	fmt.Fprintln(w, "  examine this\" would turn unexamined into clean.")
}

// -- record -------------------------------------------------------------------

func adjudicateRecord(env baselineEnv, opts adjudicateOpts, fp string, stdout, stderr io.Writer) int {
	if code := refuseOfflineWrite(env, "record an adjudication", stderr); code != 0 {
		return code
	}
	scope := adjudicate.Scope(opts.scope)
	if opts.scope == "" {
		scope = adjudicate.ScopePin
	}
	if !scope.Valid() {
		fmt.Fprintf(stderr, "aurvet: -scope %q is not one of pin, subject, rule\n", opts.scope)
		return exitUsage
	}
	expiry, err := adjudicationExpiry(opts.expiryDays)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	// The reason is checked by adjudicate.New, which owns the rule. It is checked
	// for EMPTINESS here as well, and only for emptiness, so that the operator
	// who forgot the flag is told about the flag rather than about a record they
	// never got as far as describing.
	if strings.TrimSpace(opts.reason) == "" {
		fmt.Fprintln(stderr, "aurvet: -reason is required and is not a formality: it is stored inside "+
			"the signed adjudication and is the only thing that lets anyone -- including you, in six "+
			"months -- re-evaluate the decision. An adjudication with no reason is an operator "+
			"clicking \"ignore\", which is the failure mode this whole lifecycle exists to prevent.")
		fmt.Fprintf(stderr, "  aurvet adjudicate %s -reason 'why this is acceptable' -key <file>\n", fp)
		return exitUsage
	}

	signer, closeSigner, err := resolveSigner(opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer closeSigner()
	if !reportUntrustedSigner(env, signer, "adjudication store", stderr) {
		return exitUsage
	}

	ev, err := runBaselineScan(env, opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	f, ok := findingByID(ev.Result, fp)
	if !ok {
		fmt.Fprintf(stderr, "aurvet: no finding with id %q in this scan (%d finding(s), %d gap(s))\n",
			fp, len(ev.Result.Findings), len(ev.Result.Gaps))
		fmt.Fprintln(stderr, "  ids come from the report, from `aurvet explain <id>`, or from the "+
			"refusal that sent you here. A coverage GAP has no adjudicable id: a gap says something "+
			"was not examined, and no judgement can turn unexamined into clean (INV-3).")
		return exitUsage
	}

	rec, err := adjudicate.New(adjudicate.BuiltIn(), adjudicate.Request{
		Finding: f,
		Scope:   scope,
		Reason:  opts.reason,
		// The signing key's fingerprint, not a name from a flag. "Who decided" is
		// not an authorisation claim -- the signature is that -- but it should not
		// be something anyone can type either.
		By:     signer.PublicKey().Fingerprint(),
		Now:    env.now,
		Expiry: expiry,
		Forced: opts.forceRuleScope,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		if errors.Is(err, adjudicate.ErrEpoch) {
			writeEpochDeadlock(stderr, f.RuleID)
		}
		if scope == adjudicate.ScopeRule && !opts.forceRuleScope {
			fmt.Fprintln(stderr, "  -scope rule turns this check off for every package and path on "+
				"this host, so it needs -force-rule-scope as well.")
		}
		return exitUsage
	}

	release, err := fsx.Lock(filepath.Join(env.stateDir, adjudicateLockFile), fsx.DefaultLockTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v; nothing was written\n", err)
		return exitIncomplete
	}
	defer func() { _ = release() }()

	existing, code := readStoreForRewrite(env, stderr)
	if code != 0 {
		return code
	}
	var replaced *adjudicate.Record
	kept := make([]adjudicate.Record, 0, len(existing)+1)
	for _, r := range existing {
		if r.Fingerprint == rec.Fingerprint {
			prev := r
			replaced = &prev
			continue
		}
		kept = append(kept, r)
	}
	kept = append(kept, rec)

	if err := writeAdjudicationStore(env, signer, kept); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	if opts.jsonOut {
		if err := writeJSON(stdout, adjudicateRecordDoc(rec, f, replaced, len(kept))); err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
		return exitClean
	}
	fmt.Fprintf(stdout, "adjudicated %s (%s %s:%s)\n", rec.Fingerprint, f.RuleID, f.SubjectKind, f.Subject)
	fmt.Fprintf(stdout, "  scope:   %s\n", rec.Scope.Describe())
	fmt.Fprintf(stdout, "  reason:  %s\n", rec.Reason)
	fmt.Fprintf(stdout, "  by:      %s\n", rec.By)
	fmt.Fprintf(stdout, "  expires: %s (epoch %d, semantics %s)\n",
		rec.ExpiresAt, rec.FingerprintEpoch, short12(rec.SemanticsDigest))
	if replaced != nil {
		fmt.Fprintf(stdout, "  replaced a judgement recorded %s: %s\n", replaced.At, replaced.Reason)
	}
	fmt.Fprintf(stdout, "  store:   %s (%d record(s)), signed by %s\n",
		filepath.Join(env.stateDir, adjudicationsFile), len(kept), signer.PublicKey().Fingerprint())
	fmt.Fprintln(stdout, "  the reason above is inside the signed store, and `baseline init` copies it "+
		"into the signed manifest. It expires; re-adjudicate or fix.")
	return exitClean
}

// writeEpochDeadlock turns "this rule declares no fingerprint epoch" into an
// edit somebody can make.
//
// The refusal itself is correct and must stay: without a declaration there is
// nothing to bind the judgement to, so a record could never later be told apart
// from one made against semantics that have since moved. What was missing was
// the next step, and "no" without a next step is how this deadlock survived
// three encounters.
func writeEpochDeadlock(w io.Writer, ruleID string) {
	fmt.Fprintf(w, "\n  This is a refusal by design, and it is fixable in one place:\n")
	fmt.Fprintf(w, "    1. add an entry for %q to the builtIn table in internal/adjudicate/epoch.go,\n", ruleID)
	fmt.Fprintf(w, "       listing what the rule MATCHES ON -- the data compared, the sets consulted,\n")
	fmt.Fprintf(w, "       the thresholds applied -- at Epoch: 1. Not its prose description: a\n")
	fmt.Fprintf(w, "       reworded summary must not invalidate anyone's recorded judgement.\n")
	fmt.Fprintf(w, "    2. add the same rule to testdata/adjudicate/epochs.golden.json, which is what\n")
	fmt.Fprintf(w, "       makes a later change to those inputs a test failure rather than a silent\n")
	fmt.Fprintf(w, "       loss of every suppression bound to them.\n")
	fmt.Fprintf(w, "  Until then this finding can be FIXED but not adjudicated. It is not being\n")
	fmt.Fprintf(w, "  ignored: `baseline init` will keep refusing, which is the honest outcome.\n")
}

// -- list ---------------------------------------------------------------------

// adjudicateList answers "what am I currently suppressing, and why did I say
// so" -- and, just as importantly, "what am I NOT suppressing any more".
//
// It runs the scan, because a record's state is a fact about this run and not
// about the file: dead, spent and active are only distinguishable against a set
// of findings. A listing that printed the file's contents would show an operator
// a suppression that has quietly stopped applying and call it active.
func adjudicateList(env baselineEnv, opts adjudicateOpts, stdout, stderr io.Writer) int {
	set := loadAdjudications(env)
	path := filepath.Join(env.stateDir, adjudicationsFile)
	if len(set.Records) == 0 && len(set.Faults) == 0 {
		if opts.jsonOut {
			return jsonOr(stdout, stderr, adjudicateListDoc(path, adjudicate.Outcome{}, nil))
		}
		fmt.Fprintf(stdout, "no adjudications at %s\n", path)
		fmt.Fprintln(stdout, "nothing is being suppressed on this host, which is the correct default")
		return exitClean
	}

	ev, err := runBaselineScan(env, opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	outcome := adjudicate.ApplyWith(adjudicate.BuiltIn(), set, ev.Result, env.now)

	if opts.jsonOut {
		return jsonOr(stdout, stderr, adjudicateListDoc(path, outcome, set.Faults))
	}

	fmt.Fprintf(stdout, "%d adjudication(s) at %s\n", len(set.Records), path)
	if set.SignedBy != nil {
		fmt.Fprintf(stdout, "signed by %s\n", set.SignedBy.Fingerprint())
	}
	for _, f := range set.Faults {
		fmt.Fprintf(stdout, "\n!! UNUSABLE (%s): %s\n", f.Where, f.Reason)
	}
	// Stale first, because it is the state that most looks like nothing happened:
	// the record is intact, the finding is back, and no line anywhere else says
	// why. Then the rest of the non-active states, then what is actually active.
	for _, state := range []adjudicate.State{
		adjudicate.StateStale, adjudicate.StateInvalid, adjudicate.StateExpired,
		adjudicate.StateSpent, adjudicate.StateDead, adjudicate.StateActive,
	} {
		for _, st := range outcome.ByState(state) {
			writeAdjudicationStatus(stdout, st)
		}
	}
	// INV-6: what is hidden right now, with its severity intact. A report that
	// silently omits suppressed findings lies by omission.
	if len(outcome.Suppressed) > 0 {
		fmt.Fprintf(stdout, "\ncurrently suppressed (%d):\n", len(outcome.Suppressed))
		for _, s := range outcome.Suppressed {
			fmt.Fprintf(stdout, "  [%s] %s %s:%s -- %s\n", s.Finding.Severity, s.Finding.RuleID,
				s.Finding.SubjectKind, s.Finding.Subject, s.Record.Reason)
		}
	}
	if attention := outcome.NeedsAttention(); len(attention) > 0 {
		fmt.Fprintf(stdout, "\n%d record(s) suppress nothing and need attention; "+
			"re-adjudicate or `aurvet adjudicate revoke <fingerprint>`\n", len(attention))
	}
	return adjudicateListExit(outcome, len(set.Faults))
}

// adjudicateListExit maps the listing onto the exit-code contract.
//
//	3  a record could not be read at all. Apply turns that into a coverage gap
//	   (INV-9), and a gap is exit 3 wherever it appears.
//	1  every record was readable, but at least one suppresses nothing: stale,
//	   expired, spent or dead. Actionable, and a cron job that greps for a clean
//	   suppression set should see it.
//	0  every record is doing what it claims.
//
// The SCAN's own gaps are deliberately not counted. Outcome.Kept.Gaps carries
// them through untouched, and they are a statement about the system rather than
// about the suppression set -- `aurvet scan` is where they belong. Counting them
// here would make `adjudicate list` exit 3 on every real host and so say nothing
// about the records it was asked about.
func adjudicateListExit(o adjudicate.Outcome, faults int) int {
	if len(o.ByState(adjudicate.StateInvalid)) > 0 || faults > 0 {
		return exitIncomplete
	}
	if len(o.NeedsAttention()) > 0 {
		return exitFindings
	}
	return exitClean
}

func writeAdjudicationStatus(w io.Writer, st adjudicate.Status) {
	r := st.Record
	fmt.Fprintf(w, "\n[%s] %s %s (%s scope)\n", st.State, r.RuleID, subjectOf(r), r.Scope)
	fmt.Fprintf(w, "    fingerprint: %s\n", r.Fingerprint)
	fmt.Fprintf(w, "    reason:      %s\n", r.Reason)
	fmt.Fprintf(w, "    decided:     %s by %s, expires %s\n", r.At, r.By, r.ExpiresAt)
	if st.Detail != "" {
		fmt.Fprintf(w, "    why not:     %s\n", st.Detail)
	}
	if len(st.Matched) > 0 {
		fmt.Fprintf(w, "    covers:      %s\n", strings.Join(st.Matched, ", "))
	}
	if r.Scope == adjudicate.ScopeRule && st.State == adjudicate.StateActive {
		fmt.Fprintf(w, "    !! this check is OFF EVERYWHERE on this host\n")
	}
}

func subjectOf(r adjudicate.Record) string {
	if r.Subject == "" {
		return "(every subject)"
	}
	return r.SubjectKind + ":" + r.Subject
}

// -- revoke -------------------------------------------------------------------

func adjudicateRevoke(env baselineEnv, opts adjudicateOpts, fp string, stdout, stderr io.Writer) int {
	if code := refuseOfflineWrite(env, "revoke an adjudication", stderr); code != 0 {
		return code
	}
	signer, closeSigner, err := resolveSigner(opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer closeSigner()
	if !reportUntrustedSigner(env, signer, "adjudication store", stderr) {
		return exitUsage
	}

	release, err := fsx.Lock(filepath.Join(env.stateDir, adjudicateLockFile), fsx.DefaultLockTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v; nothing was written\n", err)
		return exitIncomplete
	}
	defer func() { _ = release() }()

	existing, code := readStoreForRewrite(env, stderr)
	if code != 0 {
		return code
	}
	var kept, dropped []adjudicate.Record
	for _, r := range existing {
		if revokes(r, fp) {
			dropped = append(dropped, r)
			continue
		}
		kept = append(kept, r)
	}
	if len(dropped) == 0 {
		fmt.Fprintf(stderr, "aurvet: no adjudication with fingerprint %q in %s (%d record(s)); "+
			"`aurvet adjudicate list` shows what is there\n", fp,
			filepath.Join(env.stateDir, adjudicationsFile), len(existing))
		return exitUsage
	}
	if err := writeAdjudicationStore(env, signer, kept); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if opts.jsonOut {
		return jsonOr(stdout, stderr, map[string]any{
			"action": "revoke", "fingerprint": fp,
			"revoked": len(dropped), "remaining": len(kept),
		})
	}
	for _, r := range dropped {
		fmt.Fprintf(stdout, "revoked %s (%s %s, %s scope), decided %s: %s\n",
			r.Fingerprint, r.RuleID, subjectOf(r), r.Scope, r.At, r.Reason)
	}
	fmt.Fprintf(stdout, "%d record(s) remain in %s\n", len(kept),
		filepath.Join(env.stateDir, adjudicationsFile))
	fmt.Fprintln(stdout, "anything this record was hiding is reported in full from the next run on")
	return exitClean
}

// revokes reports whether fp names this record.
//
// Two spellings are accepted, and the second is not a convenience. A record's
// own fingerprint covers (rule, subject, SCOPE), so a pin, a subject-scope
// record and a rule-scope record over one finding have three different
// fingerprints -- by design, so a record cannot be relabelled into a wider scope.
// But the id an operator HOLDS is the FINDING id from the report, which is the
// subject-scope spelling. Accepting only the record fingerprint would mean the
// string that got you into a suppression cannot get you out of one, and a
// suppression that is hard to withdraw is a suppression that outlives its
// reason.
//
// A rule-scope record names no subject, so it has no finding-id spelling and is
// revocable only by its own fingerprint -- which is correct: turning a check back
// on everywhere should not happen as a side effect of naming one finding.
func revokes(r adjudicate.Record, fp string) bool {
	if r.Fingerprint == fp {
		return true
	}
	if r.Subject == "" {
		return false
	}
	return adjudicate.FingerprintFor(r.RuleID, r.SubjectKind, r.Subject, adjudicate.ScopeSubject) == fp
}

// -- the store ----------------------------------------------------------------

// readStoreForRewrite returns the records a rewrite must preserve.
//
// It REFUSES when the existing store is present but unreadable -- a bad
// signature, a truncated file, a schema this build does not know. The
// alternative is worse than it looks: loadAdjudications correctly reports those
// as faults and yields no records, so a rewrite would silently drop every
// judgement in the file and re-sign the result as complete. An operator who
// cannot read their own adjudications must be told, not quietly given a fresh
// empty store.
func readStoreForRewrite(env baselineEnv, stderr io.Writer) ([]adjudicate.Record, int) {
	path := filepath.Join(env.stateDir, adjudicationsFile)
	if _, err := os.Stat(path); errors.Is(err, os.ErrNotExist) {
		return nil, 0
	}
	set := loadAdjudications(env)
	if len(set.Faults) > 0 {
		fmt.Fprintf(stderr, "aurvet: refusing to rewrite %s: it is present but could not be read in "+
			"full, and a rewrite would discard what it holds\n", path)
		for _, f := range set.Faults {
			fmt.Fprintf(stderr, "  %s: %s\n", f.Where, f.Reason)
		}
		fmt.Fprintln(stderr, "  fix or remove the store deliberately; do not let a rewrite do it for you")
		return nil, exitIncomplete
	}
	return set.Records, 0
}

// writeAdjudicationStore signs and writes the store.
//
// An EMPTY set removes the files rather than writing a signed document with no
// records: an absent store suppresses nothing and is silent, while a records:[]
// document is reported as a fault on every subsequent run -- a permanent
// coverage gap manufactured by the operator tidying up.
func writeAdjudicationStore(env baselineEnv, signer baseline.Signer, recs []adjudicate.Record) error {
	path := filepath.Join(env.stateDir, adjudicationsFile)
	if len(recs) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if err := os.Remove(path + ".sig"); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := adjudicate.MarshalStore(recs)
	if err != nil {
		return err
	}
	sig, err := adjudicate.SignStore(signer, raw)
	if err != nil {
		return err
	}
	// Signature first, document second, the same order internal/chain uses: the
	// window an interruption leaves open should be the one that reads as
	// unverifiable, and an unverifiable store suppresses nothing.
	if err := writeFileAtomic(path+".sig", sig, 0o600); err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

// writeFileAtomic is temp + fsync + rename + fsync-dir.
//
// It is local to cmd rather than shared because internal/chain and
// internal/bundle each hold their own copy behind their own invariants, and
// exporting one of them for a caller in cmd would give three packages a shared
// mutable surface for no gain. What must not diverge is the ORDER (signature
// before document), and that lives in writeAdjudicationStore above.
func writeFileAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return err
	}
	name := tmp.Name()
	fail := func(e error) error {
		tmp.Close()
		_ = os.Remove(name)
		return e
	}
	if err := tmp.Chmod(perm); err != nil {
		return fail(err)
	}
	if _, err := tmp.Write(data); err != nil {
		return fail(err)
	}
	if err := tmp.Sync(); err != nil {
		return fail(err)
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(name)
		return err
	}
	if err := os.Rename(name, path); err != nil {
		_ = os.Remove(name)
		return err
	}
	d, err := os.Open(dir)
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}

// -- shared helpers -----------------------------------------------------------

// refuseOfflineWrite is INV-5 for the two subcommands that write.
//
// An --offline-root run is examining somebody else's filesystem, usually from a
// rescue environment. A judgement recorded there would be filed into a store
// that belongs to whichever system's state directory resolved -- either inside
// the tree being audited, or this host's own store, which describes a different
// machine. Both are wrong, and there is no third destination, so this is a usage
// error rather than a silent no-op.
func refuseOfflineWrite(env baselineEnv, what string, stderr io.Writer) int {
	if env.offlineRoot == "" {
		return 0
	}
	fmt.Fprintf(stderr, "aurvet: refusing to %s under --offline-root: nothing is written under the "+
		"examined tree (INV-5), and an adjudication is a judgement about ONE host's findings recorded "+
		"in THAT host's signed store\n", what)
	return exitUsage
}

// reportUntrustedSigner refuses a signing key the host does not already trust.
//
// Adding it here would mean whoever runs the command chooses what this host
// trusts forever after, which is a decision that belongs to a human with the
// fingerprint in front of them. The consequence if it were skipped is not
// abstract: a document signed by an untrusted key reads as unverifiable on the
// next run, and unverifiable reads as ABSENT -- so a baseline would silently not
// exist and an adjudication would silently not apply.
func reportUntrustedSigner(env baselineEnv, signer baseline.Signer, what string, stderr io.Writer) bool {
	if trusts(env.trusted, signer.PublicKey()) {
		return true
	}
	keys := filepath.Join(env.stateDir, trustedKeysFile)
	fmt.Fprintf(stderr, "aurvet: the signing key is not in %s, so the %s signed with it would not "+
		"verify on the next run, and a document that does not verify reads as absent (%s)\n",
		keys, what, env.trustReason)
	fmt.Fprintf(stderr, "  add it deliberately, after checking the fingerprint (%s):\n",
		signer.PublicKey().Fingerprint())
	fmt.Fprintf(stderr, "    install -Dm600 /dev/stdin %s <<'EOF'\n    %s\n    EOF\n",
		keys, signer.PublicKey().AuthorizedKey())
	return false
}

func adjudicationExpiry(days int) (time.Duration, error) {
	switch {
	case days == 0:
		return 0, nil // adjudicate.New applies DefaultExpiry
	case days < 0:
		return 0, fmt.Errorf("-expiry-days %d is not a duration a judgement can last", days)
	case time.Duration(days)*24*time.Hour > adjudicate.MaxExpiry:
		return 0, fmt.Errorf("-expiry-days %d exceeds the %d-day maximum; there is no non-expiring "+
			"suppression in this format, because a permanent one is indistinguishable a year later "+
			"from a check that was never written",
			days, int(adjudicate.MaxExpiry.Hours()/24))
	default:
		return time.Duration(days) * 24 * time.Hour, nil
	}
}

func findingByID(res finding.Result, id string) (finding.Finding, bool) {
	for _, f := range res.Findings {
		if report.FindingID(f) == id {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// -- json ---------------------------------------------------------------------

func writeJSON(w io.Writer, v any) error {
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(v)
}

func jsonOr(stdout, stderr io.Writer, v any) int {
	if err := writeJSON(stdout, v); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	return exitClean
}

func adjudicateRecordDoc(rec adjudicate.Record, f finding.Finding, replaced *adjudicate.Record, total int) map[string]any {
	doc := map[string]any{
		"action":            "adjudicate",
		"fingerprint":       rec.Fingerprint,
		"rule_id":           rec.RuleID,
		"subject":           rec.Subject,
		"subject_kind":      rec.SubjectKind,
		"scope":             string(rec.Scope),
		"reason":            rec.Reason,
		"by":                rec.By,
		"at":                rec.At,
		"expires_at":        rec.ExpiresAt,
		"fingerprint_epoch": rec.FingerprintEpoch,
		"semantics_digest":  rec.SemanticsDigest,
		"finding_severity":  f.Severity.String(),
		"records":           total,
	}
	if replaced != nil {
		doc["replaced_at"] = replaced.At
		doc["replaced_reason"] = replaced.Reason
	}
	return doc
}

func adjudicateListDoc(path string, o adjudicate.Outcome, faults []adjudicate.Fault) map[string]any {
	records := make([]map[string]any, 0, len(o.Statuses))
	for _, st := range o.Statuses {
		records = append(records, map[string]any{
			"fingerprint":       st.Record.Fingerprint,
			"state":             string(st.State),
			"suppresses":        st.State.Suppresses(),
			"detail":            st.Detail,
			"rule_id":           st.Record.RuleID,
			"subject":           st.Record.Subject,
			"subject_kind":      st.Record.SubjectKind,
			"scope":             string(st.Record.Scope),
			"reason":            st.Record.Reason,
			"by":                st.Record.By,
			"at":                st.Record.At,
			"expires_at":        st.Record.ExpiresAt,
			"fingerprint_epoch": st.Record.FingerprintEpoch,
			"covers":            st.Matched,
		})
	}
	suppressed := make([]map[string]any, 0, len(o.Suppressed))
	for _, s := range o.Suppressed {
		suppressed = append(suppressed, map[string]any{
			"rule_id":      s.Finding.RuleID,
			"subject":      s.Finding.Subject,
			"subject_kind": s.Finding.SubjectKind,
			"severity":     s.Finding.Severity.String(),
			"reason":       s.Record.Reason,
			"fingerprint":  s.Record.Fingerprint,
		})
	}
	bad := make([]map[string]string, 0, len(faults))
	for _, f := range faults {
		bad = append(bad, map[string]string{"where": f.Where, "reason": f.Reason})
	}
	sort.SliceStable(records, func(i, j int) bool {
		return records[i]["fingerprint"].(string) < records[j]["fingerprint"].(string)
	})
	return map[string]any{
		"store":            path,
		"records":          records,
		"suppressed":       suppressed,
		"faults":           bad,
		"needs_attention":  len(o.NeedsAttention()),
		"gaps_from_faults": len(o.Kept.Gaps),
	}
}
