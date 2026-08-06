// cmd/aurvet/triage.go
//
// The `triage` subcommand: ack, snooze, note, list, drop.
//
// # Why this file exists
//
// Spec §12 asks for THREE weights and the tool shipped two: a signed
// adjudication, which needs an ed25519 key and a reason of substance, and
// nothing else. So an operator with one noisy `info` finding about their own
// hand-written systemd unit had two options -- produce a key and sign a formal
// judgement about it, or ignore the tool's output. §12 says which one they pick,
// and that is the whole reason this command exists.
//
// # What is deliberate here
//
//   - NOTHING HERE CAN UNBLOCK `baseline init`. The store this writes is not the
//     store bootstrap reads, and no code path joins them: internal/triage is not
//     imported by internal/baseline, internal/chain or internal/adjudicate, and
//     baseline.go does not mention it. Both halves are enforced by tests -- the
//     structural one in internal/triage, the end-to-end one in triage_test.go,
//     which triages every critical on a host and watches `baseline init` refuse
//     with the same count and the same reasons.
//
//   - The record is UNSIGNED and every rendering says so. A reader must never
//     mistake one for a signed judgement, so `aurvet triage list` prints the word
//     and the consequence rather than leaving the absence of a "signed by" line
//     to be noticed.
//
//   - `note` suppresses nothing, and the output says that on the line that
//     records it. A `note` that quietly hid something would be the worst of the
//     three verbs, because it is the one an investigation reaches for.
//
//   - The SAME scan `adjudicate` and `baseline init` run is run here, through the
//     same runBaselineScan seam. Any other scan and the two could disagree about
//     which findings exist, so an operator would triage a finding the rest of the
//     tool does not have.
//
//   - Nothing is written under --offline-root (INV-5), and no key is needed,
//     asked for or generated.
package main

import (
	"fmt"
	"io"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/triage"
)

// triageOpts is `triage`'s input. It embeds baselineOpts for the environment and
// the scan seam, and for no other reason: no field of it that concerns signing
// is read on this path, and resolveSigner is never called.
type triageOpts struct {
	baselineOpts

	// note is the free text. Mandatory for `note`, optional for `ack` and
	// `snooze` -- the friction of a mandatory reason belongs to the signed
	// weight, and putting it here too would rebuild the wall §12 removed.
	note string

	// scope is pin or subject. Rule scope is refused; internal/triage's
	// Request.Scope carries the argument.
	scope string

	// expiryDays is 0 for the verb's own default.
	expiryDays int
}

func runTriage(opts triageOpts, stdout, stderr io.Writer) int {
	if len(opts.args) == 0 {
		triageUsage(stderr)
		return exitUsage
	}
	env, err := resolveBaselineEnv(opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	switch verb := opts.args[0]; verb {
	case "list":
		if len(opts.args) != 1 {
			fmt.Fprintln(stderr, "usage: aurvet triage list")
			return exitUsage
		}
		return triageList(env, opts, stdout, stderr)

	case "drop":
		if len(opts.args) != 2 {
			fmt.Fprintln(stderr, "usage: aurvet triage drop <fingerprint>")
			return exitUsage
		}
		return triageDrop(env, opts, opts.args[1], stdout, stderr)

	case "ack", "snooze", "note":
		if len(opts.args) != 2 {
			fmt.Fprintf(stderr, "usage: aurvet triage %s <fingerprint> [-reason <text>] "+
				"[-scope pin|subject] [-expiry-days n]\n", verb)
			return exitUsage
		}
		return triageRecord(env, opts, triage.Verb(verb), opts.args[1], stdout, stderr)

	default:
		fmt.Fprintf(stderr, "aurvet: unknown triage verb %q\n", verb)
		triageUsage(stderr)
		return exitUsage
	}
}

func triageUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aurvet triage <ack|snooze|note> <fingerprint> [-reason <text>] "+
		"[-scope pin|subject] [-expiry-days n]")
	fmt.Fprintln(w, "       aurvet triage list")
	fmt.Fprintln(w, "       aurvet triage drop <fingerprint>")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  The LIGHTWEIGHT layer (spec §12): local, UNSIGNED, keyless, expiring. It is not")
	fmt.Fprintln(w, "  a judgement and it is not evidence of one. It CANNOT unblock `baseline init`,")
	fmt.Fprintln(w, "  which reads the signed adjudication store and nothing else.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  verbs:")
	for _, v := range triage.Verbs() {
		fmt.Fprintf(w, "    %-7s %s\n", v, v.Describe())
		fmt.Fprintf(w, "            default %d day(s), maximum %d\n",
			days(v.DefaultExpiry()), days(v.MaxExpiry()))
	}
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  scopes: pin (this exact evidence, the default) or subject (this rule for this")
	fmt.Fprintln(w, "  one package or path). Rule scope is NOT offered here -- turning a check off")
	fmt.Fprintln(w, "  everywhere is a standing property of the host and needs")
	fmt.Fprintln(w, "  `aurvet adjudicate -scope rule -force-rule-scope`, which is signed and attributable.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  A coverage GAP can never be triaged (INV-3): a gap says something was not")
	fmt.Fprintln(w, "  examined, and no acknowledgement turns unexamined into examined.")
}

func days(d time.Duration) int { return int(d.Hours() / 24) }

// -- record -------------------------------------------------------------------

func triageRecord(env baselineEnv, opts triageOpts, verb triage.Verb, fp string, stdout, stderr io.Writer) int {
	if code := refuseOfflineTriageWrite(env, verb, stderr); code != 0 {
		return code
	}
	scope := adjudicate.Scope(opts.scope)
	if opts.scope == "" {
		scope = adjudicate.ScopePin
	}
	expiry, err := triageExpiry(verb, opts.expiryDays)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	// The window actually applied, resolved here so the confirmation states the
	// number the operator asked for rather than a wall-clock delta that reads one
	// day short whenever the run takes longer than nothing.
	window := expiry
	if window == 0 {
		window = verb.DefaultExpiry()
	}
	if verb == triage.VerbNote && strings.TrimSpace(opts.note) == "" {
		fmt.Fprintln(stderr, "aurvet: `triage note` requires -reason: the note is the whole point of "+
			"the verb, and an empty one annotates nothing and suppresses nothing. If you meant to "+
			"hide the finding, that is `triage ack`.")
		return exitUsage
	}

	ev, err := runBaselineScan(env, opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	f, ok := findingByID(ev.Result, fp)
	if !ok {
		writeUnknownFingerprint(stderr, ev.Result, fp)
		return exitUsage
	}

	rec, err := triage.New(adjudicate.BuiltIn(), triage.Request{
		Finding: f, Verb: verb, Scope: scope, Note: opts.note, Now: env.now, Expiry: expiry,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	release, err := fsx.Lock(filepath.Join(env.stateDir, triage.LockFile), fsx.DefaultLockTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v; nothing was written\n", err)
		return exitIncomplete
	}
	defer func() { _ = release() }()

	set := triage.Load(env.stateDir)
	if len(set.Faults) > 0 {
		// The same refusal `adjudicate` makes, for the same reason: a rewrite over
		// a store nobody could read would discard what it holds and leave a
		// perfectly valid file behind.
		fmt.Fprintf(stderr, "aurvet: refusing to rewrite %s: it is present but could not be read in "+
			"full, and a rewrite would discard what it holds\n", set.Source)
		for _, ft := range set.Faults {
			fmt.Fprintf(stderr, "  %s: %s\n", ft.Where, ft.Reason)
		}
		return exitIncomplete
	}

	var replaced *triage.Record
	kept := make([]triage.Record, 0, len(set.Records)+1)
	for _, r := range set.Records {
		if r.Verb == rec.Verb && r.Fingerprint == rec.Fingerprint {
			prev := r
			replaced = &prev
			continue
		}
		kept = append(kept, r)
	}
	kept = append(kept, rec)

	if err := triage.Save(env.stateDir, kept); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	if opts.jsonOut {
		return jsonOr(stdout, stderr, triageRecordDoc(rec, f, replaced, len(kept), env.stateDir))
	}
	fmt.Fprintf(stdout, "%s %s (%s %s:%s)\n", verb, rec.Fingerprint, f.RuleID, f.SubjectKind, f.Subject)
	fmt.Fprintf(stdout, "  effect:  %s\n", verb.Describe())
	fmt.Fprintf(stdout, "  scope:   %s\n", scope.Describe())
	if rec.Note != "" {
		fmt.Fprintf(stdout, "  note:    %s\n", rec.Note)
	}
	fmt.Fprintf(stdout, "  expires: %s (%d day(s))\n", rec.ExpiresAt, days(window))
	if rec.EpochBound() {
		fmt.Fprintf(stdout, "  bound:   fingerprint epoch %d, semantics %s -- if this rule's matching "+
			"semantics move, this record reads stale and suppresses nothing\n",
			rec.FingerprintEpoch, short12(rec.SemanticsDigest))
	} else {
		fmt.Fprintf(stdout, "  bound:   NOT bound to a fingerprint epoch (rule %q declares none), so "+
			"this record cannot be told stale if the rule changes. It expires regardless.\n", rec.RuleID)
	}
	if replaced != nil {
		fmt.Fprintf(stdout, "  replaced an earlier %s recorded %s\n", replaced.Verb, replaced.At)
	}
	fmt.Fprintf(stdout, "  store:   %s (%d record(s)), %s\n",
		filepath.Join(env.stateDir, triage.FileName), len(kept), triageUnsignedLine)
	return exitClean
}

// triageUnsignedLine is the sentence that must appear wherever a triage record
// is reported. It is a constant so that the three renderings cannot drift into
// describing this store with three different degrees of authority.
const triageUnsignedLine = "LOCAL AND UNSIGNED -- this is not a signed judgement and it does " +
	"not unblock `aurvet baseline init`"

// writeUnknownFingerprint answers the one wrong id an operator is most likely to
// have typed: the subject of a coverage GAP.
func writeUnknownFingerprint(stderr io.Writer, res finding.Result, fp string) {
	fmt.Fprintf(stderr, "aurvet: no finding with id %q in this scan (%d finding(s), %d gap(s))\n",
		fp, len(res.Findings), len(res.Gaps))
	fmt.Fprintln(stderr, "  ids come from the report, from `aurvet explain <id>`, or from "+
		"`aurvet scan -json`. A coverage GAP has no triageable id: a gap says something was not "+
		"examined, and no acknowledgement turns unexamined into examined (INV-3).")
}

// -- list ---------------------------------------------------------------------

// triageList answers "what am I hiding from myself, and what has quietly stopped
// hiding anything".
//
// It runs the scan, because a record's state is a fact about this run and not
// about the file: dead, spent and active are only distinguishable against a set
// of findings, and a listing that printed the file's contents would show an
// operator a record that has stopped applying and call it active.
func triageList(env baselineEnv, opts triageOpts, stdout, stderr io.Writer) int {
	set := triage.Load(env.stateDir)
	path := filepath.Join(env.stateDir, triage.FileName)
	if len(set.Records) == 0 && len(set.Faults) == 0 {
		if opts.jsonOut {
			return jsonOr(stdout, stderr, triageListDoc(path, triage.Outcome{}, nil))
		}
		fmt.Fprintf(stdout, "no triage records at %s\n", path)
		// "this host" is wrong under --offline-root, where the store read is the
		// examined tree's and not this machine's. Saying so would be a small lie
		// about whose suppressions were just reported empty, which is the kind of
		// sentence an operator would reasonably act on.
		where := "on this host"
		if opts.offlineRoot != "" {
			where = "in the examined tree"
		}
		fmt.Fprintf(stdout, "nothing is being held back %s, which is the correct default\n", where)
		return exitClean
	}

	ev, err := runBaselineScan(env, opts.baselineOpts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	outcome := triage.ApplyWith(adjudicate.BuiltIn(), set, ev.Result, env.now)

	if opts.jsonOut {
		return jsonOr(stdout, stderr, triageListDoc(path, outcome, set.Faults))
	}

	fmt.Fprintf(stdout, "%d triage record(s) at %s\n", len(set.Records), path)
	fmt.Fprintf(stdout, "%s\n", triageUnsignedLine)
	for _, f := range set.Faults {
		fmt.Fprintf(stdout, "\n!! UNUSABLE (%s): %s\n", f.Where, f.Reason)
	}
	// Stale first, because it is the state that most looks like nothing happened:
	// the record is intact, the finding is back, and no line anywhere else says
	// why. Then the rest of the states that suppress nothing, then what is live.
	for _, state := range []triage.State{
		triage.StateStale, triage.StateInvalid, triage.StateExpired,
		triage.StateSpent, triage.StateDead, triage.StateActive, triage.StateAnnotated,
	} {
		for _, st := range outcome.ByState(state) {
			writeTriageStatus(stdout, st)
		}
	}
	// INV-6: what is hidden right now, with its severity intact.
	if len(outcome.Suppressed) > 0 {
		fmt.Fprintf(stdout, "\ncurrently hidden from the default view (%d):\n", len(outcome.Suppressed))
		for _, s := range outcome.Suppressed {
			fmt.Fprintf(stdout, "  [%s] %s %s:%s -- %s until %s\n", s.Finding.Severity,
				s.Finding.RuleID, s.Finding.SubjectKind, s.Finding.Subject,
				s.Record.Verb, s.Record.ExpiresAt)
		}
	}
	if len(outcome.Annotated) > 0 {
		fmt.Fprintf(stdout, "\nannotated and STILL REPORTED (%d):\n", len(outcome.Annotated))
		for _, a := range outcome.Annotated {
			fmt.Fprintf(stdout, "  [%s] %s %s:%s -- %s\n", a.Finding.Severity, a.Finding.RuleID,
				a.Finding.SubjectKind, a.Finding.Subject, a.Record.Note)
		}
	}
	// §12: dead suppressions that match nothing are reported for removal.
	var removable []triage.Status
	for _, st := range outcome.NeedsAttention() {
		if st.State.NeedsRemoval() {
			removable = append(removable, st)
		}
	}
	if len(removable) > 0 {
		fmt.Fprintf(stdout, "\n%d record(s) will never do anything again; remove them so they stop "+
			"hiding the next one:\n", len(removable))
		for _, st := range removable {
			fmt.Fprintf(stdout, "  aurvet triage drop %s   # %s %s, %s\n",
				st.Record.Fingerprint, st.Record.Verb, subjectOfTriage(st.Record), st.State)
		}
	}
	if attention := outcome.NeedsAttention(); len(attention) > 0 {
		fmt.Fprintf(stdout, "\n%d record(s) suppress nothing and need attention\n", len(attention))
	}
	return triageListExit(outcome, len(set.Faults))
}

// triageListExit maps the listing onto the exit-code contract, on exactly the
// terms `adjudicate list` chose -- two commands that answer the same shape of
// question must not disagree about what their exit code means.
//
//	3  a record could not be read at all. Apply turns that into a coverage gap
//	   (INV-9), and a gap is exit 3 wherever it appears.
//	1  every record was readable, but at least one suppresses nothing: stale,
//	   expired, spent or dead. Actionable.
//	0  every record is doing what it claims -- INCLUDING a note, which claims to
//	   suppress nothing and is therefore not a problem.
//
// The SCAN's own gaps are deliberately not counted: they are a statement about
// the system rather than about the triage set, and counting them would make this
// command exit 3 on every real host and so say nothing about what it was asked.
func triageListExit(o triage.Outcome, faults int) int {
	if len(o.ByState(triage.StateInvalid)) > 0 || faults > 0 {
		return exitIncomplete
	}
	if len(o.NeedsAttention()) > 0 {
		return exitFindings
	}
	return exitClean
}

func writeTriageStatus(w io.Writer, st triage.Status) {
	r := st.Record
	fmt.Fprintf(w, "\n[%s] %s %s %s (%s scope)\n", st.State, r.Verb, r.RuleID, subjectOfTriage(r), r.Scope)
	fmt.Fprintf(w, "    fingerprint: %s\n", r.Fingerprint)
	if r.Note != "" {
		fmt.Fprintf(w, "    note:        %s\n", r.Note)
	}
	fmt.Fprintf(w, "    recorded:    %s, expires %s\n", r.At, r.ExpiresAt)
	if st.Detail != "" {
		fmt.Fprintf(w, "    effect:      %s\n", st.Detail)
	}
	if st.Caveat != "" {
		fmt.Fprintf(w, "    caveat:      %s\n", st.Caveat)
	}
	if len(st.Matched) > 0 {
		fmt.Fprintf(w, "    covers:      %s\n", strings.Join(st.Matched, ", "))
	}
}

func subjectOfTriage(r triage.Record) string { return r.SubjectKind + ":" + r.Subject }

// -- drop ---------------------------------------------------------------------

// triageDrop removes records by fingerprint. It is the counterpart to the "dead
// suppressions are reported for removal" line: a report that names a record an
// operator cannot then remove is a report that trains people to ignore it.
func triageDrop(env baselineEnv, opts triageOpts, fp string, stdout, stderr io.Writer) int {
	if code := refuseOfflineTriageWrite(env, "drop", stderr); code != 0 {
		return code
	}
	release, err := fsx.Lock(filepath.Join(env.stateDir, triage.LockFile), fsx.DefaultLockTimeout)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v; nothing was written\n", err)
		return exitIncomplete
	}
	defer func() { _ = release() }()

	set := triage.Load(env.stateDir)
	if len(set.Faults) > 0 {
		fmt.Fprintf(stderr, "aurvet: refusing to rewrite %s: it is present but could not be read in "+
			"full, and a rewrite would discard what it holds\n", set.Source)
		for _, ft := range set.Faults {
			fmt.Fprintf(stderr, "  %s: %s\n", ft.Where, ft.Reason)
		}
		return exitIncomplete
	}

	var kept, dropped []triage.Record
	for _, r := range set.Records {
		if triageNamedBy(r, fp) {
			dropped = append(dropped, r)
			continue
		}
		kept = append(kept, r)
	}
	if len(dropped) == 0 {
		fmt.Fprintf(stderr, "aurvet: no triage record with fingerprint %q in %s (%d record(s)); "+
			"`aurvet triage list` shows what is there\n", fp,
			filepath.Join(env.stateDir, triage.FileName), len(set.Records))
		return exitUsage
	}
	if err := triage.Save(env.stateDir, kept); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if opts.jsonOut {
		return jsonOr(stdout, stderr, map[string]any{
			"action": "triage drop", "fingerprint": fp,
			"dropped": len(dropped), "remaining": len(kept),
		})
	}
	for _, r := range dropped {
		fmt.Fprintf(stdout, "dropped %s %s (%s %s, %s scope), recorded %s\n",
			r.Verb, r.Fingerprint, r.RuleID, subjectOfTriage(r), r.Scope, r.At)
	}
	fmt.Fprintf(stdout, "%d record(s) remain in %s\n", len(kept),
		filepath.Join(env.stateDir, triage.FileName))
	fmt.Fprintln(stdout, "anything they were holding back is reported in full from the next run on")
	return exitClean
}

// triageNamedBy accepts two spellings, for the reason `adjudicate revoke` does:
// a record's own fingerprint covers (rule, subject, SCOPE), so a pin and a
// subject-scope record over one finding have different ones -- but the id an
// operator HOLDS is the finding id from the report, which is the subject-scope
// spelling. A record that is hard to withdraw is a record that outlives its
// reason.
func triageNamedBy(r triage.Record, fp string) bool {
	if r.Fingerprint == fp {
		return true
	}
	return adjudicate.FingerprintFor(r.RuleID, r.SubjectKind, r.Subject, adjudicate.ScopeSubject) == fp
}

// -- shared -------------------------------------------------------------------

// refuseOfflineTriageWrite is INV-5 for the four subcommands that write. An
// --offline-root run is examining somebody else's filesystem, and a record filed
// there would land either inside the tree being audited or in this host's own
// store, which describes a different machine. Both are wrong and there is no
// third destination, so this is a usage error rather than a silent no-op.
func refuseOfflineTriageWrite(env baselineEnv, what any, stderr io.Writer) int {
	if env.offlineRoot == "" {
		return 0
	}
	fmt.Fprintf(stderr, "aurvet: refusing to `triage %v` under --offline-root: nothing is written "+
		"under the examined tree (INV-5), and a triage record is a note about ONE host's findings "+
		"kept in THAT host's state directory. `aurvet triage list` reads and is allowed.\n", what)
	return exitUsage
}

func triageExpiry(v triage.Verb, days int) (time.Duration, error) {
	switch {
	case days == 0:
		return 0, nil // triage.New applies the verb's default
	case days < 0:
		return 0, fmt.Errorf("-expiry-days %d is not a duration a record can last", days)
	case time.Duration(days)*24*time.Hour > v.MaxExpiry():
		return 0, fmt.Errorf("-expiry-days %d exceeds the %d-day maximum for `%s`; triage is the "+
			"LIGHTER weight of the two, so it expires sooner than a signed adjudication and never "+
			"later. There is no non-expiring form", days, int(v.MaxExpiry().Hours()/24), v)
	default:
		return time.Duration(days) * 24 * time.Hour, nil
	}
}

// -- json ---------------------------------------------------------------------

func triageRecordDoc(rec triage.Record, f finding.Finding, replaced *triage.Record, total int, stateDir string) map[string]any {
	doc := map[string]any{
		"action":            "triage",
		"verb":              string(rec.Verb),
		"signed":            false,
		"unblocks_baseline": false,
		"suppresses":        rec.Verb.Suppresses(),
		"fingerprint":       rec.Fingerprint,
		"rule_id":           rec.RuleID,
		"subject":           rec.Subject,
		"subject_kind":      rec.SubjectKind,
		"scope":             string(rec.Scope),
		"note":              rec.Note,
		"at":                rec.At,
		"expires_at":        rec.ExpiresAt,
		"epoch_bound":       rec.EpochBound(),
		"fingerprint_epoch": rec.FingerprintEpoch,
		"finding_severity":  f.Severity.String(),
		"records":           total,
		"store":             filepath.Join(stateDir, triage.FileName),
	}
	if replaced != nil {
		doc["replaced_at"] = replaced.At
	}
	return doc
}

func triageListDoc(path string, o triage.Outcome, faults []triage.Fault) map[string]any {
	records := make([]map[string]any, 0, len(o.Statuses))
	for _, st := range o.Statuses {
		records = append(records, map[string]any{
			"fingerprint":       st.Record.Fingerprint,
			"verb":              string(st.Record.Verb),
			"state":             string(st.State),
			"suppresses":        st.State.Suppresses(),
			"needs_removal":     st.State.NeedsRemoval(),
			"detail":            st.Detail,
			"caveat":            st.Caveat,
			"rule_id":           st.Record.RuleID,
			"subject":           st.Record.Subject,
			"subject_kind":      st.Record.SubjectKind,
			"scope":             string(st.Record.Scope),
			"note":              st.Record.Note,
			"at":                st.Record.At,
			"expires_at":        st.Record.ExpiresAt,
			"epoch_bound":       st.Record.EpochBound(),
			"fingerprint_epoch": st.Record.FingerprintEpoch,
			"covers":            st.Matched,
		})
	}
	hidden := make([]map[string]any, 0, len(o.Suppressed))
	for _, s := range o.Suppressed {
		hidden = append(hidden, map[string]any{
			"rule_id": s.Finding.RuleID, "subject": s.Finding.Subject,
			"subject_kind": s.Finding.SubjectKind, "severity": s.Finding.Severity.String(),
			"verb": string(s.Record.Verb), "expires_at": s.Record.ExpiresAt,
			"fingerprint": s.Record.Fingerprint,
		})
	}
	annotated := make([]map[string]any, 0, len(o.Annotated))
	for _, a := range o.Annotated {
		annotated = append(annotated, map[string]any{
			"rule_id": a.Finding.RuleID, "subject": a.Finding.Subject,
			"subject_kind": a.Finding.SubjectKind, "severity": a.Finding.Severity.String(),
			"note": a.Record.Note, "fingerprint": a.Record.Fingerprint,
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
		"store":             path,
		"signed":            false,
		"unblocks_baseline": false,
		"records":           records,
		"hidden":            hidden,
		"annotated":         annotated,
		"faults":            bad,
		"needs_attention":   len(o.NeedsAttention()),
		"gaps_from_faults":  len(o.Kept.Gaps),
	}
}
