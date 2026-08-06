// internal/chain/replication.go
//
// Replication state (P4 task 6): which entries have been pushed somewhere the
// local machine cannot rewrite, and the loud report when the answer is "not all
// of them".
//
// # The uncomfortable part, said plainly
//
// A signed, prev_hash-linked chain is NOT tamper-proof against the machine it
// describes. It proves that whoever holds the signing key emitted those entries
// in that order; it does not prove that the copy you are reading is the whole
// chain, because entries removed from the END leave a chain that verifies exactly
// as it did before (see chain.go's header and Verify's Notes).
//
// Closing that requires something the attacker on the monitored host cannot
// retroactively change: a copy held elsewhere. That is what an Anchor is, and
// what this file populates. And here is the part that must not be softened:
//
//	PUSH CREDENTIALS NECESSARILY LIVE ON THE MONITORED MACHINE.
//
// The machine being watched holds the credential that can write to the record of
// what happened on it. So the mitigation is not local and cannot be made local by
// any amount of signing:
//
//   - the remote must REFUSE non-fast-forward updates (force-push denial), and
//   - the branch must be PROTECTED against deletion and history rewrite.
//
// Those two remote-side controls are load-bearing security controls, not
// repository hygiene. Without them, an attacker who has the credentials and the
// signing key can rewrite the remote's history too, and the anchor is worth
// nothing. ReplicationLimitsText says so in every report derived from this state
// (INV-6), because a reader who believes "it is signed, therefore it cannot be
// altered" has misunderstood the construction, and that misunderstanding is
// exactly the manufactured confidence P4's ship gate exists to prevent.
//
// # Why the local state is signed anyway
//
// The recorded anchor is a local file, so an attacker with the signing key can
// rewrite it. Signing it still buys two things. An attacker WITHOUT the key
// cannot forge a longer confirmed push (the state reads absent, and absent means
// "nothing is known to be pushed" -- the loudest reading). And an attacker with
// the key can only ever roll the anchor BACK, which adds unpushed entries to the
// report rather than removing them. There is no edit to this file that makes a
// truncated chain look complete without also producing a critical.
//
// Nothing here reads a clock: `now` is a parameter (INV-4).
package chain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

// NamespaceReplication is the SSHSIG namespace for replication state. It is its
// own namespace so that a signature over an anchor can never be presented as a
// chain entry, a manifest, an adjudication store or a delegation -- and, in the
// direction that matters here, so that a genuinely signed chain entry cannot be
// replayed as an assertion that something was pushed.
const NamespaceReplication baseline.Namespace = "replication.aurvet.dev"

// ReplicationFile is the state's filename inside the store directory.
const ReplicationFile = "replication.json"

// ReplicationSchema versions the signed document.
const ReplicationSchema = 1

// maxReplicationBytes bounds the state file. It is a small document; the cap
// exists so a hostile file terminates the reader.
const maxReplicationBytes = 1 << 16

// ErrReplication reports replication state that could not be assembled. Every
// case is a refusal to sign something that would not function as an anchor.
var ErrReplication = errors.New("chain: replication state is not assemblable")

// Rule ids for the findings this file produces.
const (
	// RuleUnpushed is the unpushed tail: entries that exist only here.
	RuleUnpushed = "chain-unpushed-entries"

	// RuleAnchorConflict is the pushed anchor disagreeing with the local chain:
	// truncation or a fork. This is the detection the whole task buys.
	RuleAnchorConflict = "chain-anchor-conflict"

	// RuleNoAnchor is the coverage gap raised when a chain exists and no usable
	// anchor does, so truncation was not checked at all (INV-9).
	RuleNoAnchor = "chain-no-anchor"
)

// SubjectChain is the subject these findings are about.
const SubjectChain = "chain"

// ReplicationLimitsText is what a pushed anchor can and cannot buy. It is
// rendered with every finding derived from replication state (INV-6) and is the
// documentation the roadmap requires, kept in the code so it travels with the
// output rather than living only in a document nobody opens during an incident.
const ReplicationLimitsText = "an anchor is only as strong as the remote's refusal to accept a " +
	"rewrite. Force-push denial and branch protection on the remote are LOAD-BEARING security " +
	"controls here, not repository hygiene: push credentials necessarily live on the monitored " +
	"machine, so the host being watched can write to the record of what happened on it. If the " +
	"remote accepts a non-fast-forward push, or the branch can be deleted or rewritten, an " +
	"attacker holding those credentials and the signing key can rewrite the remote copy too and " +
	"this anchor proves nothing. A signed chain is not tamper-proof against its own host; it is " +
	"tamper-EVIDENT only up to whatever the remote refuses to forget."

// -- the signed document ------------------------------------------------------

// Replication is the signed record of what has been pushed. Field order in this
// declaration is irrelevant: baseline.Marshal sorts by key.
type Replication struct {
	Schema int `json:"schema"`

	// Remote names where the entries were pushed, for a human. It is not
	// contacted by anything in this package: nothing here executes git and
	// nothing here opens a socket (INV-2, INV-4).
	Remote string `json:"remote"`

	// Length and Head are the anchor: how many entries were confirmed pushed and
	// the hash of the last of them.
	Length int64  `json:"length"`
	Head   string `json:"head"`

	// ConfirmedAt is when the push was confirmed, RFC3339 with an explicit
	// offset.
	ConfirmedAt string `json:"confirmed_at"`

	// ProtectedRemote is the operator's assertion that the remote denies
	// non-fast-forward updates and protects the branch. It is a CLAIM, recorded
	// so that its absence is visible; this package cannot verify it, and says so.
	ProtectedRemote bool `json:"protected_remote"`

	Note string `json:"note"`
}

// Anchor is the anchor this state asserts, for VerifyOptions.
func (r Replication) Anchor() Anchor { return Anchor{Length: r.Length, Head: r.Head} }

// ReplicationInput is what BuildReplication assembles from.
type ReplicationInput struct {
	Remote          string
	Length          int64
	Head            string
	ConfirmedAt     string
	ProtectedRemote bool
	Note            string
}

// BuildReplication validates and assembles the document. It refuses rather than
// repairs: a state that cannot function as an anchor must not be signed, because
// a signed one is trusted for exactly the check that would then not happen.
func BuildReplication(in ReplicationInput) (Replication, error) {
	if strings.TrimSpace(in.Remote) == "" {
		return Replication{}, fmt.Errorf("%w: no remote is named, so there is nothing this state "+
			"asserts the entries were pushed TO", ErrReplication)
	}
	if in.Length < 0 {
		return Replication{}, fmt.Errorf("%w: length %d is negative", ErrReplication, in.Length)
	}
	if in.Length == 0 {
		return Replication{}, fmt.Errorf("%w: a confirmed push of zero entries is not an anchor; "+
			"record no state at all instead, which reads as 'nothing is known to be pushed'",
			ErrReplication)
	}
	if err := validDigest(in.Head); err != nil {
		return Replication{}, fmt.Errorf("%w: head: %v", ErrReplication, err)
	}
	if _, err := baseline.ParseStamp(in.ConfirmedAt); err != nil {
		return Replication{}, fmt.Errorf("%w: confirmed_at: %v", ErrReplication, err)
	}
	r := Replication{
		Schema:          ReplicationSchema,
		Remote:          in.Remote,
		Length:          in.Length,
		Head:            in.Head,
		ConfirmedAt:     in.ConfirmedAt,
		ProtectedRemote: in.ProtectedRemote,
		Note:            in.Note,
	}
	if _, err := baseline.Marshal(r); err != nil {
		return Replication{}, fmt.Errorf("%w: %v", ErrReplication, err)
	}
	return r, nil
}

// SignReplication canonicalises and signs the state, returning the exact bytes
// that were signed.
func SignReplication(s baseline.Signer, r Replication) (raw, sig []byte, err error) {
	raw, err = baseline.Marshal(r)
	if err != nil {
		return nil, nil, err
	}
	sig, err = baseline.Sign(s, NamespaceReplication, raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, sig, nil
}

// ReplicationResult is what a load or a verification found. It mirrors
// PayloadResult's present-or-absent discipline: there is no "corrupt". A state
// that does not authenticate reads ABSENT, which means "nothing is known to have
// been pushed" -- the reading that produces the loudest report, and therefore the
// only safe default.
type ReplicationResult struct {
	State PayloadState

	// Replication is populated only when State is PayloadPresent.
	Replication Replication

	Key *baseline.PublicKey

	// Reason says why an absent state is absent. Never empty when absent.
	Reason string
}

// VerifyReplicationResult authenticates raw bytes and only then parses them.
//
// The ordering is the point (INV-2): baseline.VerifyCanonical hashes the bytes
// without interpreting them, so the JSON parser never sees a document that has
// not already been proven to come from a trusted key.
//
// An error means the CALLER passed something unusable (an empty trust set, say).
// A signature that does not verify is not an error: it is absence with a reason.
func VerifyReplicationResult(sig, raw []byte, trusted []*baseline.PublicKey) (ReplicationResult, error) {
	if len(trusted) == 0 {
		return ReplicationResult{}, fmt.Errorf("%w: no trusted keys were supplied; an empty trust "+
			"set must never mean 'any key will do'", baseline.ErrSignature)
	}
	if int64(len(raw)) > maxReplicationBytes {
		return ReplicationResult{Reason: fmt.Sprintf("the replication state is over %d bytes, so it "+
			"was not read", maxReplicationBytes)}, nil
	}
	canon, key, err := baseline.VerifyCanonical(sig, NamespaceReplication, raw, trusted)
	if err != nil {
		return ReplicationResult{Reason: fmt.Sprintf("the replication state does not verify under "+
			"%s, so nothing is known to have been pushed: %v", NamespaceReplication, err)}, nil
	}
	var r Replication
	if err := strictUnmarshal(canon, &r); err != nil {
		return ReplicationResult{Reason: fmt.Sprintf("the replication state does not parse: %v", err)}, nil
	}
	if r.Schema != ReplicationSchema {
		return ReplicationResult{Reason: fmt.Sprintf("replication schema %d, this build understands %d",
			r.Schema, ReplicationSchema)}, nil
	}
	// Re-encoding must reproduce the signed bytes, or this build's idea of the
	// document differs from the signer's and every answer derived from it would be
	// about a document nobody signed.
	again, err := baseline.Marshal(r)
	if err != nil || string(again) != string(canon) {
		return ReplicationResult{Reason: "the parsed replication state does not re-encode to the " +
			"bytes that were signed"}, nil
	}
	if _, err := BuildReplication(ReplicationInput{
		Remote: r.Remote, Length: r.Length, Head: r.Head,
		ConfirmedAt: r.ConfirmedAt, ProtectedRemote: r.ProtectedRemote, Note: r.Note,
	}); err != nil {
		return ReplicationResult{Reason: fmt.Sprintf("the replication state is signed but not "+
			"usable as an anchor: %v", err)}, nil
	}
	return ReplicationResult{State: PayloadPresent, Replication: r, Key: key}, nil
}

// LoadReplication reads and authenticates the state beside the chain.
//
// A missing file is absence, with a reason. An error means the store could not be
// READ -- a permission problem, a broken disk -- which is a coverage gap the
// caller must report (INV-9), not a quiet "nothing pushed".
func (s *Store) LoadReplication(trusted []*baseline.PublicKey) (ReplicationResult, error) {
	path := s.replicationPath()
	raw, err := readCapped(path, maxReplicationBytes)
	if errors.Is(err, os.ErrNotExist) {
		return ReplicationResult{Reason: "no replication state has been recorded, so no entry is " +
			"known to exist anywhere but this machine"}, nil
	}
	if err != nil {
		return ReplicationResult{}, fmt.Errorf("chain: %w", err)
	}
	sig, err := readCapped(path+SignatureSuffix, maxReplicationBytes)
	if errors.Is(err, os.ErrNotExist) {
		return ReplicationResult{Reason: "the replication state has no signature beside it, so it " +
			"reads as absent: an unsigned claim that entries were pushed is a claim anyone with " +
			"write access to this directory can make"}, nil
	}
	if err != nil {
		return ReplicationResult{}, fmt.Errorf("chain: %w", err)
	}
	return VerifyReplicationResult(sig, raw, trusted)
}

// PutReplication signs and stores the state, temp + fsync + atomic rename.
//
// offlineRoot is INV-5: the store must not be inside the tree being examined.
func (s *Store) PutReplication(signer baseline.Signer, r Replication, offlineRoot string) error {
	if err := s.checkOfflineRoot(offlineRoot); err != nil {
		return err
	}
	raw, sig, err := SignReplication(signer, r)
	if err != nil {
		return err
	}
	// Signature first, then the document: either order leaves a window, and this
	// one leaves it on the side that reads as absent rather than as a document
	// with no signature.
	if err := s.writeAtomic(s.replicationPath()+SignatureSuffix, sig, 0o600); err != nil {
		return err
	}
	return s.writeAtomic(s.replicationPath(), raw, 0o600)
}

func (s *Store) replicationPath() string {
	return filepath.Join(s.dir, ReplicationFile)
}

// -- the per-run report -------------------------------------------------------

// EntryStatus is one entry's replication state: the `pushed: bool` the roadmap
// asks the chain to record. It is derived from the anchor rather than stored on
// the entry, deliberately -- an entry is signed BEFORE it can be pushed, so a
// pushed flag inside the signed bytes would either be a lie at signing time or
// require re-signing history to update.
type EntryStatus struct {
	Seq    int64
	Hash   string
	Time   string
	Kind   string
	Pushed bool
}

// ReplicationStatus is what one run knows about replication.
type ReplicationStatus struct {
	// Length is the local chain's length; PushedLength is how much of it a usable
	// anchor confirms. PushedLength is clamped to what actually exists here and is
	// zeroed by a fork, so it is safe to index with; ClaimedLength is what the
	// anchor SAID, unclamped, which is what Verify must be given and what a report
	// must quote -- clamping the claim would hide the truncation it exists to find.
	Length        int64
	PushedLength  int64
	ClaimedLength int64

	Head       string
	PushedHead string

	Entries  []EntryStatus
	Unpushed []EntryStatus

	// Anchored reports that a usable anchor existed, which is the ONLY condition
	// under which truncation was checked at all.
	Anchored bool

	Remote          string
	ProtectedRemote bool
	ConfirmedAt     string

	// ConfirmedAge is how long ago the push was confirmed, measured against the
	// `now` passed in. Zero when there is no usable anchor.
	ConfirmedAge time.Duration

	// Conflict is non-nil when the anchor and the local chain disagree: it wraps
	// ErrTruncated (the anchor is longer) or ErrFork (the anchor names a different
	// head at its own length). Either is a critical.
	Conflict error

	// Reason carries why there is no usable anchor, verbatim from the load.
	Reason string
}

// ReplicationReport derives the status. Pure: `now` is a parameter (INV-4), and
// nothing here touches the filesystem.
func ReplicationReport(records []Record, res ReplicationResult, now time.Time) ReplicationStatus {
	st := ReplicationStatus{
		Length: int64(len(records)),
		Reason: res.Reason,
	}
	if n := len(records); n > 0 {
		st.Head = records[n-1].Hash()
	}
	if res.State == PayloadPresent {
		r := res.Replication
		st.Anchored = true
		st.Remote = r.Remote
		st.ProtectedRemote = r.ProtectedRemote
		st.ConfirmedAt = r.ConfirmedAt
		st.PushedHead = r.Head
		st.PushedLength = r.Length
		st.ClaimedLength = r.Length
		if t, err := baseline.ParseStamp(r.ConfirmedAt); err == nil && !now.IsZero() {
			if d := now.Sub(t); d > 0 {
				st.ConfirmedAge = d
			}
		}
		switch {
		case r.Length > st.Length:
			// Truncation. The remote holds entries this copy does not, and a chain
			// with its tail removed verifies perfectly on its own -- which is why
			// this check cannot come from inside the chain.
			st.Conflict = fmt.Errorf("%w: the last confirmed push covered %d entries, this copy has "+
				"%d; entries were removed from the end", ErrTruncated, r.Length, st.Length)
			st.PushedLength = st.Length
		case records[r.Length-1].Hash() != r.Head:
			// A fork: at the pushed length the two copies disagree, so history was
			// rewritten on one side of the push.
			st.Conflict = fmt.Errorf("%w: at length %d the confirmed push names %s, this copy has %s",
				ErrFork, r.Length, short(r.Head), short(records[r.Length-1].Hash()))
			st.PushedLength = 0
		}
	}

	for i, rec := range records {
		e := EntryStatus{
			Seq:    rec.Entry.Seq,
			Hash:   rec.Hash(),
			Time:   rec.Entry.Time,
			Kind:   rec.Entry.Kind,
			Pushed: int64(i) < st.PushedLength && st.Conflict == nil,
		}
		st.Entries = append(st.Entries, e)
		if !e.Pushed {
			st.Unpushed = append(st.Unpushed, e)
		}
	}
	return st
}

// AnchorOption is the anchor to hand chain.Verify, or nil when there is none.
//
// This is the explicit connection task 5 asked for: Verify cannot detect
// truncation or a cross-copy fork without an anchor, and this is where one comes
// from. A caller that ignores it gets a report whose Notes say truncation was not
// checked, which is honest but weaker.
func (s ReplicationStatus) AnchorOption() *Anchor {
	if !s.Anchored {
		return nil
	}
	a := Anchor{Length: s.ClaimedLength, Head: s.PushedHead}
	return &a
}

// Banner is the prominent, unconditional lines for normal run output.
//
// It is deliberately not a debug line and not behind a flag. An unpushed tail
// invalidates the completeness of every other statement a chain report makes, so
// it belongs above the report, not in a footnote. An absent chain produces no
// banner at all: there is nothing to push, and saying so on every run of a
// machine that never ran `baseline init` is the noise that teaches an operator to
// skip it.
func (s ReplicationStatus) Banner() []string {
	if s.Length == 0 {
		return nil
	}
	var out []string
	if s.Conflict != nil {
		out = append(out,
			fmt.Sprintf("!! CHAIN: %v", s.Conflict),
			"   the remote's copy and this one disagree; do NOT overwrite the remote. Investigate "+
				"before appending.",
		)
	}
	if len(s.Unpushed) == 0 && s.Conflict == nil {
		return nil
	}
	first, last := s.Unpushed[0].Seq, s.Unpushed[len(s.Unpushed)-1].Seq
	out = append(out, fmt.Sprintf("!! CHAIN: %d of %d entries are NOT pushed (seq %d..%d, oldest %s)",
		len(s.Unpushed), s.Length, first, last, s.Unpushed[0].Time))
	out = append(out, "   until they are pushed, truncation of this chain is undetectable: removing them "+
		"leaves a chain that still verifies.")
	switch {
	case !s.Anchored:
		out = append(out, "   no confirmed push at all — "+s.Reason)
	default:
		out = append(out, fmt.Sprintf("   last confirmed push: %d entr%s to %s at %s",
			s.PushedLength, plural(s.PushedLength), s.Remote, s.ConfirmedAt))
	}
	if s.Anchored && !s.ProtectedRemote {
		out = append(out, "   the remote is NOT recorded as protected: force-push denial and branch "+
			"protection are what make this anchor mean anything.")
	}
	return out
}

func plural(n int64) string {
	if n == 1 {
		return "y"
	}
	return "ies"
}

// Result is the findings and gaps this status contributes to a run.
//
// An unpushed tail is SUSPICIOUS, never critical: the ordinary cause is an
// operator who has not pushed yet, and an accusation there trains people to
// ignore the tool. An anchor CONFLICT is critical, because truncation or a
// rewritten history is the attack this subsystem exists to catch. No usable
// anchor is a coverage GAP, because the completeness of the chain was not checked
// -- reporting a chain as verified without saying that would be reporting clean
// for something unexamined (INV-3).
func (s ReplicationStatus) Result() finding.Result {
	var out finding.Result
	if s.Length == 0 {
		return out
	}
	if s.Conflict != nil {
		out.Findings = append(out.Findings, finding.Finding{
			RuleID:      RuleAnchorConflict,
			SubjectKind: SubjectChain,
			Subject:     SubjectChain,
			Severity:    finding.SevCritical,
			Summary:     "the chain disagrees with the last confirmed push: " + s.Conflict.Error(),
			Evidence: []string{
				fmt.Sprintf("local chain: %d entries, head %s", s.Length, short(s.Head)),
				fmt.Sprintf("confirmed push: %d entries, head %s, at %s to %s",
					s.ClaimedLength, short(s.PushedHead), s.ConfirmedAt, s.Remote),
			},
			Limits: ReplicationLimitsText,
		})
	}
	if len(s.Unpushed) > 0 {
		first, last := s.Unpushed[0].Seq, s.Unpushed[len(s.Unpushed)-1].Seq
		ev := []string{
			fmt.Sprintf("%d of %d entries exist only on this machine (seq %d..%d)",
				len(s.Unpushed), s.Length, first, last),
		}
		if s.Anchored {
			ev = append(ev, fmt.Sprintf("last confirmed push: %d entries to %s at %s (%s ago)",
				s.PushedLength, s.Remote, s.ConfirmedAt, s.ConfirmedAge.Round(time.Minute)))
			if !s.ProtectedRemote {
				ev = append(ev, "the remote is not recorded as denying force-push, so even the pushed "+
					"prefix is not anchored against a rewrite")
			}
		} else {
			ev = append(ev, "no confirmed push: "+s.Reason)
		}
		out.Findings = append(out.Findings, finding.Finding{
			RuleID:      RuleUnpushed,
			SubjectKind: SubjectChain,
			Subject:     SubjectChain,
			Severity:    finding.SevSuspicious,
			Summary: fmt.Sprintf("%d chain entr%s not pushed to any remote", len(s.Unpushed),
				plural(int64(len(s.Unpushed)))),
			Evidence: ev,
			Limits:   ReplicationLimitsText,
		})
	}
	if !s.Anchored {
		out.Gaps = append(out.Gaps, finding.Gap{
			RuleID:  RuleNoAnchor,
			Subject: SubjectChain,
			Reason: "no usable replication anchor, so the chain's COMPLETENESS was not checked: " +
				s.Reason + ". Entries removed from the end of this chain would leave it verifying " +
				"exactly as it does now",
		})
	}
	return out
}
