// internal/chain/replication_test.go
//
// Task 6, written as the attacks. The happy path is at the bottom, because a
// replication state whose only test is "it round-trips" proves nothing about the
// one thing it exists for: making an attacker's edit to the local record of what
// was pushed either fail closed or become loud.
package chain

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

func replNow() time.Time {
	t, err := time.Parse(time.RFC3339, "2026-08-06T09:00:00+02:00")
	if err != nil {
		panic(err)
	}
	return t
}

func replInput(recs []Record) ReplicationInput {
	a := HeadAnchor(recs)
	return ReplicationInput{
		Remote:          "git@example.invalid:ops/aurvet-chain.git#refs/heads/main",
		Length:          a.Length,
		Head:            a.Head,
		ConfirmedAt:     "2026-08-06T08:00:00+0200",
		ProtectedRemote: true,
		Note:            "pushed by the operator, remote refuses non-fast-forward",
	}
}

func signedReplication(t *testing.T, k *baseline.PrivateKey, in ReplicationInput) (Replication, []byte, []byte) {
	t.Helper()
	r, err := BuildReplication(in)
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, err := SignReplication(k, r)
	if err != nil {
		t.Fatal(err)
	}
	return r, raw, sig
}

// -- attack: a state signed by a key outside the trusted set -------------------

// An attacker who cannot sign must not be able to assert "everything is pushed".
// The refusal is ABSENT, not corrupt: absent means "nothing is known to have been
// pushed", which is the loudest reading, and is what a caller acts on.
func TestReplicationStateFromAnUntrustedKeyReadsAbsent(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	_, raw, sig := signedReplication(t, k, replInput(recs))

	res, err := VerifyReplicationResult(sig, raw, []*baseline.PublicKey{otherPublicKey(t)})
	if err != nil {
		t.Fatalf("an untrusted signature must be absence, not an error: %v", err)
	}
	if res.State != PayloadPresent {
		if res.Reason == "" {
			t.Fatal("absent replication state with no stated reason")
		}
	} else {
		t.Fatal("a state signed by an untrusted key was accepted")
	}

	st := ReplicationReport(recs, res, replNow())
	if st.PushedLength != 0 || len(st.Unpushed) != 3 {
		t.Fatalf("an unusable state left %d entries unpushed of 3 (pushed length %d); it must leave every one",
			len(st.Unpushed), st.PushedLength)
	}
	if st.Anchored {
		t.Fatal("an unusable state was treated as an anchor, which would mean truncation was 'checked'")
	}
	if len(st.Result().Gaps) == 0 {
		t.Fatal("no anchor and no gap: the chain's completeness was silently reported as checked (INV-9)")
	}
}

// -- attack: one flipped byte in the state ------------------------------------

func TestReplicationStateWithAnyFlippedByteReadsAbsent(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)
	_, raw, sig := signedReplication(t, k, replInput(recs))
	trusted := trust(k)

	for i := range raw {
		bad := append([]byte(nil), raw...)
		bad[i] ^= 0x01
		res, err := VerifyReplicationResult(sig, bad, trusted)
		if err != nil {
			continue // a rejection is a rejection
		}
		if res.State == PayloadPresent {
			t.Fatalf("flipping byte %d of the replication state still verified", i)
		}
	}
	for i := range sig {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 0x01
		res, err := VerifyReplicationResult(bad, raw, trusted)
		if err != nil {
			continue
		}
		if res.State == PayloadPresent {
			t.Fatalf("flipping byte %d of the signature still verified", i)
		}
	}
}

// -- attack: the anchor says the chain is longer than it is (TRUNCATION) -------

// This is the attack the whole task exists for. Task 5 records that truncation is
// invisible from inside the chain, because a chain with its tail removed is
// internally perfect. A pushed head the local machine cannot retroactively change
// is what closes it -- so a confirmed push of 3 entries against a local copy of 2
// must be a CRITICAL, not a note.
func TestAnchorClaimingMoreEntriesThanExistIsTruncation(t *testing.T) {
	k := testKey(t)
	full := buildChain(t, k, 3)
	res := presentReplication(t, k, replInput(full))

	short := full[:2]
	st := ReplicationReport(short, res, replNow())
	if !errors.Is(st.Conflict, ErrTruncated) {
		t.Fatalf("want ErrTruncated from a 3-entry anchor against a 2-entry chain, got %v", st.Conflict)
	}
	out := st.Result()
	if out.MaxSeverity() != finding.SevCritical {
		t.Fatalf("truncation against a pushed anchor rated %s, want critical", out.MaxSeverity())
	}

	// And the same anchor drives chain.Verify, which is the connection task 5
	// asked for explicitly.
	if _, err := Verify(short, VerifyOptions{Trusted: trust(k), Anchor: st.AnchorOption()}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("the replication anchor did not make Verify detect truncation: %v", err)
	}
	if _, err := Verify(short, VerifyOptions{Trusted: trust(k)}); err != nil {
		t.Fatalf("the truncated chain must verify WITHOUT an anchor, or the test proves nothing: %v", err)
	}
}

// -- attack: the anchor disagrees at its own length (FORK) --------------------

func TestAnchorDisagreeingAtItsOwnLengthIsAFork(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	in := replInput(recs)
	in.Head = digestOf("a head that was never in this chain")
	res := presentReplication(t, k, in)

	st := ReplicationReport(recs, res, replNow())
	if !errors.Is(st.Conflict, ErrFork) {
		t.Fatalf("want ErrFork when the pushed head is not the local head at that length, got %v", st.Conflict)
	}
	if st.Result().MaxSeverity() != finding.SevCritical {
		t.Fatal("a fork against the pushed anchor was not critical")
	}
	if _, err := Verify(recs, VerifyOptions{Trusted: trust(k), Anchor: st.AnchorOption()}); !errors.Is(err, ErrFork) {
		t.Fatalf("Verify did not reject the forked anchor: %v", err)
	}
}

// -- attack: rolling the recorded push BACK -----------------------------------

// An attacker with write access to the state file but not the signing key cannot
// forge a longer anchor. Replacing it with an OLD signed one is the remaining
// move, and it must only ever make MORE entries read as unpushed -- never fewer.
func TestRollingTheRecordedPushBackOnlyEverAddsUnpushedEntries(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 4)

	fresh := presentReplication(t, k, replInput(recs))
	stale := presentReplication(t, k, ReplicationInput{
		Remote:      replInput(recs).Remote,
		Length:      1,
		Head:        recs[0].Hash(),
		ConfirmedAt: "2026-01-01T00:00:00+0000",
	})

	if got := len(ReplicationReport(recs, fresh, replNow()).Unpushed); got != 0 {
		t.Fatalf("a current anchor left %d entries unpushed", got)
	}
	rolled := ReplicationReport(recs, stale, replNow())
	if len(rolled.Unpushed) != 3 {
		t.Fatalf("a rolled-back anchor reported %d unpushed of 4, want 3", len(rolled.Unpushed))
	}
	if rolled.Conflict != nil {
		t.Fatalf("a rolled-back anchor is not itself a conflict (the tail may simply be new): %v", rolled.Conflict)
	}
	if rolled.Result().MaxSeverity() == finding.SevCritical {
		t.Fatal("an unpushed tail is not an accusation; it must not be critical")
	}
	if len(rolled.Banner()) == 0 {
		t.Fatal("a rolled-back anchor produced no banner")
	}
}

// -- attack: no state at all, and a state with no signature -------------------

func TestReplicationStateWithoutASignatureReadsAbsent(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)
	dir := t.TempDir()
	s := Open(dir)

	res, err := s.LoadReplication(trust(k))
	if err != nil {
		t.Fatalf("a missing replication state is absence, not an error: %v", err)
	}
	if res.State == PayloadPresent || res.Reason == "" {
		t.Fatal("a missing replication state must read as absent WITH a reason")
	}

	rep, err := BuildReplication(replInput(recs))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := baseline.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, ReplicationFile), raw, 0o600); err != nil {
		t.Fatal(err)
	}
	res, err = s.LoadReplication(trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if res.State == PayloadPresent {
		t.Fatal("an unsigned replication state was accepted")
	}
	if !strings.Contains(res.Reason, "signature") {
		t.Fatalf("reason does not name the missing signature: %q", res.Reason)
	}
}

// -- attack: a signature made for another document type ----------------------

func TestReplicationSignatureDoesNotReplayFromAChainEntry(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 1)
	rep, err := BuildReplication(replInput(recs))
	if err != nil {
		t.Fatal(err)
	}
	raw, err := baseline.Marshal(rep)
	if err != nil {
		t.Fatal(err)
	}
	wrongNS, err := baseline.Sign(k, baseline.NamespaceChainEntry, raw)
	if err != nil {
		t.Fatal(err)
	}
	res, err := VerifyReplicationResult(wrongNS, raw, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if res.State == PayloadPresent {
		t.Fatal("a chain-entry signature was accepted as replication state")
	}

	// And the reverse: the replication namespace must be its own.
	_, _, sig := signedReplication(t, k, replInput(recs))
	ns, err := baseline.SignatureNamespace(sig)
	if err != nil {
		t.Fatal(err)
	}
	if ns != NamespaceReplication {
		t.Fatalf("replication state is signed under %q, want %q", ns, NamespaceReplication)
	}
}

// -- INV-5: never write inside the tree under examination --------------------

func TestPutReplicationRefusesInsideTheOfflineRoot(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 1)
	root := t.TempDir()
	s := Open(filepath.Join(root, "var/lib/aurvet/chain"))
	rep, err := BuildReplication(replInput(recs))
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutReplication(k, rep, root); !errors.Is(err, ErrOfflineRoot) {
		t.Fatalf("want ErrOfflineRoot, got %v", err)
	}
	if _, err := os.Stat(filepath.Join(s.Dir(), ReplicationFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused write still created the state file")
	}
}

// -- the honesty requirement -------------------------------------------------

// "Prominently" is a property of the output, and the property asserted here is
// that the banner names the count, the seq range and the consequence -- and that
// the limits text says out loud that the push credentials live on the monitored
// machine. A reader who believes a signed chain is tamper-proof has
// misunderstood, and that misunderstanding is the manufactured confidence the
// phase gate exists to prevent.
func TestBannerAndLimitsStateTheUncomfortablePart(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	st := ReplicationReport(recs, ReplicationResult{Reason: "no replication state has been recorded"}, replNow())

	banner := strings.Join(st.Banner(), "\n")
	for _, want := range []string{"3", "not pushed", "truncation"} {
		if !strings.Contains(strings.ToLower(banner), want) {
			t.Fatalf("banner does not mention %q:\n%s", want, banner)
		}
	}
	if !strings.Contains(banner, "seq 0..2") {
		t.Fatalf("banner does not name the unpushed seq range:\n%s", banner)
	}

	limits := strings.ToLower(ReplicationLimitsText)
	for _, want := range []string{
		"force-push", "branch protection", "push credentials",
	} {
		if !strings.Contains(limits, want) {
			t.Fatalf("the limits text does not say %q; it is load-bearing documentation, not prose", want)
		}
	}

	out := st.Result()
	if len(out.Findings) == 0 {
		t.Fatal("an unpushed tail produced no finding at all")
	}
	for _, f := range out.Findings {
		if f.Limits == "" {
			t.Fatalf("finding %s states no limits (INV-6)", f.RuleID)
		}
	}
}

// A chain with no entries and no state is not "unpushed": there is nothing to
// push. Saying so on every run of a machine that has never run `baseline init`
// is the noise that teaches an operator to skip the banner.
func TestAnAbsentChainProducesNoBanner(t *testing.T) {
	st := ReplicationReport(nil, ReplicationResult{Reason: "none recorded"}, replNow())
	if len(st.Banner()) != 0 {
		t.Fatalf("an absent chain produced a banner: %v", st.Banner())
	}
	if len(st.Result().Findings) != 0 || len(st.Result().Gaps) != 0 {
		t.Fatal("an absent chain produced findings or gaps about replication")
	}
}

// -- happy path, last ---------------------------------------------------------

func TestReplicationRoundTripRecordsPushedPerEntry(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	dir := t.TempDir()
	s := Open(dir)

	rep, err := BuildReplication(ReplicationInput{
		Remote:          "git@example.invalid:ops/chain.git#refs/heads/main",
		Length:          2,
		Head:            recs[1].Hash(),
		ConfirmedAt:     "2026-08-06T08:00:00+0200",
		ProtectedRemote: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.PutReplication(k, rep, ""); err != nil {
		t.Fatal(err)
	}
	res, err := s.LoadReplication(trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != PayloadPresent {
		t.Fatalf("a state written by PutReplication did not load: %s", res.Reason)
	}

	st := ReplicationReport(recs, res, replNow())
	if len(st.Entries) != 3 {
		t.Fatalf("%d per-entry states, want 3", len(st.Entries))
	}
	want := []bool{true, true, false}
	for i, e := range st.Entries {
		if e.Pushed != want[i] {
			t.Fatalf("entry %d pushed=%v, want %v", i, e.Pushed, want[i])
		}
	}
	if len(st.Unpushed) != 1 || st.Unpushed[0].Seq != 2 {
		t.Fatalf("unpushed tail is %+v, want just seq 2", st.Unpushed)
	}
	if !st.Anchored {
		t.Fatal("a verified state is an anchor")
	}
	if st.Conflict != nil {
		t.Fatalf("a prefix anchor is not a conflict: %v", st.Conflict)
	}
	if got := st.Result().Gaps; len(got) != 0 {
		t.Fatalf("an anchored chain still raised a coverage gap: %v", got)
	}
}

func TestBuildReplicationRefusesWhatCannotBeAnAnchor(t *testing.T) {
	base := ReplicationInput{
		Remote: "r", Length: 1, Head: strings.Repeat("a", 64),
		ConfirmedAt: "2026-08-06T08:00:00+0200",
	}
	mut := func(f func(*ReplicationInput)) ReplicationInput {
		in := base
		f(&in)
		return in
	}
	for name, in := range map[string]ReplicationInput{
		"no remote":       mut(func(i *ReplicationInput) { i.Remote = "" }),
		"negative length": mut(func(i *ReplicationInput) { i.Length = -1 }),
		"short head":      mut(func(i *ReplicationInput) { i.Head = "abc" }),
		"no head":         mut(func(i *ReplicationInput) { i.Head = "" }),
		"no time":         mut(func(i *ReplicationInput) { i.ConfirmedAt = "" }),
		"local time":      mut(func(i *ReplicationInput) { i.ConfirmedAt = "2026-08-06T08:00:00" }),
		"length 0 + head": mut(func(i *ReplicationInput) { i.Length = 0 }),
	} {
		if _, err := BuildReplication(in); err == nil {
			t.Errorf("%s: BuildReplication accepted it", name)
		}
	}
}

// presentReplication is a verified ReplicationResult, the way a caller would get
// one from LoadReplication.
func presentReplication(t *testing.T, k *baseline.PrivateKey, in ReplicationInput) ReplicationResult {
	t.Helper()
	_, raw, sig := signedReplication(t, k, in)
	res, err := VerifyReplicationResult(sig, raw, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if res.State != PayloadPresent {
		t.Fatalf("fixture state did not verify: %s", res.Reason)
	}
	return res
}

// -- regression: a space in an entry field must not corrupt the chain file ------

// Found while wiring `baseline init`, which writes `note: "baseline init"`.
//
// The chain file puts the canonical entry JSON and the base64 signature on one
// line separated by a space, and parseChainFile split on the FIRST space. Canonical
// JSON escapes control characters but not spaces, so any entry with a space in its
// note, host or payload namespace was written correctly and could never be read
// again -- and since an unreadable chain file is an ERROR and not an absent chain,
// one space in a note bricked the chain permanently. The separator is the LAST
// space, because base64 contains none.
func TestAnEntryFieldContainingSpacesStillRoundTrips(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	s := Open(dir)
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture()}

	rec, err := s.Append(opt, func(head *Record) (Record, error) {
		return NewRecord(k, Link(head, Entry{
			Schema: Schema, Time: "2026-08-06T09:00:00+0200", Kind: KindBaseline,
			Host: "reference host", Payload: payloadFor("manifest with spaces"),
			Note: "baseline init, written by a human with a space bar",
		}))
	})
	if err != nil {
		t.Fatal(err)
	}
	back, err := s.Load(trust(k))
	if err != nil {
		t.Fatalf("a chain entry with spaces in its fields could not be read back: %v", err)
	}
	if len(back) != 1 || back[0].Hash() != rec.Hash() {
		t.Fatalf("round trip lost the entry: %d records", len(back))
	}
	if back[0].Entry.Note != "baseline init, written by a human with a space bar" {
		t.Fatalf("the note came back as %q", back[0].Entry.Note)
	}
	if _, err := Verify(back, VerifyOptions{Trusted: trust(k)}); err != nil {
		t.Fatalf("the reloaded chain does not verify: %v", err)
	}
}
