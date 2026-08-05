// internal/chain/chain_attack_test.go
//
// The four attacks the roadmap names, each written as an attack on a real
// chain rather than as an assertion about a struct field. They differ in shape
// and in what is needed to catch them, and the tests say which is which:
//
//	wrong prev_hash  caught by the chain alone; the only one a naive verifier
//	                 catches.
//	forked           caught by the chain alone WHEN both branches are in one
//	                 file. Two separate files each verify in isolation, so the
//	                 cross-copy case needs an anchor.
//	replayed         caught by the chain alone: an entry, or a payload digest,
//	                 that appears twice.
//	truncated        NOT caught by the chain alone. Nothing is inconsistent;
//	                 there is simply less. It needs an anchor recorded outside
//	                 the chain -- root-only state, or the remote's copy (P4
//	                 task 6). The test below proves both halves: that a
//	                 truncated chain verifies clean without an anchor, and that
//	                 it is refused with one.
package chain

import (
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"path/filepath"
	"testing"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// -- wrong prev_hash ---------------------------------------------------------

func TestAttackWrongPrevHashRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)

	// Rewrite the last entry to point at a predecessor that never existed, and
	// re-sign it: the attacker here HAS the signing key, which is the case
	// worth testing. A signature does not make the link true.
	bad := recs[2].Entry
	bad.PrevHash = digestOf("an entry that was never in this chain")
	forged, err := NewRecord(k, bad)
	if err != nil {
		t.Fatal(err)
	}
	attacked := []Record{recs[0], recs[1], forged}

	if _, err := Verify(attacked, VerifyOptions{Trusted: trust(k)}); !errors.Is(err, ErrPrevHash) {
		t.Fatalf("want ErrPrevHash, got %v", err)
	}
}

// A one-byte change to a recorded prev_hash must also fail, and must fail on
// the signature first: the linkage is inside the signed bytes.
func TestAttackTamperedPrevHashFailsSignature(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)
	raw := append([]byte(nil), recs[1].Raw()...)
	i := indexOf(raw, []byte(recs[0].Hash()))
	if i < 0 {
		t.Fatal("prev_hash is not in the signed bytes at all")
	}
	raw[i] ^= 0x01
	if _, err := ParseRecord(raw, recs[1].Signature(), trust(k)); !errors.Is(err, baseline.ErrSignature) {
		t.Fatalf("want a signature failure, got %v", err)
	}
}

// -- forked ------------------------------------------------------------------

func TestAttackForkInOneFileRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)

	// A second entry 2, genuinely signed, claiming the same predecessor.
	alt := recs[1].Entry
	alt.Payload.SHA256 = digestOf("a different manifest")
	alt.Note = "the attacker's branch"
	forged, err := NewRecord(k, alt)
	if err != nil {
		t.Fatal(err)
	}
	if forged.Entry.PrevHash != recs[1].Entry.PrevHash {
		t.Fatal("fixture is not a fork")
	}
	_, err = Verify([]Record{recs[0], recs[1], forged}, VerifyOptions{Trusted: trust(k)})
	if !errors.Is(err, ErrFork) {
		t.Fatalf("want ErrFork, got %v", err)
	}
}

// Two separate copies, each a valid branch. Neither is detectable alone -- that
// is the honest statement -- and the anchor is what settles which is the real
// one.
func TestAttackForkAcrossCopiesNeedsAnAnchor(t *testing.T) {
	k := testKey(t)
	base := buildChain(t, k, 2)

	altEntry := base[1].Entry
	altEntry.Payload.SHA256 = digestOf("the attacker's manifest")
	alt, err := NewRecord(k, altEntry)
	if err != nil {
		t.Fatal(err)
	}
	branchA := base
	branchB := []Record{base[0], alt}

	for name, branch := range map[string][]Record{"honest": branchA, "attacker": branchB} {
		if _, err := Verify(branch, VerifyOptions{Trusted: trust(k)}); err != nil {
			t.Fatalf("%s branch does not verify in isolation, so the test is not "+
				"exercising a fork: %v", name, err)
		}
	}

	anchor := HeadAnchor(branchA)
	if _, err := Verify(branchB, VerifyOptions{Trusted: trust(k), Anchor: &anchor}); !errors.Is(err, ErrFork) {
		t.Fatalf("want ErrFork against the honest anchor, got %v", err)
	}
	if _, err := Verify(branchA, VerifyOptions{Trusted: trust(k), Anchor: &anchor}); err != nil {
		t.Fatalf("the honest branch was refused against its own anchor: %v", err)
	}
}

// -- replayed ----------------------------------------------------------------

// A genuine old record appended again. Every signature is real.
func TestAttackReplayedRecordRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	replayed := append(append([]Record(nil), recs...), recs[1])
	if _, err := Verify(replayed, VerifyOptions{Trusted: trust(k)}); !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay, got %v", err)
	}
}

// The subtler replay: a stale payload re-committed under a fresh, correctly
// linked, correctly signed entry -- an attacker with the key re-asserting an
// old system state as if it were current. The signatures prove nothing here;
// the repeated payload digest is what gives it away.
func TestAttackReplayedPayloadUnderFreshEntryRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)

	stale := recs[1].Entry.Payload
	next := Entry{
		Schema:   Schema,
		Seq:      3,
		PrevHash: recs[2].Hash(),
		Time:     "2026-08-05T12:00:04+0200",
		Kind:     KindAppend,
		Host:     "reference",
		Payload:  stale,
	}
	forged, err := NewRecord(k, next)
	if err != nil {
		t.Fatal(err)
	}
	attacked := append(append([]Record(nil), recs...), forged)
	if _, err := Verify(attacked, VerifyOptions{Trusted: trust(k)}); !errors.Is(err, ErrReplay) {
		t.Fatalf("want ErrReplay for a re-committed payload, got %v", err)
	}
}

// Time running backwards is a weaker signal than a repeated digest, but it is
// free and it catches a replay whose payload was rebuilt.
func TestAttackBackdatedEntryRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)
	e := Entry{
		Schema:   Schema,
		Seq:      2,
		PrevHash: recs[1].Hash(),
		Time:     "2020-01-01T00:00:00+0000",
		Kind:     KindAppend,
		Host:     "reference",
		Payload:  payloadFor("fresh but backdated"),
	}
	forged, err := NewRecord(k, e)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(append(recs, forged), VerifyOptions{Trusted: trust(k)}); !errors.Is(err, ErrTime) {
		t.Fatalf("want ErrTime, got %v", err)
	}
}

// -- truncated ---------------------------------------------------------------

func TestAttackTruncationNeedsAnAnchor(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 4)
	truncated := recs[:2]

	// Half one: it verifies. Stating this out loud is the point -- a verifier
	// that "passes" here is not broken, it is blind, and the anchor is the eye.
	rep, err := Verify(truncated, VerifyOptions{Trusted: trust(k)})
	if err != nil {
		t.Fatalf("a truncated chain is internally consistent and must verify without an anchor: %v", err)
	}
	if len(rep.Notes) == 0 {
		t.Fatal("verifying without an anchor must say that truncation was not checked")
	}
	if rep.TruncationChecked {
		t.Fatal("TruncationChecked must be false without an anchor")
	}

	// Half two: with the anchor the removal is evidence.
	anchor := HeadAnchor(recs)
	rep, err = Verify(truncated, VerifyOptions{Trusted: trust(k), Anchor: &anchor})
	if !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated, got %v", err)
	}
	if rep.Length != 2 || anchor.Length != 4 {
		t.Fatalf("report is not describing the truncation: len=%d anchor=%d", rep.Length, anchor.Length)
	}
}

// An anchor that names a head the chain does not contain at that position is a
// fork, not a truncation, and the two must not be conflated: one means entries
// were removed, the other that history was rewritten.
func TestTruncationAndForkAreDistinctErrors(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	anchor := Anchor{Length: 3, Head: digestOf("a head that never existed")}
	if _, err := Verify(recs, VerifyOptions{Trusted: trust(k), Anchor: &anchor}); !errors.Is(err, ErrFork) {
		t.Fatalf("want ErrFork for a head mismatch at equal length, got %v", err)
	}
}

// -- trust boundary ----------------------------------------------------------

// A chain signed by a key that is not trusted must be refused, not reported as
// "signed".
func TestUntrustedSignerRejected(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 2)
	other := otherPublicKey(t)
	if _, err := Verify(recs, VerifyOptions{Trusted: []*baseline.PublicKey{other}}); !errors.Is(err, baseline.ErrSignature) {
		t.Fatalf("want a signature failure for an untrusted signer, got %v", err)
	}
	if _, err := Verify(recs, VerifyOptions{}); err == nil {
		t.Fatal("an empty trusted set verified a chain")
	}
}

// A chain-entry signature must not be interchangeable with a manifest
// signature: the namespaces are what stop one document being replayed as
// another.
func TestNamespaceSeparationHolds(t *testing.T) {
	k := testKey(t)
	e := genesisEntry()
	raw, err := baseline.Marshal(e)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := baseline.Sign(k, baseline.NamespaceManifest, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecord(raw, sig, trust(k)); !errors.Is(err, baseline.ErrSignature) {
		t.Fatal("a manifest signature was accepted as a chain entry")
	}
}

// -- malformed entries -------------------------------------------------------

func TestMalformedEntriesRefused(t *testing.T) {
	k := testKey(t)
	good := genesisEntry()
	cases := map[string]func(e *Entry){
		"no time":             func(e *Entry) { e.Time = "" },
		"time with no offset": func(e *Entry) { e.Time = "2026-08-05T12:00:00" },
		"bad kind":            func(e *Entry) { e.Kind = "whatever" },
		"negative seq":        func(e *Entry) { e.Seq = -1 },
		"short prev":          func(e *Entry) { e.PrevHash = "00" },
		"no payload digest":   func(e *Entry) { e.Payload.SHA256 = "" },
		"bad namespace":       func(e *Entry) { e.Payload.Namespace = "" },
		"wrong schema":        func(e *Entry) { e.Schema = 99 },
	}
	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			e := good
			mutate(&e)
			if _, err := NewRecord(k, e); !errors.Is(err, ErrEntry) {
				t.Fatalf("want ErrEntry, got %v", err)
			}
		})
	}
}

// A record whose signed bytes are valid but not canonical is refused: its hash
// would not be reproducible from the document, and the linkage is hashes.
func TestNonCanonicalRecordRefused(t *testing.T) {
	k := testKey(t)
	raw, err := baseline.Marshal(genesisEntry())
	if err != nil {
		t.Fatal(err)
	}
	sloppy := append([]byte(" "), raw...)
	sig, err := baseline.Sign(k, baseline.NamespaceChainEntry, sloppy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParseRecord(sloppy, sig, trust(k)); !errors.Is(err, baseline.ErrNotCanonical) {
		t.Fatalf("want ErrNotCanonical, got %v", err)
	}
}

// -- helpers -----------------------------------------------------------------

func testKey(t *testing.T) *baseline.PrivateKey {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("..", "..", "testdata", "baseline", "testkey"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := baseline.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// otherPublicKey is a second, unrelated public key built in-process. Only the
// public half is needed to prove the trusted set is honoured, and no second
// private key is created anywhere -- key generation is a human action.
func otherPublicKey(t *testing.T) *baseline.PublicKey {
	t.Helper()
	pub, _, err := ed25519.GenerateKey(rand.New(rand.NewSource(11)))
	if err != nil {
		t.Fatal(err)
	}
	var blob []byte
	appendSSHString := func(dst, s []byte) []byte {
		var n [4]byte
		binary.BigEndian.PutUint32(n[:], uint32(len(s)))
		return append(append(dst, n[:]...), s...)
	}
	blob = appendSSHString(blob, []byte("ssh-ed25519"))
	blob = appendSSHString(blob, pub)
	line := "ssh-ed25519 " + base64.StdEncoding.EncodeToString(blob) + " not-a-real-key\n"
	k, err := baseline.ParsePublicKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func trust(k *baseline.PrivateKey) []*baseline.PublicKey {
	return []*baseline.PublicKey{k.PublicKey()}
}

func digestOf(s string) string {
	d := baseline.DigestBytes([]byte(s))
	return baseline.Hex(d[:])
}

func payloadFor(s string) Payload {
	return Payload{
		Kind:      PayloadManifest,
		Namespace: string(baseline.NamespaceManifest),
		SHA256:    digestOf(s),
		Bytes:     int64(len(s)),
	}
}

func genesisEntry() Entry {
	return Entry{
		Schema:   Schema,
		Seq:      0,
		PrevHash: GenesisPrev,
		Time:     "2026-08-05T12:00:00+0200",
		Kind:     KindBaseline,
		Host:     "reference",
		Payload:  payloadFor("manifest 0"),
	}
}

// buildChain makes n genuinely signed, correctly linked records.
func buildChain(t *testing.T, k *baseline.PrivateKey, n int) []Record {
	t.Helper()
	var out []Record
	for i := 0; i < n; i++ {
		e := Entry{
			Schema:  Schema,
			Time:    stampAt(i),
			Kind:    KindAppend,
			Host:    "reference",
			Payload: payloadFor("manifest " + string(rune('0'+i))),
		}
		if i == 0 {
			e.Kind = KindBaseline
		}
		var head *Record
		if i > 0 {
			head = &out[i-1]
		}
		rec, err := NewRecord(k, Link(head, e))
		if err != nil {
			t.Fatal(err)
		}
		out = append(out, rec)
	}
	return out
}

func stampAt(i int) string {
	return "2026-08-05T12:00:0" + string(rune('0'+i)) + "+0200"
}

func indexOf(hay, needle []byte) int {
outer:
	for i := 0; i+len(needle) <= len(hay); i++ {
		for j := range needle {
			if hay[i+j] != needle[j] {
				continue outer
			}
		}
		return i
	}
	return -1
}
