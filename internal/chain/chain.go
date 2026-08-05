// internal/chain/chain.go

// Package chain is the append-only, prev_hash-linked record of signed
// baselines: what was signed, when, by which key, and in what order.
//
// # What a verified chain proves, and what it does not (INV-6)
//
// It proves that every entry in the copy you are holding was signed by a key
// you trust, and that each one names its predecessor by hash, so no entry in
// the middle can be altered or removed without breaking the links after it.
//
// It does NOT prove that the copy you are holding is the whole chain. Four
// attacks are worth separating, because they need different things to catch:
//
//	wrong prev_hash  Detected here. The links do not join up.
//	forked           Detected here WHEN both branches are in one file, because
//	                 two entries then claim the same predecessor. Two separate
//	                 copies, one branch each, both verify perfectly: choosing
//	                 between them needs an Anchor.
//	replayed         Detected here, by two routes -- a record that appears
//	                 twice, and a payload digest committed twice. The second is
//	                 the one that matters: an attacker who holds the signing key
//	                 can re-commit an old manifest under a fresh, correctly
//	                 linked, genuinely signed entry, and every signature in that
//	                 attack is real.
//	truncated        NOT detected here, and this is the honest limit of the
//	                 construction. Removing entries from the END leaves a chain
//	                 that is internally perfect: nothing is inconsistent, there
//	                 is simply less. Detection needs something the attacker
//	                 cannot rewrite -- a length and head recorded in root-only
//	                 state, or the remote's copy. That is Anchor, and populating
//	                 it is P4 task 6 (replication state). Verify says so in its
//	                 report Notes whenever it runs without one, rather than
//	                 returning a bare "valid" that would be read as "complete".
//
// Everything in this file is pure: timestamps are inputs, never time.Now()
// (INV-4), nothing executes (INV-2), nothing here writes (see store.go).
package chain

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// Schema is the entry schema version, inside the signed bytes so a later build
// cannot silently reinterpret an older entry as its own shape.
const Schema = 1

// GenesisPrev is the prev_hash of the first entry: 64 zeros. A distinguished
// value rather than an empty string, so that "no predecessor" and "the field
// was omitted" cannot be confused.
const GenesisPrev = "0000000000000000000000000000000000000000000000000000000000000000"

// Entry kinds.
const (
	// KindBaseline is the first entry, written by `baseline init`.
	KindBaseline = "baseline"
	// KindAppend is every later entry.
	KindAppend = "append"
)

// PayloadManifest is the payload kind a baseline entry commits to.
const PayloadManifest = "manifest"

// The refusals a caller switches on. Each names one attack, because "the chain
// is invalid" is not an actionable message: truncated and forked call for
// different responses.
var (
	// ErrEntry reports an entry that is malformed on its face.
	ErrEntry = errors.New("chain: entry is malformed")

	// ErrPrevHash reports an entry whose prev_hash does not name its
	// predecessor. The easy attack, and the only one a naive verifier catches.
	ErrPrevHash = errors.New("chain: prev_hash does not name the preceding entry")

	// ErrFork reports two entries claiming the same predecessor, or a chain
	// that disagrees with an anchor at equal length. History was rewritten.
	ErrFork = errors.New("chain: forked history")

	// ErrReplay reports an entry or a payload committed twice.
	ErrReplay = errors.New("chain: replayed entry")

	// ErrSequence reports a break in seq numbering.
	ErrSequence = errors.New("chain: sequence is not contiguous")

	// ErrTime reports an entry timestamped before its predecessor.
	ErrTime = errors.New("chain: entry time runs backwards")

	// ErrTruncated reports a chain shorter than the anchor says it should be.
	// Entries were removed from the end.
	ErrTruncated = errors.New("chain: entries are missing from the end")
)

// LimitsText is what a verified chain cannot tell you, whatever it says. It is
// rendered with any report derived from a chain (INV-6).
const LimitsText = "a verified chain proves that the entries in THIS copy were signed by a trusted " +
	"key and link to one another; it does not prove the copy is complete. Entries removed from the " +
	"end leave a chain that still verifies, so truncation is only detectable against an anchor held " +
	"outside the chain -- root-only state or the remote. Nor does it prove any entry was TRUE: a host " +
	"already compromised when a baseline was made signs the attacker's state as the reference."

// -- the entry ---------------------------------------------------------------

// Entry is one link. Field order in this declaration is irrelevant --
// baseline.Marshal sorts by key -- so a later reordering cannot invalidate
// signatures already made.
type Entry struct {
	Schema int `json:"schema"`

	// Seq is the position, starting at 0. It is redundant with the links and
	// carried anyway: it makes a missing middle entry a distinct, nameable
	// error instead of a generic linkage failure.
	Seq int64 `json:"seq"`

	// PrevHash is sha256 over the canonical bytes of the preceding entry, hex.
	PrevHash string `json:"prev_hash"`

	// Time is when this entry was made, RFC3339 with an explicit offset. It is
	// an INPUT to everything in this package: no function here reads a clock,
	// so an auditor can reproduce every byte (INV-4).
	Time string `json:"time"`

	Kind string `json:"kind"`
	Host string `json:"host"`

	Payload Payload `json:"payload"`

	Note string `json:"note"`
}

// Payload is what this entry commits to, by digest. The document itself lives
// beside the chain (see Store.PutPayload); the chain carries only the
// commitment, so the chain file stays small enough to verify on every run.
type Payload struct {
	Kind string `json:"kind"`

	// Namespace is the signing namespace of the payload document. Recording it
	// means a verifier knows which namespace to demand, and cannot be talked
	// into checking a manifest signature against a delegation document.
	Namespace string `json:"namespace"`

	SHA256 string `json:"sha256"`
	Bytes  int64  `json:"bytes"`

	// KeyFingerprint is the key that signed the payload, for reporting. It is
	// covered by this entry's own signature, so it cannot be rewritten without
	// breaking the chain.
	KeyFingerprint string `json:"key_fingerprint"`
}

// Record is an entry together with the exact bytes that were signed and the
// detached signature over them.
//
// The raw bytes are kept rather than re-derived. Re-marshalling to compute a
// hash would mean the hash describes what this build would have written, not
// what was actually signed -- and the difference between those two is precisely
// where a chain stops meaning anything.
type Record struct {
	Entry Entry

	raw  []byte
	sig  []byte
	hash string
}

// Raw returns the canonical bytes that were signed.
func (r Record) Raw() []byte { return append([]byte(nil), r.raw...) }

// Signature returns the detached SSHSIG.
func (r Record) Signature() []byte { return append([]byte(nil), r.sig...) }

// Hash is sha256 over the signed bytes, hex: the value the next entry's
// prev_hash must carry.
func (r Record) Hash() string { return r.hash }

// Zero reports whether this is the empty Record.
func (r Record) Zero() bool { return len(r.raw) == 0 }

// NewRecord validates an entry, canonicalises it and signs it under
// baseline.NamespaceChainEntry.
//
// The namespace is domain separation: a signature over a chain entry cannot be
// presented as a signature over a manifest, a delegation or an indicator
// bundle, and vice versa.
func NewRecord(s baseline.Signer, e Entry) (Record, error) {
	if err := ValidateEntry(e); err != nil {
		return Record{}, err
	}
	raw, err := baseline.Marshal(e)
	if err != nil {
		return Record{}, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	sig, err := baseline.Sign(s, baseline.NamespaceChainEntry, raw)
	if err != nil {
		return Record{}, err
	}
	return record(e, raw, sig), nil
}

// ParseRecord authenticates raw bytes and only then parses them.
//
// Order is the point (INV-2, and the reason VerifyCanonical exists): the JSON
// parser never sees bytes that have not already been proven to come from a
// trusted key, so a hostile chain file cannot reach the parser on the strength
// of an unchecked signature.
func ParseRecord(raw, sig []byte, trusted []*baseline.PublicKey) (Record, error) {
	canon, _, err := baseline.VerifyCanonical(sig, baseline.NamespaceChainEntry, raw, trusted)
	if err != nil {
		return Record{}, err
	}
	e, err := decodeEntry(canon)
	if err != nil {
		return Record{}, err
	}
	return record(e, canon, sig), nil
}

func record(e Entry, raw, sig []byte) Record {
	d := baseline.DigestBytes(raw)
	return Record{Entry: e, raw: raw, sig: sig, hash: baseline.Hex(d[:])}
}

func decodeEntry(canon []byte) (Entry, error) {
	var e Entry
	if err := strictUnmarshal(canon, &e); err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	// Re-encoding must reproduce the signed bytes. If it does not, this build's
	// idea of the entry differs from the signer's -- a dropped field, say -- and
	// every answer derived from it would be about a document nobody signed.
	again, err := baseline.Marshal(e)
	if err != nil {
		return Entry{}, fmt.Errorf("%w: %v", ErrEntry, err)
	}
	if string(again) != string(canon) {
		return Entry{}, fmt.Errorf("%w: the parsed entry does not re-encode to the bytes that were signed", ErrEntry)
	}
	if err := ValidateEntry(e); err != nil {
		return Entry{}, err
	}
	return e, nil
}

// ValidateEntry refuses an entry that is malformed on its face. It says nothing
// about linkage, which needs the rest of the chain: see Verify.
func ValidateEntry(e Entry) error {
	if e.Schema != Schema {
		return fmt.Errorf("%w: schema %d, this build writes %d", ErrEntry, e.Schema, Schema)
	}
	if e.Seq < 0 {
		return fmt.Errorf("%w: seq %d is negative", ErrEntry, e.Seq)
	}
	if err := validDigest(e.PrevHash); err != nil {
		return fmt.Errorf("%w: prev_hash: %v", ErrEntry, err)
	}
	if _, err := baseline.ParseStamp(e.Time); err != nil {
		return fmt.Errorf("%w: time: %v", ErrEntry, err)
	}
	switch e.Kind {
	case KindBaseline, KindAppend:
	default:
		return fmt.Errorf("%w: kind %q, want %q or %q", ErrEntry, e.Kind, KindBaseline, KindAppend)
	}
	if strings.TrimSpace(e.Host) == "" {
		return fmt.Errorf("%w: host is empty", ErrEntry)
	}
	if strings.TrimSpace(e.Payload.Kind) == "" {
		return fmt.Errorf("%w: payload kind is empty", ErrEntry)
	}
	if strings.TrimSpace(e.Payload.Namespace) == "" {
		return fmt.Errorf("%w: payload namespace is empty; a commitment that does not say "+
			"which namespace signed it can be answered with the wrong document", ErrEntry)
	}
	if err := validDigest(e.Payload.SHA256); err != nil {
		return fmt.Errorf("%w: payload sha256: %v", ErrEntry, err)
	}
	if e.Payload.Bytes < 0 {
		return fmt.Errorf("%w: payload bytes %d is negative", ErrEntry, e.Payload.Bytes)
	}
	return nil
}

// Link fills in the fields that position an entry: seq and prev_hash. head is
// nil for the first entry.
func Link(head *Record, e Entry) Entry {
	if head == nil || head.Zero() {
		e.Seq = 0
		e.PrevHash = GenesisPrev
		return e
	}
	e.Seq = head.Entry.Seq + 1
	e.PrevHash = head.Hash()
	return e
}

// -- anchors -----------------------------------------------------------------

// Anchor is a chain length and head hash recorded somewhere the attacker on the
// monitored host cannot rewrite: root-only state, or the remote's copy.
//
// It exists because truncation is invisible from inside the chain. P4 task 6
// owns keeping one current; this package only consumes it, so that the two
// concerns stay separable and so that a caller with no anchor gets a report
// that SAYS it could not check rather than one that looks clean.
type Anchor struct {
	Length int64  `json:"length"`
	Head   string `json:"head"`
}

// HeadAnchor is the anchor describing a chain as it stands.
func HeadAnchor(records []Record) Anchor {
	if len(records) == 0 {
		return Anchor{}
	}
	return Anchor{Length: int64(len(records)), Head: records[len(records)-1].Hash()}
}

// -- verification ------------------------------------------------------------

// VerifyOptions is what Verify is allowed to assume.
type VerifyOptions struct {
	// Trusted is the set of keys whose signatures count. Empty is a refusal,
	// never a pass: "no keys configured" must not mean "any key will do".
	Trusted []*baseline.PublicKey

	// Anchor, when set, is what makes truncation and cross-copy forks
	// detectable. Nil means those checks did not run, and the report says so.
	Anchor *Anchor
}

// Report is what a verification established, and what it did not.
type Report struct {
	Length int64
	Head   string

	// TruncationChecked is false when no anchor was supplied. A caller
	// rendering "chain verified" without consulting this is reporting clean for
	// something it did not examine (INV-3).
	TruncationChecked bool

	// Notes state what could not be determined. Never empty when
	// TruncationChecked is false.
	Notes []string

	// Limits is what a verified chain cannot prove (INV-6).
	Limits string

	SignerFingerprints []string
}

// Verify checks a chain end to end.
//
// The checks run in the order of how badly each failure would mislead: a
// replayed record, then a fork, then sequence, then linkage, then a replayed
// payload, then time. Each returns its own sentinel, because "invalid chain"
// tells an operator nothing about what to do next.
func Verify(records []Record, opt VerifyOptions) (Report, error) {
	rep := Report{
		Length: int64(len(records)),
		Limits: LimitsText,
	}
	if len(records) > 0 {
		rep.Head = records[len(records)-1].Hash()
	}
	if opt.Anchor == nil {
		rep.Notes = append(rep.Notes, "no anchor was supplied, so truncation was NOT checked: "+
			"entries removed from the end of this chain would leave it verifying exactly as it does now")
	} else {
		rep.TruncationChecked = true
	}

	// Every record's signature, over the bytes as received, before anything
	// below interprets a single field.
	seenFP := map[string]bool{}
	for i, r := range records {
		key, err := baseline.Verify(r.sig, baseline.NamespaceChainEntry, r.raw, opt.Trusted)
		if err != nil {
			return rep, fmt.Errorf("entry %d (seq %d): %w", i, r.Entry.Seq, err)
		}
		if fp := key.Fingerprint(); !seenFP[fp] {
			seenFP[fp] = true
			rep.SignerFingerprints = append(rep.SignerFingerprints, fp)
		}
		if err := ValidateEntry(r.Entry); err != nil {
			return rep, fmt.Errorf("entry %d: %w", i, err)
		}
	}

	// Replay, form one: the same record twice. Every signature in it is real.
	byHash := map[string]int{}
	for i, r := range records {
		if j, dup := byHash[r.Hash()]; dup {
			return rep, fmt.Errorf("%w: entry %d is a byte-identical copy of entry %d", ErrReplay, i, j)
		}
		byHash[r.Hash()] = i
	}

	// Fork: two entries naming the same predecessor. Both branches verify in
	// isolation, which is why this is checked before the sequence rule -- a
	// fork reported as "non-contiguous seq" would send an operator looking for
	// a missing entry instead of a rewritten history.
	byPrev := map[string]int{}
	for i, r := range records {
		if j, dup := byPrev[r.Entry.PrevHash]; dup {
			return rep, fmt.Errorf("%w: entries %d and %d both claim %s as their predecessor",
				ErrFork, j, i, short(r.Entry.PrevHash))
		}
		byPrev[r.Entry.PrevHash] = i
	}

	for i, r := range records {
		if int64(i) != r.Entry.Seq {
			return rep, fmt.Errorf("%w: entry at position %d carries seq %d", ErrSequence, i, r.Entry.Seq)
		}
	}

	for i, r := range records {
		want := GenesisPrev
		if i > 0 {
			want = records[i-1].Hash()
		}
		if r.Entry.PrevHash != want {
			return rep, fmt.Errorf("%w: entry %d names %s, its predecessor hashes to %s",
				ErrPrevHash, i, short(r.Entry.PrevHash), short(want))
		}
	}

	// Replay, form two: the same payload committed twice under different
	// entries. This is the replay that survives a key compromise -- the
	// attacker re-asserts an old system state with a fresh, correctly linked,
	// genuinely signed entry. A manifest carries its own creation time, so two
	// identical payload digests mean the same document was committed twice,
	// never two honest observations that happened to agree.
	byPayload := map[string]int{}
	for i, r := range records {
		if j, dup := byPayload[r.Entry.Payload.SHA256]; dup {
			return rep, fmt.Errorf("%w: entries %d and %d commit to the same payload %s",
				ErrReplay, j, i, short(r.Entry.Payload.SHA256))
		}
		byPayload[r.Entry.Payload.SHA256] = i
	}

	for i := 1; i < len(records); i++ {
		prev, err := baseline.ParseStamp(records[i-1].Entry.Time)
		if err != nil {
			return rep, fmt.Errorf("entry %d: %w: time: %v", i-1, ErrEntry, err)
		}
		cur, err := baseline.ParseStamp(records[i].Entry.Time)
		if err != nil {
			return rep, fmt.Errorf("entry %d: %w: time: %v", i, ErrEntry, err)
		}
		if cur.Before(prev) {
			return rep, fmt.Errorf("%w: entry %d is timestamped %s, before entry %d at %s",
				ErrTime, i, records[i].Entry.Time, i-1, records[i-1].Entry.Time)
		}
	}

	if opt.Anchor != nil {
		a := *opt.Anchor
		switch {
		case a.Length > rep.Length:
			return rep, fmt.Errorf("%w: the anchor records %d entries, this copy has %d",
				ErrTruncated, a.Length, rep.Length)
		case a.Length > 0:
			got := records[a.Length-1].Hash()
			if got != a.Head {
				return rep, fmt.Errorf("%w: at length %d the anchor names %s, this copy has %s",
					ErrFork, a.Length, short(a.Head), short(got))
			}
		}
	}
	return rep, nil
}

// strictUnmarshal decodes one JSON document into v, refusing unknown fields and
// trailing data. A field this build does not understand carries meaning this
// build cannot evaluate, and answering questions about the document anyway is
// how a downgrade gets its "clean".
func strictUnmarshal(b []byte, v any) error {
	dec := json.NewDecoder(bytes.NewReader(b))
	dec.DisallowUnknownFields()
	if err := dec.Decode(v); err != nil {
		return err
	}
	if dec.More() {
		return errors.New("trailing data after the document")
	}
	return nil
}

func short(h string) string {
	if len(h) <= 12 {
		return h
	}
	return h[:12] + "..."
}

func validDigest(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("%q is %d characters, want 64 hex", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%q is not lowercase hex", s)
		}
	}
	return nil
}
