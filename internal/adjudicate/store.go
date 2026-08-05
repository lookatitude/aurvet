// internal/adjudicate/store.go
//
// The on-disk adjudication store: canonical bytes, a detached SSHSIG over them,
// and a reader that fails closed in every direction.
//
// # Ordering discipline
//
// ParseSignedStore verifies the signature over the RAW BYTES AS RECEIVED and only
// then parses them. Not after unmarshalling, not "parse then validate":
// canonicalising or unmarshalling attacker-controlled bytes before authenticating
// them hands the attacker the parser. baseline.VerifyCanonical enforces both
// halves -- authenticate first, then require the bytes to be canonical so the
// digest recorded elsewhere is reproducible from the document.
//
// # What a failure means
//
// Every failure yields a Set with NO RECORDS and at least one Fault, so the
// worst case is that nothing is suppressed and the run says why. There is no
// path here that returns records alongside an error for a caller to ignore.
//
// A missing store is not a failure: no adjudications is a perfectly good state,
// and it suppresses nothing anyway. A store whose signature does not verify is
// different from a missing one only in that it is REPORTED -- it still suppresses
// nothing.
//
// The namespace is baseline.NamespaceAdjudication ("adjudication.aurvet.dev"),
// distinct from the manifest and chain-entry namespaces, so a signature over an
// adjudication store can never be replayed as a manifest and vice versa.
package adjudicate

import (
	"bytes"
	"encoding/json"
	"fmt"

	"github.com/lookatitude/aurvet/internal/baseline"
)

const (
	// StoreSchema versions the on-disk envelope.
	StoreSchema = 1

	// MaxStoreBytes caps the store at 1 MiB, which is room for thousands of
	// records. A cap exists because the reader must terminate on hostile input
	// before it allocates, not because the honest case is ever near it.
	MaxStoreBytes = 1 << 20
)

// storeDoc is the canonical envelope. Records are stored sorted, so the bytes
// are a function of the SET and not of the order a caller happened to build it
// in -- otherwise two hosts holding identical adjudications would produce
// different digests.
type storeDoc struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

// MarshalStore encodes records as canonical JSON, ready to be signed.
//
// Every record is validated first. Refusing to serialise an invalid record is
// the cheap half of fail-closed: a record that would read as invalid on the way
// back in must never be signed on the way out, because a signature over it would
// suggest somebody had checked it.
func MarshalStore(records []Record) ([]byte, error) {
	recs := append([]Record(nil), records...)
	sortRecords(recs)
	seen := make(map[string]bool, len(recs))
	for i, r := range recs {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		key := r.Fingerprint + "\x00" + r.EvidenceDigest
		if seen[key] {
			return nil, fmt.Errorf("%w: two records for fingerprint %s; one finding cannot carry "+
				"two judgements", ErrRecord, r.Fingerprint)
		}
		seen[key] = true
	}
	if recs == nil {
		recs = []Record{}
	}
	return baseline.Marshal(storeDoc{SchemaVersion: StoreSchema, Records: recs})
}

// SignStore produces a detached SSHSIG over already-canonical store bytes.
//
// It does not canonicalise for the caller: re-encoding what it was handed would
// mean the bytes stored are not the bytes the caller believes it signed. Pass the
// output of MarshalStore.
//
// The signer is an ssh key -- a file, an agent, or a FIDO2 token through the
// agent. No production key is generated, requested or stored anywhere in this
// tree; that is a human action with the private half held offline.
func SignStore(s baseline.Signer, canonical []byte) ([]byte, error) {
	if _, err := baseline.Canonical(canonical); err != nil {
		return nil, fmt.Errorf("refusing to sign non-canonical store bytes: %w", err)
	}
	return baseline.Sign(s, baseline.NamespaceAdjudication, canonical)
}

// ParseStore reads an UNSIGNED store. It never returns an error: every failure
// becomes a Set with no records and a Fault, because a caller who ignores an
// error must not thereby acquire suppressions.
//
// Use it only where the bytes' authenticity is established elsewhere -- inside an
// already-verified manifest, or for a store the operator is editing locally
// before it is signed. For bytes read from disk on a monitored host, use
// ParseSignedStore.
func ParseStore(source string, raw []byte) Set {
	if len(raw) == 0 {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the adjudication store is empty"}}}
	}
	if len(raw) > MaxStoreBytes {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("the adjudication store is %d bytes, over the %d byte limit, so it "+
				"was not parsed at all", len(raw), MaxStoreBytes)}}}
	}
	// Canonical admission control before json.Unmarshal: it refuses duplicate
	// keys, floats and invalid UTF-8. json.Unmarshal keeps the LAST of two
	// duplicate keys, so a document meaning two things to two readers must not
	// get as far as being interpreted.
	if _, err := baseline.Canonical(raw); err != nil {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the adjudication store is not canonical JSON: " + err.Error()}}}
	}
	var doc storeDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the adjudication store did not parse: " + err.Error()}}}
	}
	if doc.SchemaVersion != StoreSchema {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("the adjudication store declares schema_version %d, which this "+
				"build does not understand (it knows %d); no record in it was interpreted",
				doc.SchemaVersion, StoreSchema)}}}
	}

	set := Set{Source: source}
	for i, r := range doc.Records {
		if err := r.Validate(); err != nil {
			// Kept out of Records, reported as a fault. One bad record does not
			// discard the rest -- that would let an attacker who can append a
			// single malformed record disable every legitimate adjudication --
			// but it does not suppress anything either.
			set.Faults = append(set.Faults, Fault{
				Where:  fmt.Sprintf("record %d", i),
				Reason: err.Error(),
			})
			continue
		}
		set.Records = append(set.Records, r)
	}
	if len(doc.Records) == 0 {
		set.Faults = append(set.Faults, Fault{Where: "file",
			Reason: "the adjudication store holds no records"})
	}
	return set
}

// ParseSignedStore verifies sig over raw and only then parses raw.
//
// A store that does not verify yields no records and a reported fault. The
// distinction from "absent" is deliberate: absence is silent because it
// suppresses nothing and nothing was claimed, whereas a store that was PRESENT
// and failed to verify is a claim that could not be substantiated, and an
// operator needs to know which of their adjudications just stopped applying.
func ParseSignedStore(source string, raw, sig []byte, trusted []*baseline.PublicKey) Set {
	if len(sig) == 0 {
		return Set{Source: source, Faults: []Fault{{Where: "signature",
			Reason: "the adjudication store carries no signature, so it suppresses nothing"}}}
	}
	if len(raw) > MaxStoreBytes {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("the adjudication store is %d bytes, over the %d byte limit, so it "+
				"was neither verified nor parsed", len(raw), MaxStoreBytes)}}}
	}
	canonical, key, err := baseline.VerifyCanonical(sig, baseline.NamespaceAdjudication, raw, trusted)
	if err != nil {
		return Set{Source: source, Faults: []Fault{{Where: "signature",
			Reason: "the adjudication store's signature does not verify, so it suppresses " +
				"nothing: " + err.Error()}}}
	}
	set := ParseStore(source, canonical)
	set.SignedBy = key
	return set
}
