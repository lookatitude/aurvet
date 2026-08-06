// internal/triage/store.go
//
// The on-disk triage store: canonical bytes, no signature, temp + fsync +
// atomic rename.
//
// # Why there is no signature here, stated so nobody adds one
//
// §12 makes triage "lightweight, local, unsigned". Signing it would defeat the
// purpose -- the whole reason the middle weight exists is that requiring a key
// drives operators to ignore output instead -- and it would blur the one
// distinction this layer must keep sharp. A signed triage store would be a
// signed document in the state directory that looks, to a hurried reader, like
// the signed adjudication store that gates `baseline init`.
//
// The consequence is stated rather than hidden: ANYONE WHO CAN WRITE THIS FILE
// CAN SUPPRESS ANY FINDING FROM THE DEFAULT VIEW FOR UP TO 90 DAYS. That is why
// the file is 0600 in a 0700 directory, why the expiry is bounded and short, why
// `aurvet triage list` shows the full set including what it is hiding, and above
// all why nothing that gates the trust chain reads this file. An attacker who
// can write here can already write the reports directory; what they cannot do is
// affect a signed manifest, a chain entry, or `baseline init`'s refusal.
//
// The bytes are canonical anyway (sorted keys, no floats), for a smaller reason:
// two hosts with the same records should produce the same file, so a diff
// between two machines' triage sets is a diff of the decisions and not of the
// serialiser's mood.
package triage

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/lookatitude/aurvet/internal/baseline"
)

const (
	// StoreSchema versions the on-disk envelope.
	StoreSchema = 1

	// MaxStoreBytes caps the store at 1 MiB, which is room for thousands of
	// records. The cap exists so the reader terminates on hostile input before
	// it allocates, not because the honest case is ever near it.
	MaxStoreBytes = 1 << 20

	// FileName is the store's name inside the state directory.
	FileName = "triage.json"

	// LockFile guards the read-modify-write. Two concurrent runs would otherwise
	// each read the store, each add a record, and the loser's would vanish.
	LockFile = ".triage.lock"
)

// storeDoc is the canonical envelope.
type storeDoc struct {
	SchemaVersion int      `json:"schema_version"`
	Records       []Record `json:"records"`
}

// Marshal encodes records as canonical JSON.
//
// Every record is validated first: a record that would read as invalid on the
// way back in must never be written on the way out, because it would then be
// reported as a coverage gap forever by an operator who thinks they filed it.
func Marshal(records []Record) ([]byte, error) {
	recs := append([]Record(nil), records...)
	sortRecords(recs)
	seen := make(map[string]bool, len(recs))
	for i, r := range recs {
		if err := r.Validate(); err != nil {
			return nil, fmt.Errorf("record %d: %w", i, err)
		}
		key := string(r.Verb) + "\x00" + r.Fingerprint + "\x00" + r.EvidenceDigest
		if seen[key] {
			return nil, fmt.Errorf("%w: two `%s` records for fingerprint %s", ErrRecord,
				r.Verb, r.Fingerprint)
		}
		seen[key] = true
	}
	if recs == nil {
		recs = []Record{}
	}
	return baseline.Marshal(storeDoc{SchemaVersion: StoreSchema, Records: recs})
}

// Parse reads a store. It never returns an error: every failure becomes a Set
// with no records and a Fault, because a caller who ignores an error must not
// thereby acquire suppressions.
func Parse(source string, raw []byte) Set {
	if len(raw) == 0 {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the triage store is empty"}}}
	}
	if len(raw) > MaxStoreBytes {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("the triage store is %d bytes, over the %d byte limit, so it was "+
				"not parsed at all", len(raw), MaxStoreBytes)}}}
	}
	// Canonical admission control before json.Unmarshal: it refuses duplicate
	// keys, floats and invalid UTF-8. json.Unmarshal keeps the LAST of two
	// duplicate keys, so a document meaning two things to two readers must not
	// get as far as being interpreted (INV-2).
	if _, err := baseline.Canonical(raw); err != nil {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the triage store is not canonical JSON: " + err.Error()}}}
	}
	var doc storeDoc
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&doc); err != nil {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: "the triage store did not parse: " + err.Error()}}}
	}
	if doc.SchemaVersion != StoreSchema {
		return Set{Source: source, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("the triage store declares schema_version %d, which this build does "+
				"not understand (it knows %d); no record in it was interpreted",
				doc.SchemaVersion, StoreSchema)}}}
	}

	set := Set{Source: source}
	for i, r := range doc.Records {
		if err := r.Validate(); err != nil {
			// Kept out of Records and reported. One bad record does not discard
			// the rest -- that would let anyone who can append a single malformed
			// record void every legitimate one -- but it suppresses nothing.
			set.Faults = append(set.Faults, Fault{
				Where: fmt.Sprintf("record %d", i), Reason: err.Error(),
			})
			continue
		}
		set.Records = append(set.Records, r)
	}
	if len(doc.Records) == 0 {
		set.Faults = append(set.Faults, Fault{Where: "file",
			Reason: "the triage store holds no records"})
	}
	return set
}

// Load reads the store from a state directory. An ABSENT store is the healthy
// empty set, not a fault: nothing triaged is the correct default.
//
// A state directory that is not a directory at all is also the empty set, and
// that is not the fail-open it looks like. This store only ever HIDES findings,
// so an unreadable one shows more rather than less -- whereas manufacturing a
// coverage gap out of "there is nowhere for a triage file to live" would push
// every scan with a broken state directory to exit 3 and say nothing about the
// system. The signed adjudication store, which can unblock things, is
// deliberately not this forgiving.
func Load(stateDir string) Set {
	path := filepath.Join(stateDir, FileName)
	if fi, err := os.Stat(stateDir); err != nil || !fi.IsDir() {
		return Set{Source: path}
	}
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return Set{Source: path}
	}
	if err != nil {
		return Set{Source: path, Faults: []Fault{{Where: "file",
			Reason: fmt.Sprintf("%s could not be read: %v", path, err)}}}
	}
	return Parse(path, raw)
}

// Save writes the store atomically. An EMPTY set removes the file rather than
// writing a records:[] document: an absent store is silent and suppresses
// nothing, while an empty document is reported as a fault on every subsequent
// run -- a permanent coverage gap manufactured by the operator tidying up.
func Save(stateDir string, records []Record) error {
	path := filepath.Join(stateDir, FileName)
	if len(records) == 0 {
		if err := os.Remove(path); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		return nil
	}
	raw, err := Marshal(records)
	if err != nil {
		return err
	}
	return writeFileAtomic(path, raw, 0o600)
}

// writeFileAtomic is temp + fsync + rename + fsync-dir.
//
// It is a third copy of a pattern internal/chain and cmd/aurvet each hold, and
// that is a deliberate cost rather than an oversight: the alternative is a
// shared mutable file-writing surface across four packages whose invariants
// differ. What must not diverge is that a reader never sees a half-written
// store, and that is what this function guarantees on its own.
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
