// internal/baseline/manifest.go
//
// The manifest is what gets signed and what a chain entry commits to. It is
// assembled by a pure function from values the caller measured: nothing here
// reads the filesystem (MtreeDigest reads an io.Reader the caller opened),
// nothing reads the clock, nothing writes (INV-4, INV-5).
//
// # Two layers, and the number that forces them
//
// The manifest stores sha256 of each package's mtree -- ONE record per package,
// 1,410 of them on the reference system -- and not the ~325,000 per-file hashes
// those mtrees describe. This is not an optimisation of an equivalent design:
//
//   - The per-package digest is already a commitment to every file, because
//     pacman's mtree carries each file's own sha256. Verifying a file against
//     the mtree and the mtree against this digest is the same claim as
//     verifying the file against a per-file record in the manifest, reached in
//     two steps instead of one. The second layer costs nothing to add.
//   - The per-file manifest costs on every run, forever. Every byte of it has
//     to be canonicalised, hashed, signed and verified each time. Two orders of
//     magnitude more bytes means two orders of magnitude more work in the path
//     that must not be skipped.
//   - A per-file manifest also duplicates data pacman already stores and
//     already protects, in a document that then has to be kept in step with it.
//
// What the two-layer form gives up is the ability to say WHICH file inside a
// package changed without reading that package's mtree. It cannot: it says the
// mtree changed. Reading one mtree to localise the change is a cheap second
// step, and internal/mtree already does it.
//
// # The field most easily forgotten
//
// Log.Earliest -- the earliest timestamp in pacman.log at the time the baseline
// was made. Signing it is what turns "the log is shorter than it used to be"
// from invisible into evidence: see LogTruncatedSince. A baseline without it is
// still a baseline, but log truncation becomes undetectable, so its absence is
// recorded as a coverage gap rather than passed over.
//
// # What a verified manifest proves (INV-6)
//
// That the holder of the signing key emitted exactly these digests at the time
// the document claims. NOT that the digests were honest -- a host already
// compromised when the baseline was made signs the attacker's state as the
// reference -- and NOT that this is the newest manifest, which is the chain's
// job, not this file's.
package baseline

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"sort"
	"strings"
	"time"
)

// ManifestSchema is the schema version of the signed document. It is inside the
// signed bytes so a later build cannot reinterpret an older manifest as its own
// shape.
const ManifestSchema = 1

// ErrManifest reports a manifest that could not be assembled from the values
// supplied. Every case is a refusal to sign something whose meaning is unclear.
var ErrManifest = errors.New("baseline: manifest is not assemblable")

// maxMtree bounds a single mtree on the way to its digest, in both compressed
// and decompressed terms. The reference system's largest is 1,030,840 B
// compressed and 5,665,567 B decompressed.
const (
	maxMtreeCompressed   = 16 << 20
	maxMtreeDecompressed = 64 << 20
)

// -- the document -----------------------------------------------------------

// Manifest is the signed baseline document. Field order in this declaration is
// irrelevant: Marshal sorts by key, so a later reordering cannot invalidate
// signatures already made.
type Manifest struct {
	Schema        int            `json:"schema"`
	Host          string         `json:"host"`
	Root          string         `json:"root"`
	CreatedAt     string         `json:"created_at"`
	Tier          string         `json:"tier"`
	Packages      []Package      `json:"packages"`
	Provenance    []Provenance   `json:"provenance"`
	Surfaces      []Surface      `json:"surfaces"`
	Adjudications []Adjudication `json:"adjudications"`
	Log           LogWindow      `json:"log"`
	Coverage      Coverage       `json:"coverage"`
}

// Package is one installed package and the digest of its mtree.
type Package struct {
	Name    string `json:"name"`
	Version string `json:"version"`
	Foreign bool   `json:"foreign"`

	// MtreeSHA256 is sha256 over the DECOMPRESSED mtree; see MtreeDigest.
	// Empty only when MtreeUnread says why.
	MtreeSHA256 string `json:"mtree_sha256"`
	MtreeBytes  int64  `json:"mtree_bytes"`

	// MtreeUnread is the stated reason the digest is absent. A blank digest
	// with a blank reason is refused: it would read as a fact.
	MtreeUnread string `json:"mtree_unread"`
}

// Provenance is one captured provenance snapshot, by digest. The snapshot
// itself lives in the snapshot store; the manifest commits to it.
type Provenance struct {
	PkgBase        string `json:"pkgbase"`
	SnapshotSHA256 string `json:"snapshot_sha256"`
	CapturedAt     string `json:"captured_at"`
}

// Surface is one entry of the surfaces inventory: a hook, unit, or other
// execution surface and who owned it when the baseline was made.
type Surface struct {
	Kind   string `json:"kind"`
	Path   string `json:"path"`
	Owner  string `json:"owner"`
	State  string `json:"state"`
	SHA256 string `json:"sha256"`
}

// Adjudication is one recorded decision, carried in the baseline so that a
// suppression cannot be added after the fact without breaking the signature.
// FingerprintEpoch travels with it so a change of matching semantics surfaces
// the suppression as stale rather than silently keeping or dropping it.
type Adjudication struct {
	Fingerprint      string `json:"fingerprint"`
	Scope            string `json:"scope"`
	Reason           string `json:"reason"`
	ExpiresAt        string `json:"expires_at"`
	FingerprintEpoch int    `json:"fingerprint_epoch"`
}

// LogWindow is what pacman.log covered when the baseline was made.
type LogWindow struct {
	// Earliest is the first timestamp in the log, in the log's own layout with
	// its explicit offset. Later truncation is detected against it.
	Earliest string   `json:"earliest"`
	Latest   string   `json:"latest"`
	Files    []string `json:"files"`
	Bounded  bool     `json:"bounded"`
}

// Coverage is what this manifest does not cover. Complete is derived, never
// supplied: a caller cannot assert completeness it did not achieve.
type Coverage struct {
	Complete bool  `json:"complete"`
	Gaps     []Gap `json:"gaps"`
}

// Gap mirrors finding.Gap in canonical form. It is redeclared rather than
// imported so that the signed document's shape is owned by this package and
// cannot drift when finding.Gap grows a field.
type Gap struct {
	RuleID  string `json:"rule_id"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

// -- assembly ----------------------------------------------------------------

// ManifestInput is the measured state a manifest is assembled from. Order does
// not matter; BuildManifest sorts.
type ManifestInput struct {
	Host          string
	Root          string
	CreatedAt     string // RFC3339 with an explicit offset
	Tier          string
	Packages      []PackageInput
	Provenance    []ProvenanceInput
	Surfaces      []SurfaceInput
	Adjudications []AdjudicationInput
	Log           LogInput
	Gaps          []Gap
}

type PackageInput struct {
	Name        string
	Version     string
	Foreign     bool
	MtreeSHA256 string
	MtreeBytes  int64
	MtreeUnread string
}

type ProvenanceInput struct {
	PkgBase        string
	SnapshotSHA256 string
	CapturedAt     string
}

type SurfaceInput struct {
	Kind   string
	Path   string
	Owner  string
	State  string
	SHA256 string
}

type AdjudicationInput struct {
	Fingerprint      string
	Scope            string
	Reason           string
	ExpiresAt        string
	FingerprintEpoch int
}

type LogInput struct {
	Earliest string
	Latest   string
	Files    []string
	Bounded  bool
}

// BuildManifest assembles and validates a manifest. It is a pure function of
// its argument.
//
// It refuses rather than repairs: a duplicate package, a malformed digest, a
// timestamp without an offset and a missing digest with no stated reason are
// all errors, because each one would otherwise be signed as a fact. What it
// does NOT refuse is missing evidence that was honestly reported -- an unread
// mtree, an absent log window -- which becomes a coverage gap, since refusing
// there would mean a host with one unreadable file could never have a baseline
// (INV-3, INV-9).
func BuildManifest(in ManifestInput) (Manifest, error) {
	if strings.TrimSpace(in.Host) == "" {
		return Manifest{}, fmt.Errorf("%w: host is empty", ErrManifest)
	}
	if in.Root == "" {
		return Manifest{}, fmt.Errorf("%w: root is empty", ErrManifest)
	}
	if _, err := ParseStamp(in.CreatedAt); err != nil {
		return Manifest{}, fmt.Errorf("%w: created_at: %v", ErrManifest, err)
	}
	if strings.TrimSpace(in.Tier) == "" {
		return Manifest{}, fmt.Errorf("%w: tier is empty; a manifest must record what "+
			"depth of scan it stands on", ErrManifest)
	}

	m := Manifest{
		Schema:    ManifestSchema,
		Host:      in.Host,
		Root:      in.Root,
		CreatedAt: in.CreatedAt,
		Tier:      in.Tier,
	}
	gaps := append([]Gap(nil), in.Gaps...)

	seen := map[string]bool{}
	for _, p := range in.Packages {
		if p.Name == "" {
			return Manifest{}, fmt.Errorf("%w: a package record has no name", ErrManifest)
		}
		if seen[p.Name] {
			return Manifest{}, fmt.Errorf("%w: package %q appears twice; two mtree digests "+
				"for one package cannot both be signed", ErrManifest, p.Name)
		}
		seen[p.Name] = true
		switch {
		case p.MtreeSHA256 == "" && p.MtreeUnread == "":
			return Manifest{}, fmt.Errorf("%w: package %q has no mtree digest and no reason; "+
				"an unread mtree is a gap, never a blank", ErrManifest, p.Name)
		case p.MtreeSHA256 == "":
			gaps = append(gaps, Gap{
				RuleID:  "baseline.mtree-unread",
				Subject: "pkg:" + p.Name,
				Reason:  p.MtreeUnread,
			})
		default:
			if err := validDigest(p.MtreeSHA256); err != nil {
				return Manifest{}, fmt.Errorf("%w: package %q: %v", ErrManifest, p.Name, err)
			}
		}
		// A conversion rather than a field-by-field literal, and the coupling it
		// creates between PackageInput and Package is deliberate. With a literal,
		// adding a field to BOTH types still compiles while silently leaving the
		// new field out of the manifest -- a signed document quietly missing
		// something it was supposed to commit to. The conversion refuses to
		// compile until the two layouts agree, so the omission becomes a build
		// error instead of a gap in the evidence.
		m.Packages = append(m.Packages, Package(p))
	}
	sort.Slice(m.Packages, func(i, j int) bool { return m.Packages[i].Name < m.Packages[j].Name })

	for _, p := range in.Provenance {
		if p.PkgBase == "" {
			return Manifest{}, fmt.Errorf("%w: a provenance record has no pkgbase", ErrManifest)
		}
		if err := validDigest(p.SnapshotSHA256); err != nil {
			return Manifest{}, fmt.Errorf("%w: provenance %q: %v", ErrManifest, p.PkgBase, err)
		}
		if p.CapturedAt != "" {
			if _, err := ParseStamp(p.CapturedAt); err != nil {
				return Manifest{}, fmt.Errorf("%w: provenance %q captured_at: %v", ErrManifest, p.PkgBase, err)
			}
		}
		m.Provenance = append(m.Provenance, Provenance(p))
	}
	sort.Slice(m.Provenance, func(i, j int) bool {
		if m.Provenance[i].PkgBase != m.Provenance[j].PkgBase {
			return m.Provenance[i].PkgBase < m.Provenance[j].PkgBase
		}
		return m.Provenance[i].SnapshotSHA256 < m.Provenance[j].SnapshotSHA256
	})

	for _, s := range in.Surfaces {
		if s.Path == "" {
			return Manifest{}, fmt.Errorf("%w: a surface record has no path", ErrManifest)
		}
		if s.SHA256 != "" {
			if err := validDigest(s.SHA256); err != nil {
				return Manifest{}, fmt.Errorf("%w: surface %q: %v", ErrManifest, s.Path, err)
			}
		}
		m.Surfaces = append(m.Surfaces, Surface(s))
	}
	sort.Slice(m.Surfaces, func(i, j int) bool {
		if m.Surfaces[i].Kind != m.Surfaces[j].Kind {
			return m.Surfaces[i].Kind < m.Surfaces[j].Kind
		}
		return m.Surfaces[i].Path < m.Surfaces[j].Path
	})

	for _, a := range in.Adjudications {
		if a.Fingerprint == "" {
			return Manifest{}, fmt.Errorf("%w: an adjudication has no fingerprint", ErrManifest)
		}
		if strings.TrimSpace(a.Reason) == "" {
			return Manifest{}, fmt.Errorf("%w: adjudication %s has no reason; a suppression "+
				"without a recorded reason is indistinguishable from an attacker's",
				ErrManifest, a.Fingerprint)
		}
		switch a.Scope {
		case "pin", "subject", "rule":
		default:
			return Manifest{}, fmt.Errorf("%w: adjudication %s has scope %q, want pin, subject or rule",
				ErrManifest, a.Fingerprint, a.Scope)
		}
		if a.ExpiresAt != "" {
			if _, err := ParseStamp(a.ExpiresAt); err != nil {
				return Manifest{}, fmt.Errorf("%w: adjudication %s expires_at: %v",
					ErrManifest, a.Fingerprint, err)
			}
		}
		m.Adjudications = append(m.Adjudications, Adjudication(a))
	}
	sort.Slice(m.Adjudications, func(i, j int) bool {
		return m.Adjudications[i].Fingerprint < m.Adjudications[j].Fingerprint
	})

	m.Log = LogWindow{
		Earliest: in.Log.Earliest,
		Latest:   in.Log.Latest,
		Files:    append([]string(nil), in.Log.Files...),
		Bounded:  in.Log.Bounded,
	}
	sort.Strings(m.Log.Files)
	for _, pair := range []struct{ name, val string }{
		{"earliest", m.Log.Earliest}, {"latest", m.Log.Latest},
	} {
		if pair.val == "" {
			continue
		}
		if _, err := ParseStamp(pair.val); err != nil {
			return Manifest{}, fmt.Errorf("%w: log %s: %v", ErrManifest, pair.name, err)
		}
	}
	if m.Log.Earliest == "" {
		gaps = append(gaps, Gap{
			RuleID:  "baseline.log-window-unknown",
			Subject: "/var/log/pacman.log",
			Reason: "the earliest pacman.log timestamp was not established, so later truncation " +
				"of the log cannot be detected against this baseline",
		})
	}
	if m.Log.Bounded {
		gaps = append(gaps, Gap{
			RuleID:  "baseline.log-bounded",
			Subject: "/var/log/pacman.log",
			Reason:  "pacman.log reading stopped at a limit, so the window recorded here is not the whole log",
		})
	}

	sort.Slice(gaps, func(i, j int) bool {
		if gaps[i].RuleID != gaps[j].RuleID {
			return gaps[i].RuleID < gaps[j].RuleID
		}
		return gaps[i].Subject < gaps[j].Subject
	})
	m.Coverage = Coverage{Complete: len(gaps) == 0, Gaps: gaps}

	// Assembling something Marshal would refuse is a bug here, not at signing
	// time; find it now, while there is a name to attach it to.
	if _, err := Marshal(m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	return m, nil
}

// Digest is the manifest's canonical digest -- the value a chain entry commits
// to.
func (m Manifest) Digest() ([32]byte, error) { return Digest(m) }

// EarliestLogTime is the signed pacman.log window start, "" when unknown.
func (m Manifest) EarliestLogTime() string { return m.Log.Earliest }

// LogTruncatedSince reports whether an observation made later saw a log that
// begins LATER than this baseline recorded -- which means history was removed.
//
// The comparison only runs in this direction. A log that now begins EARLIER
// than the baseline is not truncation (a rotated sibling came back into view,
// or a different set of files was read); it is reported as false, and any
// judgement about it belongs to the caller.
//
// An unparseable observation is an error, never a quiet false: "I could not
// tell" must not read as "nothing was removed" (INV-3, INV-9).
func (m Manifest) LogTruncatedSince(observedEarliest string) (bool, error) {
	if m.Log.Earliest == "" {
		return false, fmt.Errorf("%w: this baseline recorded no log window, so truncation "+
			"cannot be judged against it", ErrManifest)
	}
	base, err := ParseStamp(m.Log.Earliest)
	if err != nil {
		return false, fmt.Errorf("%w: signed log window: %v", ErrManifest, err)
	}
	if observedEarliest == "" {
		return false, fmt.Errorf("%w: no observed log window was supplied", ErrManifest)
	}
	obs, err := ParseStamp(observedEarliest)
	if err != nil {
		return false, fmt.Errorf("%w: observed log window: %v", ErrManifest, err)
	}
	return obs.After(base), nil
}

// -- signing -----------------------------------------------------------------

// SignManifest canonicalises and signs a manifest, returning the exact bytes
// that were signed alongside the detached signature. Both are returned because
// storing anything but these bytes would mean the stored document and the
// signed document are two different things.
func SignManifest(s Signer, m Manifest) (raw, sig []byte, err error) {
	raw, err = Marshal(m)
	if err != nil {
		return nil, nil, err
	}
	sig, err = Sign(s, NamespaceManifest, raw)
	if err != nil {
		return nil, nil, err
	}
	return raw, sig, nil
}

// VerifyManifest authenticates raw bytes and only then parses them.
//
// The ordering is the whole point: Verify hashes the bytes without
// interpreting them, so the JSON parser never sees a document that has not
// already been proven to come from a trusted key. Parsing first and verifying
// afterwards would hand an attacker the parser -- see VerifyCanonical.
//
// Unknown fields are refused. A manifest carrying a field this build does not
// understand carries meaning this build cannot evaluate, and answering
// questions about it anyway is how a downgrade attack gets its "clean".
func VerifyManifest(sig []byte, raw []byte, trusted []*PublicKey) (Manifest, *PublicKey, error) {
	canon, key, err := VerifyCanonical(sig, NamespaceManifest, raw, trusted)
	if err != nil {
		return Manifest{}, nil, err
	}
	m, err := decodeManifest(canon)
	if err != nil {
		return Manifest{}, nil, err
	}
	return m, key, nil
}

func decodeManifest(canon []byte) (Manifest, error) {
	dec := json.NewDecoder(bytes.NewReader(canon))
	dec.DisallowUnknownFields()
	var m Manifest
	if err := dec.Decode(&m); err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if dec.More() {
		return Manifest{}, fmt.Errorf("%w: trailing data after the manifest", ErrManifest)
	}
	if m.Schema != ManifestSchema {
		return Manifest{}, fmt.Errorf("%w: manifest schema %d, this build understands %d",
			ErrManifest, m.Schema, ManifestSchema)
	}
	// Re-marshalling must reproduce the signed bytes. If it does not, this
	// build's idea of the document differs from the signer's -- for instance a
	// field this build drops -- and any answer derived from it would be about a
	// document nobody signed.
	again, err := Marshal(m)
	if err != nil {
		return Manifest{}, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if !bytes.Equal(again, canon) {
		return Manifest{}, fmt.Errorf("%w: the parsed manifest does not re-encode to the "+
			"bytes that were signed", ErrManifest)
	}
	return m, nil
}

// -- mtree digests -----------------------------------------------------------

// MtreeDigest is sha256 over the DECOMPRESSED mtree, with the decompressed
// length.
//
// Content, not framing: a gzip member carries a modification time and a
// compression level, neither of which is part of what pacman recorded. Hashing
// the stored bytes would make a recompression -- by a backup tool, by a
// filesystem migration, by pacman itself on a reinstall of identical content --
// read as tampering, and a detector that cries wolf on maintenance is a
// detector that gets turned off.
//
// Input may be gzipped or plain; an offline root can hold either. Both paths
// are bounded, because the local database of the machine under examination is
// exactly the place a hostile mtree would be planted.
func MtreeDigest(r io.Reader) ([32]byte, int64, error) {
	br := &boundedReader{r: r, max: maxMtreeCompressed}
	head := make([]byte, 2)
	n, err := io.ReadFull(br, head)
	if err != nil && !errors.Is(err, io.ErrUnexpectedEOF) && !errors.Is(err, io.EOF) {
		return [32]byte{}, 0, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	head = head[:n]
	src := io.MultiReader(bytes.NewReader(head), br)

	h := sha256.New()
	var total int64
	if len(head) == 2 && head[0] == 0x1f && head[1] == 0x8b {
		zr, zerr := gzip.NewReader(src)
		if zerr != nil {
			return [32]byte{}, 0, fmt.Errorf("%w: gzip: %v", ErrManifest, zerr)
		}
		defer zr.Close()
		total, err = io.Copy(h, io.LimitReader(zr, maxMtreeDecompressed+1))
	} else {
		total, err = io.Copy(h, src)
	}
	if err != nil {
		return [32]byte{}, 0, fmt.Errorf("%w: %v", ErrManifest, err)
	}
	if total > maxMtreeDecompressed {
		return [32]byte{}, 0, fmt.Errorf("%w: mtree exceeds %d decompressed bytes",
			ErrManifest, maxMtreeDecompressed)
	}
	var out [32]byte
	copy(out[:], h.Sum(nil))
	return out, total, nil
}

// boundedReader caps what is read from a compressed source, so a bomb costs the
// attacker what it claims to cost.
type boundedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (b *boundedReader) Read(p []byte) (int, error) {
	if b.n >= b.max {
		return 0, fmt.Errorf("%w: input exceeds %d bytes", ErrManifest, b.max)
	}
	if int64(len(p)) > b.max-b.n {
		p = p[:b.max-b.n]
	}
	n, err := b.r.Read(p)
	b.n += int64(n)
	return n, err
}

// -- timestamps --------------------------------------------------------------

// stampLayouts are the two spellings a timestamp may take in a signed document,
// both carrying an EXPLICIT offset. A bare local time is refused: the reference
// pacman.log mixes +0000 and +0100 across a DST boundary, so a timestamp
// without an offset is ambiguous by exactly one hour, twice a year.
var stampLayouts = []string{
	"2006-01-02T15:04:05-0700", // what pacman.log writes
	time.RFC3339,
	time.RFC3339Nano,
}

// ParseStamp parses a timestamp that must carry an explicit UTC offset.
func ParseStamp(s string) (time.Time, error) {
	if s == "" {
		return time.Time{}, fmt.Errorf("%w: timestamp is empty", ErrManifest)
	}
	for _, layout := range stampLayouts {
		if t, err := time.Parse(layout, s); err == nil {
			return t, nil
		}
	}
	return time.Time{}, fmt.Errorf("%w: %q is not an RFC3339 timestamp with an explicit offset",
		ErrManifest, s)
}

func validDigest(s string) error {
	if len(s) != 64 {
		return fmt.Errorf("digest %q is %d characters, want 64 hex", s, len(s))
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("digest %q is not lowercase hex", s)
		}
	}
	return nil
}
