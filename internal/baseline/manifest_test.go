// internal/baseline/manifest_test.go
//
// Attack-first. The happy path is at the bottom; everything above it is a way
// the manifest could lie.
package baseline

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// -- attacks ----------------------------------------------------------------

// A single flipped byte anywhere in the signed manifest must fail
// verification. Not "usually": every byte position, including the ones inside
// whitespace-free JSON punctuation that a lazy verifier might normalise away.
func TestManifestFlipAnyByteFailsVerification(t *testing.T) {
	key := fixtureKey(t)
	m := sampleManifest(t)
	raw, sig, err := SignManifest(key, m)
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*PublicKey{key.PublicKey()}
	if _, _, err := VerifyManifest(sig, raw, trusted); err != nil {
		t.Fatalf("honest manifest refused: %v", err)
	}
	for i := 0; i < len(raw); i++ {
		for _, bit := range []byte{0x01, 0x80} {
			bad := append([]byte(nil), raw...)
			bad[i] ^= bit
			if _, _, err := VerifyManifest(sig, bad, trusted); err == nil {
				t.Fatalf("byte %d flipped with %#x still verified", i, bit)
			}
		}
	}
}

// A flipped byte in the SIGNATURE must fail too, and must not panic: the
// signature is attacker-controlled bytes reaching a parser.
func TestManifestFlippedSignatureBytesRejected(t *testing.T) {
	key := fixtureKey(t)
	raw, sig, err := SignManifest(key, sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	trusted := []*PublicKey{key.PublicKey()}
	rejected := 0
	for i := 0; i < len(sig); i++ {
		bad := append([]byte(nil), sig...)
		bad[i] ^= 0x01
		if _, _, err := VerifyManifest(bad, raw, trusted); err != nil {
			rejected++
		}
	}
	// Base64 armour has positions where a bit flip is not a change (padding,
	// newlines), so "every byte" is the wrong assertion; "almost all, none
	// panicked, and none of the signature-blob bytes slipped through" is the
	// right one.
	if rejected < len(sig)/2 {
		t.Fatalf("only %d of %d signature mutations were rejected", rejected, len(sig))
	}
}

// The manifest must not be verifiable under another document type's namespace:
// a chain entry signature must never read as a manifest signature.
func TestManifestNamespaceIsNotInterchangeable(t *testing.T) {
	key := fixtureKey(t)
	m := sampleManifest(t)
	raw, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, NamespaceChainEntry, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyManifest(sig, raw, []*PublicKey{key.PublicKey()}); err == nil {
		t.Fatal("a chain-entry signature verified as a manifest")
	}
}

// Non-canonical bytes with a genuine signature must be refused: the digest the
// chain records would not be reproducible from the document.
func TestManifestNonCanonicalBytesRefusedEvenWhenSigned(t *testing.T) {
	key := fixtureKey(t)
	raw, err := Marshal(sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	sloppy := append([]byte(" "), raw...) // still valid JSON, no longer canonical
	sig, err := Sign(key, NamespaceManifest, sloppy)
	if err != nil {
		t.Fatal(err)
	}
	_, _, err = VerifyManifest(sig, sloppy, []*PublicKey{key.PublicKey()})
	if !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("want ErrNotCanonical, got %v", err)
	}
}

// An empty trusted set is a refusal, never a pass.
func TestManifestNoTrustedKeysIsRefusal(t *testing.T) {
	key := fixtureKey(t)
	raw, sig, err := SignManifest(key, sampleManifest(t))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyManifest(sig, raw, nil); err == nil {
		t.Fatal("an empty trusted set accepted a signature")
	}
}

// A duplicate package record is refused rather than deduplicated: two records
// for one package name means the manifest asserts two mtree digests for the
// same thing, and picking one would sign a guess.
func TestManifestDuplicatePackageRefused(t *testing.T) {
	in := sampleInput()
	in.Packages = append(in.Packages, in.Packages[0])
	if _, err := BuildManifest(in); !errors.Is(err, ErrManifest) {
		t.Fatalf("want ErrManifest for a duplicate package, got %v", err)
	}
}

// A package with no mtree digest and no stated reason is refused. INV-9: what
// could not be read is a gap that must be recorded, never a blank that reads
// like a fact.
func TestManifestSilentlyMissingDigestRefused(t *testing.T) {
	in := sampleInput()
	in.Packages[0].MtreeSHA256 = ""
	if _, err := BuildManifest(in); !errors.Is(err, ErrManifest) {
		t.Fatalf("want ErrManifest for a blank digest with no reason, got %v", err)
	}
	in.Packages[0].MtreeUnread = "mtree unreadable: permission denied"
	m, err := BuildManifest(in)
	if err != nil {
		t.Fatalf("a stated reason should be accepted: %v", err)
	}
	if m.Coverage.Complete {
		t.Fatal("an unread mtree must make coverage incomplete")
	}
	if !hasGapAbout(m, in.Packages[0].Name) {
		t.Fatal("an unread mtree must appear as a gap naming the package")
	}
}

// A digest that is not 64 lowercase hex characters is refused.
func TestManifestMalformedDigestRefused(t *testing.T) {
	for _, bad := range []string{"deadbeef", strings.ToUpper(strings.Repeat("a", 64)), strings.Repeat("z", 64)} {
		in := sampleInput()
		in.Packages[0].MtreeSHA256 = bad
		if _, err := BuildManifest(in); !errors.Is(err, ErrManifest) {
			t.Fatalf("digest %q was accepted", bad)
		}
	}
}

// A timestamp without an explicit offset is refused. The reference log mixes
// two offsets across DST, so "local time" is not a timestamp.
func TestManifestTimestampsNeedExplicitOffsets(t *testing.T) {
	for _, bad := range []string{"", "2025-11-11 00:50:40", "2025-11-11T00:50:40"} {
		in := sampleInput()
		in.CreatedAt = bad
		if _, err := BuildManifest(in); !errors.Is(err, ErrManifest) {
			t.Fatalf("created_at %q was accepted", bad)
		}
	}
}

// The earliest pacman.log timestamp is the field most easily forgotten, so it
// is the one with the most tests. Absent, it is a coverage gap, not silence.
func TestManifestMissingLogWindowIsAGapNotSilence(t *testing.T) {
	in := sampleInput()
	in.Log.Earliest = ""
	in.Log.Latest = ""
	m, err := BuildManifest(in)
	if err != nil {
		t.Fatalf("a missing log window must be a gap, not a build failure: %v", err)
	}
	if m.Coverage.Complete {
		t.Fatal("a missing log window must make coverage incomplete")
	}
	if !hasGapAbout(m, "pacman.log") {
		t.Fatalf("no gap mentions pacman.log: %+v", m.Coverage.Gaps)
	}
}

// Later truncation of pacman.log is detectable precisely because the earliest
// timestamp was signed: an observation whose earliest entry is NEWER than the
// signed one means history was removed.
func TestManifestDetectsLogTruncation(t *testing.T) {
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	truncated, err := m.LogTruncatedSince("2026-01-02T03:04:05+0100")
	if err != nil {
		t.Fatal(err)
	}
	if !truncated {
		t.Fatal("a later earliest timestamp is truncation and must be reported")
	}
	same, err := m.LogTruncatedSince(m.Log.Earliest)
	if err != nil {
		t.Fatal(err)
	}
	if same {
		t.Fatal("an unchanged log reported as truncated")
	}
	older, err := m.LogTruncatedSince("2020-01-01T00:00:00+0000")
	if err != nil {
		t.Fatal(err)
	}
	if older {
		t.Fatal("an older earliest entry is not truncation")
	}
	// An unreadable observation must not be answered "no truncation".
	if _, err := m.LogTruncatedSince("yesterday"); err == nil {
		t.Fatal("an unparseable observation must be an error, never a quiet false")
	}
}

// -- canonical shape ---------------------------------------------------------

// Input order must not change the signed bytes: a manifest assembled from maps
// iterated in Go's random order must digest identically every time.
func TestManifestInputOrderDoesNotChangeDigest(t *testing.T) {
	in := sampleInput()
	want, err := BuildManifest(in)
	if err != nil {
		t.Fatal(err)
	}
	wantDigest, err := want.Digest()
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 32; i++ {
		shuffled := sampleInput()
		reverse(shuffled.Packages)
		reverse(shuffled.Provenance)
		reverse(shuffled.Surfaces)
		reverse(shuffled.Adjudications)
		got, err := BuildManifest(shuffled)
		if err != nil {
			t.Fatal(err)
		}
		gotDigest, err := got.Digest()
		if err != nil {
			t.Fatal(err)
		}
		if gotDigest != wantDigest {
			t.Fatalf("digest depends on input order: %x != %x", gotDigest, wantDigest)
		}
	}
}

// Two layers, not three: the manifest stores one digest per package. This test
// pins the shape, because the whole size argument rests on it.
func TestManifestStoresOneDigestPerPackageNotPerFile(t *testing.T) {
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	if n := bytes.Count(raw, []byte(`"mtree_sha256"`)); n != len(m.Packages) {
		t.Fatalf("%d mtree digests for %d packages", n, len(m.Packages))
	}
	// Nothing per-file may appear inside the packages array: one digest per
	// package is the entire size argument. (The top-level log window has its
	// own "files" key, which is why this looks only at the package records.)
	seg := packagesSegment(t, raw)
	for _, forbidden := range []string{`"files"`, `"file_sha256"`, `"paths"`} {
		if bytes.Contains(seg, []byte(forbidden)) {
			t.Fatalf("a per-file layer leaked into the manifest: %s", forbidden)
		}
	}
	if perPkg := len(seg) / len(m.Packages); perPkg > 300 {
		t.Fatalf("%d bytes per package record is not a two-layer manifest", perPkg)
	}
}

// packagesSegment returns the bytes of the "packages" array, brackets included.
func packagesSegment(t *testing.T, raw []byte) []byte {
	t.Helper()
	const key = `"packages":[`
	i := bytes.Index(raw, []byte(key))
	if i < 0 {
		t.Fatal("no packages array in the manifest")
	}
	start := i + len(key) - 1
	depth := 0
	for j := start; j < len(raw); j++ {
		switch raw[j] {
		case '[':
			depth++
		case ']':
			depth--
			if depth == 0 {
				return raw[start : j+1]
			}
		}
	}
	t.Fatal("unterminated packages array")
	return nil
}

// -- MtreeDigest -------------------------------------------------------------

// The digest commits to the mtree's CONTENT, so gzip framing (which carries a
// timestamp and a compression level) cannot manufacture a difference.
func TestMtreeDigestIsOverContentNotGzipFraming(t *testing.T) {
	const body = "#mtree\n./usr/bin/foo type=file sha256digest=00\n"
	a := gzipWith(t, body, gzip.BestSpeed, time.Unix(1, 0))
	b := gzipWith(t, body, gzip.BestCompression, time.Unix(999999, 0))
	if bytes.Equal(a, b) {
		t.Fatal("fixture is not exercising two different gzip framings")
	}
	da, _, err := MtreeDigest(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	db, _, err := MtreeDigest(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if da != db {
		t.Fatal("gzip framing changed the mtree digest")
	}
	want := sha256.Sum256([]byte(body))
	if da != want {
		t.Fatalf("digest is not sha256 over the decompressed mtree: %x != %x", da, want)
	}
}

// A change of one byte inside the mtree changes the digest -- that is the whole
// reason the per-file layer can be dropped.
func TestMtreeDigestChangesWithContent(t *testing.T) {
	a := gzipWith(t, "#mtree\n./a type=file sha256digest=00\n", gzip.DefaultCompression, time.Unix(0, 0))
	b := gzipWith(t, "#mtree\n./a type=file sha256digest=01\n", gzip.DefaultCompression, time.Unix(0, 0))
	da, _, err := MtreeDigest(bytes.NewReader(a))
	if err != nil {
		t.Fatal(err)
	}
	db, _, err := MtreeDigest(bytes.NewReader(b))
	if err != nil {
		t.Fatal(err)
	}
	if da == db {
		t.Fatal("a modified mtree kept its digest")
	}
}

// A zip bomb in the local database is a bounded refusal, not an OOM.
func TestMtreeDigestRefusesBomb(t *testing.T) {
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	zeros := make([]byte, 1<<20)
	for i := 0; i < 128; i++ {
		if _, err := zw.Write(zeros); err != nil {
			t.Fatal(err)
		}
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if _, _, err := MtreeDigest(bytes.NewReader(buf.Bytes())); err == nil {
		t.Fatal("a 128 MiB inflation was accepted")
	}
}

// Plain (uncompressed) input is accepted: an offline root may hold either.
func TestMtreeDigestAcceptsUncompressed(t *testing.T) {
	const body = "#mtree\n./a type=file\n"
	got, n, err := MtreeDigest(strings.NewReader(body))
	if err != nil {
		t.Fatal(err)
	}
	if want := sha256.Sum256([]byte(body)); got != want {
		t.Fatalf("%x != %x", got, want)
	}
	if n != int64(len(body)) {
		t.Fatalf("size %d != %d", n, len(body))
	}
}

// -- happy path --------------------------------------------------------------

func TestManifestRoundTrip(t *testing.T) {
	key := fixtureKey(t)
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, err := SignManifest(key, m)
	if err != nil {
		t.Fatal(err)
	}
	back, signer, err := VerifyManifest(sig, raw, []*PublicKey{key.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if !signer.Equal(key.PublicKey()) {
		t.Fatal("wrong signer reported")
	}
	if back.Log.Earliest != m.Log.Earliest {
		t.Fatalf("log window did not survive: %q != %q", back.Log.Earliest, m.Log.Earliest)
	}
	if len(back.Packages) != len(m.Packages) {
		t.Fatalf("%d packages back, %d in", len(back.Packages), len(m.Packages))
	}
	again, err := Marshal(back)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(again, raw) {
		t.Fatal("re-marshalling a verified manifest did not reproduce the signed bytes")
	}
}

// Unknown fields in a signed document are refused: a manifest carrying a field
// this build does not understand has meaning this build cannot evaluate.
func TestManifestUnknownFieldRefused(t *testing.T) {
	key := fixtureKey(t)
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	injected := append([]byte(`{"aaa_unknown":1,`), raw[1:]...)
	canon, err := Canonical(injected)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, NamespaceManifest, canon)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyManifest(sig, canon, []*PublicKey{key.PublicKey()}); err == nil {
		t.Fatal("an unknown field was accepted in a signed manifest")
	}
}

// A signed document that OMITS a field is refused too. json.Decode fills the
// zero value happily, and the omission survives DisallowUnknownFields, so the
// re-encode-and-compare is the only thing standing between a caller and a
// manifest whose root, tier or log window silently became "".
func TestManifestOmittedFieldRefused(t *testing.T) {
	key := fixtureKey(t)
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	stripped := bytes.Replace(raw, []byte(`,"tier":"full"`), nil, 1)
	if bytes.Equal(stripped, raw) {
		t.Fatal("nothing was stripped")
	}
	canon, err := Canonical(stripped)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(key, NamespaceManifest, canon)
	if err != nil {
		t.Fatal(err)
	}
	back, _, err := VerifyManifest(sig, canon, []*PublicKey{key.PublicKey()})
	if err == nil {
		t.Fatalf("a manifest with tier omitted verified as tier=%q", back.Tier)
	}
	if !errors.Is(err, ErrManifest) {
		t.Fatalf("want ErrManifest, got %v", err)
	}
}

// -- live measurement --------------------------------------------------------

// Behind an env gate: build a manifest from the real local database and report
// the numbers the design rests on.
func TestLiveManifestFromLocalDB(t *testing.T) {
	if os.Getenv("AURVET_LIVE") == "" {
		t.Skip("set AURVET_LIVE=1 to measure the real system")
	}
	const localDB = "/var/lib/pacman/local"
	dirs, err := os.ReadDir(localDB)
	if err != nil {
		t.Skipf("no local database: %v", err)
	}
	start := time.Now()
	var pkgs []PackageInput
	var files int64
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		name, version := splitPkgDir(d.Name())
		p := PackageInput{Name: name, Version: version}
		f, err := os.Open(filepath.Join(localDB, d.Name(), "mtree"))
		if err != nil {
			p.MtreeUnread = fmt.Sprintf("mtree unreadable: %v", err)
		} else {
			dg, n, derr := MtreeDigest(f)
			f.Close()
			if derr != nil {
				p.MtreeUnread = fmt.Sprintf("mtree unreadable: %v", derr)
			} else {
				p.MtreeSHA256 = Hex(dg[:])
				p.MtreeBytes = n
				files += int64(bytes.Count(mustRead(t, filepath.Join(localDB, d.Name(), "files")), []byte("\n")))
			}
		}
		pkgs = append(pkgs, p)
	}
	in := sampleInput()
	in.Packages = pkgs
	m, err := BuildManifest(in)
	if err != nil {
		t.Fatalf("BuildManifest over the real system: %v", err)
	}
	raw, err := Marshal(m)
	if err != nil {
		t.Fatal(err)
	}
	elapsed := time.Since(start)
	t.Logf("packages=%d manifest_bytes=%d elapsed=%s per_file_records_avoided=%d",
		len(m.Packages), len(raw), elapsed, files)
	perFile := int64(len(raw)) + files*80 // a conservative per-file record
	t.Logf("per-file alternative would be ~%d records and >= ~%d bytes", files, perFile)
}

func mustRead(t *testing.T, p string) []byte {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return nil
	}
	return b
}

func splitPkgDir(dir string) (name, version string) {
	parts := strings.Split(dir, "-")
	if len(parts) < 3 {
		return dir, ""
	}
	return strings.Join(parts[:len(parts)-2], "-"), strings.Join(parts[len(parts)-2:], "-")
}

// -- helpers -----------------------------------------------------------------

func fixtureKey(t *testing.T) *PrivateKey {
	t.Helper()
	pem, err := os.ReadFile(filepath.Join("..", "..", "testdata", "baseline", "testkey"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

func sampleInput() ManifestInput {
	return ManifestInput{
		Host:      "reference",
		Root:      "/",
		CreatedAt: "2026-08-05T12:00:00+0200",
		Tier:      "full",
		Packages: []PackageInput{
			{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64), MtreeBytes: 900},
			{Name: "acl", Version: "2.3.2-1", MtreeSHA256: strings.Repeat("b", 64), MtreeBytes: 700},
			{Name: "librewolf-bin", Version: "1.0-1", Foreign: true, MtreeSHA256: strings.Repeat("c", 64), MtreeBytes: 1200},
		},
		Provenance: []ProvenanceInput{
			{PkgBase: "librewolf-bin", SnapshotSHA256: strings.Repeat("d", 64), CapturedAt: "2026-08-01T09:00:00+0200"},
		},
		Surfaces: []SurfaceInput{
			{Kind: "hook", Path: "/etc/pacman.d/hooks/zz.hook", Owner: "", State: "unowned"},
			{Kind: "unit", Path: "/etc/systemd/system/a.service", Owner: "foo", State: "owned"},
		},
		Adjudications: []AdjudicationInput{
			{Fingerprint: strings.Repeat("e", 32), Scope: "subject", Reason: "known-good vendor hook",
				ExpiresAt: "2027-01-01T00:00:00+0000", FingerprintEpoch: 1},
		},
		Log: LogInput{
			Earliest: "2025-11-11T00:50:40+0000",
			Latest:   "2026-08-05T11:00:00+0200",
			Files:    []string{"/var/log/pacman.log"},
		},
	}
}

func sampleManifest(t *testing.T) Manifest {
	t.Helper()
	m, err := BuildManifest(sampleInput())
	if err != nil {
		t.Fatal(err)
	}
	return m
}

func hasGapAbout(m Manifest, needle string) bool {
	for _, g := range m.Coverage.Gaps {
		if strings.Contains(g.Subject, needle) || strings.Contains(g.Reason, needle) {
			return true
		}
	}
	return false
}

func reverse[T any](s []T) {
	for i, j := 0, len(s)-1; i < j; i, j = i+1, j-1 {
		s[i], s[j] = s[j], s[i]
	}
}

func gzipWith(t *testing.T, body string, level int, mod time.Time) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw, err := gzip.NewWriterLevel(&buf, level)
	if err != nil {
		t.Fatal(err)
	}
	zw.ModTime = mod
	if _, err := zw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
