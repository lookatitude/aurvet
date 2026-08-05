// internal/chain/fixture_test.go
//
// A committed chain, pinned as a golden. Everything in the signing path is
// deterministic -- ed25519 is, canonical serialisation is, and no function here
// reads a clock -- so this file must be reproduced byte for byte. A failure
// means the wire format moved, which means every chain already written stopped
// verifying: that is a release-blocking event, not a fixture to regenerate
// without thinking.
//
// Regenerate deliberately with AURVET_UPDATE_FIXTURES=1, and only after
// deciding that breaking existing chains is intended.
package chain

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lookatitude/aurvet/internal/baseline"
)

const fixtureDir = "../../testdata/chain"

func TestGoldenChainIsReproducedByteForByte(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 3)
	want := encodeChainFile(recs)

	path := filepath.Join(fixtureDir, "golden.chain")
	if os.Getenv("AURVET_UPDATE_FIXTURES") != "" {
		if err := os.WriteFile(path, want, 0o644); err != nil {
			t.Fatal(err)
		}
		t.Log("fixture rewritten")
	}
	got, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	if string(got) != string(want) {
		t.Fatal("the chain wire format drifted: every chain already written would stop verifying")
	}

	// And it must still verify from bytes, not only from the records in memory.
	parsed, err := parseChainFile(got, trust(k))
	if err != nil {
		t.Fatalf("the golden chain does not load: %v", err)
	}
	if _, err := Verify(parsed, VerifyOptions{Trusted: trust(k)}); err != nil {
		t.Fatalf("the golden chain does not verify: %v", err)
	}
	anchor := HeadAnchor(parsed)
	if _, err := Verify(parsed, VerifyOptions{Trusted: trust(k), Anchor: &anchor}); err != nil {
		t.Fatalf("the golden chain does not verify against its own anchor: %v", err)
	}

	// The truncated fixture is the same chain with its last record cut off: it
	// loads, it verifies, and only the anchor exposes it.
	short := encodeChainFile(parsed[:2])
	shortPath := filepath.Join(fixtureDir, "golden-truncated.chain")
	if os.Getenv("AURVET_UPDATE_FIXTURES") != "" {
		if err := os.WriteFile(shortPath, short, 0o644); err != nil {
			t.Fatal(err)
		}
	}
	shortGot, err := os.ReadFile(shortPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(shortGot) != string(short) {
		t.Fatal("the truncated fixture is not a prefix of the golden chain")
	}
	shortParsed, err := parseChainFile(shortGot, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(shortParsed, VerifyOptions{Trusted: trust(k)}); err != nil {
		t.Fatalf("the truncated chain must verify without an anchor: %v", err)
	}
	if _, err := Verify(shortParsed, VerifyOptions{Trusted: trust(k), Anchor: &anchor}); !errors.Is(err, ErrTruncated) {
		t.Fatalf("want ErrTruncated against the full chain's anchor, got %v", err)
	}
}

// The signatures in the fixture were made by this package; the fixture in
// testdata/baseline was made by OpenSSH and is what pins interoperability.
// This one pins the CHAIN framing on top of it, and the namespace it uses.
func TestGoldenChainUsesTheChainEntryNamespace(t *testing.T) {
	k := testKey(t)
	recs := buildChain(t, k, 1)
	ns, err := baseline.SignatureNamespace(recs[0].Signature())
	if err != nil {
		t.Fatal(err)
	}
	if ns != baseline.NamespaceChainEntry {
		t.Fatalf("chain entries are signed under %q, want %q", ns, baseline.NamespaceChainEntry)
	}
}
