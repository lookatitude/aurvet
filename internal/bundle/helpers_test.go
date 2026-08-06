package bundle

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// No production key material exists anywhere in this repository, and none is
// created here. Every key below is derived from a fixed one-byte seed, so it is
// deterministic, reproducible by anyone reading the test, and obviously not a
// real key to anyone who glances at it. Generating a release root key is a human
// action performed on hardware; see docs/key-compromise-runbook.md.

// testSigner implements baseline.Signer over a raw ed25519 key. It exists so the
// whole verification path can be exercised without an OpenSSH private key file
// and without ssh-agent.
type testSigner struct {
	priv ed25519.PrivateKey
	pub  *baseline.PublicKey
}

func (s *testSigner) PublicKey() *baseline.PublicKey { return s.pub }

func (s *testSigner) SignSSH(data []byte) ([]byte, error) {
	var b []byte
	b = appendSSHString(b, []byte(baseline.AlgoEd25519))
	b = appendSSHString(b, ed25519.Sign(s.priv, data))
	return b, nil
}

func appendSSHString(dst, s []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	return append(append(dst, n[:]...), s...)
}

func newTestSigner(t *testing.T, seed byte, comment string) *testSigner {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	blob := appendSSHString(nil, []byte(baseline.AlgoEd25519))
	blob = appendSSHString(blob, priv.Public().(ed25519.PublicKey))
	line := string(baseline.AlgoEd25519) + " " + base64.StdEncoding.EncodeToString(blob) + " " + comment
	pub, err := baseline.ParsePublicKey([]byte(line))
	if err != nil {
		t.Fatalf("parse throwaway public key: %v", err)
	}
	return &testSigner{priv: priv, pub: pub}
}

// skPublicKeyLine builds an sk-ssh-ed25519 authorized_keys line for a throwaway
// key. Only the public half is needed: parseRootSet checks the algorithm, and
// nothing in the hardware-backing test ever signs.
func skPublicKeyLine(t *testing.T, seed byte) string {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	blob := appendSSHString(nil, []byte(baseline.AlgoSKEd25519))
	blob = appendSSHString(blob, priv.Public().(ed25519.PublicKey))
	blob = appendSSHString(blob, []byte("ssh:aurvet-test"))
	return string(baseline.AlgoSKEd25519) + " " + base64.StdEncoding.EncodeToString(blob) + " throwaway"
}

// -- the reference instants --------------------------------------------------
//
// Every timestamp is a constant. Nothing in this package reads a clock, so a
// fixture signed today verifies identically in ten years, and the golden files
// are byte-stable.
const (
	fixNow           = "2026-08-06T12:00:00+02:00"
	fixDelIssued     = "2026-07-01T00:00:00Z"
	fixDelUntil      = "2026-10-01T00:00:00Z"
	fixKeyNotBefore  = "2026-07-01T00:00:00Z"
	fixKeyNotAfter   = "2026-09-01T00:00:00Z"
	fixBundleIssued  = "2026-08-01T00:00:00Z"
	fixBundleUntil   = "2026-09-01T00:00:00Z"
	fixPrevDigestOne = "1111111111111111111111111111111111111111111111111111111111111111"
)

func mustStamp(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := baseline.ParseStamp(s)
	if err != nil {
		t.Fatalf("parse %q: %v", s, err)
	}
	return ts
}

// -- fixture -----------------------------------------------------------------

type fixture struct {
	roots  []*testSigner
	set    RootSet
	online *testSigner

	del     *Delegation
	delRaw  []byte
	delSigs [][]byte

	bundle *Bundle
	bRaw   []byte
	bSig   []byte
}

// newFixture builds a complete, genuinely signed 2-of-3 trust path.
func newFixture(t *testing.T) *fixture {
	t.Helper()
	f := &fixture{
		roots: []*testSigner{
			newTestSigner(t, 0x01, "root-a"),
			newTestSigner(t, 0x02, "root-b"),
			newTestSigner(t, 0x03, "root-c"),
		},
		online: newTestSigner(t, 0x10, "online-1"),
	}
	set, err := NewRootSet(1, RootThreshold, []*baseline.PublicKey{
		f.roots[0].PublicKey(), f.roots[1].PublicKey(), f.roots[2].PublicKey(),
	})
	if err != nil {
		t.Fatal(err)
	}
	f.set = set
	f.setDelegation(t, f.defaultDelegation(), 0, 1)
	f.setBundle(t, f.defaultBundle(), f.online)
	return f
}

func (f *fixture) defaultDelegation() *Delegation {
	return &Delegation{
		SpecVersion:    SpecVersion,
		RootGeneration: 1,
		Serial:         7,
		IssuedAt:       fixDelIssued,
		ValidUntil:     fixDelUntil,
		SigningKeys: []SigningKey{{
			PublicKey: f.online.PublicKey().AuthorizedKey(),
			NotBefore: fixKeyNotBefore,
			NotAfter:  fixKeyNotAfter,
		}},
	}
}

func (f *fixture) defaultBundle() *Bundle {
	return &Bundle{
		SpecVersion:   SpecVersion,
		BundleVersion: 5,
		IssuedAt:      fixBundleIssued,
		ValidUntil:    fixBundleUntil,
		PrevDigest:    fixPrevDigestOne,
		Indicators: Indicators{
			SourceHosts: []HostIndicator{
				{Host: "0x0.st", Match: MatchExact, Class: HostPaste, Note: "paste site"},
				{Host: "bit.ly", Match: MatchDomainSuffix, Class: HostShortener, Note: "shortener"},
			},
			KnownBadNames: []NameIndicator{
				{Name: "librewolf-fix-bin", Note: "removed from the AUR in 2025"},
			},
			RebuildRepos: []RepoIndicator{
				{Name: "chaotic-aur", Host: "cdn-mirror.chaotic.cx", Class: RepoKnownRebuild,
					Note: "signs AUR-authored packages, so pgp validation means nothing here"},
			},
			Digests: []DigestIndicator{
				{SHA256: "aa" + "00000000000000000000000000000000000000000000000000000000000000", Note: "example"},
			},
			Thresholds: []Threshold{
				{Name: "max_pkgbuild_bytes", Value: 262144},
			},
		},
	}
}

// setDelegation marshals, signs with the named root indices, and records the
// result. The signatures are real: nothing in this package is exercised against
// a stub.
func (f *fixture) setDelegation(t *testing.T, d *Delegation, signers ...int) {
	t.Helper()
	raw, err := baseline.Marshal(d)
	if err != nil {
		t.Fatal(err)
	}
	var sigs [][]byte
	for _, i := range signers {
		sig, err := baseline.Sign(f.roots[i], baseline.NamespaceDelegation, raw)
		if err != nil {
			t.Fatal(err)
		}
		sigs = append(sigs, sig)
	}
	f.del, f.delRaw, f.delSigs = d, raw, sigs
}

func (f *fixture) setBundle(t *testing.T, b *Bundle, signer *testSigner) {
	t.Helper()
	raw, err := baseline.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := baseline.Sign(signer, baseline.NamespaceBundle, raw)
	if err != nil {
		t.Fatal(err)
	}
	f.bundle, f.bRaw, f.bSig = b, raw, sig
}

// signRawBundle signs arbitrary bytes as a bundle. Used by the tests that need a
// document this build's own encoder would refuse to produce.
func (f *fixture) signRawBundle(t *testing.T, raw []byte, signer *testSigner) []byte {
	t.Helper()
	sig, err := baseline.Sign(signer, baseline.NamespaceBundle, raw)
	if err != nil {
		t.Fatal(err)
	}
	return sig
}

func (f *fixture) input(t *testing.T) Input {
	t.Helper()
	return Input{
		Roots:          f.set,
		DelegationRaw:  f.delRaw,
		DelegationSigs: f.delSigs,
		BundleRaw:      f.bRaw,
		BundleSig:      f.bSig,
		Now:            mustStamp(t, fixNow),
	}
}

// floorAt is a floor pinned to a version and the digest of the fixture bundle.
func (f *fixture) floorAt(version int64, digest string, accepted string) Floor {
	return Floor{
		Schema:              FloorSchema,
		MinBundleVersion:    version,
		HeadDigest:          digest,
		MinDelegationSerial: 7,
		IndicatorCount:      6,
		RootGeneration:      1,
		AcceptedAt:          accepted,
		CheckedAt:           accepted,
	}
}
