// internal/bundle/bundle_test.go
//
// Format, round-trip and golden-stability tests. The adversarial cases live in
// attack_test.go; these establish that the thing being attacked actually works,
// and that its bytes do not drift.
package bundle

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/baseline"
)

func TestHappyPathVerifiesAndAdvancesTheFloor(t *testing.T) {
	f := newFixture(t)
	st := Verify(f.input(t))

	if st.State != StateActive {
		t.Fatalf("state %v (%s), gaps %+v", st.State, st.Refusal, st.Gaps)
	}
	if !st.State.CoverageComplete() || !st.State.UsableIndicators() {
		t.Fatal("an active bundle must be both complete and usable")
	}
	// The ONLY gap on this path is the one the fixture itself causes: its root
	// keys are throwaway software keys, and a software root key is a real
	// weakening of INV-7 that must be reported rather than tolerated quietly. A
	// release build's hardware root set produces no gap at all here.
	if len(st.Gaps) != 1 || !gapMentions(st, "software keys") {
		t.Fatalf("unexpected gaps: %+v", st.Gaps)
	}
	if st.Coverage.Active != 6 || len(st.Coverage.Inert) != 0 {
		t.Fatalf("coverage %+v", st.Coverage)
	}
	if st.BundleVersion != 5 || st.Digest != DigestOf(f.bRaw) {
		t.Fatalf("version %d digest %s", st.BundleVersion, st.Digest)
	}
	if st.DelegationSerial != 7 || st.DelegationExpiry != fixDelUntil {
		t.Fatalf("delegation %d %s", st.DelegationSerial, st.DelegationExpiry)
	}
	if len(st.RootFingerprints) != 3 || st.RootGeneration != 1 {
		t.Fatalf("roots %v gen %d", st.RootFingerprints, st.RootGeneration)
	}
	if st.Limits == "" {
		t.Fatal("INV-6: a result with no limits statement")
	}
	if !st.FloorAdvances {
		t.Fatal("a first acceptance must advance the floor")
	}
	if st.NextFloor.MinBundleVersion != 5 || st.NextFloor.HeadDigest != st.Digest ||
		st.NextFloor.IndicatorCount != 6 || st.NextFloor.MinDelegationSerial != 7 {
		t.Fatalf("next floor %+v", st.NextFloor)
	}
}

// Re-verifying the bundle already recorded in the floor is the ordinary
// every-run path, and must not read as a fork.
func TestReverifyingTheHeldBundleIsNotAFork(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, DigestOf(f.bRaw), fixBundleIssued)

	st := Verify(in)
	if st.State != StateActive {
		t.Fatalf("state %v: %s", st.State, st.Refusal)
	}
	if st.FloorAdvances {
		t.Fatal("re-verifying the same bundle advanced the floor")
	}
}

// Reordering the members of the document must not change its digest -- that is
// what canonical serialisation buys -- while changing any byte of MEANING must.
func TestReorderingMembersDoesNotChangeTheDigest(t *testing.T) {
	f := newFixture(t)
	reordered := `{"valid_until":"` + fixBundleUntil + `","spec_version":1,"prev_digest":"` +
		fixPrevDigestOne + `","issued_at":"` + fixBundleIssued + `","bundle_version":5,` +
		`"indicators":` + string(mustSubdoc(t, f.bRaw, "indicators")) + `}`

	canon, err := baseline.Canonical([]byte(reordered))
	if err != nil {
		t.Fatal(err)
	}
	if DigestOf(canon) != DigestOf(f.bRaw) {
		t.Fatalf("reordering changed the digest:\n%s\n%s", canon, f.bRaw)
	}
}

// mustSubdoc extracts one top-level member's canonical text. Crude on purpose:
// a real JSON walk here would hide the very byte-level property being tested.
func mustSubdoc(t *testing.T, canon []byte, member string) []byte {
	t.Helper()
	key := `"` + member + `":`
	i := strings.Index(string(canon), key)
	if i < 0 {
		t.Fatalf("no member %q", member)
	}
	start := i + len(key)
	depth := 0
	for j := start; j < len(canon); j++ {
		switch canon[j] {
		case '{', '[':
			depth++
		case '}', ']':
			depth--
			if depth == 0 {
				return canon[start : j+1]
			}
		}
	}
	t.Fatalf("unterminated member %q", member)
	return nil
}

func TestValidateBundleRejects(t *testing.T) {
	base := func() *Bundle {
		f := &fixture{online: newTestSigner(t, 0x10, "online-1")}
		return f.defaultBundle()
	}
	cases := []struct {
		name string
		edit func(*Bundle)
		want error
	}{
		{"wrong spec version", func(b *Bundle) { b.SpecVersion = 2 }, ErrBundle},
		{"zero bundle version", func(b *Bundle) { b.BundleVersion = 0 }, ErrBundle},
		{"expired on publication", func(b *Bundle) { b.ValidUntil = b.IssuedAt }, ErrBundle},
		{"no offset on a timestamp", func(b *Bundle) { b.ValidUntil = "2026-09-01 00:00:00" }, ErrBundle},
		{"short prev digest", func(b *Bundle) { b.PrevDigest = "abc" }, ErrBundle},
		{"uppercase prev digest", func(b *Bundle) { b.PrevDigest = strings.Repeat("AB", 32) }, ErrBundle},
		{"v1 with a predecessor", func(b *Bundle) { b.BundleVersion = 1 }, ErrBundle},
		{"re-genesis at v5", func(b *Bundle) { b.PrevDigest = GenesisPrev }, ErrBundle},
		{"unsorted hosts", func(b *Bundle) {
			b.Indicators.SourceHosts[0], b.Indicators.SourceHosts[1] =
				b.Indicators.SourceHosts[1], b.Indicators.SourceHosts[0]
		}, ErrBundle},
		{"duplicate name", func(b *Bundle) {
			b.Indicators.KnownBadNames = append(b.Indicators.KnownBadNames, b.Indicators.KnownBadNames[0])
		}, ErrBundle},
		{"empty host", func(b *Bundle) { b.Indicators.SourceHosts[0].Host = "  " }, ErrBundle},
		{"unclassified repo", func(b *Bundle) { b.Indicators.RebuildRepos[0].Class = "" }, ErrBundle},
		{"bad indicator digest", func(b *Bundle) { b.Indicators.Digests[0].SHA256 = "zz" }, ErrBundle},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			b := base()
			tc.edit(b)
			if err := ValidateBundle(b); !errors.Is(err, tc.want) {
				t.Fatalf("want %v, got %v", tc.want, err)
			}
		})
	}
}

func TestValidateDelegationRejects(t *testing.T) {
	f := newFixture(t)
	cases := []struct {
		name string
		edit func(*Delegation)
	}{
		{"wrong spec version", func(d *Delegation) { d.SpecVersion = 2 }},
		{"zero serial", func(d *Delegation) { d.Serial = 0 }},
		{"no signing keys and no retirement", func(d *Delegation) { d.SigningKeys = nil }},
		{"key outlives the delegation", func(d *Delegation) { d.SigningKeys[0].NotAfter = "2026-11-01T00:00:00Z" }},
		{"backwards key window", func(d *Delegation) { d.SigningKeys[0].NotAfter = fixKeyNotBefore }},
		{"unparseable key", func(d *Delegation) { d.SigningKeys[0].PublicKey = "ssh-ed25519 zzz" }},
		{"rsa key", func(d *Delegation) { d.SigningKeys[0].PublicKey = "ssh-rsa AAAAB3NzaC1yc2E=" }},
		{"upgrade message without retirement", func(d *Delegation) { d.UpgradeMessage = "upgrade please" }},
		{"delegation lifetime over a year", func(d *Delegation) { d.ValidUntil = "2028-01-01T00:00:00Z" }},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			d := f.defaultDelegation()
			tc.edit(d)
			if err := ValidateDelegation(d); err == nil {
				t.Fatal("accepted")
			}
		})
	}
}

// Two keys named in one delegation must be sorted by fingerprint and distinct,
// so one logical delegation has one canonical spelling.
func TestDelegationWithTwoOverlappingKeys(t *testing.T) {
	f := newFixture(t)
	second := newTestSigner(t, 0x11, "online-2")
	a := SigningKey{PublicKey: f.online.PublicKey().AuthorizedKey(),
		NotBefore: fixKeyNotBefore, NotAfter: fixKeyNotAfter}
	b := SigningKey{PublicKey: second.PublicKey().AuthorizedKey(),
		NotBefore: fixKeyNotBefore, NotAfter: fixKeyNotAfter}
	if f.online.PublicKey().Fingerprint() > second.PublicKey().Fingerprint() {
		a, b = b, a
	}
	d := f.defaultDelegation()
	d.SigningKeys = []SigningKey{a, b}
	if err := ValidateDelegation(d); err != nil {
		t.Fatalf("a sorted two-key delegation must validate: %v", err)
	}

	d.SigningKeys = []SigningKey{b, a}
	if err := ValidateDelegation(d); !errors.Is(err, ErrDelegation) {
		t.Fatalf("an unsorted delegation must be refused, got %v", err)
	}
	d.SigningKeys = []SigningKey{a, a}
	if err := ValidateDelegation(d); !errors.Is(err, ErrDelegation) {
		t.Fatalf("a duplicated key must be refused, got %v", err)
	}
}

func TestNewRootSetRefusesDegenerateShapes(t *testing.T) {
	k := []*baseline.PublicKey{
		newTestSigner(t, 1, "a").PublicKey(),
		newTestSigner(t, 2, "b").PublicKey(),
		newTestSigner(t, 3, "c").PublicKey(),
	}
	if _, err := NewRootSet(1, 1, k); !errors.Is(err, ErrRootSet) {
		t.Fatalf("a threshold of 1 must be refused, got %v", err)
	}
	if _, err := NewRootSet(0, 2, k); !errors.Is(err, ErrRootSet) {
		t.Fatalf("generation 0 must be refused, got %v", err)
	}
	if _, err := NewRootSet(1, 3, k[:2]); !errors.Is(err, ErrRootSet) {
		t.Fatalf("an unsatisfiable threshold must be refused, got %v", err)
	}
	if _, err := NewRootSet(1, 2, []*baseline.PublicKey{k[0], k[0], k[1]}); !errors.Is(err, ErrRootSet) {
		t.Fatalf("a duplicated root key must be refused, got %v", err)
	}
	if _, err := NewRootSet(1, 2, []*baseline.PublicKey{k[0], nil, k[1]}); !errors.Is(err, ErrRootSet) {
		t.Fatalf("a nil root key must be refused, got %v", err)
	}
}

// -- floor -------------------------------------------------------------------

func TestFloorRoundTrip(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenFloor(dir, FloorOptions{CacheDir: t.TempDir(), EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Load(); ok || err != nil {
		t.Fatalf("an absent floor must be (false, nil): ok=%v err=%v", ok, err)
	}

	want := Floor{Schema: FloorSchema, MinBundleVersion: 5, HeadDigest: strings.Repeat("ab", 32),
		MinDelegationSerial: 7, IndicatorCount: 6, RootGeneration: 1,
		AcceptedAt: fixBundleIssued, CheckedAt: fixNow}
	if err := s.Save(want); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Load()
	if err != nil || !ok {
		t.Fatalf("ok=%v err=%v", ok, err)
	}
	if got != want {
		t.Fatalf("round trip:\n got %+v\nwant %+v", got, want)
	}

	fi, err := os.Stat(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Fatalf("floor mode %04o, want 0600", fi.Mode().Perm())
	}
}

// A floor whose contents are not canonical was not written by this tool, and is
// an error rather than "no floor" -- the no-floor state is exactly what an
// attacker wants to manufacture.
func TestNonCanonicalFloorIsAnErrorNotAbsence(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFloor(dir, FloorOptions{EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.Path(), []byte(`{ "schema": 1, "min_bundle_version": 3 }`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, ok, err := s.Load(); err == nil || ok {
		t.Fatalf("want an error, got ok=%v err=%v", ok, err)
	}
}

// -- cache -------------------------------------------------------------------

func TestCacheRoundTripAndAbsence(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "cache")
	c := OpenCache(dir)

	a, err := c.Load()
	if err != nil {
		t.Fatalf("an absent cache must not be an error: %v", err)
	}
	if a.BundleRaw != nil || a.DelegationRaw != nil || len(a.DelegationSigs) != 0 {
		t.Fatalf("absent cache returned %+v", a)
	}

	f := newFixture(t)
	want := Artifacts{
		DelegationRaw: f.delRaw, DelegationSigs: f.delSigs,
		BundleRaw: f.bRaw, BundleSig: f.bSig,
	}
	if err := c.Store(want); err != nil {
		t.Fatal(err)
	}
	got, err := c.Load()
	if err != nil {
		t.Fatal(err)
	}
	if string(got.BundleRaw) != string(want.BundleRaw) ||
		string(got.BundleSig) != string(want.BundleSig) ||
		string(got.DelegationRaw) != string(want.DelegationRaw) ||
		len(got.DelegationSigs) != 2 {
		t.Fatalf("round trip lost something: %d sigs", len(got.DelegationSigs))
	}

	// And the cached bytes verify, which is the property that matters: the
	// cache is untrusted storage and everything in it is re-authenticated.
	in := f.input(t)
	in.DelegationRaw, in.DelegationSigs = got.DelegationRaw, got.DelegationSigs
	in.BundleRaw, in.BundleSig = got.BundleRaw, got.BundleSig
	if st := Verify(in); st.State != StateActive {
		t.Fatalf("state %v: %s", st.State, st.Refusal)
	}
}

// -- golden ------------------------------------------------------------------

// The fixtures are byte-stable: ed25519 is deterministic, canonical
// serialisation is deterministic, and nothing in this package reads a clock. A
// diff here means the wire format moved, which is a decision, not an accident --
// so it must show up as a failing test rather than as a silently different
// document that older verifiers reject.
//
// Regenerate deliberately with AURVET_UPDATE_GOLDEN=1.
func TestGoldenFixturesAreByteStable(t *testing.T) {
	f := newFixture(t)
	dir := filepath.Join("..", "..", "testdata", "bundle")
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"delegation.json", f.delRaw},
		{"delegation.json.sig.1", f.delSigs[0]},
		{"delegation.json.sig.2", f.delSigs[1]},
		{"bundle.json", f.bRaw},
		{"bundle.json.sig", f.bSig},
	} {
		path := filepath.Join(dir, tc.name)
		want, err := os.ReadFile(path)
		if os.Getenv("AURVET_UPDATE_GOLDEN") == "1" {
			if err := os.MkdirAll(dir, 0o755); err != nil {
				t.Fatal(err)
			}
			if err := os.WriteFile(path, tc.data, 0o644); err != nil {
				t.Fatal(err)
			}
			continue
		}
		if err != nil {
			t.Fatalf("%s: %v (regenerate with AURVET_UPDATE_GOLDEN=1)", tc.name, err)
		}
		if string(want) != string(tc.data) {
			t.Fatalf("%s drifted:\n want %q\n  got %q", tc.name, want, tc.data)
		}
	}

	// The golden files must still verify end to end, not merely match.
	raw, err := os.ReadFile(filepath.Join(dir, "bundle.json"))
	if err != nil {
		t.Fatal(err)
	}
	sig, err := os.ReadFile(filepath.Join(dir, "bundle.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()}); err != nil {
		t.Fatalf("the golden bundle does not verify: %v", err)
	}
}

func TestStateStrings(t *testing.T) {
	for st, want := range map[State]string{
		StateUnavailable: "unavailable", StateRefused: "refused",
		StateExpired: "expired", StateActive: "active",
	} {
		if st.String() != want {
			t.Fatalf("%d -> %q, want %q", st, st.String(), want)
		}
	}
	if StateRefused.UsableIndicators() || StateUnavailable.UsableIndicators() {
		t.Fatal("a refused or absent bundle must not be matched against")
	}
	if StateExpired.CoverageComplete() || StateRefused.CoverageComplete() ||
		StateUnavailable.CoverageComplete() {
		t.Fatal("only an active bundle is complete coverage")
	}
}
