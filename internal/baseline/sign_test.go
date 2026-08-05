// internal/baseline/sign_test.go
//
// Attack tests first, happy path after. Every one of these is a way a signature
// could be made to verify when it should not: a flipped byte, a replayed
// signature from another context, a substituted public key, an empty trust set.

package baseline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/binary"
	"errors"
	"math/rand"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testSigner(t *testing.T) *PrivateKey {
	t.Helper()
	_, priv, _ := genKey(t, "")
	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// -- attack: any single-byte change to the message ---------------------------

// The property the roadmap names: sign, flip ANY single byte, verify must fail.
// Iterated over every byte position of every document in a generated corpus,
// because a single hand-picked example proves only that one byte was covered.
func TestVerifyFailsAfterFlippingAnySingleMessageByte(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}
	rng := rand.New(rand.NewSource(3))

	for doc := 0; doc < 12; doc++ {
		msg, err := Marshal(randomDoc(rng, 0))
		if err != nil {
			t.Fatal(err)
		}
		sig, err := Sign(k, NamespaceChainEntry, msg)
		if err != nil {
			t.Fatal(err)
		}
		if _, err := Verify(sig, NamespaceChainEntry, msg, trust); err != nil {
			t.Fatalf("valid signature refused: %v", err)
		}
		for pos := range msg {
			for _, bit := range []byte{0x01, 0x40} {
				m := append([]byte(nil), msg...)
				m[pos] ^= bit
				if _, err := Verify(sig, NamespaceChainEntry, m, trust); err == nil {
					t.Fatalf("verified after flipping message byte %d of %q", pos, msg)
				}
			}
		}
	}
}

// -- attack: any single-byte change to the signature -------------------------

func TestVerifyFailsAfterFlippingAnySingleSignatureByte(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}
	msg := []byte(`{"a":1}`)
	sig, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := unarmor(sig)
	if err != nil {
		t.Fatal(err)
	}
	for pos := range body {
		m := append([]byte(nil), body...)
		m[pos] ^= 0x01
		if _, err := Verify(armor(m), NamespaceChainEntry, msg, trust); err == nil {
			t.Fatalf("verified after flipping signature byte %d", pos)
		}
	}
}

// -- attack: replay into another context -------------------------------------

// Without domain separation a signature over bare canonical bytes can be lifted
// out of one document type and replayed as another whenever the two can produce
// identical bytes. The SSHSIG namespace is the context string, and it is signed,
// so verifying under the wrong namespace must fail.
func TestSignatureDoesNotReplayAcrossNamespaces(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}
	msg := []byte(`{"kind":"ambiguous"}`)

	sig, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig, NamespaceManifest, msg, trust); !errors.Is(err, ErrSignature) {
		t.Fatalf("a chain-entry signature verified as a manifest: %v", err)
	}
	if _, err := Verify(sig, Namespace("chain-entry.aurvet.dev "), msg, trust); err == nil {
		t.Fatal("a near-miss namespace verified")
	}
	if _, err := Sign(k, Namespace(""), msg); err == nil {
		t.Fatal("an empty namespace must be refused: it is the absence of domain separation")
	}
}

// -- attack: substituted or absent trust -------------------------------------

func TestVerifyRefusesAnEmptyTrustSet(t *testing.T) {
	k := testSigner(t)
	msg := []byte(`{"a":1}`)
	sig, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	// "No keys configured" must never mean "any key will do". This is the one
	// failure mode that turns the whole chain into decoration.
	if _, err := Verify(sig, NamespaceChainEntry, msg, nil); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature for an empty trust set, got %v", err)
	}
}

func TestVerifyRefusesASignatureFromAnUntrustedKey(t *testing.T) {
	signer := testSigner(t)
	other := testSigner(t)
	msg := []byte(`{"a":1}`)
	sig, err := Sign(signer, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig, NamespaceChainEntry, msg, []*PublicKey{other.PublicKey()}); !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature, got %v", err)
	}
}

// A detached SSHSIG states its own public key. If a verifier trusted that field
// it would verify anything, so swapping in an attacker key -- even a trusted one
// -- must not produce a pass.
func TestVerifyRefusesASubstitutedEmbeddedKey(t *testing.T) {
	signer := testSigner(t)
	attacker := testSigner(t)
	msg := []byte(`{"a":1}`)
	sig, err := Sign(signer, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := unarmor(sig)
	if err != nil {
		t.Fatal(err)
	}
	swapped := bytes.Replace(body, signer.PublicKey().blob, attacker.PublicKey().blob, 1)
	if bytes.Equal(swapped, body) {
		t.Fatal("could not find the embedded public key to swap")
	}
	for _, trust := range [][]*PublicKey{
		{attacker.PublicKey()},
		{signer.PublicKey()},
		{signer.PublicKey(), attacker.PublicKey()},
	} {
		if _, err := Verify(armor(swapped), NamespaceChainEntry, msg, trust); !errors.Is(err, ErrSignature) {
			t.Fatalf("a key-swapped signature verified: %v", err)
		}
	}
}

// -- attack: malformed signature containers ----------------------------------

func TestVerifyRefusesMalformedSignatures(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}
	msg := []byte(`{"a":1}`)
	sig, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := unarmor(sig)
	if err != nil {
		t.Fatal(err)
	}

	cases := map[string][]byte{
		"empty":               nil,
		"not armoured":        []byte("hello"),
		"wrong armour type":   []byte("-----BEGIN CERTIFICATE-----\nAAAA\n-----END CERTIFICATE-----\n"),
		"truncated body":      armor(body[:len(body)/2]),
		"missing magic":       armor(body[6:]),
		"trailing bytes":      armor(append(append([]byte(nil), body...), 0x00)),
		"empty body":          armor(nil),
		"two documents":       append(append([]byte(nil), sig...), sig...),
		"rsa-shaped sig blob": armor(withSignatureBlob(t, body, "ssh-rsa", bytes.Repeat([]byte{1}, 64))),
		"short ed25519 sig":   armor(withSignatureBlob(t, body, string(AlgoEd25519), bytes.Repeat([]byte{1}, 63))),
	}
	for name, in := range cases {
		if _, err := Verify(in, NamespaceChainEntry, msg, trust); err == nil {
			t.Errorf("%s: verified", name)
		} else if !errors.Is(err, ErrSignature) {
			t.Errorf("%s: unexpected error class: %v", name, err)
		}
	}
}

// withSignatureBlob rebuilds a signature container with a different inner
// signature blob, leaving everything else intact.
func withSignatureBlob(t *testing.T, body []byte, algo string, sig []byte) []byte {
	t.Helper()
	parsed, err := parseSignature(body)
	if err != nil {
		t.Fatal(err)
	}
	var inner sshWriter
	inner.writeString([]byte(algo))
	inner.writeString(sig)

	var w sshWriter
	w.writeRaw([]byte(sshsigMagic))
	w.writeUint32(1)
	w.writeString(parsed.keyBlob)
	w.writeString([]byte(parsed.namespace))
	w.writeString(nil)
	w.writeString([]byte(parsed.hashAlgo))
	w.writeString(inner.bytes())
	return w.bytes()
}

// A downgrade to sha256 must not be accepted just because OpenSSH allows it:
// one hash means one thing to verify.
func TestVerifyRefusesAHashAlgorithmDowngrade(t *testing.T) {
	k := testSigner(t)
	msg := []byte(`{"a":1}`)
	sig, err := signWithHash(k, NamespaceChainEntry, msg, "sha256")
	if err != nil {
		t.Fatal(err)
	}
	_, err = Verify(sig, NamespaceChainEntry, msg, []*PublicKey{k.PublicKey()})
	if !errors.Is(err, ErrSignature) {
		t.Fatalf("want ErrSignature for a sha256 signature, got %v", err)
	}
	if !strings.Contains(err.Error(), "sha512") {
		t.Fatalf("refusal does not say what is required: %v", err)
	}
}

// -- ordering: authenticate before parsing -----------------------------------

// VerifyCanonical must check the signature over the RAW bytes before it hands
// them to a parser. Asserted by shape: bytes that are neither validly signed nor
// parseable must fail as a SIGNATURE error, and only validly signed bytes are
// ever reported as non-canonical.
func TestVerifyCanonicalAuthenticatesBeforeParsing(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}

	junk := []byte(`{"a":`) // signed, but not parseable
	sig, err := Sign(k, NamespaceChainEntry, junk)
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCanonical(sig, NamespaceChainEntry, junk, trust); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("validly signed junk: want ErrNotCanonical, got %v", err)
	}
	// Same junk, signature over something else: the signature failure must win,
	// which is only possible if the signature was checked first.
	other, err := Sign(k, NamespaceChainEntry, []byte(`{"a":1}`))
	if err != nil {
		t.Fatal(err)
	}
	if _, _, err := VerifyCanonical(other, NamespaceChainEntry, junk, trust); !errors.Is(err, ErrSignature) {
		t.Fatalf("unsigned junk: want ErrSignature, got %v", err)
	}
}

// A signature over well-formed but NON-canonical bytes is refused. Accepting one
// would mean the digest that goes into the chain is not reproducible from the
// document it names.
func TestVerifyCanonicalRefusesNonCanonicalSignedBytes(t *testing.T) {
	k := testSigner(t)
	trust := []*PublicKey{k.PublicKey()}
	sloppy := []byte(`{"b":1,"a":2}`) // valid JSON, keys unsorted
	sig, err := Sign(k, NamespaceManifest, sloppy)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig, NamespaceManifest, sloppy, trust); err != nil {
		t.Fatalf("the raw signature itself should be valid: %v", err)
	}
	_, _, err = VerifyCanonical(sig, NamespaceManifest, sloppy, trust)
	if !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("want ErrNotCanonical, got %v", err)
	}
}

func TestVerifyCanonicalReturnsTheCanonicalBytesAndSigner(t *testing.T) {
	k := testSigner(t)
	doc := map[string]any{"kind": "manifest", "n": 3}
	msg, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	sig, err := Sign(k, NamespaceManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	canon, signer, err := VerifyCanonical(sig, NamespaceManifest, msg, []*PublicKey{k.PublicKey()})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(canon, msg) {
		t.Fatalf("canonical bytes differ:\n %s\n %s", canon, msg)
	}
	if !signer.Equal(k.PublicKey()) {
		t.Fatal("wrong signer reported")
	}
}

// SignatureKey exposes the CLAIMED signer for diagnostics. It must be documented
// and treated as unauthenticated; the test pins that it is only a claim.
func TestSignatureKeyIsOnlyAClaim(t *testing.T) {
	signer := testSigner(t)
	attacker := testSigner(t)
	msg := []byte(`{"a":1}`)
	sig, err := Sign(signer, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	body, err := unarmor(sig)
	if err != nil {
		t.Fatal(err)
	}
	swapped := armor(bytes.Replace(body, signer.PublicKey().blob, attacker.PublicKey().blob, 1))
	claimed, err := SignatureKey(swapped)
	if err != nil {
		t.Fatal(err)
	}
	if !claimed.Equal(attacker.PublicKey()) {
		t.Fatal("SignatureKey should report the claim as written")
	}
	if _, err := Verify(swapped, NamespaceChainEntry, msg, []*PublicKey{attacker.PublicKey()}); err == nil {
		t.Fatal("the claim must not be enough to verify")
	}
}

// -- determinism -------------------------------------------------------------

// ed25519 is deterministic and nothing here reads a clock (INV-4), so signing
// the same bytes twice must produce identical output. A signature that varies
// run to run cannot be reproduced by an auditor.
func TestSignIsDeterministic(t *testing.T) {
	k := testSigner(t)
	msg := []byte(`{"a":1}`)
	a, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	b, err := Sign(k, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(a, b) {
		t.Fatal("signing is not deterministic")
	}
}

// -- interop with the real ssh-keygen ---------------------------------------

// ssh-keygen -Y sign produces a detached SSHSIG. If this package can verify it,
// the format claim is real rather than aspirational.
func TestVerifiesASignatureMadeBySSHKeygen(t *testing.T) {
	dir, priv, pub := genKey(t, "")
	msgPath := filepath.Join(dir, "msg")
	msg := []byte(`{"a":1,"b":"x"}`)
	if err := os.WriteFile(msgPath, msg, 0o600); err != nil {
		t.Fatal(err)
	}
	out, err := exec.Command("ssh-keygen", "-Y", "sign", "-f", priv,
		"-n", string(NamespaceChainEntry), msgPath).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen -Y sign: %v\n%s", err, out)
	}
	sig, err := os.ReadFile(msgPath + ".sig")
	if err != nil {
		t.Fatal(err)
	}
	line, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(sig, NamespaceChainEntry, msg, []*PublicKey{k}); err != nil {
		t.Fatalf("ssh-keygen's signature was refused: %v", err)
	}
	if _, err := Verify(sig, NamespaceManifest, msg, []*PublicKey{k}); err == nil {
		t.Fatal("namespace separation does not hold against ssh-keygen's output")
	}
}

// ...and the other direction: ssh-keygen must accept what this package emits.
func TestSSHKeygenVerifiesOurSignature(t *testing.T) {
	dir, priv, pub := genKey(t, "")
	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	msg := []byte(`{"a":1,"b":"x"}`)
	sig, err := Sign(k, NamespaceManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	sigPath := filepath.Join(dir, "ours.sig")
	if err := os.WriteFile(sigPath, sig, 0o600); err != nil {
		t.Fatal(err)
	}

	cmd := exec.Command("ssh-keygen", "-Y", "check-novalidate",
		"-n", string(NamespaceManifest), "-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y check-novalidate rejected our signature: %v\n%s", err, out)
	}

	// And with identity validation, which is how a human would check a chain
	// entry by hand from the runbook.
	pubLine, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	allowed := filepath.Join(dir, "allowed_signers")
	if err := os.WriteFile(allowed, []byte("auditor@example "+string(pubLine)), 0o600); err != nil {
		t.Fatal(err)
	}
	cmd = exec.Command("ssh-keygen", "-Y", "verify", "-f", allowed,
		"-I", "auditor@example", "-n", string(NamespaceManifest), "-s", sigPath)
	cmd.Stdin = bytes.NewReader(msg)
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen -Y verify rejected our signature: %v\n%s", err, out)
	}

	// A tampered message must be rejected by ssh-keygen too, so the test above
	// is not passing for some unrelated reason.
	cmd = exec.Command("ssh-keygen", "-Y", "check-novalidate",
		"-n", string(NamespaceManifest), "-s", sigPath)
	cmd.Stdin = bytes.NewReader([]byte(`{"a":2,"b":"x"}`))
	if out, err := cmd.CombinedOutput(); err == nil {
		t.Fatalf("ssh-keygen accepted a tampered message:\n%s", out)
	}
}

// -- the agent path ---------------------------------------------------------

// The agent is the path that makes the hardware story real, so it is exercised
// against a real ssh-agent. A FIDO2 token could not be exercised here (none
// available); the receipt says so.
func TestAgentSignerAgainstARealSSHAgent(t *testing.T) {
	for _, bin := range []string{"ssh-agent", "ssh-add", "ssh-keygen"} {
		if _, err := exec.LookPath(bin); err != nil {
			t.Skipf("%s not available", bin)
		}
	}
	dir, priv, _ := genKey(t, "")
	sock := filepath.Join(t.TempDir(), "agent.sock")

	agentCmd := exec.Command("ssh-agent", "-D", "-a", sock)
	if err := agentCmd.Start(); err != nil {
		t.Fatalf("ssh-agent: %v", err)
	}
	t.Cleanup(func() {
		_ = agentCmd.Process.Kill()
		_, _ = agentCmd.Process.Wait()
	})
	waitForSocket(t, sock)

	add := exec.Command("ssh-add", priv)
	add.Env = append(os.Environ(), "SSH_AUTH_SOCK="+sock, "DISPLAY=", "SSH_ASKPASS=")
	if out, err := add.CombinedOutput(); err != nil {
		t.Fatalf("ssh-add: %v\n%s", err, out)
	}

	agent, err := DialAgent(sock)
	if err != nil {
		t.Fatalf("DialAgent: %v", err)
	}
	defer agent.Close()

	keys, err := agent.Keys()
	if err != nil {
		t.Fatalf("Keys: %v", err)
	}
	if len(keys) != 1 {
		t.Fatalf("agent holds %d usable keys, want 1", len(keys))
	}
	msg := []byte(`{"via":"agent"}`)
	sig, err := Sign(agent.Signer(keys[0]), NamespaceChainEntry, msg)
	if err != nil {
		t.Fatalf("Sign via agent: %v", err)
	}
	if _, err := Verify(sig, NamespaceChainEntry, msg, keys); err != nil {
		t.Fatalf("agent signature refused: %v", err)
	}
	// Cross-check the agent's output with the file signer's: same key, same
	// deterministic algorithm, so the bytes must match.
	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	fileKey, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatal(err)
	}
	fileSig, err := Sign(fileKey, NamespaceChainEntry, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(sig, fileSig) {
		t.Fatal("agent and file signers disagree on the same key and message")
	}
	_ = dir
}

func waitForSocket(t *testing.T, path string) {
	t.Helper()
	for i := 0; i < 200; i++ {
		if _, err := os.Stat(path); err == nil {
			return
		}
		sleepMillis(10)
	}
	t.Fatalf("ssh-agent never created %s", path)
}

// -- sk (FIDO2) verification -------------------------------------------------

// No FIDO2 token was available, so this constructs an sk signature with a
// software key and the sk framing to exercise the VERIFICATION path. It proves
// the framing is implemented; it does NOT prove interoperability with real
// hardware, and the receipt says so.
func TestSKSignatureVerificationFraming(t *testing.T) {
	pub, priv, err := ed25519.GenerateKey(rand.New(rand.NewSource(21)))
	if err != nil {
		t.Fatal(err)
	}
	const app = "ssh:aurvet"
	var blob sshWriter
	blob.writeString([]byte(AlgoSKEd25519))
	blob.writeString(pub)
	blob.writeString([]byte(app))
	key, err := ParsePublicKeyBlob(blob.bytes())
	if err != nil {
		t.Fatal(err)
	}

	msg := []byte(`{"sk":true}`)
	signed := sshsigBlob(NamespaceChainEntry, "sha512", msg)
	sig, counter, flags := skSign(priv, app, signed, 7, 0x01)

	container := skContainer(key, NamespaceChainEntry, sig, flags, counter)
	if _, err := Verify(container, NamespaceChainEntry, msg, []*PublicKey{key}); err != nil {
		t.Fatalf("sk signature refused: %v", err)
	}
	// The counter is inside the signed data, so bumping it must break it: an
	// attacker replaying an old touch with a new counter must not verify.
	bad := skContainer(key, NamespaceChainEntry, sig, flags, counter+1)
	if _, err := Verify(bad, NamespaceChainEntry, msg, []*PublicKey{key}); err == nil {
		t.Fatal("sk counter is not covered by the signature")
	}
	// A different application string is a different key, so it must fail.
	var other sshWriter
	other.writeString([]byte(AlgoSKEd25519))
	other.writeString(pub)
	other.writeString([]byte("ssh:other"))
	otherKey, err := ParsePublicKeyBlob(other.bytes())
	if err != nil {
		t.Fatal(err)
	}
	if _, err := Verify(skContainer(otherKey, NamespaceChainEntry, sig, flags, counter),
		NamespaceChainEntry, msg, []*PublicKey{otherKey}); err == nil {
		t.Fatal("sk application string is not bound into the signature")
	}
}

// -- test helpers -----------------------------------------------------------

func sleepMillis(n int) { time.Sleep(time.Duration(n) * time.Millisecond) }

// skSign fakes what a FIDO2 token does, with a software key, so the sk framing
// can be exercised at all. It is not a claim about hardware.
func skSign(priv ed25519.PrivateKey, app string, signedBlob []byte, counter uint32, flags byte) ([]byte, uint32, byte) {
	appHash := sha256.Sum256([]byte(app))
	msgHash := sha256.Sum256(signedBlob)
	var buf bytes.Buffer
	buf.Write(appHash[:])
	buf.WriteByte(flags)
	var ctr [4]byte
	binary.BigEndian.PutUint32(ctr[:], counter)
	buf.Write(ctr[:])
	buf.Write(msgHash[:])
	return ed25519.Sign(priv, buf.Bytes()), counter, flags
}

func skContainer(key *PublicKey, ns Namespace, sig []byte, flags byte, counter uint32) []byte {
	var inner sshWriter
	inner.writeString([]byte(AlgoSKEd25519))
	inner.writeString(sig)
	inner.writeByte(flags)
	inner.writeUint32(counter)

	var w sshWriter
	w.writeRaw([]byte(sshsigMagic))
	w.writeUint32(sshsigVersion)
	w.writeString(key.blob)
	w.writeString([]byte(ns))
	w.writeString(nil)
	w.writeString([]byte(sshsigHashAlgo))
	w.writeString(inner.bytes())
	return armor(w.bytes())
}

// -- committed fixtures -----------------------------------------------------

// The fixture signature was produced by OpenSSH, not by this package, and is
// pinned as a golden: ed25519 is deterministic and nothing in the signing path
// reads a clock, so Sign must reproduce it byte for byte. A failure here means
// the wire format moved and every signature already in a chain stopped
// verifying. It also keeps coverage on a machine with no ssh-keygen, where the
// interop tests skip.
//
// The key is a throwaway committed in the clear; see testdata/baseline/README.md
// for why no production key exists anywhere in this tree.
func TestFixtureSignatureIsReproducedByteForByte(t *testing.T) {
	const dir = "../../testdata/baseline"
	msg, err := os.ReadFile(filepath.Join(dir, "message.json"))
	if err != nil {
		t.Fatal(err)
	}
	wantSig, err := os.ReadFile(filepath.Join(dir, "message.json.sig"))
	if err != nil {
		t.Fatal(err)
	}
	privPEM, err := os.ReadFile(filepath.Join(dir, "testkey"))
	if err != nil {
		t.Fatal(err)
	}
	pubLine, err := os.ReadFile(filepath.Join(dir, "testkey.pub"))
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(privPEM)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	pub, err := ParsePublicKey(pubLine)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !k.PublicKey().Equal(pub) {
		t.Fatal("fixture key halves disagree")
	}
	// The fixture bytes must already be canonical, or the fixture is teaching the
	// wrong lesson.
	if canon, err := Canonical(msg); err != nil || !bytes.Equal(canon, msg) {
		t.Fatalf("fixture message is not canonical: %v", err)
	}
	if _, _, err := VerifyCanonical(wantSig, NamespaceManifest, msg, []*PublicKey{pub}); err != nil {
		t.Fatalf("OpenSSH's fixture signature was refused: %v", err)
	}
	got, err := Sign(k, NamespaceManifest, msg)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(bytes.TrimSpace(got), bytes.TrimSpace(wantSig)) {
		t.Fatalf("signature bytes drifted from the golden:\n got %s\nwant %s", got, wantSig)
	}
}
