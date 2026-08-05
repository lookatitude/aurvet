// internal/baseline/sign.go
//
// Detached ed25519 signatures over canonical JSON.
//
// # Detached, and deliberately not git commit signing
//
// Signing the git commit that carries a chain entry would couple this tool to
// the user's git configuration -- their signing key, their gpg.format, their
// commit hooks -- and would make the chain's trust depend on a program this tool
// does not control. A detached signature can also be stored, copied and verified
// independently of the document it covers, which is what the chain needs: an
// entry can be re-signed, replicated or audited without rewriting history.
//
// # The wire format is OpenSSH's SSHSIG, not one invented here
//
// Same reasoning as keys.go. Using SSHSIG means `ssh-keygen -Y verify` can
// check a chain entry by hand, from a runbook, with no aurvet binary present --
// which matters exactly when the machine that produced the entry is the machine
// under suspicion. Both directions are exercised against the real ssh-keygen in
// sign_test.go.
//
// # Domain separation
//
// SSHSIG carries a signed `namespace` string, and that is the context prefix
// this file uses: the signature is over
//
//	"SSHSIG" || namespace || reserved || hash_algorithm || SHA512(message)
//
// so a signature made for one document type cannot be replayed as another even
// if the two could ever produce identical canonical bytes. Namespaces are named
// per document type (NamespaceManifest, NamespaceChainEntry, ...), Verify
// requires an exact match, and an empty namespace is refused at signing time
// because "no namespace" is the absence of the control.
//
// # What a valid signature proves (INV-6)
//
// That the holder of the private key emitted exactly these bytes under exactly
// this namespace. Not that the bytes are true, not that the scan behind them saw
// everything, not that the host was clean, and not that this is the newest
// entry -- freshness is the chain's linkage and the replication state, not a
// property of any single signature.

package baseline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"crypto/sha512"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"strings"
)

// ErrSignature reports a signature that does not verify, for any reason: bad
// bytes, wrong key, wrong namespace, unsupported algorithm, malformed container.
// The reasons are deliberately one error class. A caller must not be able to
// branch on "invalid vs. merely untrusted" and accidentally treat one as a pass.
var ErrSignature = errors.New("baseline: signature does not verify")

// Namespace is the SSHSIG namespace: the signed context string that keeps a
// signature made for one document type from being replayed as another.
type Namespace string

const (
	// NamespaceManifest covers a baseline manifest (P4 task 4).
	NamespaceManifest Namespace = "manifest.aurvet.dev"
	// NamespaceChainEntry covers one hash-chain entry (P4 task 5).
	NamespaceChainEntry Namespace = "chain-entry.aurvet.dev"
	// NamespaceAdjudication covers an adjudication record (P4 task 9).
	NamespaceAdjudication Namespace = "adjudication.aurvet.dev"
	// NamespaceBundle covers an indicator bundle (P5).
	NamespaceBundle Namespace = "bundle.aurvet.dev"
	// NamespaceDelegation covers the root-key delegation document (P5). It is
	// separate from NamespaceBundle on purpose: a bundle signature must never be
	// usable as a delegation, or an online key could name itself.
	NamespaceDelegation Namespace = "delegation.aurvet.dev"
)

const (
	sshsigMagic     = "SSHSIG"
	sshsigVersion   = 1
	sshsigHashAlgo  = "sha512"
	maxSignatureLen = 1 << 16
)

// Signer produces SSH signatures. Two implementations exist: *PrivateKey (an
// unencrypted ed25519 key file) and *AgentSigner (ssh-agent, which is also the
// only path to a FIDO2 token). The interface is exported so a future hardware
// path can be added without touching Sign.
type Signer interface {
	// PublicKey returns the verifying half.
	PublicKey() *PublicKey

	// SignSSH signs data and returns an SSH signature blob: `string algorithm,
	// string signature`, plus the sk framing for token-held keys.
	SignSSH(data []byte) ([]byte, error)
}

// SignSSH implements Signer for a key held in a file.
func (k *PrivateKey) SignSSH(data []byte) ([]byte, error) {
	var w sshWriter
	w.writeString([]byte(AlgoEd25519))
	w.writeString(ed25519.Sign(k.priv, data))
	return w.bytes(), nil
}

// AgentSigner signs through ssh-agent. This is the path that keeps the private
// half off the monitored machine (INV-7): the agent may be forwarded from
// another host, or may be backed by a FIDO2 token.
type AgentSigner struct {
	agent *Agent
	pub   *PublicKey
}

// Signer returns a Signer for one of the agent's keys.
func (a *Agent) Signer(pub *PublicKey) *AgentSigner { return &AgentSigner{agent: a, pub: pub} }

// PublicKey implements Signer.
func (s *AgentSigner) PublicKey() *PublicKey { return s.pub }

// SignSSH implements Signer.
func (s *AgentSigner) SignSSH(data []byte) ([]byte, error) {
	return s.agent.signRaw(s.pub, data)
}

// Sign produces a detached, PEM-armoured SSHSIG over message.
//
// message is expected to be canonical bytes from Marshal. Sign does not
// canonicalise for the caller: silently re-encoding what it was handed would
// mean the bytes stored are not the bytes the caller believes it signed.
//
// Signing is deterministic (ed25519 is, and nothing here reads a clock, INV-4),
// so the same key and message always yield the same armour -- an auditor can
// reproduce it.
func Sign(s Signer, ns Namespace, message []byte) ([]byte, error) {
	if err := validNamespace(ns); err != nil {
		return nil, err
	}
	pub := s.PublicKey()
	if pub == nil || len(pub.blob) == 0 {
		return nil, fmt.Errorf("%w: signer has no public key", ErrKeyFormat)
	}
	sigBlob, err := s.SignSSH(sshsigBlob(ns, sshsigHashAlgo, message))
	if err != nil {
		return nil, err
	}
	var w sshWriter
	w.writeRaw([]byte(sshsigMagic))
	w.writeUint32(sshsigVersion)
	w.writeString(pub.blob)
	w.writeString([]byte(ns))
	w.writeString(nil) // reserved
	w.writeString([]byte(sshsigHashAlgo))
	w.writeString(sigBlob)
	return armor(w.bytes()), nil
}

// signWithHash exists for the downgrade test: it builds a signature with a hash
// algorithm other than sha512, which Verify must refuse. It is unexported
// because production code has exactly one choice.
func signWithHash(s Signer, ns Namespace, message []byte, hashAlgo string) ([]byte, error) {
	sigBlob, err := s.SignSSH(sshsigBlob(ns, hashAlgo, message))
	if err != nil {
		return nil, err
	}
	var w sshWriter
	w.writeRaw([]byte(sshsigMagic))
	w.writeUint32(sshsigVersion)
	w.writeString(s.PublicKey().blob)
	w.writeString([]byte(ns))
	w.writeString(nil)
	w.writeString([]byte(hashAlgo))
	w.writeString(sigBlob)
	return armor(w.bytes()), nil
}

// Verify checks a detached signature over message, which MUST be the raw bytes
// as received.
//
// Ordering is the point of this API: authenticate first, parse afterwards.
// Nothing in this function interprets message -- it is hashed, not parsed -- so
// a caller that verifies before unmarshalling never hands attacker-controlled
// structure to a parser on the strength of an unchecked signature. See
// VerifyCanonical for the composed form.
//
// An empty trusted set is a refusal, never a pass: "no keys configured" must not
// mean "any key will do".
func Verify(sig []byte, ns Namespace, message []byte, trusted []*PublicKey) (*PublicKey, error) {
	if len(trusted) == 0 {
		return nil, fmt.Errorf("%w: no trusted public keys were supplied", ErrSignature)
	}
	if err := validNamespace(ns); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	body, err := unarmor(sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	parsed, err := parseSignature(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	if parsed.version != sshsigVersion {
		return nil, fmt.Errorf("%w: SSHSIG version %d, want %d",
			ErrSignature, parsed.version, sshsigVersion)
	}
	if parsed.namespace != string(ns) {
		return nil, fmt.Errorf("%w: signature is for namespace %q, this is %q",
			ErrSignature, parsed.namespace, ns)
	}
	if parsed.hashAlgo != sshsigHashAlgo {
		return nil, fmt.Errorf("%w: hash algorithm %q, only %q is accepted",
			ErrSignature, parsed.hashAlgo, sshsigHashAlgo)
	}
	claimed, err := ParsePublicKeyBlob(parsed.keyBlob)
	if err != nil {
		return nil, fmt.Errorf("%w: embedded public key: %v", ErrSignature, err)
	}
	// The embedded key is a CLAIM. It is used only to find the caller's trusted
	// key; the verification below runs against the trusted copy, so substituting
	// the field cannot help an attacker.
	var key *PublicKey
	for _, t := range trusted {
		if t != nil && t.Equal(claimed) {
			key = t
			break
		}
	}
	if key == nil {
		return nil, fmt.Errorf("%w: signed by %s, which is not in the trusted set",
			ErrSignature, claimed.Fingerprint())
	}
	signed := sshsigBlob(ns, parsed.hashAlgo, message)
	if err := verifySigBlob(key, parsed.sigBlob, signed); err != nil {
		return nil, err
	}
	return key, nil
}

// VerifyCanonical verifies a signature over raw bytes and only then canonicalises
// them, requiring the result to be identical.
//
// Both halves are load-bearing. Verifying first means the parser never sees
// unauthenticated structure. Requiring raw == canonical means a signature over
// sloppily encoded JSON is refused rather than admitted: if the bytes that were
// signed are not the bytes canonicalisation produces, then the digest recorded
// in the chain cannot be recomputed from the document, and the chain's linkage
// stops meaning anything.
func VerifyCanonical(sig []byte, ns Namespace, raw []byte, trusted []*PublicKey) ([]byte, *PublicKey, error) {
	key, err := Verify(sig, ns, raw, trusted)
	if err != nil {
		return nil, nil, err
	}
	canonical, err := Canonical(raw)
	if err != nil {
		return nil, nil, err
	}
	if !bytes.Equal(canonical, raw) {
		return nil, nil, fmt.Errorf("%w: the signed bytes are validly signed but "+
			"not canonical, so their digest is not reproducible from the document",
			ErrNotCanonical)
	}
	return canonical, key, nil
}

// SignatureKey reports the public key a detached signature CLAIMS to have been
// made with.
//
// It is unauthenticated, by construction: anyone can rewrite the field. Use it
// to tell a user which key they are missing, never to decide whether to trust
// something.
func SignatureKey(sig []byte) (*PublicKey, error) {
	body, err := unarmor(sig)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	parsed, err := parseSignature(body)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return ParsePublicKeyBlob(parsed.keyBlob)
}

// SignatureNamespace reports the namespace a detached signature claims. Also
// unauthenticated in isolation -- it is covered by the signature, but reading it
// out here does not check the signature.
func SignatureNamespace(sig []byte) (Namespace, error) {
	body, err := unarmor(sig)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSignature, err)
	}
	parsed, err := parseSignature(body)
	if err != nil {
		return "", fmt.Errorf("%w: %v", ErrSignature, err)
	}
	return Namespace(parsed.namespace), nil
}

// -- internals --------------------------------------------------------------

func validNamespace(ns Namespace) error {
	if ns == "" {
		return fmt.Errorf("%w: an empty namespace is the absence of domain separation", ErrSignature)
	}
	if len(ns) > 255 {
		return fmt.Errorf("%w: namespace is %d bytes", ErrSignature, len(ns))
	}
	for i := 0; i < len(ns); i++ {
		if c := ns[i]; c <= ' ' || c > '~' {
			return fmt.Errorf("%w: namespace contains byte %#02x at %d", ErrSignature, c, i)
		}
	}
	return nil
}

// sshsigBlob builds the bytes that are actually signed. Note that the namespace
// and the hash algorithm are inside it: neither can be changed after the fact
// without breaking the signature.
func sshsigBlob(ns Namespace, hashAlgo string, message []byte) []byte {
	var h []byte
	switch hashAlgo {
	case "sha512":
		sum := sha512.Sum512(message)
		h = sum[:]
	case "sha256":
		// Only reachable from signWithHash, which exists so the downgrade
		// refusal can be tested against a real signature.
		sum := sha256.Sum256(message)
		h = sum[:]
	default:
		// An unknown algorithm must not silently become "no hash". Use a value
		// that cannot verify.
		h = nil
	}
	var w sshWriter
	w.writeRaw([]byte(sshsigMagic))
	w.writeString([]byte(ns))
	w.writeString(nil) // reserved
	w.writeString([]byte(hashAlgo))
	w.writeString(h)
	return w.bytes()
}

type parsedSignature struct {
	version   uint32
	keyBlob   []byte
	namespace string
	hashAlgo  string
	sigBlob   []byte
}

func parseSignature(body []byte) (*parsedSignature, error) {
	if len(body) > maxSignatureLen {
		return nil, fmt.Errorf("%d bytes is not a signature", len(body))
	}
	if !bytes.HasPrefix(body, []byte(sshsigMagic)) {
		return nil, errors.New("missing SSHSIG magic")
	}
	r := sshReader{buf: body[len(sshsigMagic):]}
	version, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("version: %v", err)
	}
	keyBlob, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("public key: %v", err)
	}
	ns, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("namespace: %v", err)
	}
	reserved, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("reserved: %v", err)
	}
	if len(reserved) != 0 {
		return nil, fmt.Errorf("reserved field carries %d bytes", len(reserved))
	}
	hashAlgo, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("hash algorithm: %v", err)
	}
	sigBlob, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("signature: %v", err)
	}
	if err := r.atEnd(); err != nil {
		return nil, err
	}
	return &parsedSignature{
		version:   version,
		keyBlob:   keyBlob,
		namespace: string(ns),
		hashAlgo:  string(hashAlgo),
		sigBlob:   sigBlob,
	}, nil
}

// verifySigBlob checks the inner SSH signature against the TRUSTED key.
func verifySigBlob(key *PublicKey, sigBlob, signed []byte) error {
	r := sshReader{buf: sigBlob}
	algo, err := r.readString()
	if err != nil {
		return fmt.Errorf("%w: signature algorithm: %v", ErrSignature, err)
	}
	if Algorithm(algo) != key.Algorithm {
		return fmt.Errorf("%w: signature says %q, key is %q", ErrSignature, algo, key.Algorithm)
	}
	raw, err := r.readString()
	if err != nil {
		return fmt.Errorf("%w: signature bytes: %v", ErrSignature, err)
	}
	if len(raw) != ed25519.SignatureSize {
		return fmt.Errorf("%w: signature is %d bytes, want %d",
			ErrSignature, len(raw), ed25519.SignatureSize)
	}

	switch key.Algorithm {
	case AlgoEd25519:
		if err := r.atEnd(); err != nil {
			return fmt.Errorf("%w: %v", ErrSignature, err)
		}
		if !ed25519.Verify(key.key, signed, raw) {
			return fmt.Errorf("%w: ed25519 verification failed", ErrSignature)
		}
		return nil

	case AlgoSKEd25519:
		// PROTOCOL.u2f: a token signs
		//   SHA256(application) || flags || counter || SHA256(message)
		// where message is the SSHSIG blob above. The application string and the
		// counter are therefore covered by the signature, which is why a replay
		// with a bumped counter cannot verify.
		//
		// NOT EXERCISED AGAINST REAL HARDWARE: no FIDO2 token was available. The
		// framing is tested with a software key, so treat this as "format
		// implemented", not "proven interoperable".
		flags, err := r.readByte()
		if err != nil {
			return fmt.Errorf("%w: sk flags: %v", ErrSignature, err)
		}
		counter, err := r.readUint32()
		if err != nil {
			return fmt.Errorf("%w: sk counter: %v", ErrSignature, err)
		}
		if err := r.atEnd(); err != nil {
			return fmt.Errorf("%w: %v", ErrSignature, err)
		}
		appHash := sha256.Sum256([]byte(key.Application))
		msgHash := sha256.Sum256(signed)
		var buf bytes.Buffer
		buf.Write(appHash[:])
		buf.WriteByte(flags)
		var ctr [4]byte
		binary.BigEndian.PutUint32(ctr[:], counter)
		buf.Write(ctr[:])
		buf.Write(msgHash[:])
		if !ed25519.Verify(key.key, buf.Bytes(), raw) {
			return fmt.Errorf("%w: sk-ed25519 verification failed", ErrSignature)
		}
		return nil

	default:
		return fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, key.Algorithm)
	}
}

// armor wraps a signature exactly the way OpenSSH does, down to the line width.
//
// encoding/pem would also produce something ssh-keygen accepts, but it wraps at
// 64 columns where OpenSSH wraps at 70, and the file bytes would then differ from
// what `ssh-keygen -Y sign` writes for the same key and message. Byte-identical
// output is worth the twelve lines: it makes the golden fixture meaningful, and
// it means a signature regenerated by either tool is the same file rather than a
// spurious diff in the chain.
func armor(body []byte) []byte {
	const (
		begin = "-----BEGIN SSH SIGNATURE-----\n"
		end   = "-----END SSH SIGNATURE-----\n"
		width = 70
	)
	b64 := base64.StdEncoding.EncodeToString(body)
	var out bytes.Buffer
	out.WriteString(begin)
	for i := 0; i < len(b64); i += width {
		j := min(i+width, len(b64))
		out.WriteString(b64[i:j])
		out.WriteByte('\n')
	}
	out.WriteString(end)
	return out.Bytes()
}

// unarmor is strict: exactly one PEM block, of the right type, with nothing
// after it. A file carrying two signatures is ambiguous about which one was
// checked, and ambiguity in a verifier is a bug an attacker chooses the meaning
// of.
func unarmor(sig []byte) ([]byte, error) {
	if len(sig) == 0 {
		return nil, errors.New("empty signature")
	}
	if len(sig) > maxSignatureLen {
		return nil, fmt.Errorf("%d bytes is not a signature", len(sig))
	}
	blk, rest := pem.Decode(sig)
	if blk == nil {
		return nil, errors.New("not a PEM-armoured signature")
	}
	if blk.Type != "SSH SIGNATURE" {
		return nil, fmt.Errorf("armour type %q, want SSH SIGNATURE", blk.Type)
	}
	if len(blk.Headers) != 0 {
		return nil, errors.New("armour carries headers")
	}
	if strings.TrimSpace(string(rest)) != "" {
		return nil, errors.New("trailing data after the signature")
	}
	if len(blk.Bytes) == 0 {
		return nil, errors.New("empty signature body")
	}
	return blk.Bytes, nil
}
