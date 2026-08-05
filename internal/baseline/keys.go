// internal/baseline/keys.go
//
// Key handling, in OpenSSH's formats and no others.
//
// # Why OpenSSH's format, and why not a simpler one
//
// The threat model is a machine that may already be compromised. A signing key
// sitting in a file on that machine is a key the attacker has. What saves the
// design is not discipline ("keep the key elsewhere") but hardware: if the key
// format is OpenSSH's, the user can hold the private half on a FIDO2 token as an
// `sk-ssh-ed25519@openssh.com` key, and the private half then never exists on
// the monitored host at all. That is INV-7 satisfied by hardware.
//
// Reusing the existing format is precisely what buys that, so this file invents
// no container of its own -- not even a simpler one. The consequence is that it
// must parse `openssh-key-v1`, which is done here with the standard library only
// (golang.org/x/crypto/ssh is not a dependency of this project and is not going
// to become one for the sake of convenience).
//
// # Which signing paths actually work today
//
//	ssh-keygen ed25519 key, no passphrase   ParsePrivateKey -> FileSigner. Works,
//	                                        exercised against real ssh-keygen.
//	ssh-agent (any key the agent holds)     AgentSigner. Works, exercised against
//	                                        a real ssh-agent + ssh-add.
//	passphrase-protected private key file   REFUSED (ErrKeyEncrypted). The KDF is
//	                                        bcrypt_pbkdf, which needs Blowfish,
//	                                        which is not in the standard library.
//	                                        Route it through ssh-agent instead.
//	FIDO2 sk-ssh-ed25519 key file           REFUSED for signing: the private
//	                                        scalar is in the token, not the file.
//	                                        Signing requires the token, i.e. the
//	                                        agent path. VERIFICATION of sk
//	                                        signatures is implemented here, but
//	                                        has NOT been exercised against real
//	                                        hardware -- no token was available.
//	                                        Treat sk support as "format
//	                                        understood", not "proven end to end".
//
// Nothing in this file executes anything (INV-2): keys are parsed, and the agent
// is spoken to over its socket protocol, never by shelling out to ssh-add.

package baseline

import (
	"bytes"
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/binary"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"strings"
	"time"
)

// Algorithm is an SSH public key algorithm name, as it appears on the wire and
// as the first field of an authorized_keys line.
type Algorithm string

const (
	// AlgoEd25519 is a software ed25519 key.
	AlgoEd25519 Algorithm = "ssh-ed25519"
	// AlgoSKEd25519 is a FIDO2/U2F-backed ed25519 key: the private scalar lives
	// in the token and never on this host.
	AlgoSKEd25519 Algorithm = "sk-ssh-ed25519@openssh.com"
)

var (
	// ErrKeyFormat reports key material this package cannot read, or that
	// contradicts itself.
	ErrKeyFormat = errors.New("baseline: malformed key")

	// ErrKeyEncrypted reports a passphrase-protected private key. See the file
	// comment: this is a deliberate boundary, not an oversight.
	ErrKeyEncrypted = errors.New("baseline: private key is passphrase-protected")

	// ErrUnsupportedAlgorithm reports a key that is not ed25519. RSA, ECDSA and
	// DSA are not accepted: one signature algorithm means one thing to verify,
	// and an algorithm field a verifier honours is an algorithm an attacker
	// chooses.
	ErrUnsupportedAlgorithm = errors.New("baseline: unsupported key algorithm")

	// ErrAgent reports a failure talking to ssh-agent.
	ErrAgent = errors.New("baseline: ssh-agent")
)

// maxKeyBlob bounds anything read from a key file or the agent socket. Key blobs
// are tens of bytes; a length prefix claiming more than this is hostile or
// broken, and either way must not become an allocation.
const maxKeyBlob = 1 << 16

// PublicKey is an ed25519 or FIDO2-backed ed25519 public key.
//
// It is the only thing verification needs (INV-7): scan, diff and verify run
// with the public key alone, and the private half is required only to append.
type PublicKey struct {
	Algorithm Algorithm

	// Comment is the trailing free text of an authorized_keys line. It is
	// untrusted display data and carries no authority whatsoever.
	Comment string

	// Application is the sk-key's application string (conventionally
	// "ssh:something"). Empty for software keys.
	Application string

	key  ed25519.PublicKey
	blob []byte // the SSH wire encoding, which is what the fingerprint is over
}

// ParsePublicKey reads one authorized_keys-style line: `<algo> <base64> [comment]`.
//
// It refuses anything whose algorithm field disagrees with the algorithm inside
// the blob. That agreement matters: a verifier that trusts the outer label can
// be pointed at one key while checking another.
func ParsePublicKey(line []byte) (*PublicKey, error) {
	text := strings.TrimRight(string(line), "\r\n")
	if i := strings.IndexAny(text, "\r\n"); i >= 0 {
		return nil, fmt.Errorf("%w: expected a single line", ErrKeyFormat)
	}
	fields := strings.SplitN(strings.TrimSpace(text), " ", 3)
	if len(fields) < 2 {
		return nil, fmt.Errorf("%w: expected `<algorithm> <base64> [comment]`", ErrKeyFormat)
	}
	blob, err := base64.StdEncoding.DecodeString(fields[1])
	if err != nil {
		return nil, fmt.Errorf("%w: base64: %v", ErrKeyFormat, err)
	}
	k, err := ParsePublicKeyBlob(blob)
	if err != nil {
		return nil, err
	}
	if string(k.Algorithm) != fields[0] {
		return nil, fmt.Errorf("%w: line says %q, blob says %q",
			ErrKeyFormat, fields[0], k.Algorithm)
	}
	if len(fields) == 3 {
		k.Comment = strings.TrimSpace(fields[2])
	}
	return k, nil
}

// ParsePublicKeyBlob reads the SSH wire encoding of a public key.
func ParsePublicKeyBlob(blob []byte) (*PublicKey, error) {
	if len(blob) > maxKeyBlob {
		return nil, fmt.Errorf("%w: %d bytes is not a key", ErrKeyFormat, len(blob))
	}
	r := sshReader{buf: blob}
	algoBytes, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: algorithm: %v", ErrKeyFormat, err)
	}
	algo := Algorithm(algoBytes)
	if algo != AlgoEd25519 && algo != AlgoSKEd25519 {
		return nil, fmt.Errorf("%w: %q", ErrUnsupportedAlgorithm, algo)
	}
	pub, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: public key: %v", ErrKeyFormat, err)
	}
	if len(pub) != ed25519.PublicKeySize {
		return nil, fmt.Errorf("%w: public key is %d bytes, want %d",
			ErrKeyFormat, len(pub), ed25519.PublicKeySize)
	}
	k := &PublicKey{Algorithm: algo, key: ed25519.PublicKey(pub)}
	if algo == AlgoSKEd25519 {
		app, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("%w: sk application: %v", ErrKeyFormat, err)
		}
		k.Application = string(app)
	}
	if err := r.atEnd(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFormat, err)
	}
	k.blob = append([]byte(nil), blob...)
	return k, nil
}

// Blob returns the SSH wire encoding.
func (k *PublicKey) Blob() []byte { return append([]byte(nil), k.blob...) }

// AuthorizedKey renders the key as OpenSSH writes it in a .pub file.
func (k *PublicKey) AuthorizedKey() string {
	s := string(k.Algorithm) + " " + base64.StdEncoding.EncodeToString(k.blob)
	if k.Comment != "" {
		s += " " + k.Comment
	}
	return s
}

// Fingerprint is the string `ssh-keygen -l` prints: SHA256 over the wire blob,
// standard base64 with padding stripped. It is deliberately byte-for-byte the
// same string OpenSSH shows, because a fingerprint that only this tool can
// produce is a fingerprint nobody can cross-check in a runbook.
func (k *PublicKey) Fingerprint() string {
	sum := sha256.Sum256(k.blob)
	return "SHA256:" + strings.TrimRight(base64.StdEncoding.EncodeToString(sum[:]), "=")
}

// HardwareBacked reports whether the private half lives in a FIDO2 token.
func (k *PublicKey) HardwareBacked() bool { return k.Algorithm == AlgoSKEd25519 }

// Equal compares wire blobs, which is the only comparison that means "the same
// key": comment and label are not part of identity.
func (k *PublicKey) Equal(other *PublicKey) bool {
	return other != nil && bytes.Equal(k.blob, other.blob)
}

// -- private keys -----------------------------------------------------------

// PrivateKey is an unencrypted software ed25519 key read from an
// `openssh-key-v1` container.
type PrivateKey struct {
	pub  *PublicKey
	priv ed25519.PrivateKey
}

// PublicKey returns the public half.
func (k *PrivateKey) PublicKey() *PublicKey { return k.pub }

const opensshMagic = "openssh-key-v1\x00"

// ParsePrivateKey reads a PEM-armoured `openssh-key-v1` private key.
//
// The container states the public key twice -- once in the outer blob, once
// beside the private half -- and this refuses to load one where the two
// disagree, or where the private half does not derive the public one. Either
// disagreement would let a file advertise key A while signing with key B, which
// is a chain that verifies against a key its author never controlled.
func ParsePrivateKey(pemBytes []byte) (*PrivateKey, error) {
	blk, _ := pem.Decode(pemBytes)
	if blk == nil {
		return nil, fmt.Errorf("%w: not PEM", ErrKeyFormat)
	}
	if blk.Type != "OPENSSH PRIVATE KEY" {
		return nil, fmt.Errorf("%w: PEM type %q, want OPENSSH PRIVATE KEY (ssh-keygen -t ed25519)",
			ErrUnsupportedAlgorithm, blk.Type)
	}
	body := blk.Bytes
	if !bytes.HasPrefix(body, []byte(opensshMagic)) {
		return nil, fmt.Errorf("%w: missing openssh-key-v1 magic", ErrKeyFormat)
	}
	r := sshReader{buf: body[len(opensshMagic):]}

	cipher, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: ciphername: %v", ErrKeyFormat, err)
	}
	kdf, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: kdfname: %v", ErrKeyFormat, err)
	}
	if _, err := r.readString(); err != nil { // kdfoptions
		return nil, fmt.Errorf("%w: kdfoptions: %v", ErrKeyFormat, err)
	}
	if string(cipher) != "none" || string(kdf) != "none" {
		return nil, fmt.Errorf("%w (cipher %q, kdf %q): decrypting it needs "+
			"bcrypt_pbkdf, which is outside the standard library and this tool "+
			"takes no third-party dependencies. Load the key into ssh-agent and "+
			"sign through the agent, or keep the key on a FIDO2 token",
			ErrKeyEncrypted, cipher, kdf)
	}
	n, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("%w: key count: %v", ErrKeyFormat, err)
	}
	if n != 1 {
		return nil, fmt.Errorf("%w: container holds %d keys, want exactly 1", ErrKeyFormat, n)
	}
	pubBlob, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: public blob: %v", ErrKeyFormat, err)
	}
	pub, err := ParsePublicKeyBlob(pubBlob)
	if err != nil {
		return nil, err
	}
	inner, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: private section: %v", ErrKeyFormat, err)
	}
	if err := r.atEnd(); err != nil {
		return nil, fmt.Errorf("%w: %v", ErrKeyFormat, err)
	}
	if pub.Algorithm == AlgoSKEd25519 {
		return nil, fmt.Errorf("%w: %s is a FIDO2 key: the private scalar is in "+
			"the token, so signing must go through ssh-agent with the token present",
			ErrUnsupportedAlgorithm, pub.Algorithm)
	}
	return parsePrivateSection(inner, pub)
}

func parsePrivateSection(inner []byte, pub *PublicKey) (*PrivateKey, error) {
	p := sshReader{buf: inner}
	c1, err := p.readUint32()
	if err != nil {
		return nil, fmt.Errorf("%w: checkint: %v", ErrKeyFormat, err)
	}
	c2, err := p.readUint32()
	if err != nil {
		return nil, fmt.Errorf("%w: checkint: %v", ErrKeyFormat, err)
	}
	if c1 != c2 {
		// For an unencrypted key this is corruption; for an encrypted one it is
		// how OpenSSH detects a wrong passphrase. Either way, do not proceed.
		return nil, fmt.Errorf("%w: private section checkints differ (%d != %d)",
			ErrKeyFormat, c1, c2)
	}
	algo, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: inner algorithm: %v", ErrKeyFormat, err)
	}
	if Algorithm(algo) != AlgoEd25519 {
		return nil, fmt.Errorf("%w: inner algorithm %q", ErrUnsupportedAlgorithm, algo)
	}
	innerPub, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: inner public key: %v", ErrKeyFormat, err)
	}
	privBytes, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: private key: %v", ErrKeyFormat, err)
	}
	comment, err := p.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: comment: %v", ErrKeyFormat, err)
	}
	// The tail is 1,2,3... padding to the cipher block size. Check it: a
	// container that does not pad the way OpenSSH pads is not a container
	// OpenSSH wrote, and reading it anyway is how a parser grows a second,
	// undocumented dialect.
	for i, b := range p.rest() {
		if int(b) != i+1 {
			return nil, fmt.Errorf("%w: bad padding at offset %d", ErrKeyFormat, i)
		}
	}
	if len(privBytes) != ed25519.PrivateKeySize {
		return nil, fmt.Errorf("%w: private key is %d bytes, want %d",
			ErrKeyFormat, len(privBytes), ed25519.PrivateKeySize)
	}
	if !bytes.Equal(innerPub, pub.key) {
		return nil, fmt.Errorf("%w: the container's two copies of the public key disagree",
			ErrKeyFormat)
	}
	priv := ed25519.PrivateKey(append([]byte(nil), privBytes...))
	derived, ok := priv.Public().(ed25519.PublicKey)
	if !ok || !bytes.Equal(derived, pub.key) {
		return nil, fmt.Errorf("%w: the private key does not derive the stated public key",
			ErrKeyFormat)
	}
	// Comment is display-only; keep it so a fingerprint printout is legible.
	pubCopy := *pub
	if pubCopy.Comment == "" {
		pubCopy.Comment = string(comment)
	}
	return &PrivateKey{pub: &pubCopy, priv: priv}, nil
}

// -- ssh-agent --------------------------------------------------------------

// Agent is a connection to an ssh-agent.
//
// This is the path that makes the hardware story real: an agent holding a FIDO2
// `sk-ssh-ed25519` key signs with the token, and it is also how a
// passphrase-protected key is used without this package implementing a KDF.
type Agent struct {
	conn net.Conn
}

const (
	agentcRequestIdentities = 11
	agentIdentitiesAnswer   = 12
	agentcSignRequest       = 13
	agentSignResponse       = 14
	agentFailure            = 5
	agentMaxResponse        = 1 << 20
)

// DialAgent connects to the agent at socketPath. Pass the value of SSH_AUTH_SOCK;
// this package does not read the environment itself, because an ambient $HOME or
// $SSH_AUTH_SOCK is exactly the implicit input INV-4 forbids.
func DialAgent(socketPath string) (*Agent, error) {
	if socketPath == "" {
		return nil, fmt.Errorf("%w: no socket path (SSH_AUTH_SOCK is unset)", ErrAgent)
	}
	conn, err := net.Dial("unix", socketPath)
	if err != nil {
		return nil, fmt.Errorf("%w: dial: %v", ErrAgent, err)
	}
	return &Agent{conn: conn}, nil
}

// Close releases the connection.
func (a *Agent) Close() error { return a.conn.Close() }

// SetDeadline bounds agent I/O. A FIDO2 key makes the agent wait for a human to
// touch a token, so callers want a generous but finite deadline rather than a
// hang that looks like a crash.
func (a *Agent) SetDeadline(t time.Time) error { return a.conn.SetDeadline(t) }

// Keys lists the public keys the agent holds.
func (a *Agent) Keys() ([]*PublicKey, error) {
	resp, err := a.request(agentcRequestIdentities, nil)
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 || resp[0] != agentIdentitiesAnswer {
		return nil, fmt.Errorf("%w: unexpected reply to identity request", ErrAgent)
	}
	r := sshReader{buf: resp[1:]}
	n, err := r.readUint32()
	if err != nil {
		return nil, fmt.Errorf("%w: identity count: %v", ErrAgent, err)
	}
	if n > 1024 {
		return nil, fmt.Errorf("%w: agent claims %d identities", ErrAgent, n)
	}
	var out []*PublicKey
	for i := uint32(0); i < n; i++ {
		blob, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("%w: identity %d: %v", ErrAgent, i, err)
		}
		comment, err := r.readString()
		if err != nil {
			return nil, fmt.Errorf("%w: identity %d comment: %v", ErrAgent, i, err)
		}
		k, err := ParsePublicKeyBlob(blob)
		if err != nil {
			// An agent commonly holds RSA keys too. Skipping what this tool
			// cannot use is not a coverage gap: the caller asked for ed25519.
			continue
		}
		k.Comment = string(comment)
		out = append(out, k)
	}
	return out, nil
}

// signRaw asks the agent to sign data with the given key, returning the SSH
// signature blob.
func (a *Agent) signRaw(pub *PublicKey, data []byte) ([]byte, error) {
	var w sshWriter
	w.writeString(pub.blob)
	w.writeString(data)
	w.writeUint32(0) // no flags: ed25519 has no flag-selected hash
	resp, err := a.request(agentcSignRequest, w.bytes())
	if err != nil {
		return nil, err
	}
	if len(resp) == 0 || resp[0] != agentSignResponse {
		if len(resp) > 0 && resp[0] == agentFailure {
			return nil, fmt.Errorf("%w: refused to sign (key not loaded, or the "+
				"token was not touched)", ErrAgent)
		}
		return nil, fmt.Errorf("%w: unexpected reply to sign request", ErrAgent)
	}
	r := sshReader{buf: resp[1:]}
	sig, err := r.readString()
	if err != nil {
		return nil, fmt.Errorf("%w: signature: %v", ErrAgent, err)
	}
	return sig, nil
}

func (a *Agent) request(kind byte, payload []byte) ([]byte, error) {
	var hdr [5]byte
	binary.BigEndian.PutUint32(hdr[:4], uint32(len(payload)+1))
	hdr[4] = kind
	if _, err := a.conn.Write(hdr[:]); err != nil {
		return nil, fmt.Errorf("%w: write: %v", ErrAgent, err)
	}
	if len(payload) > 0 {
		if _, err := a.conn.Write(payload); err != nil {
			return nil, fmt.Errorf("%w: write: %v", ErrAgent, err)
		}
	}
	var lenBuf [4]byte
	if _, err := io.ReadFull(a.conn, lenBuf[:]); err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrAgent, err)
	}
	n := binary.BigEndian.Uint32(lenBuf[:])
	if n == 0 || n > agentMaxResponse {
		return nil, fmt.Errorf("%w: reply claims %d bytes", ErrAgent, n)
	}
	buf := make([]byte, n)
	if _, err := io.ReadFull(a.conn, buf); err != nil {
		return nil, fmt.Errorf("%w: read: %v", ErrAgent, err)
	}
	return buf, nil
}

// -- SSH wire encoding ------------------------------------------------------

type sshWriter struct{ buf bytes.Buffer }

func (w *sshWriter) writeString(b []byte) {
	w.writeUint32(uint32(len(b)))
	w.buf.Write(b)
}

func (w *sshWriter) writeUint32(v uint32) {
	var tmp [4]byte
	binary.BigEndian.PutUint32(tmp[:], v)
	w.buf.Write(tmp[:])
}

func (w *sshWriter) writeByte(b byte) { w.buf.WriteByte(b) }

func (w *sshWriter) writeRaw(b []byte) { w.buf.Write(b) }

func (w *sshWriter) bytes() []byte { return w.buf.Bytes() }

// sshReader reads length-prefixed SSH wire values out of a buffer that is
// already in memory. Every read is bounds-checked against what is actually
// there: a length prefix is attacker-controlled input, and treating one as an
// allocation size is the classic way to turn a parser into a denial of service.
type sshReader struct {
	buf []byte
	off int
}

func (r *sshReader) readUint32() (uint32, error) {
	if r.off+4 > len(r.buf) {
		return 0, fmt.Errorf("truncated: want 4 bytes at offset %d of %d", r.off, len(r.buf))
	}
	v := binary.BigEndian.Uint32(r.buf[r.off : r.off+4])
	r.off += 4
	return v, nil
}

func (r *sshReader) readString() ([]byte, error) {
	n, err := r.readUint32()
	if err != nil {
		return nil, err
	}
	if int64(n) > int64(len(r.buf)-r.off) {
		return nil, fmt.Errorf("length %d exceeds the %d bytes remaining", n, len(r.buf)-r.off)
	}
	s := r.buf[r.off : r.off+int(n)]
	r.off += int(n)
	return s, nil
}

func (r *sshReader) readByte() (byte, error) {
	if r.off >= len(r.buf) {
		return 0, fmt.Errorf("truncated: want 1 byte at offset %d of %d", r.off, len(r.buf))
	}
	b := r.buf[r.off]
	r.off++
	return b, nil
}

func (r *sshReader) rest() []byte { return r.buf[r.off:] }

// atEnd reports trailing bytes as an error. Ignoring them would let one blob
// carry a second, invisible payload past the part that was checked.
func (r *sshReader) atEnd() error {
	if r.off != len(r.buf) {
		return fmt.Errorf("%d trailing bytes", len(r.buf)-r.off)
	}
	return nil
}
