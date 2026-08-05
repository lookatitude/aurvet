// internal/baseline/keys_test.go
//
// The attacks come first here. A key parser that only has happy-path tests is a
// parser nobody has checked, and this one reads a container the user can be
// talked into downloading.

package baseline

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/pem"
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
)

// -- interop with the real ssh-keygen ---------------------------------------

// genKey runs the real ssh-keygen. "Implements the format" and "implements THE
// format" are different claims, and only this test can tell them apart.
func genKey(t *testing.T, passphrase string, extra ...string) (dir, priv, pub string) {
	t.Helper()
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir = t.TempDir()
	priv = filepath.Join(dir, "id")
	args := append([]string{"-q", "-t", "ed25519", "-N", passphrase,
		"-C", "aurvet-test-key", "-f", priv}, extra...)
	out, err := exec.Command("ssh-keygen", args...).CombinedOutput()
	if err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	return dir, priv, priv + ".pub"
}

func TestParsePrivateKeyReadsWhatSSHKeygenWrote(t *testing.T) {
	_, priv, pub := genKey(t, "")

	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(pemBytes)
	if err != nil {
		t.Fatalf("ParsePrivateKey: %v", err)
	}
	line, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	p, err := ParsePublicKey(line)
	if err != nil {
		t.Fatalf("ParsePublicKey: %v", err)
	}
	if !bytes.Equal(k.PublicKey().Blob(), p.Blob()) {
		t.Fatal("private and public files disagree about the public key")
	}
	if p.Comment != "aurvet-test-key" {
		t.Fatalf("comment: %q", p.Comment)
	}
	if p.Algorithm != AlgoEd25519 {
		t.Fatalf("algorithm: %q", p.Algorithm)
	}
	if p.HardwareBacked() {
		t.Fatal("a software key must not claim hardware backing")
	}
	// The public line we emit must be the line ssh-keygen emits.
	if got, want := p.AuthorizedKey(), strings.TrimSpace(string(line)); got != want {
		t.Fatalf("authorized_keys line differs:\n got %s\nwant %s", got, want)
	}
}

// The fingerprint is what a human compares in a runbook, so it has to be the
// same string OpenSSH prints -- not merely a hash of the same bytes.
func TestFingerprintMatchesSSHKeygen(t *testing.T) {
	_, _, pub := genKey(t, "")
	out, err := exec.Command("ssh-keygen", "-l", "-f", pub).Output()
	if err != nil {
		t.Fatalf("ssh-keygen -l: %v", err)
	}
	fields := strings.Fields(string(out))
	if len(fields) < 2 {
		t.Fatalf("unexpected ssh-keygen output: %q", out)
	}
	line, err := os.ReadFile(pub)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePublicKey(line)
	if err != nil {
		t.Fatal(err)
	}
	if k.Fingerprint() != fields[1] {
		t.Fatalf("fingerprint %q != ssh-keygen %q", k.Fingerprint(), fields[1])
	}
}

// -- the honest boundary ----------------------------------------------------

// A passphrase-protected key needs bcrypt_pbkdf, which needs Blowfish, which is
// not in the standard library and is not worth a module in a security tool. The
// refusal must therefore be explicit and must point at the path that does work.
func TestParsePrivateKeyRefusesAnEncryptedKeyAndSaysWhatToDo(t *testing.T) {
	_, priv, _ := genKey(t, "correct horse battery staple")
	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	_, err = ParsePrivateKey(pemBytes)
	if !errors.Is(err, ErrKeyEncrypted) {
		t.Fatalf("want ErrKeyEncrypted, got %v", err)
	}
	if !strings.Contains(err.Error(), "ssh-agent") {
		t.Fatalf("refusal does not name the working path: %v", err)
	}
}

func TestParsePrivateKeyRefusesNonEd25519(t *testing.T) {
	if _, err := exec.LookPath("ssh-keygen"); err != nil {
		t.Skip("ssh-keygen not available")
	}
	dir := t.TempDir()
	priv := filepath.Join(dir, "rsa")
	if out, err := exec.Command("ssh-keygen", "-q", "-t", "rsa", "-b", "2048",
		"-N", "", "-f", priv).CombinedOutput(); err != nil {
		t.Fatalf("ssh-keygen: %v\n%s", err, out)
	}
	pemBytes, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePrivateKey(pemBytes); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("want ErrUnsupportedAlgorithm, got %v", err)
	}
	line, err := os.ReadFile(priv + ".pub")
	if err != nil {
		t.Fatal(err)
	}
	if _, err := ParsePublicKey(line); !errors.Is(err, ErrUnsupportedAlgorithm) {
		t.Fatalf("public rsa: want ErrUnsupportedAlgorithm, got %v", err)
	}
}

// -- attacks on the private key container -----------------------------------

func TestParsePrivateKeyAttacks(t *testing.T) {
	_, priv, _ := genKey(t, "")
	good, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	blk, _ := pem.Decode(good)
	if blk == nil {
		t.Fatal("fixture is not PEM")
	}

	mutate := func(fn func(b []byte) []byte) []byte {
		body := fn(append([]byte(nil), blk.Bytes...))
		return pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: body})
	}

	cases := map[string][]byte{
		"not pem":         []byte("hello"),
		"wrong pem type":  pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: blk.Bytes}),
		"empty body":      pem.EncodeToMemory(&pem.Block{Type: blk.Type}),
		"truncated body":  mutate(func(b []byte) []byte { return b[:len(b)/2] }),
		"bad magic":       mutate(func(b []byte) []byte { b[0] ^= 0xff; return b }),
		"trailing data":   mutate(func(b []byte) []byte { return append(b, 'x') }),
		"flipped in body": mutate(func(b []byte) []byte { b[len(b)-40] ^= 0x01; return b }),
	}
	for name, in := range cases {
		if _, err := ParsePrivateKey(in); err == nil {
			t.Errorf("%s: parsed without error", name)
		} else if !errors.Is(err, ErrKeyFormat) && !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%s: unexpected error class: %v", name, err)
		}
	}
}

// The container states the public key twice: once in the outer blob and once
// beside the private half. If they can disagree, a signer can be made to
// advertise key A while signing with key B -- so disagreement is a refusal.
func TestParsePrivateKeyRefusesInconsistentPublicHalf(t *testing.T) {
	_, priv, _ := genKey(t, "")
	good, err := os.ReadFile(priv)
	if err != nil {
		t.Fatal(err)
	}
	k, err := ParsePrivateKey(good)
	if err != nil {
		t.Fatal(err)
	}
	pub := k.PublicKey().key
	blk, _ := pem.Decode(good)
	body := blk.Bytes

	// Corrupt the FIRST occurrence of the 32 public bytes (the outer blob) and
	// leave the inner copy intact: the two now disagree.
	i := bytes.Index(body, pub)
	if i < 0 {
		t.Fatal("could not locate the public key inside the container")
	}
	mangled := append([]byte(nil), body...)
	mangled[i] ^= 0x01
	in := pem.EncodeToMemory(&pem.Block{Type: blk.Type, Bytes: mangled})
	if _, err := ParsePrivateKey(in); !errors.Is(err, ErrKeyFormat) {
		t.Fatalf("want ErrKeyFormat for a self-inconsistent container, got %v", err)
	}
}

// -- attacks on the public key line -----------------------------------------

func TestParsePublicKeyAttacks(t *testing.T) {
	good := ed25519.PublicKey(bytes.Repeat([]byte{7}, ed25519.PublicKeySize))
	blob := marshalEd25519Blob(good)
	b64 := base64.StdEncoding.EncodeToString(blob)

	cases := map[string]string{
		"empty":               "",
		"one field":           "ssh-ed25519",
		"not base64":          "ssh-ed25519 !!!!",
		"algorithm mismatch":  "ssh-rsa " + b64,
		"short key":           "ssh-ed25519 " + base64.StdEncoding.EncodeToString(marshalShortEd25519Blob()),
		"trailing blob bytes": "ssh-ed25519 " + base64.StdEncoding.EncodeToString(append(append([]byte(nil), blob...), 'x')),
	}
	for name, in := range cases {
		_, err := ParsePublicKey([]byte(in))
		if err == nil {
			t.Errorf("%s: parsed without error", name)
			continue
		}
		if !errors.Is(err, ErrKeyFormat) && !errors.Is(err, ErrUnsupportedAlgorithm) {
			t.Errorf("%s: unexpected error class: %v", name, err)
		}
	}
	// A comment is arbitrary text, so a second key-looking token on the line is a
	// comment and not an error. What must hold is that whatever is accepted
	// round-trips to the same blob.
	k, err := ParsePublicKey([]byte("ssh-ed25519 " + b64 + " a comment with spaces"))
	if err != nil {
		t.Fatalf("valid line refused: %v", err)
	}
	if k.Comment != "a comment with spaces" {
		t.Fatalf("comment: %q", k.Comment)
	}
	if !bytes.Equal(k.Blob(), blob) {
		t.Fatal("blob did not round-trip")
	}
}

// A hardware-backed key must be recognisable as such, because that is the whole
// INV-7 argument: the private half never existed on this machine.
func TestParsePublicKeyAcceptsSKKeysAndMarksThemHardwareBacked(t *testing.T) {
	pub := ed25519.PublicKey(bytes.Repeat([]byte{3}, ed25519.PublicKeySize))
	var b sshWriter
	b.writeString([]byte(AlgoSKEd25519))
	b.writeString(pub)
	b.writeString([]byte("ssh:aurvet"))
	line := string(AlgoSKEd25519) + " " + base64.StdEncoding.EncodeToString(b.bytes()) + " token"
	k, err := ParsePublicKey([]byte(line))
	if err != nil {
		t.Fatalf("sk key refused: %v", err)
	}
	if !k.HardwareBacked() {
		t.Fatal("sk-ssh-ed25519 must report hardware backing")
	}
	if k.Application != "ssh:aurvet" {
		t.Fatalf("application: %q", k.Application)
	}
	if k.AuthorizedKey() != line {
		t.Fatalf("round trip: %q", k.AuthorizedKey())
	}
}

func marshalEd25519Blob(pub ed25519.PublicKey) []byte {
	var w sshWriter
	w.writeString([]byte(AlgoEd25519))
	w.writeString(pub)
	return w.bytes()
}

func marshalShortEd25519Blob() []byte {
	var w sshWriter
	w.writeString([]byte(AlgoEd25519))
	w.writeString([]byte{1, 2, 3})
	return w.bytes()
}

// -- wire reader ------------------------------------------------------------

// The SSH wire reader is where a length prefix becomes an allocation, so it gets
// its own attacks: a 4GB length field in a 40-byte buffer must be a refusal, not
// a panic and not an allocation.
func TestSSHReaderRefusesLyingLengths(t *testing.T) {
	r := sshReader{buf: []byte{0xff, 0xff, 0xff, 0xff, 1, 2, 3}}
	if _, err := r.readString(); err == nil {
		t.Fatal("a length longer than the buffer must be refused")
	}
	r = sshReader{buf: []byte{0, 0, 0}}
	if _, err := r.readString(); err == nil {
		t.Fatal("a truncated length prefix must be refused")
	}
	r = sshReader{buf: []byte{0, 0, 0, 2, 'h', 'i', 'x'}}
	s, err := r.readString()
	if err != nil || string(s) != "hi" {
		t.Fatalf("readString: %q %v", s, err)
	}
	if err := r.atEnd(); err == nil {
		t.Fatal("trailing bytes must be refused")
	}
}
