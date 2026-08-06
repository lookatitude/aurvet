// internal/chain/store.go
//
// The chain on disk, and the payloads it commits to.
//
// # Crash safety
//
// Every write is temp + fsync + atomic rename, with the directory fsynced
// afterwards so the rename itself survives a power cut. There is no window in
// which the chain file is half a chain: a reader sees the old file or the new
// one. An interrupted append leaves the temp file unlinked and the old chain
// exactly as it was -- which is the correct outcome, because the alternative is
// a chain whose last entry is a fragment and whose verification therefore fails
// for a reason that looks identical to tampering.
//
// # Absent is not corrupt
//
// A payload with no valid signature reads as ABSENT. The two provoke different
// responses and must not be confused: absent means "there is no baseline here
// yet, make one"; corrupt means "something is wrong, investigate before you
// touch anything". Unauthenticated bytes are never handed back to the caller,
// so nothing downstream can act on them by accident.
//
// The chain FILE is the deliberate exception. A missing chain is absent, but a
// chain file whose header is not ours, or whose records do not verify, is an
// error -- treating that as "no chain yet" would invite writing a fresh chain
// over whatever is really there, which is exactly the outcome an attacker
// wants.
//
// # The file format
//
// A header line, then one line per record: the canonical entry JSON, a space,
// and the base64 of the armoured detached signature. Canonical JSON never
// contains a raw newline (control characters are escaped), so a record is
// always exactly one line, and the signature is base64ed rather than inlined
// because SSHSIG armour is multi-line. Line-oriented so that append is a
// concatenation and so a human can read what is there.
package chain

import (
	"bytes"
	"encoding/base64"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
)

// ChainFile is the chain's filename inside the store directory.
const ChainFile = "chain.log"

// FileHeader is the first line of a chain file. A version in the header, not
// only in the entries, so a future format change is a clear refusal rather than
// a parse that half works.
const FileHeader = "aurvet-chain-v1"

// SignatureSuffix is appended to a payload's filename to name its detached
// signature.
const SignatureSuffix = ".sig"

// payloadsSubdir holds the signed documents the chain commits to.
const payloadsSubdir = "payloads"

// maxChainBytes bounds a chain file. At ~600 bytes per record this is over a
// million entries: far past any real chain, and still a bound.
const maxChainBytes = 1 << 29

// maxPayloadBytes bounds one payload document.
const maxPayloadBytes = 1 << 27

var (
	// ErrChainFile reports a chain file that is not one. Distinct from an
	// absent chain, which is not an error.
	ErrChainFile = errors.New("chain: file is not an aurvet chain")

	// ErrOfflineRoot is INV-5: the destination is inside the tree being
	// examined.
	ErrOfflineRoot = errors.New("chain: refusing to write inside the examined tree")
)

// Store is a chain directory. Constructing one performs no I/O and takes no
// lock, so an offline or read-only caller can name a store it will only read.
type Store struct {
	dir string

	// beforeRename is a test seam for the crash-safety path: it runs after the
	// temp file is written and fsynced and before the rename, which is the one
	// interval where an interruption could plausibly leave the store in a state
	// nobody designed. Nil in production; nothing reads it from outside this
	// package.
	beforeRename func() error
}

// Open names a store. It does not create it.
func Open(dir string) *Store { return &Store{dir: dir} }

// Dir is the store directory.
func (s *Store) Dir() string { return s.dir }

// Path is the chain file.
func (s *Store) Path() string { return filepath.Join(s.dir, ChainFile) }

func (s *Store) payloadPath(digest string) string {
	return filepath.Join(s.dir, payloadsSubdir, digest+".json")
}

// -- loading -----------------------------------------------------------------

// Load reads and verifies the whole chain.
//
// A missing chain file is absent: no records, no error. Anything else that is
// wrong -- a foreign header, a malformed line, a signature that does not verify
// -- is an error, because "I could not read the chain" must never be presented
// as "there is no chain".
//
// Every record is authenticated before its bytes are parsed (ParseRecord), so a
// hostile chain file never reaches the JSON parser on the strength of an
// unchecked signature.
func (s *Store) Load(trusted []*baseline.PublicKey) ([]Record, error) {
	f, err := os.Open(s.Path())
	if errors.Is(err, os.ErrNotExist) {
		return nil, nil
	}
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	defer f.Close()

	b, err := io.ReadAll(io.LimitReader(f, maxChainBytes+1))
	if err != nil {
		return nil, fmt.Errorf("chain: %w", err)
	}
	if int64(len(b)) > maxChainBytes {
		return nil, fmt.Errorf("%w: over %d bytes", ErrChainFile, maxChainBytes)
	}
	return parseChainFile(b, trusted)
}

func parseChainFile(b []byte, trusted []*baseline.PublicKey) ([]Record, error) {
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if len(lines) == 0 || lines[0] != FileHeader {
		head := ""
		if len(lines) > 0 {
			head = lines[0]
		}
		return nil, fmt.Errorf("%w: first line is %q, want %q", ErrChainFile, head, FileHeader)
	}
	var out []Record
	for i, ln := range lines[1:] {
		if ln == "" {
			return nil, fmt.Errorf("%w: line %d is empty", ErrChainFile, i+2)
		}
		// The LAST space, not the first. Canonical JSON escapes control characters
		// but NOT spaces, so any entry whose note, host or payload namespace
		// contains one -- `"note":"baseline init"` is the first real example --
		// puts a space inside the JSON. Splitting on the first space then cut the
		// record in half: the file was written correctly and could never be read
		// again, and because an unreadable chain file is an ERROR rather than an
		// absent chain (see this file's header), one space in a note bricked the
		// chain permanently. Base64 contains no spaces, so the last space is
		// always the separator.
		sp := strings.LastIndexByte(ln, ' ')
		if sp < 0 {
			return nil, fmt.Errorf("%w: line %d has no signature field", ErrChainFile, i+2)
		}
		raw, encSig := ln[:sp], ln[sp+1:]
		sig, err := base64.StdEncoding.DecodeString(encSig)
		if err != nil {
			return nil, fmt.Errorf("%w: line %d signature: %v", ErrChainFile, i+2, err)
		}
		rec, err := ParseRecord([]byte(raw), sig, trusted)
		if err != nil {
			return nil, fmt.Errorf("chain: entry %d: %w", i, err)
		}
		out = append(out, rec)
	}
	return out, nil
}

func encodeChainFile(records []Record) []byte {
	var buf bytes.Buffer
	buf.WriteString(FileHeader)
	buf.WriteByte('\n')
	for _, r := range records {
		buf.Write(r.raw)
		buf.WriteByte(' ')
		buf.WriteString(base64.StdEncoding.EncodeToString(r.sig))
		buf.WriteByte('\n')
	}
	return buf.Bytes()
}

// -- appending ---------------------------------------------------------------

// AppendOptions is what an append needs to know before it is allowed to write.
type AppendOptions struct {
	// Trusted verifies the existing chain. An append onto a chain that cannot
	// be verified is an append onto something unknown.
	Trusted []*baseline.PublicKey

	// Root is the system root whose db.lck decides whether appending is allowed
	// at all. "" means the live system.
	Root string

	// OfflineRoot, when set, is the tree being examined; the store must not be
	// inside it (INV-5).
	OfflineRoot string

	// LockTimeout bounds the wait for the advisory lock.
	LockTimeout time.Duration
}

// Append adds one record under the advisory lock.
//
// build is called with the verified head so the caller can link its entry to
// what is actually there, not to what it read a moment ago outside the lock.
// That is the whole reason the callback exists: a read-modify-write split
// across the lock boundary is how two appenders manufacture a fork.
//
// The refusals happen in order and BEFORE build runs: no work, and no
// signature, is produced for a write that was never going to be allowed.
func (s *Store) Append(opt AppendOptions, build func(head *Record) (Record, error)) (Record, error) {
	if err := s.checkOfflineRoot(opt.OfflineRoot); err != nil {
		return Record{}, err
	}
	lock, err := DetectDBLock(opt.Root)
	if err != nil {
		return Record{}, err
	}
	if err := lock.GuardAppend(); err != nil {
		return Record{}, err
	}

	release, err := s.lock(opt.LockTimeout)
	if err != nil {
		return Record{}, err
	}
	defer release()

	existing, err := s.Load(opt.Trusted)
	if err != nil {
		return Record{}, err
	}
	if _, err := Verify(existing, VerifyOptions{Trusted: opt.Trusted}); err != nil && len(existing) > 0 {
		return Record{}, fmt.Errorf("chain: refusing to append to a chain that does not verify: %w", err)
	}

	var head *Record
	if n := len(existing); n > 0 {
		head = &existing[n-1]
	}
	rec, err := build(head)
	if err != nil {
		return Record{}, err
	}
	// The linkage is checked here, against the head the builder was handed,
	// before the whole-chain verification below. Two entries claiming the same
	// predecessor is a FORK when it is found in a file; from an appender it is
	// simply an entry that does not link, and reporting it as a fork would send
	// an operator looking for rewritten history that does not exist.
	if want := wantPrev(head); rec.Entry.PrevHash != want {
		return Record{}, fmt.Errorf("%w: the record names %s, the head hashes to %s",
			ErrPrevHash, short(rec.Entry.PrevHash), short(want))
	}
	if want := wantSeq(head); rec.Entry.Seq != want {
		return Record{}, fmt.Errorf("%w: the record carries seq %d, the head is at %d",
			ErrSequence, rec.Entry.Seq, want-1)
	}

	next := append(append([]Record(nil), existing...), rec)
	// The new chain must verify as a whole before it is written. A record that
	// does not link, or that replays a payload, is refused here rather than
	// written and discovered on the next run.
	if _, err := Verify(next, VerifyOptions{Trusted: opt.Trusted}); err != nil {
		return Record{}, err
	}
	if err := s.writeAtomic(s.Path(), encodeChainFile(next), 0o600); err != nil {
		return Record{}, err
	}
	return rec, nil
}

func wantPrev(head *Record) string {
	if head == nil || head.Zero() {
		return GenesisPrev
	}
	return head.Hash()
}

func wantSeq(head *Record) int64 {
	if head == nil || head.Zero() {
		return 0
	}
	return head.Entry.Seq + 1
}

func (s *Store) checkOfflineRoot(offline string) error {
	if offline == "" || offline == "/" {
		return nil
	}
	root, err := filepath.Abs(filepath.Clean(offline))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOfflineRoot, err)
	}
	dir, err := filepath.Abs(filepath.Clean(s.dir))
	if err != nil {
		return fmt.Errorf("%w: %v", ErrOfflineRoot, err)
	}
	if dir == root || strings.HasPrefix(dir, root+string(filepath.Separator)) {
		return fmt.Errorf("%w: %s is inside %s, and a scan must not write into the filesystem "+
			"it is auditing", ErrOfflineRoot, dir, root)
	}
	return nil
}

// -- payloads ----------------------------------------------------------------

// PayloadState is present-or-absent. There is deliberately no "corrupt".
type PayloadState int

const (
	// PayloadAbsent means there is nothing here that can be trusted: no file,
	// no signature, a signature that does not verify, a signature from a key
	// outside the trusted set, or bytes that are not the document asked for.
	PayloadAbsent PayloadState = iota

	// PayloadPresent means the bytes were signed by a trusted key under the
	// namespace asked for and hash to the digest asked for.
	PayloadPresent
)

func (s PayloadState) String() string {
	if s == PayloadPresent {
		return "present"
	}
	return "absent"
}

// PayloadResult is what LoadPayload found.
type PayloadResult struct {
	State PayloadState

	// Raw is populated only when State is PayloadPresent. Unauthenticated bytes
	// are never returned: a caller cannot act on what it was not given.
	Raw []byte

	Key *baseline.PublicKey

	// Reason says why an absent payload is absent. Never empty when absent:
	// "no baseline" and "a baseline whose signature does not verify" call for
	// different human responses, even though both read as absent to the code.
	Reason string
}

// PutPayload stores a signed document and returns the digest it is filed under.
//
// The signature is stored beside it, unmodified. The digest is computed here
// rather than accepted from the caller, so the name of the file is always a
// fact about its contents.
func (s *Store) PutPayload(ns baseline.Namespace, raw, sig []byte) (string, error) {
	if int64(len(raw)) > maxPayloadBytes {
		return "", fmt.Errorf("chain: payload over %d bytes", maxPayloadBytes)
	}
	got, err := baseline.SignatureNamespace(sig)
	if err != nil {
		return "", err
	}
	if got != ns {
		return "", fmt.Errorf("%w: the signature claims namespace %q, this payload is %q",
			baseline.ErrSignature, got, ns)
	}
	d := baseline.DigestBytes(raw)
	digest := baseline.Hex(d[:])
	if err := os.MkdirAll(filepath.Join(s.dir, payloadsSubdir), 0o700); err != nil {
		return "", fmt.Errorf("chain: %w", err)
	}
	// Signature first, then the document. Either order leaves a window; this
	// one leaves the window on the side that reads as absent rather than as a
	// document with no signature.
	if err := s.writeAtomic(s.payloadPath(digest)+SignatureSuffix, sig, 0o600); err != nil {
		return "", err
	}
	if err := s.writeAtomic(s.payloadPath(digest), raw, 0o600); err != nil {
		return "", err
	}
	return digest, nil
}

// LoadPayload authenticates a stored document.
//
// Nothing that fails to authenticate is an error. An error from this function
// means the store could not be READ -- a permission problem, a broken disk --
// which is a coverage gap the caller must report (INV-9). Everything else is
// absent, with a reason.
func (s *Store) LoadPayload(digest string, ns baseline.Namespace, trusted []*baseline.PublicKey) (PayloadResult, error) {
	if err := validDigest(digest); err != nil {
		return PayloadResult{Reason: fmt.Sprintf("not a payload digest: %v", err)}, nil
	}
	raw, err := readCapped(s.payloadPath(digest), maxPayloadBytes)
	if errors.Is(err, os.ErrNotExist) {
		return PayloadResult{Reason: "no payload is stored under this digest"}, nil
	}
	if err != nil {
		return PayloadResult{}, fmt.Errorf("chain: %w", err)
	}
	sig, err := readCapped(s.payloadPath(digest)+SignatureSuffix, maxPayloadBytes)
	if errors.Is(err, os.ErrNotExist) {
		return PayloadResult{Reason: "the payload has no signature beside it, so it reads as absent"}, nil
	}
	if err != nil {
		return PayloadResult{}, fmt.Errorf("chain: %w", err)
	}

	canon, key, err := baseline.VerifyCanonical(sig, ns, raw, trusted)
	if err != nil {
		return PayloadResult{Reason: fmt.Sprintf("the payload does not verify under %s, so it reads "+
			"as absent: %v", ns, err)}, nil
	}
	d := baseline.DigestBytes(canon)
	if got := baseline.Hex(d[:]); got != digest {
		return PayloadResult{Reason: fmt.Sprintf("the stored bytes hash to %s, not the %s they are "+
			"filed under", short(got), short(digest))}, nil
	}
	return PayloadResult{State: PayloadPresent, Raw: canon, Key: key}, nil
}

func readCapped(path string, max int64) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	b, err := io.ReadAll(io.LimitReader(f, max+1))
	if err != nil {
		return nil, err
	}
	if int64(len(b)) > max {
		return nil, fmt.Errorf("%s is over %d bytes", path, max)
	}
	return b, nil
}

// -- atomic write ------------------------------------------------------------

// writeAtomic writes to a temp file in the destination directory, fsyncs it,
// renames it into place and then fsyncs the directory.
//
// Each step is load-bearing. Same directory, or the rename would cross a
// filesystem and stop being atomic. fsync the file, or the rename can land
// while the contents are still in cache and a crash leaves a correctly named
// empty file. fsync the directory, or the rename itself can be lost. A failure
// anywhere removes the temp file: no debris beside a chain that must be
// unambiguous.
func (s *Store) writeAtomic(path string, data []byte, perm os.FileMode) error {
	dir := filepath.Dir(path)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	tmp, err := os.CreateTemp(dir, "."+filepath.Base(path)+".tmp-*")
	if err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	tmpName := tmp.Name()
	cleanup := func() { _ = os.Remove(tmpName) }

	if err := tmp.Chmod(perm); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chain: %w", err)
	}
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chain: %w", err)
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		cleanup()
		return fmt.Errorf("chain: %w", err)
	}
	if err := tmp.Close(); err != nil {
		cleanup()
		return fmt.Errorf("chain: %w", err)
	}
	if s.beforeRename != nil {
		if err := s.beforeRename(); err != nil {
			cleanup()
			return err
		}
	}
	if err := os.Rename(tmpName, path); err != nil {
		cleanup()
		return fmt.Errorf("chain: %w", err)
	}
	return syncDir(dir)
}

func syncDir(dir string) error {
	d, err := os.Open(dir)
	if err != nil {
		return fmt.Errorf("chain: %w", err)
	}
	defer d.Close()
	if err := d.Sync(); err != nil {
		return fmt.Errorf("chain: fsync %s: %w", dir, err)
	}
	return nil
}
