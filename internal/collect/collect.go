// internal/collect/collect.go
//
// Package collect is phase 1 of the staged privilege model (spec §11.1): the
// only part of aurvet that runs while holding CAP_DAC_READ_SEARCH.
//
// IT CONTAINS NO PARSERS, and that is the architectural point of P1-B rather
// than a style preference. The tool's job is parsing attacker-controlled input
// while needing to read root-only files; those two requirements are separated in
// time instead of accepted together. This package therefore does five things --
// directory walk, confined open, fstat, streaming sha256, and a newline split of
// the local database's plain-text `files` to learn which paths to open -- and
// buffers raw bytes for everything else. Decompression, tokenising and
// interpretation all happen after the capability is dropped, so a parser bug is
// an unprivileged bug. RecordedPolicy states why the fifth is a name list rather
// than a parser, and where the line is.
//
// The tier decides HOW MUCH is read here, not later: after the drop this process
// can read nothing a normal user cannot, so a verification tier whose hash set
// were chosen in phase 2 would be a tier that silently could not do its job.
//
// The consequence is stated plainly because it constrains future work: anything
// this collector did not buffer is unavailable to analysis for that run, by
// construction. A new check that needs evidence phase 1 does not gather requires
// changing this file, not just the analyser.
//
// Nothing here presents file hashing as novel -- `pacman -Qkk` verifies the same
// digests. What this collector adds is offline-root operation, parallelism, and
// evidence as data: structured output, correlation input, and the raw mtree
// bytes P4's baseline hashes so that tampering with the mtree itself becomes
// detectable.
package collect

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"hash/maphash"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/safe"
)

// The kinds of thing phase 1 finds. The first four are the strings mtree writes
// for its type= keyword, so the analyse phase compares Kind against Entry.Type
// directly rather than translating between two vocabularies -- a translation
// table is somewhere for a mismatch to hide. The last two exist because asking
// about a RECORDED path can produce two answers a walk never produces: the path
// is not there, and the path is there but could not be examined coherently.
const (
	KindFile  = "file"
	KindLink  = "link"
	KindDir   = "dir"
	KindOther = "other" // fifo, socket, device: recorded, never opened for content

	// KindAbsent: the confined open returned ENOENT. An observed absence, and
	// deliberately NOT a gap -- a packaged file that was deleted is a fact this
	// phase established, not a hole in its coverage.
	KindAbsent = "absent"

	// KindUnread: the path exists in some form and could not be examined --
	// refused as a symlink component, unreadable, mutated mid-scan. Unread
	// carries the reason, and there is ALWAYS a Gap naming the same subject, so
	// the analyse phase consumes this rather than raising a second gap for the
	// same shortfall.
	KindUnread = "unread"
)

// RecordedPolicy says what phase 1 does with the paths the local database's
// plain-text `files` records. It is how a verification tier's hash set is
// decided BEFORE the capability is dropped, which it has to be: after the drop
// the process holds nothing, so a phase-2 decision to read a root-only file is a
// decision that fails.
//
// WHY READING `files` IS NOT A PARSER (spec §11.1). `files` is plain text and
// its %FILES% section is a newline-delimited list of names; extracting it is a
// newline split and a prefix test. Phase 1 already turns attacker-controlled
// bytes into names -- getdents returns directory entries from a hostile
// filesystem and the walk splits and joins them into paths -- so this is the
// same operation through a different syscall. What §11.1 keeps out of the
// privileged phase is a FORMAT parser: nested, escaped, compressed or
// length-prefixed input that can be driven into a bug. The mtree is gzip and
// carries vis(3) escapes, so it stays in phase 2; `files` has none of those
// properties. Nothing here decompresses, unescapes, or interprets a field.
type RecordedPolicy int

const (
	// RecordedIgnore: the recorded paths are not visited at all. The zero value,
	// so a caller that does not ask for them does not silently get them.
	RecordedIgnore RecordedPolicy = iota

	// RecordedStat: each recorded path is opened once, confined, and fstat'd.
	// Nothing is read. This is what tier meta needs -- a missing file, a swapped
	// symlink and a fifo are all still established from a descriptor.
	RecordedStat

	// RecordedSecurity: RecordedStat, plus a digest for everything the
	// DESCRIPTOR'S OWN MODE says decides what runs (executable, setuid, setgid,
	// sticky) and everything under a watched path. This is tier triage.
	RecordedSecurity

	// RecordedAll: every recorded regular file is hashed. This is tier full and
	// tier paranoid.
	RecordedAll
)

// ErrConfig reports a configuration that cannot be collected from. It is the one
// error Collect returns: every other failure is a coverage gap attributed to a
// subject (INV-9), because a scan that aborts on the first refused file reports
// nothing about the thousands of files it never reached.
var ErrConfig = errors.New("collect: invalid configuration")

// beforeHashForTest runs after a file's descriptor is open and before its digest
// is taken. Production leaves it nil; collect_test.go uses it to reach the three
// windows a test cannot open from outside -- a panic mid-subject, a hang
// mid-subject, and a rewrite between the open and the re-fstat. Same device as
// fsx's afterHashForTest, for the same reason.
var beforeHashForTest func(rel string)

// Config is the collector's whole input. Collect is a pure function of it
// (INV-4): no ambient paths, no dependence on the working directory, and
// --offline-root is the Root field rather than a second code path.
type Config struct {
	// Root is the absolute path of the tree being examined: "/" for a live
	// system, a mountpoint under --offline-root.
	Root string

	// DBPath is the pacman local database, absolute and inside Root. Its raw
	// desc/files/mtree bytes are buffered here because they are unreadable
	// after the drop.
	DBPath string

	// Walk lists subtrees to walk, relative to Root. Empty means the whole
	// tree. Every regular file found under one is hashed.
	Walk []string

	// Sweep lists subtrees enumerated for METADATA ONLY: every entry is
	// described from the fstat of a confined open and nothing is read. It is
	// what the unowned-file and setuid sweeps need, and separating it from Walk
	// is what keeps those sweeps from silently costing a full-tree hash.
	Sweep []string

	// Recorded says what to do with the paths the local database records. See
	// RecordedPolicy: this is where a tier's hash set is decided, while the
	// capability is still held.
	Recorded RecordedPolicy

	// Skip lists subtrees never entered, relative to Root. What lands here is
	// recorded in Raw.Skipped so a report can state it: a skip the operator
	// cannot see is a silent hole (INV-3).
	Skip []string

	// BufferPaths lists individual files, relative to Root, whose raw bytes are
	// buffered verbatim -- the surface files (units, hooks) later phases parse
	// unprivileged.
	BufferPaths []string

	// Workers is the number of concurrent hashing goroutines.
	Workers int

	// SubjectTimeout bounds one file. A hang is bounded rather than terminal;
	// zero means unbounded.
	SubjectTimeout time.Duration

	// MaxBufferBytes caps everything buffered in memory, and MaxDBFileBytes
	// caps any single buffered file. Both are hostile-input bounds: a local
	// database is attacker-writable on a compromised host, and an unbounded
	// read there is a memory-exhaustion primitive against the PRIVILEGED phase.
	MaxBufferBytes int64
	MaxDBFileBytes int64

	// MaxFiles and MaxDepth bound the walk itself, so a crafted tree cannot
	// turn it into unbounded memory or unbounded recursion.
	MaxFiles int64
	MaxDepth int
}

// DefaultConfig returns the configuration used against a real root. The measured
// numbers behind the bounds are in the field comments; the caller overrides what
// it must and leaves the rest.
func DefaultConfig(root string) Config {
	return Config{
		Root:   root,
		DBPath: filepath.Join(root, "var/lib/pacman/local"),
		Walk:   nil,
		Skip:   DefaultSkip(),
		// Hashing is I/O bound, so more workers than cores still helps, but the
		// cap keeps the fd count and the kernel's readahead pressure sane.
		Workers:        min(2*runtime.NumCPU(), 16),
		SubjectTimeout: 30 * time.Second,
		// 41 MB is the measured buffer on the reference system (16.2 MB
		// compressed mtree, 24.1 MB files, 0.7 MB desc, 0.4 MB surface files).
		// 256 MB is ~6x that: far above legitimate use, far below hurting the
		// host.
		MaxBufferBytes: 256 << 20,
		// The largest single mtree measured is 5.7 MB.
		MaxDBFileBytes: 64 << 20,
		// ~325k packaged paths are recorded on the reference system; a full walk
		// of a live root sees more, so this is deliberately loose.
		MaxFiles: 4 << 20,
		MaxDepth: 128,
	}
}

// DefaultSkip lists the subtrees a walk must not enter. Each is here for a
// stated reason, because a skip list is where coverage quietly disappears:
//
//   - proc, sys: pseudo-filesystems. Reading them is not reading files, and
//     /proc/kcore alone is terabytes of address space.
//   - dev: device nodes. A read of the wrong one blocks or drains entropy.
//   - run: tmpfs of sockets and pid files; nothing packaged lives there.
//   - tmp, var/tmp, var/cache: volatile by definition, nothing digest-covered.
//   - home, root, media, mnt: user and removable data. Not package-owned, and
//     hashing a user's home directory is a surprise a security tool should not
//     spring. Persistence surfaces under home are P1-C's business, reached by
//     explicit path rather than by a blanket walk.
//
// Nothing digest-covered is lost: the analyse phase compares mtree records
// against this evidence, so a packaged path that a skip hid is a gap THERE. This
// list can hide unowned files, not owned ones.
func DefaultSkip() []string {
	return []string{"proc", "sys", "dev", "run", "tmp", "var/tmp", "var/cache",
		"home", "root", "media", "mnt", "lost+found"}
}

// Package is one local-database directory, buffered as bytes. The directory name
// is NOT split into name and version here: that is parsing, and it happens after
// the drop.
type Package struct {
	// Dir is the directory name as it appears in the database, e.g.
	// "a52dec-0.8.0-1".
	Dir string

	// Desc, FileList and MTree are the raw bytes of desc, files and mtree.
	// MTree is still gzipped -- decompressing it here would put a decompressor
	// in the privileged phase, which is exactly what the split forbids.
	Desc     []byte
	FileList []byte
	MTree    []byte
}

// File is one walked filesystem object, described entirely by the fstat of the
// descriptor that was used to read it.
type File struct {
	// Path is "./"-rooted, matching how mtree records paths, so the analyse
	// phase joins the two without rewriting either.
	Path string
	Kind string

	// SHA256 is the lowercase hex digest, streamed from the open descriptor. It
	// is empty for everything that is not a regular file, and empty for a
	// regular file whose digest could not be established -- in which case there
	// is a Gap naming it. An empty digest is never "no content".
	SHA256 string

	Size int64

	// Mode is the permission word only (st.Mode & 0o7777), so it compares
	// directly against mtree's mode= and still carries the setuid, setgid and
	// sticky bits the SUID/SGID checks read.
	Mode uint32

	UID, GID uint32
	Nlink    uint64

	// Ino and Dev identify the object that was actually examined, and are what
	// makes the hardlink population analysable after the fact.
	Ino, Dev uint64

	// Mtime is the modification time as the kernel reports it. Seconds and
	// nanoseconds are kept separate rather than folded into a float: mtree's
	// time= is a float and the analyse phase decides how to compare them, but
	// evidence should not lose precision before that decision is made.
	Mtime, MtimeNsec int64

	// Link is the recorded target of a symlink, decoded from the kernel and NOT
	// resolved. 4,145 legitimate targets on the reference system contain "..";
	// resolving them would manufacture findings, and following them while
	// holding read capability over the whole filesystem would be worse.
	Link string

	// Unread is why this path could not be examined, set only with KindUnread.
	// A Gap with the same subject was raised alongside it, so a consumer states
	// the shortfall once rather than twice.
	Unread string
}

// Raw is everything phase 1 buffered, and the only thing the analyse phase gets
// to see. Nothing in it has been interpreted.
type Raw struct {
	// Root echoes the tree this evidence describes, so a Raw is
	// self-identifying once it leaves the collector.
	Root string

	Packages []Package
	Files    []File

	// Buffered maps a requested BufferPaths entry to its raw bytes.
	Buffered map[string][]byte

	// DBListed reports whether the local database directory was enumerated at
	// all. It is not derivable from len(Packages): a database that lists but
	// holds nothing and a database that could not be opened both yield zero
	// packages, and the caller owes its user different answers for the two --
	// an empty system versus a scan that never had an oracle. There is a Gap
	// carrying the reason in the second case.
	DBListed bool

	// Skipped lists the subtrees that were not entered, "./"-rooted.
	Skipped []string

	// Gaps are the subjects that could not be examined. Every refusal, panic,
	// timeout and bound in this package lands here: incomplete coverage is
	// reported as incomplete (INV-3) and drives exit 3.
	Gaps []finding.Gap

	// BufferedBytes is what the buffers actually cost, for comparison against
	// the ~41 MB measured budget.
	BufferedBytes int64
}

// ByPath indexes Files on their "./"-rooted path, which is the form mtree
// records, so the analyse phase joins evidence to records without rewriting
// either. One path yields one File: the collector already deduplicates its
// leaves, so a duplicate here would be a bug rather than a shape to merge.
//
// It COPIES every File into the map, which is what Index exists to avoid: on
// the reference system that copy is 63 MiB of live heap for 392,343 records,
// second only to Files itself. Prefer Index; this remains for callers that want
// a plain map and for the tests that pin Index's contract to it.
func (r Raw) ByPath() map[string]File {
	m := make(map[string]File, len(r.Files))
	for _, f := range r.Files {
		m[f.Path] = f
	}
	return m
}

// Index answers ByPath's question -- what did phase 1 record for this
// "./"-rooted path -- without a second copy of the evidence.
//
// It is a side table of slice positions over Files, so the per-path cost is one
// machine word instead of a whole File plus a map entry: 6.3 MiB instead of 63
// MiB on the reference system. That matters more than it sounds, because peak
// RSS tracks LIVE heap at roughly 2:1 under the default GOGC -- measured, not
// assumed -- so a MiB not retained is about two MiB the process never asks the
// kernel for.
//
// The hash is seeded per Index rather than fixed. Paths come from the
// filesystem being examined and from packages' own `files` lists, both
// attacker-controlled on a compromised host, and a fixed hash over
// attacker-chosen keys is a collision-flooding primitive that would turn one
// lookup into a linear scan. runtime maps are seeded for exactly this reason and
// nothing here may be weaker than the map it replaces.
//
// Index does not copy Files and does not own it. A caller that mutates Files
// afterwards changes what Lookup answers, which is the same relationship a slice
// has with a subslice; Collect hands out evidence it has already closed, so no
// production caller is in that position.
type Index struct {
	files   []File
	slots   []int32 // position in files, plus one; zero means empty
	mask    uint64
	seed    maphash.Seed
	entries int
}

// indexSlotLimit is the largest population Index will build a side table for.
// Above it a slot cannot address the slice in an int32, which is a silently
// wrong answer rather than a slow one, so Index falls back to a linear scan and
// says so here rather than truncating. Config.MaxFiles is 4Mi, so nothing a
// collector produces comes near it.
const indexSlotLimit = 1 << 30

// Index builds the lookup. It is O(len(Files)) and allocates one slot table.
func (r Raw) Index() Index {
	ix := Index{files: r.Files, seed: maphash.MakeSeed(), entries: len(r.Files)}
	if len(r.Files) == 0 || len(r.Files) > indexSlotLimit {
		ix.entries = distinctPaths(r.Files)
		return ix
	}
	// Load factor 0.5, so a lookup terminates within a few probes even when the
	// table is full of near-collisions.
	n := 1
	for n < 2*len(r.Files) {
		n <<= 1
	}
	ix.slots = make([]int32, n)
	ix.mask = uint64(n - 1)
	ix.entries = 0
	for i := range r.Files {
		p := r.Files[i].Path
		h := maphash.String(ix.seed, p) & ix.mask
		for {
			switch s := ix.slots[h]; {
			case s == 0:
				ix.slots[h] = int32(i) + 1
				ix.entries++
			case r.Files[s-1].Path == p:
				// Last writer wins, which is what a map assignment does. A
				// duplicate is a collector bug either way; the two lookups
				// disagreeing about which File it meant would be worse.
				ix.slots[h] = int32(i) + 1
			default:
				h = (h + 1) & ix.mask
				continue
			}
			break
		}
	}
	return ix
}

// Lookup returns the evidence phase 1 recorded for a "./"-rooted path.
func (ix Index) Lookup(path string) (File, bool) {
	if len(ix.slots) == 0 {
		for i := range ix.files {
			if ix.files[i].Path == path {
				return ix.files[i], true
			}
		}
		return File{}, false
	}
	for h := maphash.String(ix.seed, path) & ix.mask; ; h = (h + 1) & ix.mask {
		s := ix.slots[h]
		if s == 0 {
			return File{}, false
		}
		if f := &ix.files[s-1]; f.Path == path {
			return *f, true
		}
	}
}

// Len is the number of distinct paths the index answers for, so a caller can
// compare it against what it expected to be examined.
func (ix Index) Len() int { return ix.entries }

// distinctPaths counts distinct paths the slow way, for the population Index
// refuses to build a slot table for.
func distinctPaths(files []File) int {
	seen := make(map[string]struct{}, len(files))
	for i := range files {
		seen[files[i].Path] = struct{}{}
	}
	return len(seen)
}

// Complete reports whether every subject was examined. It mirrors
// finding.Result.Complete so a caller cannot forget that a Raw with gaps is not
// a clean sweep.
func (r Raw) Complete() bool { return len(r.Gaps) == 0 }

// Collect walks cfg.Root, opens every file through fsx.OpenConfined, streams
// sha256 from that same descriptor, and buffers the raw database bytes.
//
// It returns an error only for a configuration it cannot act on. Everything
// else -- an unreadable file, a swapped path, a panic, a hang, a bound reached
// -- is a Gap on the returned Raw, because a partial answer plus an honest
// account of what is missing is the only useful output of a scan over a hostile
// filesystem.
func Collect(cfg Config) (Raw, error) {
	cfg, dbRel, err := cfg.normalise()
	if err != nil {
		return Raw{}, err
	}

	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		return Raw{}, fmt.Errorf("%w: opening root %q: %w", ErrConfig, cfg.Root, err)
	}
	defer root.Close()

	c := &collector{
		cfg:  cfg,
		root: root,
		raw: Raw{
			Root:     cfg.Root,
			Buffered: map[string][]byte{},
		},
	}

	// The database first. It is the evidence that becomes unreadable the moment
	// the capability is dropped, so it is not left until after a walk that a
	// bound might cut short.
	c.collectDB(dbRel)
	c.collectBufferPaths()

	// Then the walk, which produces the leaf paths, the recorded paths the
	// database named, and the one pass that opens each of them exactly once.
	leaves := c.walk()
	leaves = c.appendRecorded(leaves)
	c.hashAll(leaves)

	sort.Slice(c.raw.Packages, func(i, j int) bool { return c.raw.Packages[i].Dir < c.raw.Packages[j].Dir })
	sort.Slice(c.raw.Files, func(i, j int) bool { return c.raw.Files[i].Path < c.raw.Files[j].Path })
	sort.Slice(c.raw.Gaps, func(i, j int) bool {
		if c.raw.Gaps[i].Subject != c.raw.Gaps[j].Subject {
			return c.raw.Gaps[i].Subject < c.raw.Gaps[j].Subject
		}
		return c.raw.Gaps[i].Reason < c.raw.Gaps[j].Reason
	})
	sort.Strings(c.raw.Skipped)

	// Close the evidence before handing it out: see collector.done.
	c.mu.Lock()
	c.done = true
	raw := c.raw
	c.mu.Unlock()

	return raw, nil
}

// normalise validates the configuration and returns it with defaults filled in,
// together with the database path made relative to Root.
//
// A relative Root is refused rather than resolved against the working directory:
// that is precisely the ambient-path dependency INV-4 exists to prevent, and a
// privileged process resolving a relative path is a privileged process trusting
// whoever set its cwd.
func (cfg Config) normalise() (Config, string, error) {
	if !filepath.IsAbs(cfg.Root) {
		return cfg, "", fmt.Errorf("%w: root %q is not absolute", ErrConfig, cfg.Root)
	}
	cfg.Root = filepath.Clean(cfg.Root)

	dbRel := ""
	if cfg.DBPath != "" {
		rel, err := filepath.Rel(cfg.Root, filepath.Clean(cfg.DBPath))
		if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
			return cfg, "", fmt.Errorf("%w: db path %q is outside root %q", ErrConfig, cfg.DBPath, cfg.Root)
		}
		dbRel = rel
	}

	def := DefaultConfig(cfg.Root)
	if cfg.Workers <= 0 {
		cfg.Workers = def.Workers
	}
	if cfg.MaxBufferBytes <= 0 {
		cfg.MaxBufferBytes = def.MaxBufferBytes
	}
	if cfg.MaxDBFileBytes <= 0 {
		cfg.MaxDBFileBytes = def.MaxDBFileBytes
	}
	if cfg.MaxFiles <= 0 {
		cfg.MaxFiles = def.MaxFiles
	}
	if cfg.MaxDepth <= 0 {
		cfg.MaxDepth = def.MaxDepth
	}
	if len(cfg.Walk) == 0 {
		cfg.Walk = []string{"."}
	}
	return cfg, dbRel, nil
}

// collector holds the mutable state of one Collect call. It is not exported and
// does not outlive the call: Collect's purity is the reason.
type collector struct {
	cfg  Config
	root *os.Root

	mu  sync.Mutex // guards raw during the concurrent hash pass
	raw Raw

	// done closes the evidence. A subject abandoned by safe.RunTimeout keeps
	// running -- Go cannot interrupt a goroutine -- and would otherwise append
	// to the evidence AFTER Collect returned it, which is both a data race on
	// the returned value and a claim about a file the scan already reported it
	// could not examine. Late records are dropped; the gap that named the
	// timeout is the honest account.
	done bool
}

func (c *collector) gap(ruleID, subject, format string, args ...any) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.raw.Gaps = append(c.raw.Gaps, finding.Gap{
		RuleID:  ruleID,
		Subject: subject,
		Reason:  fmt.Sprintf(format, args...),
	})
}

func (c *collector) addFile(f File) {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.done {
		return
	}
	c.raw.Files = append(c.raw.Files, f)
}

// ---------------------------------------------------------------- database ----

// collectDB buffers the raw desc, files and mtree of every package directory.
//
// Enumeration mirrors alpm.LoadLocalDB's measured rules -- a non-directory entry
// is a gap unless it is exactly ALPM_DB_VERSION, the entire benign
// non-directory population of that directory -- but nothing here interprets a
// byte of what it reads.
func (c *collector) collectDB(dbRel string) {
	if dbRel == "" {
		return
	}
	dir, err := c.openDirRel(dbRel)
	if err != nil {
		c.gap("collect-db", dbRel, "local database could not be opened: %v; no package metadata was buffered, so every integrity verdict in this run is unreliable", err)
		return
	}
	defer dir.Close()

	names, err := dir.ReadDir(-1)
	if err != nil {
		c.gap("collect-db", dbRel, "local database could not be listed: %v", err)
		return
	}
	c.mu.Lock()
	c.raw.DBListed = true
	c.mu.Unlock()

	for _, e := range names {
		switch {
		case e.IsDir():
		case e.Type()&fs.ModeSymlink != 0, e.Type().IsRegular():
			// ALPM_DB_VERSION is the one expected non-directory. Anything else
			// is unexpected, and unexpected is a gap: the measured cost of that
			// rule on the reference system is zero gaps, which is what makes it
			// affordable.
			if e.Name() != "ALPM_DB_VERSION" {
				c.gap("collect-db", e.Name(), "database entry is not a directory (%s); no metadata was buffered for it", e.Type())
			}
			continue
		default:
			c.gap("collect-db", e.Name(), "database entry is not a directory (%s); no metadata was buffered for it", e.Type())
			continue
		}

		pkg := Package{Dir: e.Name()}
		pkg.Desc = c.bufferDBFile(dbRel, e.Name(), "desc")
		pkg.FileList = c.bufferDBFile(dbRel, e.Name(), "files")
		pkg.MTree = c.bufferDBFile(dbRel, e.Name(), "mtree")

		c.mu.Lock()
		c.raw.Packages = append(c.raw.Packages, pkg)
		c.mu.Unlock()
	}
}

// bufferDBFile reads one database file whole, through the same confined open
// every other read in this package uses. A missing mtree or files is a gap, not
// a fatal error: one unreadable package must not cost the other 1409.
func (c *collector) bufferDBFile(dbRel, pkgDir, name string) []byte {
	rel := path3(dbRel, pkgDir, name)
	subject := pkgDir + "/" + name

	f, st, err := fsx.OpenConfined(c.root, rel)
	if err != nil {
		c.gap("collect-db", subject, "could not be read: %v", err)
		return nil
	}
	defer f.Close()

	if st.Size > c.cfg.MaxDBFileBytes {
		c.gap("collect-db", subject, "is %d bytes, over the %d-byte per-file buffer ceiling; it was not buffered and cannot be analysed",
			st.Size, c.cfg.MaxDBFileBytes)
		return nil
	}
	if !c.reserve(st.Size) {
		c.gap("collect-db", subject, "not buffered: the %d-byte buffer ceiling was reached, so this package was not analysed",
			c.cfg.MaxBufferBytes)
		return nil
	}

	// Bounded by the ceiling checked above, and re-checked while reading: the
	// size came from an fstat and a file can grow between the two.
	b, err := readAll(f, st.Size, c.cfg.MaxDBFileBytes)
	if err != nil {
		c.release(st.Size)
		c.gap("collect-db", subject, "could not be read: %v", err)
		return nil
	}
	// The re-fstat is not optional even here: a database file swapped
	// mid-collection would otherwise be buffered as if it were coherent.
	if err := fsx.CheckUnchanged(f, st); err != nil {
		c.release(st.Size)
		c.gap("collect-db", subject, "%v; the bytes read were not coherent and were discarded", err)
		return nil
	}
	c.release(st.Size)
	c.reserve(int64(len(b)))
	return b
}

// collectBufferPaths buffers the individual files a later phase will parse.
func (c *collector) collectBufferPaths() {
	for _, p := range c.cfg.BufferPaths {
		rel := strings.TrimPrefix(p, "./")
		f, st, err := fsx.OpenConfined(c.root, rel)
		if err != nil {
			c.gap("collect-buffer", p, "could not be read: %v; nothing that needs its contents can be analysed", err)
			continue
		}
		if st.Size > c.cfg.MaxDBFileBytes {
			c.gap("collect-buffer", p, "is %d bytes, over the %d-byte per-file buffer ceiling", st.Size, c.cfg.MaxDBFileBytes)
			f.Close()
			continue
		}
		if !c.reserve(st.Size) {
			c.gap("collect-buffer", p, "not buffered: the %d-byte buffer ceiling was reached", c.cfg.MaxBufferBytes)
			f.Close()
			continue
		}
		b, err := readAll(f, st.Size, c.cfg.MaxDBFileBytes)
		if err == nil {
			err = fsx.CheckUnchanged(f, st)
		}
		f.Close()
		c.release(st.Size)
		if err != nil {
			c.gap("collect-buffer", p, "could not be read: %v", err)
			continue
		}
		c.reserve(int64(len(b)))

		c.mu.Lock()
		c.raw.Buffered[p] = b
		c.mu.Unlock()
	}
}

// reserve accounts for size against the buffer ceiling, reporting whether it
// fits. release gives an accounted reservation back.
func (c *collector) reserve(size int64) bool {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.raw.BufferedBytes+size > c.cfg.MaxBufferBytes {
		return false
	}
	c.raw.BufferedBytes += size
	return true
}

func (c *collector) release(size int64) {
	c.mu.Lock()
	defer c.mu.Unlock()
	c.raw.BufferedBytes -= size
}

// -------------------------------------------------------------------- walk ----

// hashPolicy is what one leaf's descriptor is read for. It is decided before the
// open and, for hashIfSecurity, completed from the fstat of the descriptor that
// would be hashed -- never from a stat of the path taken separately.
type hashPolicy int

const (
	hashNever      hashPolicy = iota // opened, fstat'd, not read
	hashIfSecurity                   // read if the descriptor's own mode says it decides what runs
	hashAlways                       // read
)

// leaf is a path phase 1 will open exactly once: a regular file the walk found,
// an entry whose type the kernel would not name in its dirent, or a path the
// local database records.
type leaf struct {
	rel    string // "./"-rooted, as recorded
	open   string // the same path without "./", as fsx wants it
	policy hashPolicy

	// recorded marks a leaf that came from the database rather than from the
	// walk. It changes how absence and a symlink leaf are treated: for a
	// recorded path both are answers, for a walked path they cannot occur.
	recorded bool
}

// walk enumerates the configured subtrees and records everything it can describe
// without reading content -- directories, symlinks, and the fifos, sockets and
// devices that must never be opened for content. It returns the regular files
// for the hash pass.
//
// Descent uses openat(2) from the parent's descriptor with O_NOFOLLOW, so a
// directory this walk enters is the directory it listed. It never re-resolves a
// path it has already walked, and it never follows a symlink to a directory: a
// symlinked directory is evidence about the link, not a second place to look.
func (c *collector) walk() []leaf {
	var leaves []leaf
	for _, sub := range c.cfg.Walk {
		c.walkSubtree(sub, hashAlways, false, &leaves)
	}
	for _, sub := range c.cfg.Sweep {
		c.walkSubtree(sub, hashNever, true, &leaves)
	}
	return leaves
}

// walkSubtree enters one configured subtree. policy is what its regular files
// are opened for; optional says a subtree that is simply not there is an answer
// rather than a hole.
//
// The distinction matters. A Walk subtree is named explicitly, so its absence is
// a configuration the caller should hear about. A Sweep subtree comes from a
// standard set -- usr, etc, opt, boot, srv -- and not every root has every one of
// them; gapping the missing ones would put a permanent exit 3 on every machine
// without /opt, which trains an operator to ignore code 3. Only ENOENT is
// forgiven: a subtree that exists and could not be opened is still a hole.
func (c *collector) walkSubtree(sub string, policy hashPolicy, optional bool, leaves *[]leaf) {
	rel := strings.TrimPrefix(sub, "./")
	rel = strings.TrimSuffix(rel, "/")
	if rel == "" {
		rel = "."
	}
	dir, err := c.openDirRel(rel)
	if err != nil {
		if optional && errors.Is(err, fs.ErrNotExist) {
			return
		}
		c.gap("collect-walk", display(rel), "subtree could not be opened: %v; nothing beneath it was examined", err)
		return
	}
	defer dir.Close()
	c.walkDir(dir, rel, 0, policy, leaves)
}

// walkDir lists one directory from its open descriptor and recurses. dirRel is
// the directory's path relative to Root, "." for the root itself.
func (c *collector) walkDir(dir *os.File, dirRel string, depth int, policy hashPolicy, leaves *[]leaf) {
	if depth > c.cfg.MaxDepth {
		c.gap("collect-walk", display(dirRel), "not examined: the walk depth limit of %d was reached, which a legitimate tree does not reach", c.cfg.MaxDepth)
		return
	}
	entries, err := dir.ReadDir(-1)
	if err != nil {
		c.gap("collect-walk", display(dirRel), "directory could not be listed: %v; its contents were not examined", err)
		return
	}
	// getdents order is filesystem-dependent; sorting here makes the recursion
	// order, and therefore the gap order, reproducible.
	sort.Slice(entries, func(i, j int) bool { return entries[i].Name() < entries[j].Name() })

	dirFd := int(dir.Fd())
	for _, e := range entries {
		childRel := join(dirRel, e.Name())
		if c.skipped(childRel) {
			c.mu.Lock()
			c.raw.Skipped = append(c.raw.Skipped, display(childRel))
			c.mu.Unlock()
			continue
		}

		c.mu.Lock()
		over := int64(len(c.raw.Files))+int64(len(*leaves)) >= c.cfg.MaxFiles
		c.mu.Unlock()
		if over {
			c.gap("collect-walk", display(dirRel), "walk stopped at %d entries; the remainder of this tree was not examined", c.cfg.MaxFiles)
			return
		}

		switch {
		case e.Type().IsDir():
			c.walkChildDir(dirFd, childRel, e.Name(), depth, policy, leaves)
		case e.Type().IsRegular():
			*leaves = append(*leaves, leaf{rel: display(childRel), open: childRel, policy: policy})
		case e.Type()&fs.ModeSymlink != 0:
			c.recordSymlink(dirFd, childRel, e.Name())
		case e.Type()&fs.ModeIrregular != 0:
			// DT_UNKNOWN: the filesystem would not say. The hash pass finds
			// out from an fstat of a confined open, which is the only
			// trustworthy answer anyway.
			*leaves = append(*leaves, leaf{rel: display(childRel), open: childRel, policy: policy})
		default:
			// fifo, socket, device. Recorded from an fstatat, never opened for
			// content: a blocking open on a fifo is denial of tool.
			c.recordNonContent(dirFd, childRel, e.Name())
		}
	}
}

// walkChildDir opens a child directory from its parent's descriptor and recurses
// into it. The open is O_NOFOLLOW: if the directory the listing named has been
// replaced by a symlink since, the descent is refused rather than redirected.
func (c *collector) walkChildDir(dirFd int, childRel, name string, depth int, policy hashPolicy, leaves *[]leaf) {
	fd, err := openatNoFollow(dirFd, name, unix.O_RDONLY|unix.O_DIRECTORY)
	if err != nil {
		c.gap("collect-walk", display(childRel), "directory could not be opened: %v; its contents were not examined", err)
		return
	}
	child := os.NewFile(uintptr(fd), display(childRel))
	defer child.Close()

	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		c.gap("collect-walk", display(childRel), "directory could not be fstatted: %v", err)
		return
	}
	c.addFile(fileFromStat(display(childRel), KindDir, st))
	c.walkDir(child, childRel, depth+1, policy, leaves)
}

// recordSymlink records a link's own metadata and its target as bytes. readlinkat
// from the parent's descriptor is a single resolution of the name and reads no
// file; the target is NOT resolved, here or anywhere else in the tool.
func (c *collector) recordSymlink(dirFd int, childRel, name string) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirFd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		c.gap("collect-walk", display(childRel), "symlink could not be fstatted: %v", err)
		return
	}
	target, err := readlinkat(dirFd, name)
	if err != nil {
		c.gap("collect-walk", display(childRel), "symlink target could not be read: %v; the recorded link= cannot be compared", err)
		return
	}
	f := fileFromStat(display(childRel), KindLink, st)
	f.Link = target
	c.addFile(f)
}

// recordNonContent records a fifo, socket or device from an fstatat. It exists
// so that "not a regular file" is evidence rather than absence.
func (c *collector) recordNonContent(dirFd int, childRel, name string) {
	var st unix.Stat_t
	if err := unix.Fstatat(dirFd, name, &st, unix.AT_SYMLINK_NOFOLLOW); err != nil {
		c.gap("collect-walk", display(childRel), "could not be fstatted: %v", err)
		return
	}
	c.addFile(fileFromStat(display(childRel), KindOther, st))
}

// skipped reports whether rel is a configured skip. It matches whole path
// components, so a skip of "run" does not also swallow "usr/lib/runtime".
func (c *collector) skipped(rel string) bool {
	for _, s := range c.cfg.Skip {
		if rel == strings.Trim(strings.TrimPrefix(s, "./"), "/") {
			return true
		}
	}
	return false
}

// ---------------------------------------------------------------- recorded ----

// watchedPrefixes and watchedExact are the paths tier triage hashes whatever
// their mode says, because what they contain decides what runs even when nothing
// about them is executable: unit files, pacman hooks, shell fragments sourced at
// login, and the loader's preload list.
//
// They are matched on the "./"-rooted recorded form, as strings, with no
// resolution: this list decides what to READ, so a lookup that followed a
// symlink to answer it would be taking its instructions from the filesystem it
// is examining.
var (
	watchedPrefixes = []string{
		"./usr/lib/systemd/",
		"./etc/systemd/",
		"./usr/share/libalpm/hooks/",
		"./etc/pacman.d/hooks/",
		"./etc/profile.d/",
	}
	watchedExact = []string{"./etc/ld.so.preload"}
)

// watched reports whether a "./"-rooted path is one triage reads unconditionally.
func watched(rel string) bool {
	for _, p := range watchedExact {
		if rel == p {
			return true
		}
	}
	for _, p := range watchedPrefixes {
		if strings.HasPrefix(rel, p) {
			return true
		}
	}
	return false
}

// appendRecorded adds the paths the local database records to the leaf list,
// deduplicated against everything the walk already found.
//
// Deduplication is not an optimisation. Two leaves for one path would mean two
// confined opens of the same name, which is exactly the second resolution
// internal/fsx exists to prevent, and it would put two Files with the same path
// into the evidence for Raw.ByPath to silently collapse.
func (c *collector) appendRecorded(leaves []leaf) []leaf {
	if c.cfg.Recorded == RecordedIgnore {
		return leaves
	}
	policy := hashNever
	switch c.cfg.Recorded {
	case RecordedSecurity:
		policy = hashIfSecurity
	case RecordedAll:
		policy = hashAlways
	}

	// Everything already spoken for: leaves queued by the walk, and the paths
	// the walk described without queueing them (directories, symlinks, fifos).
	seen := make(map[string]int, len(leaves))
	for i, l := range leaves {
		seen[l.rel] = i
	}
	c.mu.Lock()
	for _, f := range c.raw.Files {
		if _, ok := seen[f.Path]; !ok {
			seen[f.Path] = -1
		}
	}
	pkgs := c.raw.Packages
	c.mu.Unlock()

	for _, pkg := range pkgs {
		if len(pkg.FileList) == 0 {
			continue
		}
		paths, bad := recordedPaths(pkg.FileList)
		leaves = slices.Grow(leaves, len(paths))
		for _, b := range bad {
			// Measured on the reference system: zero recorded paths are
			// absolute, contain a ".." component, or carry a NUL. There is no
			// legitimate population to accommodate, so any occurrence is
			// reported rather than normalised into something openable.
			c.gap("collect-recorded", pkg.Dir,
				"the package records the path %q, which is not a safe relative path; it was not examined", b)
		}
		for _, rel := range paths {
			if i, ok := seen[rel]; ok {
				if i >= 0 && leaves[i].policy < policy {
					leaves[i].policy = policy
					leaves[i].recorded = true
				}
				continue
			}
			seen[rel] = len(leaves)
			// open is a substring of rel rather than a second string. The two
			// forms of one path differ by a two-byte prefix, and holding them
			// separately cost 24 MiB on the reference system -- of which the
			// worse half was invisible: the un-rooted form used to be a slice of
			// the whole `files` blob, so one leaf pinned the entire buffer.
			leaves = append(leaves, leaf{rel: rel, open: rel[2:], policy: policy, recorded: true})
		}
	}
	return leaves
}

// recordedPaths extracts the non-directory paths one package's plain-text
// `files` records, in the "./"-rooted form mtree uses, and the ones it refuses
// verbatim.
//
// This is a newline split and a prefix test, NOT a parser -- see RecordedPolicy
// for why that distinction is the one spec §11.1 draws. The %FILES% section is a
// list of names, one per line, directories written with a trailing slash;
// %BACKUP% lines carry a second tab-separated field and are deliberately not
// read here, because the exemption they feed is derived from parsed hooks in
// phase 2 anyway. A line is refused, never repaired: a path that needs fixing
// before it can be opened is a path whose meaning this phase would be inventing.
//
// It walks the buffer a line at a time instead of calling strings.Split on a
// copy of it. Split allocated the whole `files` blob as a string and a header
// per line -- 113 MB of garbage across 1,410 packages on the reference system --
// and, worse, returned SUBSLICES of that copy, so a single retained path kept
// the blob alive. Each accepted path is one fresh allocation carrying both forms
// the collector needs; the caller takes the un-rooted one as paths[i][2:].
func recordedPaths(b []byte) (paths, bad []string) {
	inFiles := false
	for len(b) > 0 {
		line := b
		if i := bytes.IndexByte(b, '\n'); i >= 0 {
			line, b = b[:i], b[i+1:]
		} else {
			b = nil
		}
		line = bytes.TrimSuffix(line, []byte("\r"))
		if len(line) == 0 {
			continue
		}
		if line[0] == '%' && line[len(line)-1] == '%' {
			inFiles = string(line) == "%FILES%"
			continue
		}
		if !inFiles {
			continue
		}
		if line[len(line)-1] == '/' {
			// A directory. It carries no digest and no target, so there is
			// nothing to open it for.
			continue
		}
		rooted := "./" + string(line)
		if !safeRecordedPath(rooted[2:]) {
			bad = append(bad, rooted[2:])
			continue
		}
		paths = append(paths, rooted)
	}
	return paths, bad
}

// safeRecordedPath applies the same rule internal/fsx applies to a path before
// any syscall: relative, no NUL, no empty, "." or ".." component. It is checked
// here as well as there so the refusal is attributable to the package that
// recorded it rather than to whichever open happened to fail.
func safeRecordedPath(p string) bool {
	if p == "" || strings.HasPrefix(p, "/") || strings.ContainsRune(p, 0) {
		return false
	}
	for _, part := range strings.Split(strings.TrimPrefix(p, "./"), "/") {
		switch part {
		case "", ".", "..":
			return false
		}
	}
	return true
}

// -------------------------------------------------------------------- hash ----

// hashAll runs the confined open, the streaming digest and the re-fstat over
// every leaf, cfg.Workers at a time.
//
// Every worker goroutine's body is wrapped in safe.Run, and every subject inside
// it in safe.RunTimeout. Both are necessary and neither substitutes for the
// other: a panic in a goroutine cannot be recovered by the goroutine that
// started it, so a recover in this function would not save the process. The
// worker pool pulls from an index rather than a channel so that a worker which
// somehow dies anyway cannot deadlock the producer, and answered[] means a
// subject that never reported becomes a gap instead of silence.
func (c *collector) hashAll(leaves []leaf) {
	if len(leaves) == 0 {
		return
	}
	// One allocation for the evidence instead of eighteen doublings. Growing
	// Files by append cost 266 MB of copying on the reference system, and at the
	// last doubling the old and new backing arrays are both live -- an 81 MiB
	// spike for 54 MiB of evidence, paid at the point the heap is already at its
	// largest. Every leaf yields at most one File, so this cannot over-reserve.
	c.mu.Lock()
	if need := len(c.raw.Files) + len(leaves); cap(c.raw.Files) < need {
		grown := make([]File, len(c.raw.Files), need)
		copy(grown, c.raw.Files)
		c.raw.Files = grown
	}
	c.mu.Unlock()

	answered := make([]bool, len(leaves))

	var (
		next atomic.Int64
		wg   sync.WaitGroup
	)
	ctx := context.Background()

	workers := min(c.cfg.Workers, len(leaves))
	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// The recover that keeps the process alive. It has to be here, in
			// the goroutine's own top-level body.
			err, _ := safe.Run(fmt.Sprintf("collect-worker-%d", worker), func() error {
				for {
					i := int(next.Add(1)) - 1
					if i >= len(leaves) {
						return nil
					}
					l := leaves[i]
					err, panicked := safe.RunTimeout(ctx, l.rel, c.cfg.SubjectTimeout,
						func(context.Context) error { return c.examine(l) })
					switch {
					case panicked:
						c.gap("collect-file", l.rel, "%v; this file was not examined and the failure is in aurvet, not necessarily in the file", err)
					case err != nil:
						c.gap("collect-file", l.rel, "%v", err)
					}
					answered[i] = true
				}
			})
			if err != nil {
				c.gap("collect-worker", fmt.Sprintf("worker-%d", worker),
					"%v; the files it had not yet reached are reported individually below", err)
			}
		}(w)
	}
	wg.Wait()

	// A subject with no verdict is not a clean subject. This catches the failure
	// modes a return value cannot report -- notably runtime.Goexit, which
	// terminates a worker without ever unwinding through safe.Run's return.
	for i, ok := range answered {
		if !ok {
			c.gap("collect-file", leaves[i].rel, "no verdict was recorded: the worker examining it did not return")
		}
	}
}

// examine opens one leaf confined, streams its digest from that descriptor if
// the leaf's policy calls for one, and re-fstats the same descriptor afterwards.
//
// There is no stat before the open and the path is never resolved a second time.
// Everything recorded about this file comes from the descriptor fsx.OpenConfined
// returned, which is what makes the digest and the metadata statements about the
// same object rather than about a path at two different instants. The hashing
// decision for hashIfSecurity is taken from THAT fstat, so it is a statement
// about the file that would be read and not about the mode a package recorded.
func (c *collector) examine(l leaf) error {
	f, st, err := fsx.OpenConfined(c.root, l.open)
	if err != nil {
		return c.examineFailure(l, st, err)
	}
	defer f.Close()

	if beforeHashForTest != nil {
		beforeHashForTest(l.rel)
	}

	if !hashWanted(l.policy, l.rel, st) {
		// A metadata-only record still owes the file the mutation check:
		// otherwise its size and mode could describe a different generation of
		// the file than the descriptor that is being reported on.
		if err := fsx.CheckUnchanged(f, st); err != nil {
			return c.unread(l, err)
		}
		c.addFile(fileFromStat(l.rel, KindFile, st))
		return nil
	}

	sum, n, err := fsx.Digest(f, st)
	if err != nil {
		// Includes fsx.ErrMutatedDuringScan, which accuses the scan's timing
		// rather than the package -- so it must not become a digest of
		// incoherent bytes, and must not be silence either.
		return c.unread(l, err)
	}

	rec := fileFromStat(l.rel, KindFile, st)
	rec.SHA256 = sum
	if n != st.Size {
		// The re-fstat above already proved size and mtime unchanged, so this
		// is a short read that reported no error. Recording the bytes actually
		// hashed keeps the digest and the size describing the same read.
		rec.Size = n
	}
	c.addFile(rec)
	return nil
}

// examineFailure turns a refused open into evidence. A walked leaf can only ever
// fail for a reason worth gapping; a RECORDED leaf has two failures that are
// answers rather than holes, and conflating them with a refusal would report a
// deleted file and an unreadable one as the same thing.
func (c *collector) examineFailure(l leaf, st unix.Stat_t, err error) error {
	switch {
	case errors.Is(err, fsx.ErrNotRegular):
		// Not a gap: we asked what it was and got a definite answer. What it is
		// exactly comes from the fstat, so "other" is a claim we can support.
		c.addFile(fileFromStat(l.rel, KindOther, st))
		return nil

	case l.recorded && errors.Is(err, fs.ErrNotExist):
		// The packaged path is simply not there. Established from a confined
		// open, so it is an observation and not a refusal.
		c.addFile(File{Path: l.rel, Kind: KindAbsent})
		return nil

	case l.recorded && errors.Is(err, fsx.ErrSymlink):
		// O_NOFOLLOW refused the leaf, which is how we learn it is a symlink.
		// The target is READ and never resolved: 4,145 legitimate targets on the
		// reference system contain "..", and resolving them while holding read
		// capability over the tree would be worse than useless.
		target, rerr := fsx.ReadLinkConfined(c.root, l.open)
		if rerr != nil {
			return c.unread(l, rerr)
		}
		c.addFile(File{Path: l.rel, Kind: KindLink, Link: target})
		return nil
	}
	return c.unread(l, err)
}

// unread records that a path could not be examined and returns the error, so the
// caller raises the one gap that names it. A recorded path also gets a File, so
// the analyse phase can tell "not examined" from "never asked about" without
// re-deriving it from the gap list.
func (c *collector) unread(l leaf, err error) error {
	if l.recorded {
		c.addFile(File{Path: l.rel, Kind: KindUnread, Unread: err.Error()})
	}
	return err
}

// hashWanted completes the hashing decision from the fstat of the descriptor
// that would be read.
//
// The security-relevant subset is keyed on THAT mode, not on the mode the
// package recorded. The recorded mode is what a package claims; the mode on the
// descriptor is what the kernel will honour when something executes the file,
// and a file made executable after installation is precisely the case worth
// reading.
func hashWanted(p hashPolicy, rel string, st unix.Stat_t) bool {
	switch p {
	case hashAlways:
		return true
	case hashIfSecurity:
		return st.Mode&0o7111 != 0 || watched(rel)
	}
	return false
}

// ------------------------------------------------------------------ helpers ---

// fileFromStat builds a File from the fstat of the descriptor that was examined.
// Only the permission bits of st.Mode are kept: the type is already in kind, and
// mtree's mode= is a permission word.
func fileFromStat(path, kind string, st unix.Stat_t) File {
	return File{
		Path:      path,
		Kind:      kind,
		Size:      st.Size,
		Mode:      st.Mode & 0o7777,
		UID:       st.Uid,
		GID:       st.Gid,
		Nlink:     uint64(st.Nlink),
		Ino:       st.Ino,
		Dev:       st.Dev,
		Mtime:     st.Mtim.Sec,
		MtimeNsec: st.Mtim.Nsec,
	}
}

// openDirRel opens a directory relative to Root through os.Root, used only for
// the walk's entry points and the database directory. Every descent below them
// goes through openatNoFollow from a descriptor this call produced.
func (c *collector) openDirRel(rel string) (*os.File, error) {
	return c.root.OpenFile(rel, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
}

// openatNoFollow opens name relative to dirFd, refusing a symlink at the leaf
// and never blocking. It is the descent primitive: O_NOFOLLOW cannot be
// delegated to os.Root, which retries THROUGH an in-root symlink even when it is
// passed (see internal/fsx).
func openatNoFollow(dirFd int, name string, flags int) (int, error) {
	for {
		fd, err := unix.Openat(dirFd, name, flags|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			if err == unix.ELOOP {
				return -1, fsx.ErrSymlink
			}
			return -1, err
		}
		return fd, nil
	}
}

// readlinkat reads a symlink target of any length the kernel will report,
// growing the buffer until the answer is not truncated. A truncated target
// compared as a string is a false finding, so "probably big enough" is not good
// enough.
func readlinkat(dirFd int, name string) (string, error) {
	for size := 256; size <= 64<<10; size *= 4 {
		buf := make([]byte, size)
		n, err := unix.Readlinkat(dirFd, name, buf)
		if err != nil {
			return "", err
		}
		if n < size {
			return string(buf[:n]), nil
		}
	}
	return "", fmt.Errorf("symlink target longer than %d bytes", 64<<10)
}

// readAll reads f whole, refusing to grow past hard. size is the fstat's
// expectation and only sizes the first allocation: a file that grew between the
// fstat and the read must be bounded by the ceiling, not by the guess.
func readAll(f *os.File, size, hard int64) ([]byte, error) {
	if size < 0 || size > hard {
		size = 0
	}
	buf := make([]byte, 0, size+1)
	for {
		if len(buf) == cap(buf) {
			buf = append(buf, 0)[:len(buf)]
		}
		n, err := f.Read(buf[len(buf):cap(buf)])
		buf = buf[:len(buf)+n]
		if int64(len(buf)) > hard {
			return nil, fmt.Errorf("file grew past the %d-byte ceiling while being read", hard)
		}
		if err != nil {
			if err == io.EOF {
				return buf, nil
			}
			return nil, &fs.PathError{Op: "read", Path: f.Name(), Err: err}
		}
	}
}

// join joins a directory relative path with a child name, keeping "." as the
// root marker rather than letting it into the path.
func join(dirRel, name string) string {
	if dirRel == "." || dirRel == "" {
		return name
	}
	return dirRel + "/" + name
}

// path3 joins three components of a relative path.
func path3(a, b, cc string) string { return join(join(a, b), cc) }

// display renders a relative path the way mtree records it, so evidence and
// mtree records are directly comparable.
func display(rel string) string {
	if rel == "." || rel == "" {
		return "."
	}
	return "./" + rel
}
