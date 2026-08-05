// internal/collect/collect.go
//
// Package collect is phase 1 of the staged privilege model (spec §11.1): the
// only part of aurvet that runs while holding CAP_DAC_READ_SEARCH.
//
// IT CONTAINS NO PARSERS, and that is the architectural point of P1-B rather
// than a style preference. The tool's job is parsing attacker-controlled input
// while needing to read root-only files; those two requirements are separated in
// time instead of accepted together. This package therefore does four things --
// directory walk, confined open, fstat, streaming sha256 -- and buffers raw
// bytes for everything else. Decompression, tokenising and interpretation all
// happen after the capability is dropped, so a parser bug is an unprivileged
// bug.
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
	"context"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path/filepath"
	"runtime"
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

// The four kinds of thing a walk finds. They are the strings mtree writes for
// its type= keyword, so the analyse phase compares Kind against Entry.Type
// directly rather than translating between two vocabularies -- a translation
// table is somewhere for a mismatch to hide.
const (
	KindFile  = "file"
	KindLink  = "link"
	KindDir   = "dir"
	KindOther = "other" // fifo, socket, device: recorded, never opened for content
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
	// tree.
	Walk []string

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

	// Then the walk, which produces the leaf paths, and the hash pass over them.
	leaves := c.walk()
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

// leaf is a path the walk found but did not read: a regular file, or an entry
// whose type the kernel would not name in its dirent.
type leaf struct {
	rel  string // "./"-rooted, as recorded
	open string // the same path without "./", as fsx wants it
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
		rel := strings.TrimPrefix(sub, "./")
		rel = strings.TrimSuffix(rel, "/")
		if rel == "" {
			rel = "."
		}
		dir, err := c.openDirRel(rel)
		if err != nil {
			c.gap("collect-walk", display(rel), "subtree could not be opened: %v; nothing beneath it was examined", err)
			continue
		}
		c.walkDir(dir, rel, 0, &leaves)
		dir.Close()
	}
	return leaves
}

// walkDir lists one directory from its open descriptor and recurses. dirRel is
// the directory's path relative to Root, "." for the root itself.
func (c *collector) walkDir(dir *os.File, dirRel string, depth int, leaves *[]leaf) {
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
			c.walkChildDir(dirFd, childRel, e.Name(), depth, leaves)
		case e.Type().IsRegular():
			*leaves = append(*leaves, leaf{rel: display(childRel), open: childRel})
		case e.Type()&fs.ModeSymlink != 0:
			c.recordSymlink(dirFd, childRel, e.Name())
		case e.Type()&fs.ModeIrregular != 0:
			// DT_UNKNOWN: the filesystem would not say. The hash pass finds
			// out from an fstat of a confined open, which is the only
			// trustworthy answer anyway.
			*leaves = append(*leaves, leaf{rel: display(childRel), open: childRel})
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
func (c *collector) walkChildDir(dirFd int, childRel, name string, depth int, leaves *[]leaf) {
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
	c.walkDir(child, childRel, depth+1, leaves)
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

// examine opens one leaf confined, streams its digest from that descriptor, and
// re-fstats the same descriptor afterwards.
//
// There is no stat before the open and the path is never resolved a second time.
// Everything recorded about this file comes from the descriptor fsx.OpenConfined
// returned, which is what makes the digest and the metadata statements about the
// same object rather than about a path at two different instants.
func (c *collector) examine(l leaf) error {
	f, st, err := fsx.OpenConfined(c.root, l.open)
	if err != nil {
		if errors.Is(err, fsx.ErrNotRegular) {
			// Not a gap: we asked what it was and got a definite answer. What
			// it is exactly comes from the fstat, so "other" is a claim we can
			// support.
			c.addFile(fileFromStat(l.rel, KindOther, st))
			return nil
		}
		return err
	}
	defer f.Close()

	if beforeHashForTest != nil {
		beforeHashForTest(l.rel)
	}

	sum, n, err := fsx.Digest(f, st)
	if err != nil {
		// Includes fsx.ErrMutatedDuringScan, which accuses the scan's timing
		// rather than the package -- so it must not become a digest of
		// incoherent bytes, and must not be silence either.
		return err
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
