// internal/fsx/source.go
//
// A read-only view of a tree, satisfiable either by a live confined root or by
// bytes buffered from one earlier.
//
// # Why this type exists: spec §11.1
//
// §11.1 splits a scan in two. Phase 1 holds CAP_DAC_READ_SEARCH and does nothing
// but READ -- walk, confined open, fstat, buffer raw bytes. The transition then
// drops every capability irrevocably, and phase 2 -- decompress, parse,
// correlate -- runs holding nothing. The point is that the parsers are the attack
// surface: a unit file, a hook, a desktop entry or a preload list is
// attacker-influenced input, and a bug in code that reads one must not be
// reachable while the process can read files its user cannot.
//
// internal/collect already obeys this for file integrity. The persistence-surface
// readers did not: they took an *os.Root and read-then-parsed in one pass, so
// their parsing ran with the capability still held. Source is what lets them be
// handed BYTES instead of a root, so the same parser serves both phases and there
// is exactly one implementation of each format.
//
// # Two backings, one interface, and why it is a struct
//
// Live(root) reads through the confined API -- os.Root plus O_NOFOLLOW plus the
// fstat-after-open regular-file check, unchanged from what the readers did
// before. Buffered(...) answers from a map filled during phase 1.
//
// It is a concrete struct rather than an interface because every caller wants the
// same three operations with the same semantics, and an interface would invite a
// third implementation whose refusals differ. A Source that resolved symlinks, or
// that read an unbounded file, would silently weaken every check built on it.
//
// # What a Buffered source deliberately cannot do
//
// It cannot hand back a file descriptor. Integrity verification needs one -- the
// TOCTOU-safe hash reads and re-stats the SAME fd -- and that is why collect
// keeps its own path and is not expressed through this type. Source is for
// formats read whole and bounded, which is every persistence surface.
package fsx

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"golang.org/x/sys/unix"
)

// ErrNoSource reports a zero Source. It is a refusal rather than an empty
// result: "nothing was configured" and "the tree is empty" are different facts,
// and a reader that cannot tell them apart reports a clean system for a
// programming error.
var ErrNoSource = errors.New("fsx: no source backing")

// Ent is one directory entry. It carries only what the surface readers use --
// the name and whether it is a directory, a symlink or a regular file -- because
// a buffered source can honestly reproduce those and nothing more.
type Ent struct {
	Name string
	Mode fs.FileMode
}

// IsDir reports a directory.
func (e Ent) IsDir() bool { return e.Mode.IsDir() }

// IsSymlink reports a symbolic link. It is a distinct question from IsDir
// because a *.wants entry is a symlink and resolving it is the check.
func (e Ent) IsSymlink() bool { return e.Mode&fs.ModeSymlink != 0 }

// IsRegular reports a regular file.
func (e Ent) IsRegular() bool { return e.Mode.IsRegular() }

// File is one buffered file: its bytes and the stat that was taken of the same
// descriptor they were read from.
type File struct {
	Data []byte
	Stat unix.Stat_t
}

// Source reads one tree. The zero value is unusable and says so (ErrNoSource)
// rather than reporting an empty tree.
type Source struct {
	// root is set for a live source and nil for a buffered one.
	root *os.Root

	// files and dirs back a buffered source. A path present in files with a nil
	// error is readable; a path present in errs failed, and the recorded error is
	// replayed so phase 2 produces the same gap phase 1 would have.
	files map[string]File
	dirs  map[string][]Ent
	links map[string]string
	errs  map[string]error

	// modes records the mode of a path in its own right, which a listing of its
	// PARENT does not carry. It exists because the mode of a directory is itself
	// evidence: unit-execstart-hijackable rates on a group- or world-writable
	// search-path directory, and losing those bits in the phase transition would
	// silence that rule rather than move it.
	modes map[string]fs.FileMode
}

// Live returns a Source reading through root with the confined API.
func Live(root *os.Root) Source { return Source{root: root} }

// Root reports the live root, or nil for a buffered source. It exists for the
// one legitimate caller that still needs a descriptor -- integrity collection --
// and returning nil rather than panicking lets a caller degrade rather than die.
func (s Source) Root() *os.Root { return s.root }

// Live reports whether this Source reads the filesystem now.
func (s Source) IsLive() bool { return s.root != nil }

// Zero reports an unusable Source.
func (s Source) Zero() bool {
	return s.root == nil && s.files == nil && s.dirs == nil && s.links == nil
}

// Stat reports the mode of rel in its own right. A listing of the parent gives
// an entry's TYPE but not its permission bits, and those bits are evidence.
func (s Source) Stat(rel string) (fs.FileMode, error) {
	rel = strings.TrimPrefix(rel, "/")
	if s.root != nil {
		st, err := fs.Stat(s.root.FS(), rel)
		if err != nil {
			return 0, err
		}
		return st.Mode(), nil
	}
	if s.Zero() {
		return 0, ErrNoSource
	}
	if err, ok := s.errs["s:"+rel]; ok {
		return 0, err
	}
	if m, ok := s.modes[rel]; ok {
		return m, nil
	}
	if f, ok := s.files[rel]; ok {
		return fs.FileMode(f.Stat.Mode).Perm(), nil
	}
	return 0, &fs.PathError{Op: "stat", Path: rel, Err: fs.ErrNotExist}
}

// maxSourceFile bounds one buffered file. Every format read through a Source is
// a small text file; the bound exists because a scanner buffer sized by
// attacker-supplied bytes is not something a security tool gets to have. A file
// over the bound is a recorded ERROR, never a truncated read: a truncated parse
// can lose the last directive, and a unit that lost its last ExecStart is
// indistinguishable from one that never had one.
const maxSourceFile = 1 << 20

// ReadFile reads rel whole, bounded, and returns the stat of the descriptor the
// bytes came from.
//
// Live: through OpenConfined, so a symlink leaf, a directory, a fifo and
// anything not a regular file are refused rather than followed or blocked on.
// Buffered: the bytes phase 1 recorded, or the error it recorded instead.
func (s Source) ReadFile(rel string) ([]byte, unix.Stat_t, error) {
	var zero unix.Stat_t
	rel = strings.TrimPrefix(rel, "/")
	if s.root != nil {
		f, st, err := OpenConfined(s.root, rel)
		if err != nil {
			return nil, zero, err
		}
		defer f.Close()
		b, rerr := io.ReadAll(io.LimitReader(f, maxSourceFile+1))
		if rerr != nil {
			return nil, zero, rerr
		}
		if int64(len(b)) > maxSourceFile {
			return nil, zero, fmt.Errorf("%w: %s is larger than %d bytes",
				fs.ErrInvalid, rel, maxSourceFile)
		}
		return b, st, nil
	}
	if s.Zero() {
		return nil, zero, ErrNoSource
	}
	if err, ok := s.errs[rel]; ok {
		return nil, zero, err
	}
	if f, ok := s.files[rel]; ok {
		return f.Data, f.Stat, nil
	}
	return nil, zero, &fs.PathError{Op: "readfile", Path: rel, Err: fs.ErrNotExist}
}

// ReadLink returns a symlink's target TEXT, unresolved.
//
// Never filepath.EvalSymlinks and never os.Readlink on a joined path: the
// recorded target is the evidence, and resolving it would answer a question
// about the running system rather than about the tree being examined.
func (s Source) ReadLink(rel string) (string, error) {
	rel = strings.TrimPrefix(rel, "/")
	if s.root != nil {
		return ReadLinkConfined(s.root, rel)
	}
	if s.Zero() {
		return "", ErrNoSource
	}
	if err, ok := s.errs["l:"+rel]; ok {
		return "", err
	}
	if t, ok := s.links[rel]; ok {
		return t, nil
	}
	return "", &fs.PathError{Op: "readlink", Path: rel, Err: fs.ErrNotExist}
}

// ReadDir lists rel, sorted by name.
//
// The sort is contractual rather than cosmetic: directory order is a filesystem
// artefact, and a scan whose findings come out in a different order on two
// machines is a scan whose output cannot be diffed.
func (s Source) ReadDir(rel string) ([]Ent, error) {
	rel = strings.TrimPrefix(rel, "/")
	if s.root != nil {
		f, err := s.root.Open(rel)
		if err != nil {
			return nil, err
		}
		defer f.Close()
		des, err := f.ReadDir(-1)
		if err != nil {
			return nil, err
		}
		out := make([]Ent, 0, len(des))
		for _, de := range des {
			out = append(out, Ent{Name: de.Name(), Mode: de.Type()})
		}
		sort.Slice(out, func(i, j int) bool { return out[i].Name < out[j].Name })
		return out, nil
	}
	if s.Zero() {
		return nil, ErrNoSource
	}
	if err, ok := s.errs["d:"+rel]; ok {
		return nil, err
	}
	if ents, ok := s.dirs[rel]; ok {
		return ents, nil
	}
	return nil, &fs.PathError{Op: "readdir", Path: rel, Err: fs.ErrNotExist}
}

// Buffer is a Source under construction: phase 1 fills one and phase 2 reads it.
// It is a distinct type from Source so a filled buffer cannot be mistaken for a
// live root, and so nothing can add to a Source after the capability is gone.
type Buffer struct {
	files map[string]File
	dirs  map[string][]Ent
	links map[string]string
	errs  map[string]error
	modes map[string]fs.FileMode
}

// NewBuffer returns an empty Buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		files: map[string]File{},
		dirs:  map[string][]Ent{},
		links: map[string]string{},
		errs:  map[string]error{},
		modes: map[string]fs.FileMode{},
	}
}

// Source seals the buffer into a read-only Source.
func (b *Buffer) Source() Source {
	return Source{files: b.files, dirs: b.dirs, links: b.links, errs: b.errs, modes: b.modes}
}

// Len reports how many files were buffered, for the run's own reporting.
func (b *Buffer) Len() int { return len(b.files) }

// AddFile records a file's bytes, or the error that reading it produced. An
// error is recorded rather than dropped so phase 2 raises the same coverage gap
// phase 1 would have (INV-9): "I could not read it" must survive the transition
// intact, or the drop itself turns a refusal into silence.
func (b *Buffer) AddFile(rel string, data []byte, st unix.Stat_t, err error) {
	rel = strings.TrimPrefix(rel, "/")
	if err != nil {
		b.errs[rel] = err
		return
	}
	b.files[rel] = File{Data: data, Stat: st}
}

// AddLink records a symlink target, or the error reading it produced.
func (b *Buffer) AddLink(rel, target string, err error) {
	rel = strings.TrimPrefix(rel, "/")
	if err != nil {
		b.errs["l:"+rel] = err
		return
	}
	b.links[rel] = target
}

// AddDir records a directory listing, or the error listing it produced.
func (b *Buffer) AddDir(rel string, ents []Ent, err error) {
	rel = strings.TrimPrefix(rel, "/")
	if err != nil {
		b.errs["d:"+rel] = err
		return
	}
	sorted := append([]Ent(nil), ents...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].Name < sorted[j].Name })
	b.dirs[rel] = sorted
}

// AddMode records a path's own mode, or the error stat'ing it produced.
func (b *Buffer) AddMode(rel string, mode fs.FileMode, err error) {
	rel = strings.TrimPrefix(rel, "/")
	if err != nil {
		b.errs["s:"+rel] = err
		return
	}
	b.modes[rel] = mode
}

// Has reports whether a file was already buffered, so a caller enumerating
// overlapping directories does not read the same path twice.
func (b *Buffer) Has(rel string) bool {
	rel = strings.TrimPrefix(rel, "/")
	_, ok := b.files[rel]
	if ok {
		return true
	}
	_, ok = b.errs[rel]
	return ok
}

// CopyTree reads dir and every regular file directly inside it into the buffer,
// recording listing and read errors rather than discarding them. It does not
// recurse: every surface this serves is a flat directory of configuration files
// plus, for units, explicitly named drop-in subdirectories, and a recursive
// buffer over an attacker-influenced tree is an unbounded read.
//
// A missing directory is recorded as a listing error, not skipped: absent and
// unreadable are different facts and only the caller knows which of them is
// ordinary for a given path.
func (b *Buffer) CopyTree(src Source, dir string) {
	ents, err := src.ReadDir(dir)
	b.AddDir(dir, ents, err)
	if err != nil {
		return
	}
	mode, merr := src.Stat(dir)
	b.AddMode(dir, mode, merr)
	for _, e := range ents {
		rel := path.Join(dir, e.Name)
		switch {
		case e.IsSymlink():
			t, lerr := src.ReadLink(rel)
			b.AddLink(rel, t, lerr)
		case e.IsRegular():
			if b.Has(rel) {
				continue
			}
			data, st, ferr := src.ReadFile(rel)
			b.AddFile(rel, data, st, ferr)
		}
	}
}

// FS exposes the Source as an io/fs.FS.
//
// This exists because several readers consume a tree through fs.FS rather than
// path by path -- internal/hook's parser takes one, and the hook and misc
// surfaces use fs.Stat and fs.ReadDir over it. Implementing the interface means
// those callers are unchanged by the phase split: the same parser runs against a
// live root in phase 1 or against buffered bytes in phase 2, and there is no
// second copy of any format's reader to drift from the first.
//
// A live Source returns os.Root's own FS, so its confinement is the kernel's.
// A buffered one answers from the maps, and refuses everything not buffered.
func (s Source) FS() fs.FS {
	if s.root != nil {
		return s.root.FS()
	}
	return bufFS{s}
}

// bufFS answers fs.FS reads from buffered bytes.
type bufFS struct{ s Source }

func (b bufFS) Open(name string) (fs.File, error) {
	if !fs.ValidPath(name) {
		return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrInvalid}
	}
	if name == "." {
		return &memDir{name: ".", ents: b.s.dirs["."]}, nil
	}
	if ents, ok := b.s.dirs[name]; ok {
		return &memDir{name: name, ents: ents, mode: b.s.modes[name] | fs.ModeDir}, nil
	}
	if f, ok := b.s.files[name]; ok {
		return &memFile{name: name, data: f.Data}, nil
	}
	// A recorded failure is replayed here too, so a directory phase 1 could not
	// list stays unlistable rather than becoming empty.
	if err, ok := b.s.errs["d:"+name]; ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	if err, ok := b.s.errs[name]; ok {
		return nil, &fs.PathError{Op: "open", Path: name, Err: err}
	}
	return nil, &fs.PathError{Op: "open", Path: name, Err: fs.ErrNotExist}
}

// memFile is a buffered regular file.
type memFile struct {
	name string
	data []byte
	off  int
}

func (f *memFile) Stat() (fs.FileInfo, error) {
	return memInfo{name: path.Base(f.name), size: int64(len(f.data))}, nil
}

func (f *memFile) Read(p []byte) (int, error) {
	if f.off >= len(f.data) {
		return 0, io.EOF
	}
	n := copy(p, f.data[f.off:])
	f.off += n
	return n, nil
}

func (f *memFile) Close() error { return nil }

// memDir is a buffered directory. It implements fs.ReadDirFile so fs.ReadDir
// works over it without the caller knowing which backing it has.
type memDir struct {
	name string
	ents []Ent
	mode fs.FileMode
	off  int
}

func (d *memDir) Stat() (fs.FileInfo, error) {
	return memInfo{name: path.Base(d.name), mode: d.mode | fs.ModeDir}, nil
}

func (d *memDir) Read([]byte) (int, error) {
	return 0, &fs.PathError{Op: "read", Path: d.name, Err: fs.ErrInvalid}
}

func (d *memDir) Close() error { return nil }

func (d *memDir) ReadDir(n int) ([]fs.DirEntry, error) {
	rest := d.ents[d.off:]
	if n > 0 && n < len(rest) {
		rest = rest[:n]
	}
	d.off += len(rest)
	out := make([]fs.DirEntry, 0, len(rest))
	for _, e := range rest {
		out = append(out, memDirEnt{e})
	}
	if len(out) == 0 && n > 0 {
		return nil, io.EOF
	}
	return out, nil
}

// memDirEnt adapts an Ent to fs.DirEntry.
type memDirEnt struct{ e Ent }

func (m memDirEnt) Name() string { return m.e.Name }
func (m memDirEnt) IsDir() bool  { return m.e.IsDir() }
func (m memDirEnt) Type() fs.FileMode {
	return m.e.Mode & fs.ModeType
}
func (m memDirEnt) Info() (fs.FileInfo, error) {
	return memInfo{name: m.e.Name, mode: m.e.Mode}, nil
}

// memInfo is the minimum fs.FileInfo the readers consult: the name, the size and
// whether it is a directory. Times are deliberately zero -- a buffered source
// records no mtime through this path, and inventing one would let a check reason
// about a timestamp that came from nowhere.
type memInfo struct {
	name string
	size int64
	mode fs.FileMode
}

func (i memInfo) Name() string       { return i.name }
func (i memInfo) Size() int64        { return i.size }
func (i memInfo) Mode() fs.FileMode  { return i.mode }
func (i memInfo) ModTime() time.Time { return time.Time{} }
func (i memInfo) IsDir() bool        { return i.mode.IsDir() }
func (i memInfo) Sys() any           { return nil }
