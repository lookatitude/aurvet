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
}

// NewBuffer returns an empty Buffer.
func NewBuffer() *Buffer {
	return &Buffer{
		files: map[string]File{},
		dirs:  map[string][]Ent{},
		links: map[string]string{},
		errs:  map[string]error{},
	}
}

// Source seals the buffer into a read-only Source.
func (b *Buffer) Source() Source {
	return Source{files: b.files, dirs: b.dirs, links: b.links, errs: b.errs}
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
