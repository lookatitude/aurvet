// internal/own/index.go
//
// Package own answers one question, and it is the question the whole of P1-C
// rests on: does any installed package own this path?
//
// P1-C's premise is "unowned means worth looking at" -- an ExecStart pointing
// at a file no package installed, a hook nobody shipped. That premise is only
// as good as the oracle behind it, so the failure mode to fear here is not a
// missed detection but a manufactured one: answer "unowned" for a path that is
// in fact packaged and every surface check downstream produces false positives
// at volume, which is how a scanner teaches its user to ignore it.
//
// Two design points follow from that:
//
//   - Symlinks are resolved, because /bin -> usr/bin and /lib -> usr/lib are
//     ordinary on Arch and a non-resolving oracle calls everything under them
//     unowned. Resolution is the substance of this package, not a refinement.
//   - "Unowned" and "could not tell" are different answers. Resolve returns
//     three states; a path whose resolution fails is Unresolved, which is a
//     coverage gap for the caller to report (INV-9), never a finding. Resolve
//     is the ONLY lookup: a two-value variant cannot carry the third state, so
//     offering one would hand every caller a way to print a gap as a finding.
//
// Nothing here executes anything (INV-2) and nothing here writes (INV-5). The
// filesystem is reached only through internal/fsx's confined API: an offline
// root is a parameter, not a second code path (INV-4), and
// filepath.EvalSymlinks would resolve against the RUNNING filesystem and walk
// straight out of an --offline-root tree.
package own

import (
	"errors"
	"fmt"
	"strings"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/fsx"
	"golang.org/x/sys/unix"
)

// ErrUnresolved wraps every reason a path could not be resolved. Callers match
// on it to turn the failure into a finding.Gap rather than into silence.
var ErrUnresolved = errors.New("path could not be resolved")

// maxHops bounds symlink traversal, mirroring Linux's MAXSYMLINKS. A loop is
// not a hypothetical: two links pointing at each other cost nothing to create
// and would otherwise hang the scan on an attacker-controlled tree.
const maxHops = 40

// State is the answer's third dimension. Two states would force "I could not
// tell" to masquerade as one of the other two, and either masquerade is a lie:
// as Owned it hides a planted file, as Unowned it invents one.
type State int

const (
	// Owned: an installed package records this path.
	Owned State = iota
	// Unowned: the path resolved, and no package records the result. This is
	// a fact the caller may act on.
	Unowned
	// Unresolved: resolution failed. INV-9 -- a coverage gap, never a finding
	// and never silence.
	Unresolved
)

func (s State) String() string {
	switch s {
	case Owned:
		return "owned"
	case Unowned:
		return "unowned"
	case Unresolved:
		return "unresolved"
	default:
		return "unknown"
	}
}

// Owners is a path -> package index over the installed set. It is immutable
// after Index returns and therefore safe for concurrent readers; resolution
// accumulates no state, so two callers asking about the same path get the same
// answer in any order (INV-4).
type Owners struct {
	// byPath is keyed on the CANONICAL path form: slash-separated, relative
	// to the scanned root, no leading "/", no leading "./", no trailing "/".
	// That is pacman's own recording form, so indexing needs no rewriting and
	// only caller input is normalized -- one normalization, in one direction.
	byPath map[string]string

	// src is the tree symlinks are resolved against; the zero Source means
	// there is none. That is not a degraded mode to be papered over: it means
	// the caller has no tree (a test, or an index built from a DB alone), and
	// the honest answer is then whatever the recorded paths say, with no
	// resolution claimed.
	//
	// It is an fsx.Source rather than an *os.Root so the oracle can be built
	// AFTER the capability is dropped, from bytes buffered while it was held
	// (spec §11.1). The resolution it performs is identical either way -- see
	// fsx.Source, whose contract test asserts the two backings answer alike.
	src fsx.Source
}

// Index builds the oracle from the installed package set with no filesystem
// behind it. Lookups answer from recorded paths only.
//
// Prefer IndexIn wherever a root exists. Without one, every path reached
// through a symlinked directory -- /bin/foo, /lib/libc.so.6 -- reads as
// Unowned, which is precisely the false-positive engine this package exists to
// prevent.
func Index(pkgs []alpm.Package) *Owners { return IndexIn(fsx.Source{}, pkgs) }

// IndexIn builds the oracle and binds the tree its lookups resolve against.
// root is the scanned root -- "/" for a live scan, the offline tree for
// --offline-root. It is read, never written.
func IndexIn(src fsx.Source, pkgs []alpm.Package) *Owners {
	o := &Owners{byPath: make(map[string]string, 1<<18), src: src}
	for _, p := range pkgs {
		for _, f := range p.Files {
			key, err := canonical(f)
			if err != nil {
				// A recorded path this package cannot key is not silently
				// dropped into "unowned" territory by accident: it simply
				// never matches, and the path it describes will surface to
				// the caller as Unowned or Unresolved on its own merits.
				continue
			}
			// First writer wins. Two packages claiming one path is a pacman
			// file conflict, which cannot normally exist; picking
			// deterministically beats picking by map iteration order.
			if _, dup := o.byPath[key]; !dup {
				o.byPath[key] = p.Name
			}
		}
	}
	return o
}

// Len reports the number of distinct canonical paths indexed.
func (o *Owners) Len() int { return len(o.byPath) }

// Resolve is the only lookup, deliberately.
//
// An earlier revision also carried Owner(path) (pkg string, ok bool) -- the
// two-value shape the roadmap named. It was removed rather than documented,
// because it cannot express the third state: a path whose resolution failed
// returned ("", false), byte-identical to a path that genuinely nobody owns.
// P1-C's premise is "unowned is suspicious", so every consumer here is one that
// reports a finding on a false, and that is exactly the caller the two-value
// form must never have. A comment saying "do not use this for findings" next to
// the more convenient of two functions loses to convenience at some call site
// eventually, and the loss is silent: a coverage gap printed as a finding, which
// is INV-9's precise failure mode. There is no honest yes/no question here, so
// there is no honest two-value answer.
//
// Resolve is the full answer. It accepts both "/usr/bin/foo" and "usr/bin/foo"
// (and mtree's "./usr/bin/foo"), normalizes once, and returns the owning
// package with Owned, or Unowned, or Unresolved together with a non-nil error
// wrapping ErrUnresolved.
//
// A ".." component in the INPUT is refused rather than normalized away:
// collapsing it lexically is a second interpretation of the path, and the
// interpretation that matters is the kernel's. A ".." inside a symlink TARGET
// is different and is handled -- 4,145 of the reference system's 49,033
// packaged link targets contain one, so refusing those would gap thousands of
// correct paths.
func (o *Owners) Resolve(path string) (pkg string, st State, err error) {
	key, err := canonical(path)
	if err != nil {
		return "", Unresolved, err
	}

	// The literal hit is checked before any syscall. Most paths are recorded
	// exactly as they are asked about, and the cheapest resolution is the one
	// that never touches the filesystem.
	if pkg, ok := o.byPath[key]; ok {
		return pkg, Owned, nil
	}

	resolved, err := o.resolve(key)
	if err != nil {
		return "", Unresolved, err
	}
	if resolved != key {
		if pkg, ok := o.byPath[resolved]; ok {
			return pkg, Owned, nil
		}
	}
	return "", Unowned, nil
}

// resolve walks key component by component, replacing each symlink with its
// target, and returns the canonical path the kernel would arrive at within
// root. With a nil root it is the identity function.
//
// Absolute symlink targets are re-rooted at the SCANNED root rather than at
// the running filesystem's "/". That is the chroot reading, and it is the only
// one compatible with --offline-root: a link recorded as /usr/bin/sh inside an
// offline tree describes that tree's /usr/bin/sh, not this machine's.
func (o *Owners) resolve(key string) (string, error) {
	if o.src.Zero() {
		return key, nil
	}

	remaining := strings.Split(key, "/")
	resolved := make([]string, 0, len(remaining))
	hops := 0

	for len(remaining) > 0 {
		comp := remaining[0]
		remaining = remaining[1:]

		switch comp {
		case "", ".":
			continue
		case "..":
			// Only reachable from a symlink target; canonical() refuses it in
			// input. Popping past the root would leave the scanned tree, and
			// we do not get to guess what is out there.
			if len(resolved) == 0 {
				return "", fmt.Errorf("%w: %q leaves the scanned root", ErrUnresolved, key)
			}
			resolved = resolved[:len(resolved)-1]
			continue
		}

		cand := strings.Join(append(append([]string{}, resolved...), comp), "/")
		target, err := o.src.ReadLink(cand)
		if err != nil {
			switch {
			case errors.Is(err, unix.EINVAL):
				// Not a symlink. The overwhelmingly common case.
				resolved = append(resolved, comp)
				continue
			case errors.Is(err, unix.ENOENT), errors.Is(err, unix.ENOTDIR):
				// A definite non-existence, not an inability: nothing here
				// resolves and nothing beyond it can. The remainder is kept
				// literal so an absent path still gets a fair lookup, and the
				// caller receives Unowned -- which is the true answer for a
				// unit whose ExecStart names a binary that is not there.
				resolved = append(resolved, comp)
				resolved = append(resolved, remaining...)
				return strings.Join(resolved, "/"), nil
			default:
				// EACCES, ELOOP, an os.Root escape, a truncated target. We do
				// not know what this path is; saying "unowned" here would
				// invent a finding out of a permission bit (INV-9).
				return "", fmt.Errorf("%w: %q: %v", ErrUnresolved, cand, err)
			}
		}

		hops++
		if hops > maxHops {
			return "", fmt.Errorf("%w: %q: too many symlink hops", ErrUnresolved, key)
		}
		if strings.HasPrefix(target, "/") {
			// Re-root: an absolute target discards everything resolved so far.
			resolved = resolved[:0]
			target = strings.TrimPrefix(target, "/")
		}
		remaining = append(strings.Split(target, "/"), remaining...)
	}

	return strings.Join(resolved, "/"), nil
}

// canonical returns the index's key form for a path: slash-separated, relative
// to the scanned root, no leading "/" or "./", no trailing "/". Callers arrive
// with all three shapes -- pacman's "usr/bin/foo", a unit file's absolute
// "/usr/bin/foo", mtree's "./usr/bin/foo" -- and every one of them means the
// same file, so they must produce the same key or the index answers by accident
// of input formatting.
//
// It refuses what fsx refuses, for the same reason and with the same strictness:
// an empty path, a NUL (which truncates at the syscall boundary, so the path Go
// reports and the path the kernel opens differ), a "." or ".." component, and
// the root itself, which no package owns as a file.
func canonical(p string) (string, error) {
	if p == "" {
		return "", fmt.Errorf("%w: empty path", ErrUnresolved)
	}
	if strings.ContainsRune(p, 0) {
		return "", fmt.Errorf("%w: path contains NUL", ErrUnresolved)
	}
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" {
		return "", fmt.Errorf("%w: path names the root", ErrUnresolved)
	}
	for _, c := range strings.Split(p, "/") {
		switch c {
		case "", ".", "..":
			return "", fmt.Errorf("%w: %q has a %q component", ErrUnresolved, p, c)
		}
	}
	return p, nil
}
