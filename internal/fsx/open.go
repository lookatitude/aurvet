// internal/fsx/open.go
//
// Package fsx is the only place in the tree that opens attacker-controlled
// paths on a live filesystem. Everything it exports exists to make one
// property true: a packaged path is resolved exactly once, and every
// subsequent question about that file is asked of the file descriptor that
// resolution produced.
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"strings"

	"golang.org/x/sys/unix"
)

// The three refusals a caller has to tell apart. None of them is a critical
// finding: an unopenable or non-regular path is a coverage gap attributable to
// its subject (INV-9), and a gap says what it could not prove (INV-6) rather
// than guessing at the answer.
var (
	// ErrSymlink means the leaf was a symlink and was refused unresolved.
	// It is deliberately not "escaped the root": we never looked at the
	// target, so we cannot claim to know where it pointed.
	ErrSymlink = errors.New("path component is a symlink, refused unresolved")

	// ErrNotRegular means the fd we hold is not a regular file -- a fifo, a
	// directory, a device, a socket. Refused after the open, from the fstat
	// of that same fd.
	ErrNotRegular = errors.New("not a regular file")

	// ErrUnsafePath means the caller's relative path was rejected before any
	// syscall was issued.
	ErrUnsafePath = errors.New("unsafe relative path")
)

// OpenConfined opens rel beneath root and returns the open file together with
// the fstat of the descriptor it returns. rel is a slash-separated path
// relative to root, with or without the leading "./" that mtree records.
//
// It opens ONCE. There is no stat before the open, and callers must not
// re-derive the path afterwards: a path resolved twice is a TOCTOU window, and
// between the two resolutions an attacker on the monitored system swaps the
// path for a symlink, so the tool hashes something other than what it checked.
// Everything downstream -- the digest, the mode bits, the mutation check --
// reads from the descriptor returned here.
//
// The resolution is split so that each half gets the guarantee it needs:
//
//   - the directory components go through os.Root (Go 1.24+, which is why the
//     module floor is 1.24), so no component can be swapped for a symlink
//     leading out of the tree. That matters most under --offline-root, where
//     the whole tree is attacker-controlled.
//   - the leaf is opened with openat(2) against the resulting directory fd,
//     with O_NOFOLLOW, so a symlink standing where a regular file was
//     recorded is refused rather than followed. This cannot be delegated to
//     os.Root: Root.OpenFile retries THROUGH an in-root symlink even when the
//     caller passes O_NOFOLLOW, which silently turns a swapped path into a
//     successful hash of the swap target.
//
// O_NONBLOCK is not decoration. A packaged path replaced by a fifo blocks an
// RDONLY open forever, so without it a hostile filesystem stops being a
// finding and becomes a hang -- denial of tool with no panic to recover from.
// O_NONBLOCK gets us the descriptor; the S_ISREG check is what refuses it.
//
// The function is a pure function of (root, rel): no ambient state, no
// dependence on the process working directory. An offline root is a
// parameter, not a second code path (INV-4).
func OpenConfined(root *os.Root, rel string) (*os.File, unix.Stat_t, error) {
	var zero unix.Stat_t

	dir, base, err := splitConfined(rel)
	if err != nil {
		return nil, zero, &fs.PathError{Op: "openconfined", Path: rel, Err: err}
	}

	// The directory fd is opened read-only rather than with O_PATH because a
	// collect phase holding CAP_DAC_READ_SEARCH is not subject to the
	// permission check either way, and an os.File is what os.Root hands back.
	parent, err := root.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		// os.Root already reports escapes, ENOENT and ENOTDIR with the
		// offending component named; rewriting that would lose detail.
		return nil, zero, err
	}
	defer parent.Close()

	var fd int
	for {
		fd, err = unix.Openat(int(parent.Fd()), base,
			unix.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK|unix.O_CLOEXEC, 0)
		if err != unix.EINTR {
			break
		}
	}
	if err != nil {
		if err == unix.ELOOP || err == unix.EMLINK {
			// O_NOFOLLOW on a symlink leaf: ELOOP on Linux. The target was
			// never resolved, which is the whole point.
			err = ErrSymlink
		}
		return nil, zero, &fs.PathError{Op: "openat", Path: rel, Err: err}
	}

	// fstat the fd we just got, never the path we just used.
	var st unix.Stat_t
	if err := unix.Fstat(fd, &st); err != nil {
		unix.Close(fd)
		return nil, zero, &fs.PathError{Op: "fstat", Path: rel, Err: err}
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		unix.Close(fd)
		return nil, zero, &fs.PathError{Op: "openconfined", Path: rel, Err: ErrNotRegular}
	}

	return os.NewFile(uintptr(fd), rel), st, nil
}

// splitConfined validates rel and splits it into the directory to confine to
// and the leaf to open. It is intentionally stricter than os.Root: measured on
// the reference system, zero packaged paths are absolute, contain a ".."
// component, or fail to be "./"-rooted, so any such path is hostile by
// construction and there is no legitimate population to accommodate.
//
// Refusing here rather than relying on os.Root is not redundancy for its own
// sake: it keeps the refusal attributable to the path rather than to whatever
// errno the kernel happened to produce, and "some lower layer probably catches
// this" is not a guarantee.
func splitConfined(rel string) (dir, base string, err error) {
	if rel == "" {
		return "", "", ErrUnsafePath
	}
	if strings.HasPrefix(rel, "/") {
		return "", "", ErrUnsafePath
	}
	if strings.ContainsRune(rel, 0) {
		// A NUL truncates the path at the syscall boundary, so the path Go
		// reports and the path the kernel opens would differ.
		return "", "", ErrUnsafePath
	}
	// mtree records every path as ./usr/bin/foo. Accept that form so the
	// collector need not rewrite paths before it can open them, but accept it
	// only as an exact leading component.
	rel = strings.TrimPrefix(rel, "./")

	parts := strings.Split(rel, "/")
	for _, p := range parts {
		switch p {
		case "", ".", "..":
			// Empty covers "a//b" and a trailing slash; "." and ".." are
			// refused outright rather than normalised away, because
			// normalising a path is a second interpretation of it.
			return "", "", ErrUnsafePath
		}
	}
	if len(parts) == 1 {
		return ".", parts[0], nil
	}
	return strings.Join(parts[:len(parts)-1], "/"), parts[len(parts)-1], nil
}
