// internal/fsx/readlink.go
package fsx

import (
	"io/fs"
	"os"

	"golang.org/x/sys/unix"
)

// ReadLinkConfined reads a symlink's own target without following it, resolving
// every directory component through root.
//
// This complements OpenConfined rather than duplicating it, and the pairing is
// the point: OpenConfined opens with O_NOFOLLOW, so a symlink found where a file
// was recorded is refused rather than followed. That makes it structurally
// incapable of reading a link's own target — opening the link is exactly what
// must not happen. readlinkat(2) is the right syscall, and it does not follow the
// leaf either, so there is no descriptor to hold.
//
// The parent directory is resolved ONCE through os.Root, so no directory
// component can be swapped for a symlink leading out of the tree; the leaf is
// then named against that directory descriptor.
//
// Callers compare the returned value against a recorded target AS A STRING and
// must not resolve it. Measured on the reference system: 4,145 of 49,033
// legitimate type=link targets contain a ".." component, so resolving them would
// manufacture thousands of findings out of correct packaging.
//
// Moved here from internal/check/tier.go, which had grown its own copy of this
// function plus a second implementation of splitConfined's path guard. The check
// lane recorded the duplication rather than hiding it and flagged the move,
// correctly, as outside its scope. Two implementations of a path-confinement
// guard drift, and the drifted one is the one that stops confining.
func ReadLinkConfined(root *os.Root, rel string) (string, error) {
	dir, base, err := splitConfined(rel)
	if err != nil {
		return "", &fs.PathError{Op: "readlinkconfined", Path: rel, Err: err}
	}

	parent, err := root.OpenFile(dir, os.O_RDONLY|unix.O_DIRECTORY|unix.O_CLOEXEC, 0)
	if err != nil {
		return "", err
	}
	defer parent.Close()

	buf := make([]byte, unix.PathMax)
	for {
		n, err := unix.Readlinkat(int(parent.Fd()), base, buf)
		if err == unix.EINTR {
			continue
		}
		if err != nil {
			return "", &fs.PathError{Op: "readlinkat", Path: rel, Err: err}
		}
		if n == len(buf) {
			// Truncated. Comparing a prefix of the target against the whole
			// recorded target can only produce a false mismatch, so refuse
			// rather than report a disagreement this call cannot substantiate.
			return "", &fs.PathError{Op: "readlinkat", Path: rel, Err: ErrUnsafePath}
		}
		return string(buf[:n]), nil
	}
}
