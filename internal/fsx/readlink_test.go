// internal/fsx/readlink_test.go
package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ReadLinkConfined arrived here from internal/check, where it had no direct
// tests of its own -- it was only exercised through the integrity checks. It is
// now exported from the package that owns path confinement, so it gets the same
// hostile-input treatment as OpenConfined. hostileRoot is shared with open_test.go.

// The contract that the whole link check rests on: the RECORDED form is
// returned, byte for byte, unresolved. Measured on the reference system, 4,145
// of 49,033 legitimate type=link targets contain a ".." component, so a
// resolving implementation would manufacture thousands of findings out of
// correct packaging.
func TestReadLinkConfinedReturnsTheRecordedTargetUnresolved(t *testing.T) {
	root, _ := hostileRoot(t)

	got, err := ReadLinkConfined(root, "outlink")
	if err != nil {
		t.Fatalf("ReadLinkConfined: %v", err)
	}
	if got != "../outside/secret.txt" {
		t.Errorf("target = %q, want %q (unresolved)", got, "../outside/secret.txt")
	}
	if filepath.IsAbs(got) {
		t.Errorf("target %q was resolved to an absolute path; it must be returned as recorded", got)
	}
}

// Reading a link must not read what the link points AT. outlink escapes the
// root; if this returned the file's contents, or an error caused by trying to
// open the target, the function would be following what it was asked only to
// describe.
func TestReadLinkConfinedDoesNotFollowTheLink(t *testing.T) {
	root, _ := hostileRoot(t)

	got, err := ReadLinkConfined(root, "outlink")
	if err != nil {
		t.Fatalf("ReadLinkConfined: %v", err)
	}
	if strings.Contains(got, "SECRET-OUTSIDE-THE-ROOT") {
		t.Fatal("ReadLinkConfined returned the target's CONTENTS; it followed the link")
	}
}

// mtree records every path as ./usr/bin/foo, so that form must work without the
// caller rewriting it first.
func TestReadLinkConfinedAcceptsMtreeDotSlashPrefix(t *testing.T) {
	root, _ := hostileRoot(t)

	got, err := ReadLinkConfined(root, "./inlink")
	if err != nil {
		t.Fatalf("ReadLinkConfined: %v", err)
	}
	if got != "payload.txt" {
		t.Errorf("target = %q, want %q", got, "payload.txt")
	}
}

// A directory component that is itself an escaping symlink must not be
// traversed. escdir -> ../outside, so escdir/secret.txt would leave the tree.
func TestReadLinkConfinedRefusesEscapingDirectoryComponent(t *testing.T) {
	root, _ := hostileRoot(t)

	if got, err := ReadLinkConfined(root, "escdir/secret.txt"); err == nil {
		t.Fatalf("escaping directory component was traversed, returned %q", got)
	}
}

// The path guard is the same one OpenConfined uses, and it must reject rather
// than normalise: normalising a path is a second interpretation of it, and the
// two interpretations are where a confinement bypass lives. Measured: zero
// packaged paths on the reference system are absolute, contain "..", or fail to
// be "./"-rooted, so any such path is hostile by construction.
//
// The refusal must come from OUR guard, asserted as ErrUnsafePath, not merely
// from os.Root happening to reject the same path. An earlier version of this
// test only checked err != nil and passed even with splitConfined's ".."
// refusal deliberately removed, because os.Root refused independently -- so it
// was measuring defence in depth rather than the guard it named. The
// OpenConfined equivalent caught that neutralisation; this one now does too.
func TestReadLinkConfinedRefusesUnsafeRelativePaths(t *testing.T) {
	root, _ := hostileRoot(t)

	for _, rel := range []string{
		"",
		"/etc/passwd",
		"../outside/secret.txt",
		"./../outside/secret.txt",
		"usr/../../outside/secret.txt",
		"usr/bin/..",
		"usr//bin/hello",
		"usr\x00bin/hello",
	} {
		t.Run(rel, func(t *testing.T) {
			got, err := ReadLinkConfined(root, rel)
			if err == nil {
				t.Fatalf("unsafe path %q accepted, returned %q", rel, got)
			}
			if !errors.Is(err, ErrUnsafePath) {
				t.Errorf("ReadLinkConfined(%q) err = %v, want ErrUnsafePath", rel, err)
			}
		})
	}
}

// A regular file is not a symlink. The error must say so rather than return an
// empty target that a caller could mistake for "points nowhere".
func TestReadLinkConfinedOnARegularFileIsAnErrorNotAnEmptyTarget(t *testing.T) {
	root, _ := hostileRoot(t)

	got, err := ReadLinkConfined(root, "payload.txt")
	if err == nil {
		t.Fatalf("reading a regular file as a link succeeded, returned %q", got)
	}
	if got != "" {
		t.Errorf("target = %q on error, want empty", got)
	}
}

// An absent path must be distinguishable from a refusal: one is an observed
// absence, the other is a coverage gap (INV-9), and the integrity checks report
// them differently.
func TestReadLinkConfinedMissingPathIsNotExist(t *testing.T) {
	root, _ := hostileRoot(t)

	if _, err := ReadLinkConfined(root, "usr/bin/nope"); !os.IsNotExist(err) {
		t.Fatalf("missing path gave %v, want an IsNotExist error", err)
	}
}

// Every error must name the path, or a gap in a 458,724-entry scan is
// unattributable and therefore unactionable.
func TestReadLinkConfinedErrorNamesThePath(t *testing.T) {
	root, _ := hostileRoot(t)

	_, err := ReadLinkConfined(root, "usr/bin/nope")
	if err == nil {
		t.Fatal("expected an error")
	}
	if !strings.Contains(err.Error(), "usr/bin/nope") {
		t.Errorf("error %q does not name the path", err)
	}
}
