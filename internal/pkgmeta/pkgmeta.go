// internal/pkgmeta/pkgmeta.go
//
// Package pkgmeta reads the two metadata files a build leaves behind:
// .BUILDINFO (what one build actually did) and .SRCINFO (what the recipe
// declares).
//
// # Why both, and why now
//
// .BUILDINFO carries pkgbuild_sha256sum -- the digest of the PKGBUILD that was
// actually built -- plus builddir and startdir. That digest is the only local
// evidence that answers "was this package built from the recipe the AUR
// published?" (spec §5.1). It is NOT retained in the pacman local database: it
// exists inside the package archive and in the build directory, and nowhere
// else. .SRCINFO declares the sources and dependencies, which is what a
// dependency-closure review needs before makepkg runs.
//
// Both are ephemeral, which is why these readers precede the baseline: 16 of 39
// foreign packages on the reference system (41%) already have neither a cache
// clone nor a retained artifact.
//
// # Everything here is keyed on pkgbase
//
// spec §7: snapshots are keyed on pkgbase, not pkgname. The measurement that
// makes it load-bearing, and the trap in it, are recorded on
// TestSRCINFOSplitPackage: the local database reports 237 split packages, the
// repositories report 432 for the same system, and a reader that believes the
// first number silently mis-keys the 195 packages whose siblings are not
// installed here. This package never infers a pkgbase from a pkgname -- an
// absent pkgbase is reported as missing (INV-6).
//
// # Purity, confinement, and no new dependencies
//
// Parsers take an io.Reader, so they are pure functions of their bytes and can
// be pointed at an archive member, a file, or a snapshot. The two file-reading
// entry points take an *os.Root and go through fsx.OpenConfined: a build
// directory sits under a user's home and a clone came from the AUR, so neither
// is a trusted path. Nothing here writes (INV-5) and nothing here executes
// anything (INV-2) -- there is no call to bsdtar, no call to pacman, and no
// evaluation of any value read.
package pkgmeta

import (
	"errors"
	"fmt"
	"io"
	"strings"
)

// The sentinels a caller switches on. None of these is a finding: a metadata
// file that could not be read says nothing about whether the package is
// malicious, so each is a coverage gap attributable to one package (INV-9).
var (
	// ErrLimit reports input that exceeded a bound rather than input that was
	// wrong.
	ErrLimit = errors.New("pkgmeta: input exceeds a bound")

	// ErrFormat reports input that is not the file it was supposed to be --
	// most importantly a .SRCINFO with no pkgbase, which has no key to be
	// filed under.
	ErrFormat = errors.New("pkgmeta: malformed metadata")

	// ErrCompression reports a package archive whose compression this module
	// cannot decompress. See CompressionOf for the decision and its reasoning.
	ErrCompression = errors.New("pkgmeta: archive compression not readable with the standard library")

	// ErrNoBuildInfo reports an archive that was read successfully and holds no
	// .BUILDINFO member. Deliberately distinct from ErrCompression: "there is
	// nothing there" and "I could not look" are different facts.
	ErrNoBuildInfo = errors.New("pkgmeta: archive has no .BUILDINFO member")
)

// Gap rule identifiers.
const (
	// RuleBuildInfo is a .BUILDINFO that is absent, unreadable, or missing a
	// field a provenance check depends on.
	RuleBuildInfo = "pkgmeta-buildinfo"

	// RuleSRCINFO is a .SRCINFO this reader could not fully account for.
	RuleSRCINFO = "pkgmeta-srcinfo"
)

// SubjectPkgBase is the subject kind for gaps from this package. It names the
// unit these files describe, which is the base and never the package name.
const SubjectPkgBase = "pkgbase"

// Limits bounds every attacker-sized quantity in both formats. Exported and
// copyable so a caller can tighten one bound and a test can prove each fires.
type Limits struct {
	// MaxFileBytes caps one metadata file. Measured on the reference system:
	// the largest cached .SRCINFO is 17,715 B (flutter, 17 packages) and the
	// largest .BUILDINFO seen is ~120 KiB, dominated by its `installed` list of
	// the whole build environment.
	MaxFileBytes int64

	// MaxArchiveBytes caps the DECOMPRESSED bytes read out of a package
	// archive while looking for .BUILDINFO. It bounds a gzip bomb by more than
	// the ratio alone can.
	MaxArchiveBytes int64

	// MaxTarMembers caps the archive members inspected before giving up.
	MaxTarMembers int

	// MaxLines caps the lines parsed in one metadata file.
	MaxLines int

	// MaxLineBytes caps one line. The longest real line is a renamed source
	// URL, around 200 B.
	MaxLineBytes int

	// MaxValuesPerKey caps repeated keys -- `installed` in .BUILDINFO (278 in
	// the checked-in fixture, ~1,400 for a package built on a full desktop)
	// and `source` in .SRCINFO.
	MaxValuesPerKey int

	// MaxPackages caps the pkgname sections in one .SRCINFO. The largest split
	// base in the reference cache builds 17.
	MaxPackages int

	// MaxUnparsed caps the retained unparsable lines. The COUNT is always
	// exact; only the retained sample is bounded, because the count is what the
	// gap reports and a sample is only there to make it actionable.
	MaxUnparsed int
}

// DefaultLimits returns bounds with headroom over the measured worst case
// rather than fitted to it (see the field comments for the measurements).
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:    8 << 20,
		MaxArchiveBytes: 256 << 20,
		MaxTarMembers:   500_000,
		MaxLines:        200_000,
		MaxLineBytes:    64 << 10,
		MaxValuesPerKey: 50_000,
		MaxPackages:     10_000,
		MaxUnparsed:     32,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxArchiveBytes <= 0 {
		l.MaxArchiveBytes = d.MaxArchiveBytes
	}
	if l.MaxTarMembers <= 0 {
		l.MaxTarMembers = d.MaxTarMembers
	}
	if l.MaxLines <= 0 {
		l.MaxLines = d.MaxLines
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = d.MaxLineBytes
	}
	if l.MaxValuesPerKey <= 0 {
		l.MaxValuesPerKey = d.MaxValuesPerKey
	}
	if l.MaxPackages <= 0 {
		l.MaxPackages = d.MaxPackages
	}
	if l.MaxUnparsed <= 0 {
		l.MaxUnparsed = d.MaxUnparsed
	}
	return l
}

// field is one parsed "key = value" line.
//
// Indentation is deliberately NOT recorded. .SRCINFO's section structure is
// conventionally expressed with a leading tab, but that is a convention and not
// a guarantee -- testdata/pkgmeta/nperf-gui-appimage.SRCINFO writes its pkgname
// indented -- so carrying the indentation would only invite a parser to trust
// it. The key decides.
type field struct {
	key   string
	value string
}

// scanFields is the one line parser both formats use. Both are the same shape:
// UTF-8 text, one `key = value` per line, keys repeatable, '#' comments.
//
// It is written by hand rather than with bufio.Scanner because the per-line cap
// has to be a reported refusal (ErrLimit) and not bufio's silent
// ErrTooLong-shaped truncation: a truncated value is a wrong value, and this
// input is attacker-controlled.
func scanFields(r io.Reader, lim Limits) ([]field, []string, error) {
	data, err := readCapped(r, lim.MaxFileBytes)
	if err != nil {
		return nil, nil, err
	}

	var fields []field
	var unparsed []string
	unparsedCount := 0
	perKey := map[string]int{}

	lines := strings.Split(string(data), "\n")
	if len(lines) > lim.MaxLines {
		return nil, nil, fmt.Errorf("%w: %d lines, over the %d cap", ErrLimit, len(lines), lim.MaxLines)
	}
	for _, line := range lines {
		// A CRLF file otherwise puts a \r at the end of every value.
		line = strings.TrimRight(line, "\r")
		if len(line) > lim.MaxLineBytes {
			return nil, nil, fmt.Errorf("%w: a line is %d bytes, over the %d cap", ErrLimit, len(line), lim.MaxLineBytes)
		}
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}
		key, value, ok := strings.Cut(trimmed, "=")
		if !ok {
			unparsedCount++
			if len(unparsed) < lim.MaxUnparsed {
				unparsed = append(unparsed, trimmed)
			}
			continue
		}
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" {
			unparsedCount++
			if len(unparsed) < lim.MaxUnparsed {
				unparsed = append(unparsed, trimmed)
			}
			continue
		}
		perKey[key]++
		if perKey[key] > lim.MaxValuesPerKey {
			return nil, nil, fmt.Errorf("%w: key %q repeats more than %d times", ErrLimit, key, lim.MaxValuesPerKey)
		}
		fields = append(fields, field{key: key, value: strings.TrimSpace(value)})
	}
	// unparsedCount is reported to the caller through the length of the
	// returned slice only when it fits; the exact count travels separately.
	if unparsedCount > len(unparsed) {
		unparsed = append(unparsed, fmt.Sprintf("(and %d more unparsable lines)", unparsedCount-len(unparsed)))
	}
	return fields, unparsed, nil
}

// readCapped reads at most max bytes and reports the cap rather than silently
// truncating: a truncated metadata file parses into a plausible-looking record
// of something that was never there.
func readCapped(r io.Reader, max int64) ([]byte, error) {
	data, err := io.ReadAll(io.LimitReader(r, max+1))
	if err != nil {
		// An ErrLimit from an underlying capped reader is already the right
		// answer and must not be reworded into a read failure.
		return nil, err
	}
	if int64(len(data)) > max {
		return nil, fmt.Errorf("%w: input exceeds the %d byte cap", ErrLimit, max)
	}
	return data, nil
}
