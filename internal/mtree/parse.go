// internal/mtree/parse.go

// Package mtree reads the per-package mtree that pacman stores in the local
// database, turning it into records the integrity checks compare against what
// is on disk.
//
// Nothing here is novel on its own: `pacman -Qkk` already verifies installed
// files against these same digests. This package exists because the digests
// are needed as *data* -- for offline-root operation, for parallel and
// structured output, for correlation with other evidence, and because P4's
// baseline hashes the mtree itself so that tampering with the mtree, which
// `-Qkk` structurally cannot see, becomes detectable.
//
// Everything in this package is a pure function of its input (INV-4) and runs
// after the privilege drop, on bytes the collector already buffered. It parses
// and never executes (INV-2). Input is attacker-controlled: an AUR package's
// mtree was generated on the machine that built it. Every refusal here is a
// coverage gap the caller must attribute to one package (INV-9), never a
// silent pass and never a global abort.
package mtree

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"strconv"
	"strings"
)

// ErrSyntax reports an mtree record this parser cannot read.
var ErrSyntax = errors.New("mtree: malformed record")

// Entry is one mtree record, with /set inheritance already applied.
//
// Fields absent from the record are left at their zero value; Type tells the
// consumer which of them are meaningful. A dir carries no Size and no digest,
// and a link carries Link instead.
type Entry struct {
	// Path is the recorded path with vis(3) escapes decoded, still rooted at
	// "./" as mtree records it. It is a byte string and is not guaranteed to
	// be valid UTF-8.
	Path string

	// Type is "file", "dir" or "link" -- the three that occur. mtree's own
	// default of "file" is applied when no record and no /set names a type.
	Type string

	Size int64

	// Mode is the raw octal permission word as recorded, e.g. 0o4755. It is
	// deliberately not an fs.FileMode: fs.FileMode encodes setuid, setgid and
	// sticky outside the low twelve bits, and those three bits are precisely
	// what the SUID/SGID checks read. Compare against st.Mode&0o7777.
	Mode uint32

	// Time is the recorded mtime in seconds. It is a float because pacman
	// writes one (every one of the 461,601 time= values on the reference
	// system carries a fractional part), and truncating it to an integer
	// would make the temporal correlation key lie about ordering.
	Time float64

	// SHA256 and MD5 are lowercase hex as recorded, empty when absent. 237
	// entries carry md5digest; a record may carry both.
	SHA256 string
	MD5    string

	// Link is the recorded target of a type=link record, decoded but NOT
	// resolved. It is compared as a string: 4,145 legitimate targets contain
	// "..", so resolving them would manufacture findings, and following them
	// while running with elevated read capability would be worse.
	Link string
}

// Parse reads a decompressed mtree. See Limits.Parse; this uses DefaultLimits.
func Parse(r io.Reader) ([]Entry, error) { return DefaultLimits().Parse(r) }

// ParseGzip reads the gzipped mtree as stored in the local database. See
// Limits.ParseGzip; this uses DefaultLimits.
func ParseGzip(r io.Reader) ([]Entry, error) { return DefaultLimits().ParseGzip(r) }

// ParseGzip decompresses under lim and parses the result.
func (lim Limits) ParseGzip(r io.Reader) ([]Entry, error) {
	plain, err := lim.Decompress(r)
	if err != nil {
		return nil, err
	}
	return lim.Parse(bytes.NewReader(plain))
}

// Parse reads a decompressed mtree and returns its on-disk records.
//
// Package metadata records (`./.PKGINFO` and friends) are filtered out: they
// describe the package, not the filesystem, and looking for them on disk would
// report a missing file for every installed package.
//
// A record whose path is absolute, contains "..", or is not "./"-rooted is
// refused rather than sanitised. Zero such paths exist across the ~325k
// recorded on the reference system, so an occurrence is not ambiguous.
func (lim Limits) Parse(r io.Reader) ([]Entry, error) {
	sc := bufio.NewScanner(r)
	// The initial buffer must not exceed the cap, or a token larger than the
	// cap fits without the scanner ever needing to grow -- and the bound never
	// fires. bufio only checks the cap on growth.
	sc.Buffer(make([]byte, 0, min(64<<10, lim.MaxLineBytes)), lim.MaxLineBytes)

	if err := scanHeader(sc); err != nil {
		return nil, err
	}

	var (
		out      []Entry
		defaults keywords
		line     int64 = 1
	)
	for sc.Scan() {
		line++
		text := strings.TrimRight(sc.Text(), " \t")
		if text == "" || strings.HasPrefix(text, "#") {
			continue
		}
		fields := strings.Fields(text)
		switch fields[0] {
		case "/set":
			if err := defaults.set(fields[1:]); err != nil {
				return nil, atLine(line, err)
			}
		case "/unset":
			if err := defaults.unset(fields[1:]); err != nil {
				return nil, atLine(line, err)
			}
		default:
			e, keep, err := record(fields, defaults)
			if err != nil {
				return nil, atLine(line, err)
			}
			if !keep {
				continue
			}
			if int64(len(out)) >= lim.MaxEntries {
				return nil, fmt.Errorf("%w: more than %d records", ErrLimit, lim.MaxEntries)
			}
			out = append(out, e)
		}
	}
	if err := sc.Err(); err != nil {
		if errors.Is(err, bufio.ErrTooLong) {
			return nil, fmt.Errorf("%w: record longer than %d bytes", ErrLimit, lim.MaxLineBytes)
		}
		return nil, fmt.Errorf("mtree: read: %w", err)
	}
	return out, nil
}

// record turns one path line into an Entry, reporting whether it describes
// something that should exist on disk.
func record(fields []string, kw keywords) (Entry, bool, error) {
	path, err := Unvis(fields[0])
	if err != nil {
		return Entry{}, false, err
	}
	if err := ValidatePath(path); err != nil {
		return Entry{}, false, err
	}
	if err := kw.set(fields[1:]); err != nil {
		return Entry{}, false, err
	}
	if isPackageMetadata(path) {
		return Entry{}, false, nil
	}
	e := Entry{
		Path:   path,
		Type:   kw.typ,
		Size:   kw.size,
		Mode:   kw.mode,
		Time:   kw.time,
		SHA256: kw.sha256,
		MD5:    kw.md5,
		Link:   kw.link,
	}
	if e.Type == "" {
		e.Type = "file" // mtree's documented default.
	}
	return e, true, nil
}

// isPackageMetadata reports whether a path is one of the dot-files mtree
// records for the package itself rather than for the filesystem.
//
// The rule is the shape, not a list: a top-level dot-file directly under the
// package root. On the reference system that matches exactly ./.BUILDINFO
// (1410), ./.PKGINFO (1410) and ./.INSTALL (57), and nothing else -- no
// installed package ships a dot-file at the filesystem root. Keying on the
// shape also covers .MTREE and .CHANGELOG, which a package built by other
// tooling can carry and a hand-maintained list would miss.
func isPackageMetadata(path string) bool {
	rest, ok := strings.CutPrefix(path, "./.")
	return ok && !strings.Contains(rest, "/")
}

// keywords holds the values a /set makes inheritable, and doubles as the
// accumulator for one record's own keywords.
type keywords struct {
	typ    string
	size   int64
	mode   uint32
	time   float64
	sha256 string
	md5    string
	link   string
}

// set applies `keyword=value` pairs, overriding what is already there.
//
// Keywords this parser does not model are ignored. mtree defines more of them
// than pacman writes (nlink, flags, uid, gid), and refusing a whole package
// over one we do not read would be a coverage gap we invented ourselves.
func (kw *keywords) set(pairs []string) error {
	for _, p := range pairs {
		key, val, ok := strings.Cut(p, "=")
		if !ok {
			return fmt.Errorf("%w: keyword %q has no value", ErrSyntax, p)
		}
		if err := kw.apply(key, val); err != nil {
			return err
		}
	}
	return nil
}

func (kw *keywords) apply(key, val string) error {
	switch key {
	case "type":
		kw.typ = val
	case "size":
		n, err := strconv.ParseInt(val, 10, 64)
		if err != nil || n < 0 {
			return fmt.Errorf("%w: size=%q", ErrSyntax, val)
		}
		kw.size = n
	case "mode":
		n, err := strconv.ParseUint(val, 8, 32)
		if err != nil || n > 0o7777 {
			return fmt.Errorf("%w: mode=%q", ErrSyntax, val)
		}
		kw.mode = uint32(n)
	case "time":
		// Float, and seconds. pacman writes "1773995553.0"; some mtree
		// writers use "sec.nsec", which parses to the same instant here.
		f, err := strconv.ParseFloat(val, 64)
		if err != nil {
			return fmt.Errorf("%w: time=%q", ErrSyntax, val)
		}
		kw.time = f
	case "sha256digest", "sha256":
		if err := checkHex(key, val, 64); err != nil {
			return err
		}
		kw.sha256 = val
	case "md5digest", "md5":
		if err := checkHex(key, val, 32); err != nil {
			return err
		}
		kw.md5 = val
	case "link":
		// Decoded, never resolved. Targets legitimately contain "..".
		s, err := Unvis(val)
		if err != nil {
			return err
		}
		kw.link = s
	}
	return nil
}

// unset removes inherited keywords. `/unset all` clears everything.
func (kw *keywords) unset(names []string) error {
	if len(names) == 0 {
		return fmt.Errorf("%w: /unset names no keyword", ErrSyntax)
	}
	for _, n := range names {
		if n == "all" {
			*kw = keywords{}
			continue
		}
		switch n {
		case "type":
			kw.typ = ""
		case "size":
			kw.size = 0
		case "mode":
			kw.mode = 0
		case "time":
			kw.time = 0
		case "sha256digest", "sha256":
			kw.sha256 = ""
		case "md5digest", "md5":
			kw.md5 = ""
		case "link":
			kw.link = ""
		}
	}
	return nil
}

// checkHex refuses a digest that is not exactly n lowercase hex characters. A
// digest that is not a digest can only ever compare unequal, which would be
// reported as a modified file rather than as the unreadable record it is.
func checkHex(key, val string, n int) error {
	if len(val) != n {
		return fmt.Errorf("%w: %s=%q is %d characters, want %d", ErrSyntax, key, val, len(val), n)
	}
	for i := 0; i < len(val); i++ {
		c := val[i]
		if (c < '0' || c > '9') && (c < 'a' || c > 'f') {
			return fmt.Errorf("%w: %s=%q is not lowercase hex", ErrSyntax, key, val)
		}
	}
	return nil
}

// atLine attributes a refusal to the record that caused it, so the coverage gap
// the caller reports can name something more useful than the package.
func atLine(line int64, err error) error {
	return fmt.Errorf("line %d: %w", line, err)
}
