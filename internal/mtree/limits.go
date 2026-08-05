// internal/mtree/limits.go
package mtree

import (
	"bufio"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"strings"
)

// The sentinels a caller switches on. Each one is a coverage gap attributable
// to one package (INV-9), never a finding: refusing to read an mtree says
// nothing about whether the files it describes were modified.
var (
	// ErrLimit reports input that exceeded a bound rather than input that was
	// wrong. Hangs outrank panics, so everything here is bounded.
	ErrLimit = errors.New("mtree: input exceeds a bound")

	// ErrGzip reports a compressed stream that could not be inflated.
	ErrGzip = errors.New("mtree: not a readable gzip stream")

	// ErrHeader reports a stream whose first line is not "#mtree".
	ErrHeader = errors.New("mtree: missing #mtree header")

	// ErrPath reports a recorded path that escapes the package root.
	ErrPath = errors.New("mtree: path escapes the package root")
)

// Limits bounds everything an attacker-supplied mtree controls.
//
// The values are exported and copyable so a caller can tighten them and so a
// test can prove each bound fires independently; DefaultLimits is what the
// scan uses.
type Limits struct {
	// MaxCompressed caps the compressed bytes read, before inflation.
	MaxCompressed int64

	// MaxDecompressed is the absolute ceiling on inflated bytes. It exists
	// because the ratio cap alone is defeated by padding the input.
	MaxDecompressed int64

	// MaxRatio caps decompressed/compressed. It exists because the absolute
	// ceiling alone still lets a few KiB of input allocate all of it.
	MaxRatio int64

	// RatioFloor is the output size below which the ratio is not judged. A
	// gzip member has fixed overhead, so a tiny file's ratio is meaningless.
	RatioFloor int64

	// MaxEntries caps the records one mtree yields; the slice is held in
	// memory for every package at once.
	MaxEntries int64

	// MaxLineBytes caps one record.
	MaxLineBytes int
}

// DefaultLimits returns bounds derived from the reference system, each with
// headroom over the largest real value rather than fitted to it.
//
// Measured over the 1410 installed mtrees, 2026-08-05: largest compressed
// 1,030,840 B; largest decompressed 5,665,567 B; compression ratio 1.30 min,
// 2.86 median, 17.05 max; most records in one mtree 39,999; longest line
// 298 B. A 100x ratio cap is therefore roughly six times the worst legitimate
// case and still bounds a zip bomb to the compressed size it actually cost the
// attacker to ship.
func DefaultLimits() Limits {
	return Limits{
		MaxCompressed:   16 << 20, // ~16x the largest observed
		MaxDecompressed: 64 << 20, // ~11x the largest observed
		MaxRatio:        100,      // ~6x the worst observed
		RatioFloor:      1 << 20,
		MaxEntries:      1_000_000, // 25x the largest observed
		MaxLineBytes:    64 << 10,  // 220x the longest observed
	}
}

// Decompress inflates a gzipped mtree under lim.
//
// The result is buffered rather than streamed because the whole mtree is
// parsed anyway and the ceiling is what makes buffering safe. This runs after
// the privilege drop: spec §11.1 puts decompression in the unprivileged
// analyse phase precisely because it is a place a hostile input gets to reach.
func (lim Limits) Decompress(r io.Reader) ([]byte, error) {
	in := &countingReader{r: r, max: lim.MaxCompressed}
	zr, err := gzip.NewReader(in)
	if err != nil {
		if errors.Is(err, errCompressedTooLarge) {
			return nil, fmt.Errorf("%w: compressed input over %d bytes", ErrLimit, lim.MaxCompressed)
		}
		return nil, fmt.Errorf("%w: %v", ErrGzip, err)
	}
	defer zr.Close()

	var out bytes.Buffer
	buf := make([]byte, 32<<10)
	for {
		n, rerr := zr.Read(buf)
		if n > 0 {
			if int64(out.Len())+int64(n) > lim.MaxDecompressed {
				return nil, fmt.Errorf("%w: decompressed over %d bytes", ErrLimit, lim.MaxDecompressed)
			}
			out.Write(buf[:n])
			// Judged as it inflates, not afterwards: the point of the cap is
			// to stop before the memory is spent.
			if o := int64(out.Len()); o > lim.RatioFloor && o > in.n*lim.MaxRatio {
				return nil, fmt.Errorf("%w: %d bytes from %d compressed exceeds %dx",
					ErrLimit, o, in.n, lim.MaxRatio)
			}
		}
		if rerr == io.EOF {
			return out.Bytes(), nil
		}
		if rerr != nil {
			if errors.Is(rerr, errCompressedTooLarge) {
				return nil, fmt.Errorf("%w: compressed input over %d bytes", ErrLimit, lim.MaxCompressed)
			}
			// io.ErrUnexpectedEOF here is a truncated member: the mtree in the
			// local database was cut short, which is not a clean scan.
			return nil, fmt.Errorf("%w: %v", ErrGzip, rerr)
		}
	}
}

var errCompressedTooLarge = errors.New("compressed input over the cap")

// countingReader bounds and counts what is read from the compressed source.
type countingReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *countingReader) Read(p []byte) (int, error) {
	if c.max > 0 {
		if c.n >= c.max {
			return 0, errCompressedTooLarge
		}
		if int64(len(p)) > c.max-c.n {
			p = p[:c.max-c.n]
		}
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// scanHeader consumes the first line and requires it to be the mtree magic.
//
// Every one of the 1410 installed mtrees begins with exactly "#mtree". A file
// that does not is not an mtree, and guessing that the rest might still parse
// would mean reporting on records from something else entirely.
func scanHeader(sc *bufio.Scanner) error {
	if !sc.Scan() {
		if err := sc.Err(); err != nil {
			return fmt.Errorf("mtree: read: %w", err)
		}
		return fmt.Errorf("%w: input is empty", ErrHeader)
	}
	line := strings.TrimRight(sc.Text(), " \t")
	if line != "#mtree" && !strings.HasPrefix(line, "#mtree ") {
		return fmt.Errorf("%w: first line is %q", ErrHeader, line)
	}
	return nil
}

// ValidatePath refuses a recorded path that is not confined to the package
// root, and is called on the DECODED path so that a "." hidden in an octal
// escape cannot slip past.
//
// Zero of the ~325k paths recorded on the reference system are absolute,
// contain a ".." component, or fail to be "./"-rooted. That measurement is
// what makes this a refusal rather than a repair: there is no legitimate case
// to preserve, and the mtree of an AUR package was generated by the same build
// that would want to escape.
//
// Link targets are NOT validated here. 4,145 of them legitimately contain
// "..", and they are compared as strings and never resolved.
func ValidatePath(p string) error {
	rest, ok := strings.CutPrefix(p, "./")
	if !ok {
		return fmt.Errorf("%w: %q is not ./-rooted", ErrPath, p)
	}
	if rest == "" {
		return fmt.Errorf("%w: %q names no file", ErrPath, p)
	}
	if strings.IndexByte(p, 0) >= 0 {
		return fmt.Errorf("%w: %q contains NUL", ErrPath, p)
	}
	// A trailing slash names the same directory, so ignore one before
	// splitting; an empty component anywhere else is malformed.
	for i, c := range strings.Split(strings.TrimSuffix(rest, "/"), "/") {
		switch c {
		case "..":
			return fmt.Errorf("%w: %q has a .. component", ErrPath, p)
		case "":
			return fmt.Errorf("%w: %q has an empty component at %d", ErrPath, p, i)
		}
	}
	return nil
}
