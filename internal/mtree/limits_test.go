// internal/mtree/limits_test.go
package mtree

import (
	"bytes"
	"compress/gzip"
	"errors"
	"math/rand"
	"strings"
	"testing"
)

func gz(t *testing.T, plain []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	w := gzip.NewWriter(&buf)
	if _, err := w.Write(plain); err != nil {
		t.Fatalf("gzip write: %v", err)
	}
	if err := w.Close(); err != nil {
		t.Fatalf("gzip close: %v", err)
	}
	return buf.Bytes()
}

// The defaults are measurements, not guesses, and drifting them silently would
// either re-open the bomb or start refusing real packages. Measured over the
// 1410 installed mtrees: largest compressed 1,030,840 B, largest decompressed
// 5,665,567 B, compression ratio 1.30 min / 2.86 median / 17.05 max, most
// records in one mtree 39,999, longest line 298 B.
func TestDefaultLimitsClearMeasuredReality(t *testing.T) {
	lim := DefaultLimits()
	checks := []struct {
		name         string
		got, atLeast int64
	}{
		{"MaxCompressed", lim.MaxCompressed, 1030840},
		{"MaxDecompressed", lim.MaxDecompressed, 5665567},
		{"MaxRatio", lim.MaxRatio, 18},
		{"MaxEntries", lim.MaxEntries, 39999},
		{"MaxLineBytes", int64(lim.MaxLineBytes), 298},
	}
	for _, c := range checks {
		if c.got < c.atLeast {
			t.Errorf("%s = %d, below the measured maximum %d", c.name, c.got, c.atLeast)
		}
	}
	if lim.MaxRatio > 1000 {
		t.Errorf("MaxRatio = %d, too loose to bound a bomb", lim.MaxRatio)
	}
}

// 17.05x is the highest ratio any installed mtree reaches. A cap that fires on
// legitimate data is worse than no cap: it turns every large package into a
// coverage gap.
func TestDecompressAcceptsRealisticRatio(t *testing.T) {
	var b strings.Builder
	b.WriteString("#mtree\n")
	for i := 0; b.Len() < 4<<20; i++ {
		b.WriteString("./usr/share/doc/pkg/file")
		b.WriteString(strings.Repeat("x", i%40))
		b.WriteString(" time=1773995553.0 size=1 sha256digest=")
		b.WriteString(shaA52)
		b.WriteByte('\n')
	}
	plain := []byte(b.String())
	comp := gz(t, plain)
	ratio := float64(len(plain)) / float64(len(comp))
	if ratio < 18 {
		t.Fatalf("fixture ratio %.1fx does not exceed the measured 17.05x maximum", ratio)
	}
	got, err := DefaultLimits().Decompress(bytes.NewReader(comp))
	if err != nil {
		t.Fatalf("Decompress of a %.1fx input: %v", ratio, err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("Decompress returned %d bytes, want %d", len(got), len(plain))
	}
}

func TestDecompressRejectsRatioBomb(t *testing.T) {
	// 8 MiB of zeros: far under the absolute ceiling, so only the ratio cap
	// can stop it.
	plain := make([]byte, 8<<20)
	comp := gz(t, plain)
	ratio := len(plain) / len(comp)
	if ratio <= int(DefaultLimits().MaxRatio) {
		t.Fatalf("fixture ratio %dx does not exceed the cap", ratio)
	}
	got, err := DefaultLimits().Decompress(bytes.NewReader(comp))
	if err == nil {
		t.Fatalf("Decompress of a %dx bomb returned %d bytes, want an error", ratio, len(got))
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
	t.Logf("rejected %d compressed bytes claiming %d (%dx): %v", len(comp), len(plain), ratio, err)
}

// The ratio cap alone is not enough: an attacker who pads the compressed input
// keeps the ratio respectable while still asking for unbounded memory.
func TestDecompressRejectsAbsoluteCeiling(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxRatio = 1 << 30 // disable the ratio cap, leaving only the ceiling
	lim.MaxDecompressed = 1 << 16
	plain := bytes.Repeat([]byte("#mtree\n"), 1<<14) // 112 KiB
	_, err := lim.Decompress(bytes.NewReader(gz(t, plain)))
	if err == nil {
		t.Fatal("Decompress exceeded MaxDecompressed without an error")
	}
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
	t.Logf("ceiling fired: %v", err)
}

// Reading unbounded compressed input is its own denial of service, before a
// single byte is inflated.
func TestDecompressRejectsOversizedCompressedInput(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxCompressed = 512
	// Incompressible, so the compressed form really is over the cap and it is
	// the compressed cap rather than the ratio that has to catch it.
	noise := make([]byte, 8<<10)
	rng := rand.New(rand.NewSource(1))
	rng.Read(noise)
	comp := gz(t, noise)
	if int64(len(comp)) <= lim.MaxCompressed {
		t.Fatalf("fixture compressed to %d bytes, not over the %d cap", len(comp), lim.MaxCompressed)
	}
	_, err := lim.Decompress(bytes.NewReader(comp))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}

func TestDecompressRejectsCorruptGzip(t *testing.T) {
	good := gz(t, []byte("#mtree\n./usr type=dir\n"))
	cases := []struct {
		name string
		in   []byte
	}{
		{"truncated mid-stream", good[:len(good)-8]},
		{"truncated to the header", good[:4]},
		{"empty", nil},
		{"not gzip at all", []byte("#mtree\n./usr type=dir\n")},
		{"flipped byte in the deflate stream", flip(good, len(good)/2)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := DefaultLimits().Decompress(bytes.NewReader(c.in))
			if err == nil {
				t.Fatalf("Decompress = %q, want an error", got)
			}
			if !errors.Is(err, ErrGzip) {
				t.Fatalf("error = %v, want ErrGzip", err)
			}
			if !strings.Contains(err.Error(), "mtree") {
				t.Errorf("error %q does not name the package", err.Error())
			}
		})
	}
}

func flip(b []byte, i int) []byte {
	out := bytes.Clone(b)
	out[i] ^= 0xff
	return out
}

// Zero paths across the ~325k recorded on the reference system are absolute,
// contain "..", or fail to be "./"-rooted. Any occurrence is therefore
// damning rather than ambiguous, and is refused rather than repaired -- an
// mtree shipped by an AUR package was written by whoever built it.
func TestValidatePath(t *testing.T) {
	good := []string{
		"./usr/bin/pacman",
		"./usr/share/alsa/Librem 5.conf",
		"./.BUILDINFO",
		"./a..b/c",   // "..": only as a whole component
		"./...",      // three dots is an ordinary name
		"./usr/lib/", // trailing slash is odd but not an escape
	}
	for _, p := range good {
		if err := ValidatePath(p); err != nil {
			t.Errorf("ValidatePath(%q) = %v, want nil", p, err)
		}
	}
	bad := []string{
		"/etc/shadow",
		"../etc/shadow",
		"./../etc/shadow",
		"./usr/../../etc/shadow",
		"./usr/bin/..",
		"..",
		".",
		"./",
		"usr/bin/pacman",
		"",
		"./usr/bin/x\x00y",
		"./usr//bin",
	}
	for _, p := range bad {
		err := ValidatePath(p)
		if err == nil {
			t.Errorf("ValidatePath(%q) = nil, want ErrPath", p)
			continue
		}
		if !errors.Is(err, ErrPath) {
			t.Errorf("ValidatePath(%q) = %v, want ErrPath", p, err)
			continue
		}
		t.Logf("refused: %v", err)
	}
}

// A record count is bounded independently of the byte ceiling: the slice is
// what the analyse phase holds in memory for every package at once.
func TestParseRejectsTooManyEntries(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxEntries = 2
	in := "#mtree\n./a type=dir\n./b type=dir\n./c type=dir\n"
	_, err := lim.Parse(strings.NewReader(in))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}

func TestParseRejectsOverlongLine(t *testing.T) {
	lim := DefaultLimits()
	lim.MaxLineBytes = 64
	in := "#mtree\n./" + strings.Repeat("a", 4096) + " type=dir\n"
	_, err := lim.Parse(strings.NewReader(in))
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("error = %v, want ErrLimit", err)
	}
}
