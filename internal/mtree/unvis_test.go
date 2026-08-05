// internal/mtree/unvis_test.go
package mtree

import (
	"errors"
	"strings"
	"testing"
)

// The escapes that actually occur. Measured over all 1410 installed mtrees on
// the reference system: 397 lines carry a backslash, 669 backslashes total, and
// every one of them is octal — 659 `\040`, plus `\043`, `\133`, 4×`\134` and the
// two-byte UTF-8 pair `\303\236`. The rest of the table below is not decoration:
// unvis(3) defines those forms, an attacker-supplied mtree may use them, and a
// decoder that only knows `\040` would either mis-decode or reject them.
func TestUnvisTable(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want string
	}{
		// Measured on the reference system.
		{"no escape at all", "./usr/bin/pacman", "./usr/bin/pacman"},
		{"octal space", `./a/Librem\0405.conf`, "./a/Librem 5.conf"},
		{"octal hash", `./a/\043b`, "./a/#b"},
		{"octal bracket", `./usr/bin/\133`, "./usr/bin/["},
		{"octal backslash", `./a/\134b`, `./a/\b`},
		{"octal utf8 pair", `./x/\303\236foo.go`, "./x/\xc3\x9efoo.go"},
		{"several in one path", `./A\040B\040C`, "./A B C"},

		// Defined by unvis(3), absent from pacman's output.
		{"short octal", `\0`, "\x00"},
		{"two-digit octal", `\40`, " "},
		{"octal then digit", `\0408`, " 8"},
		{"octal max", `\377`, "\xff"},
		{"backslash escape", `a\\b`, `a\b`},
		{"alert", `a\ab`, "a\ab"},
		{"backspace", `a\bb`, "a\bb"},
		{"formfeed", `a\fb`, "a\fb"},
		{"newline", `a\nb`, "a\nb"},
		{"carriage return", `a\rb`, "a\rb"},
		{"space", `a\sb`, "a b"},
		{"tab", `a\tb`, "a\tb"},
		{"vertical tab", `a\vb`, "a\vb"},
		{"escape", `a\Eb`, "a\x1bb"},
		{"control", `a\^Db`, "a\x04b"},
		{"control at", `\^@`, "\x00"},
		{"control underscore", `\^_`, "\x1f"},
		{"delete", `\^?`, "\x7f"},
		{"meta", `\M-A`, "\xc1"},
		{"meta control", `\M^A`, "\x81"},
		{"meta delete", `\M^?`, "\xff"},
		{"octal stops at non-octal digit", `\778`, "\x3f8"},
		{"end marker is nothing", `abc\$`, "abc"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Unvis(c.in)
			if err != nil {
				t.Fatalf("Unvis(%q): %v", c.in, err)
			}
			if got != c.want {
				t.Errorf("Unvis(%q) = %q, want %q", c.in, got, c.want)
			}
		})
	}
}

// A decoder that guesses at a malformed escape invents a path. INV-9: this is a
// coverage gap the caller must attribute to a subject, so it has to be an error
// rather than a best-effort string.
//
// This is deliberately stricter than libbsd's strnunvis(3), which was used as
// the oracle for the valid table above. Measured against libbsd 0.12.2, that
// implementation decodes every one of the inputs below without complaint:
// `\q` becomes "q", `\-` becomes "-", a trailing backslash vanishes, `\^~`
// becomes 0x1e and `\400` wraps to 0x00. Each of those silently yields a path
// that is not the path the mtree named, and a path we then fail to find on
// disk is reported as a missing file. Refusing to decode makes it a gap
// attributable to one package instead of a fabricated finding.
func TestUnvisRejectsMalformed(t *testing.T) {
	bad := []struct {
		name string
		in   string
	}{
		{"lone trailing backslash", `./usr/bin/x\`},
		{"unknown escape letter", `./usr/\q`},
		{"unknown escape dash", `./usr/\-x`},
		{"octal out of byte range", `./usr/\400`},
		{"truncated control", `./usr/\^`},
		{"control out of range", `./usr/\^~`},
		{"truncated meta", `./usr/\M`},
		{"meta without form", `./usr/\Mx`},
		{"truncated meta control", `./usr/\M^`},
		{"meta control out of range", `./usr/\M^~`},
		{"meta of a non-printable byte", "./usr/\\M-\x01"},
	}
	for _, c := range bad {
		t.Run(c.name, func(t *testing.T) {
			got, err := Unvis(c.in)
			if err == nil {
				t.Fatalf("Unvis(%q) = %q, want error", c.in, got)
			}
			if !errors.Is(err, ErrVisEscape) {
				t.Errorf("Unvis(%q) error = %v, want ErrVisEscape", c.in, err)
			}
			if !strings.Contains(err.Error(), "mtree") {
				t.Errorf("error %q does not name the package", err.Error())
			}
		})
	}
}

// The fast path must not alter a string that carries no escape, including one
// holding raw high bytes — mtree paths are byte strings, not necessarily UTF-8.
func TestUnvisPassesThroughRawBytes(t *testing.T) {
	in := "./x/\xff\xfe"
	got, err := Unvis(in)
	if err != nil {
		t.Fatalf("Unvis: %v", err)
	}
	if got != in {
		t.Errorf("Unvis(%q) = %q, want unchanged", in, got)
	}
}
