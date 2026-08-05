// internal/mtree/unvis.go
package mtree

import (
	"errors"
	"fmt"
	"strings"
)

// ErrVisEscape reports a backslash sequence this decoder will not decode.
//
// It is a sentinel because the caller has to turn it into a coverage gap
// attributed to one package (INV-9), not into a finding and not into silence.
var ErrVisEscape = errors.New("mtree: malformed vis(3) escape")

// simpleEscapes are the one-character vis(3) escapes: the byte that follows the
// backslash maps directly to one output byte.
//
// Derived from libbsd 0.12.2's strnunvis(3), which is the unvis available on
// the target platform and was used as the oracle for the decoder's test table.
var simpleEscapes = [256]struct {
	b  byte
	ok bool
}{
	'\\': {'\\', true},
	'a':  {0x07, true}, // alert
	'b':  {0x08, true}, // backspace
	'E':  {0x1b, true}, // escape
	'f':  {0x0c, true}, // form feed
	'n':  {0x0a, true}, // newline
	'r':  {0x0d, true}, // carriage return
	's':  {0x20, true}, // space
	't':  {0x09, true}, // tab
	'v':  {0x0b, true}, // vertical tab
}

// Unvis decodes a vis(3)-escaped mtree field.
//
// Every path and every link target in a pacman mtree is vis-encoded. Measured
// over the 1410 installed mtrees on the reference system: 397 lines carry a
// backslash and 669 backslashes appear in total, all of them octal -- 659
// `\040` (space), plus `\043`, `\133`, four `\134` and one two-byte UTF-8 pair
// `\303\236`. A decoder that passes those through undecoded looks for a file
// whose name contains a literal backslash, does not find it, and reports a
// missing file for every one of them.
//
// The rest of the escape set is decoded because unvis(3) defines it and an
// mtree shipped by an AUR package was generated on the attacker's machine.
// Unlike strnunvis(3), which decodes anything it does not recognise as the
// character itself, an escape this function cannot decode unambiguously is an
// error: quietly producing a different path than the one recorded turns a
// parse gap into a fabricated missing-file finding.
//
// The result is a byte string, not necessarily valid UTF-8; mtree paths are
// byte strings and are compared as such.
func Unvis(s string) (string, error) {
	// The overwhelming majority of paths carry no escape at all.
	if !strings.Contains(s, `\`) {
		return s, nil
	}
	var out strings.Builder
	out.Grow(len(s))
	for i := 0; i < len(s); {
		if s[i] != '\\' {
			out.WriteByte(s[i])
			i++
			continue
		}
		b, emit, n, err := decodeEscape(s[i:])
		if err != nil {
			return "", err
		}
		if emit {
			out.WriteByte(b)
		}
		i += n
	}
	return out.String(), nil
}

// decodeEscape decodes the escape sequence at the start of s, which begins with
// a backslash. It returns the decoded byte, whether that byte is emitted at all
// (the `\$` end marker decodes to nothing), and how many input bytes the
// sequence consumed.
func decodeEscape(s string) (b byte, emit bool, n int, err error) {
	if len(s) < 2 {
		return 0, false, 0, escapeErr("trailing backslash", s)
	}
	switch c := s[1]; {
	case simpleEscapes[c].ok:
		return simpleEscapes[c].b, true, 2, nil

	// `\$` is vis(3)'s end-of-encoding marker and encodes no byte.
	case c == '$':
		return 0, false, 2, nil

	// Octal, one to three digits. This is the only form pacman emits.
	case c >= '0' && c <= '7':
		v := 0
		n = 1
		for n < 4 && n < len(s) && s[n] >= '0' && s[n] <= '7' {
			v = v*8 + int(s[n]-'0')
			n++
		}
		if v > 0xff {
			// strnunvis(3) truncates to the low byte here; that silently
			// renames the file, so refuse instead.
			return 0, false, 0, escapeErr("octal value out of byte range", s[:n])
		}
		return byte(v), true, n, nil

	// `\^c` is a control character; `\M-c` and `\M^c` set the high bit.
	case c == '^':
		b, err = decodeCtrl(s, 2)
		return b, true, 3, err
	case c == 'M':
		if len(s) < 4 {
			return 0, false, 0, escapeErr("truncated meta escape", s)
		}
		switch s[2] {
		case '-':
			// Only printable ASCII has an unambiguous meta form.
			if s[3] < 0x20 || s[3] > 0x7e {
				return 0, false, 0, escapeErr("meta of a non-printable byte", s[:4])
			}
			return s[3] | 0x80, true, 4, nil
		case '^':
			b, err = decodeCtrl(s, 3)
			return b | 0x80, true, 4, err
		default:
			return 0, false, 0, escapeErr("meta escape is neither \\M- nor \\M^", s[:3])
		}
	}
	return 0, false, 0, escapeErr("unknown escape", s[:2])
}

// decodeCtrl decodes the control character named at s[i], the byte after a `^`.
// `?` is DEL; otherwise the byte must be one of `@` through `_`, the range for
// which "control" means anything.
func decodeCtrl(s string, i int) (byte, error) {
	if i >= len(s) {
		return 0, escapeErr("truncated control escape", s)
	}
	c := s[i]
	switch {
	case c == '?':
		return 0x7f, nil
	case c >= 0x40 && c <= 0x5f:
		return c & 0x1f, nil
	}
	return 0, escapeErr("control escape out of range", s[:i+1])
}

func escapeErr(what, seq string) error {
	return fmt.Errorf("%w: %s in %q", ErrVisEscape, what, seq)
}
