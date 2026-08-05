// internal/baseline/canon.go

// Package baseline holds the cryptographic core the P4 baseline and trust chain
// stand on: canonical serialisation, OpenSSH ed25519 key handling and detached
// signatures over canonical bytes.
//
// Everything here is a pure function of its arguments (INV-4). Nothing reads the
// wall clock -- a timestamp is an input, because a signature that depends on
// when it was made cannot be reproduced -- nothing reads $HOME or a global, and
// nothing writes (INV-5). Nothing executes: signature and key material are
// parsed, never handed to a shell or a helper binary (INV-2).
//
// # What canonical means here, and why each rule exists
//
// A signature is a signature over BYTES. If two encoders can produce two byte
// strings for one logical document, then a manifest signed on the monitored host
// can fail to verify on the auditor's, and the whole chain reports tampering
// that never happened. Determinism is the feature; the rules follow from it:
//
//   - Object keys are sorted by UTF-8 byte order. That is also what "fixed field
//     order" buys: because the order is derived from the key bytes and never
//     from Go struct declaration order, moving a field in a later refactor
//     cannot invalidate signatures already made.
//   - Floats are REFUSED, never rounded. IEEE-754 has several spellings of one
//     value, encoding/json has changed how it picks between them, and a rounded
//     float is a verification failure waiting years to happen with no attacker
//     involved. See Seconds for how a fractional mtree timestamp crosses into
//     canonical form without a float.
//   - Strings must be valid UTF-8. encoding/json substitutes U+FFFD for invalid
//     bytes, which can map two DISTINCT mtree paths (they are byte strings, not
//     UTF-8) onto one canonical document -- a collision inside something signed.
//     Callers hand over an escaped form instead; mtree already has vis(3).
//   - No HTML escaping, no \u escaping of non-ASCII, minimal control escapes:
//     one spelling per string.
//   - Duplicate keys are refused, in input and in struct tags. A document with
//     two "a" keys means two things to two parsers.
//
// # What a valid signature over these bytes does and does not prove (INV-6)
//
// It proves the holder of a private key emitted exactly these bytes. It does not
// prove they were true, that the scan behind them was complete, that the host
// was not already compromised when they were made, or that the entry is still
// the newest one -- that last is the chain's job (P4 task 5), not this file's.
package baseline

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"
)

// MaxDepth bounds nesting in a canonical document, in both directions: it stops
// a hostile document from exhausting the stack on the way in, and a cyclic Go
// value from looping forever on the way out.
const MaxDepth = 64

var (
	// ErrFloat reports a float in a document that is about to be signed, or a
	// number in canonical input that is not an exact 64-bit integer. Both are
	// refused rather than rounded.
	ErrFloat = errors.New("baseline: non-integer number in canonical document")

	// ErrNotUTF8 reports a string or key that is not valid UTF-8.
	ErrNotUTF8 = errors.New("baseline: string is not valid UTF-8")

	// ErrUnsupportedType reports a Go type with no canonical spelling.
	ErrUnsupportedType = errors.New("baseline: type has no canonical encoding")

	// ErrDuplicateKey reports two occurrences of one object key.
	ErrDuplicateKey = errors.New("baseline: duplicate object key")

	// ErrNotCanonical reports input that is not a single well-formed JSON
	// document within the canonical limits.
	ErrNotCanonical = errors.New("baseline: input is not canonical JSON")
)

// Marshal encodes v as canonical JSON with no trailing newline.
//
// Accepted: nil, bool, every sized int and uint, string (and named string types
// such as Seconds), slices, arrays, maps with string-kinded keys, structs, and
// pointers or interfaces holding any of those. Everything else is refused --
// including []byte, because "bytes" have no single obvious spelling and a silent
// choice of base64 or hex is exactly the kind of encoder disagreement this
// package exists to prevent. Use Hex and pass a string.
//
// A struct with no encodable exported fields is refused rather than encoded as
// {}. time.Time is the case that matters: its fields are unexported, so a
// permissive encoder would sign an empty object where a timestamp was meant.
func Marshal(v any) ([]byte, error) {
	var e encoder
	if err := e.value(reflect.ValueOf(v), "$", 0); err != nil {
		return nil, err
	}
	return e.buf.Bytes(), nil
}

// Digest is sha256 over Marshal(v).
func Digest(v any) ([32]byte, error) {
	b, err := Marshal(v)
	if err != nil {
		return [32]byte{}, err
	}
	return sha256.Sum256(b), nil
}

// DigestBytes is sha256 over bytes that are already canonical. Callers that
// received bytes from outside should run them through Canonical (and compare)
// first; hashing whatever arrived says nothing about what it means.
func DigestBytes(canonical []byte) [32]byte { return sha256.Sum256(canonical) }

// Hex is the lowercase hex spelling digests use everywhere in this codebase.
func Hex(b []byte) string { return hex.EncodeToString(b) }

// Canonical re-encodes raw JSON into canonical form.
//
// It exists for two jobs. First, round-tripping: canonical -> parse -> canonical
// must be byte-identical, which is what lets a verifier confirm that the bytes
// it authenticated are the same bytes it is about to interpret. Second,
// admission control: input with duplicate keys, floats, invalid UTF-8, trailing
// data or excessive nesting is refused outright.
//
// Note the ordering discipline this supports and does not replace: a caller
// verifying a signed document must verify the signature over the RAW bytes
// first, then call this and require the result to equal them. Canonicalising
// before authenticating means parsing attacker-controlled input with the
// attacker's parser choice, which is the bug this API is shaped to avoid.
func Canonical(raw []byte) ([]byte, error) {
	if !utf8.Valid(raw) {
		return nil, fmt.Errorf("%w: input bytes", ErrNotUTF8)
	}
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.UseNumber()
	v, err := decodeValue(dec, "$", 0)
	if err != nil {
		return nil, err
	}
	if _, err := dec.Token(); !errors.Is(err, io.EOF) {
		return nil, fmt.Errorf("%w: trailing data after the document", ErrNotCanonical)
	}
	out, err := Marshal(v)
	if err != nil {
		return nil, err
	}
	// encoding/json turns a lone surrogate escape into U+FFFD silently, so a
	// document could re-encode to something other than what it said. Refuse when
	// U+FFFD appears in the output without a literal source in the input. This
	// is belt-and-braces: a caller following the verify-then-canonicalise-and-
	// compare discipline above already rejects any mangling, because the
	// re-encoded bytes would differ from the bytes that were signed.
	if bytes.Contains(out, []byte("�")) && !bytes.Contains(raw, []byte("�")) &&
		!containsFold(raw, `�`) {
		return nil, fmt.Errorf("%w: unpaired surrogate escape", ErrNotCanonical)
	}
	return out, nil
}

func containsFold(raw []byte, needle string) bool {
	return bytes.Contains(bytes.ToLower(raw), []byte(needle))
}

// -- Seconds ----------------------------------------------------------------

// Seconds is a fractional-second timestamp in canonical form: a plain decimal
// STRING, never a JSON number.
//
// It exists because mtree.Entry.Time is a float64 and every one of the reference
// system's 461,601 time= values carries a fractional part, so a timestamp has to
// cross into a float-free document somehow. The three candidates and why this
// one won:
//
//	integer nanoseconds  loses information. float64 near 1.7e9 seconds has a
//	                     spacing of ~240ns, so ns is coarse enough there -- but
//	                     for small values the float is FINER than a nanosecond
//	                     and the conversion silently truncates. internal/mtree
//	                     already records why truncating makes ordering lie.
//	the float itself     refused by rule, for the reasons in the package doc.
//	shortest exact       strconv.FormatFloat(f, 'f', -1, 64) emits the fewest
//	                     decimal digits that parse back to the IDENTICAL float64.
//	                     'f' never uses an exponent, so there is one spelling.
//
// SecondsFromFloat verifies the round trip by construction and returns an error
// rather than a lossy string, so a value that could not survive the crossing
// becomes a refusal, not a quietly wrong timestamp in a signed manifest.
type Seconds string

// SecondsFromFloat converts a float64 seconds value to canonical form. Non-
// finite values are refused: neither NaN nor an infinity is a timestamp.
func SecondsFromFloat(f float64) (Seconds, error) {
	if math.IsNaN(f) || math.IsInf(f, 0) {
		return "", fmt.Errorf("%w: %v is not a finite timestamp", ErrFloat, f)
	}
	s := strconv.FormatFloat(f, 'f', -1, 64)
	back, err := strconv.ParseFloat(s, 64)
	if err != nil || math.Float64bits(back) != math.Float64bits(f) {
		return "", fmt.Errorf("%w: %v does not round-trip through %q", ErrFloat, f, s)
	}
	return Seconds(s), nil
}

// Float recovers the exact float64 a Seconds was made from.
//
// It is strict about spelling: only the canonical form is accepted, so "1.50",
// "01", "+1", "1e3" and "Inf" are all errors. Two spellings of one timestamp
// inside a signed document is the ambiguity this package refuses to carry.
func (s Seconds) Float() (float64, error) {
	if !validDecimal(string(s)) {
		return 0, fmt.Errorf("%w: %q is not a plain decimal", ErrNotCanonical, string(s))
	}
	f, err := strconv.ParseFloat(string(s), 64)
	if err != nil {
		return 0, fmt.Errorf("%w: %q: %v", ErrNotCanonical, string(s), err)
	}
	if strconv.FormatFloat(f, 'f', -1, 64) != string(s) {
		return 0, fmt.Errorf("%w: %q is not the canonical spelling of %v",
			ErrNotCanonical, string(s), f)
	}
	return f, nil
}

// validDecimal reports whether s is [-]digits[.digits] with digits on both
// sides of any point. Hand-written rather than delegated: strconv.ParseFloat
// also accepts hex floats, exponents, infinities and underscore separators.
func validDecimal(s string) bool {
	s = strings.TrimPrefix(s, "-")
	intPart, frac, hasPoint := strings.Cut(s, ".")
	if !allDigits(intPart) {
		return false
	}
	if hasPoint && !allDigits(frac) {
		return false
	}
	return true
}

func allDigits(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return false
		}
	}
	return true
}

// -- encoder ----------------------------------------------------------------

type encoder struct{ buf bytes.Buffer }

func (e *encoder) value(v reflect.Value, path string, depth int) error {
	if depth > MaxDepth {
		return fmt.Errorf("%w: %s exceeds the depth limit of %d (a cycle?)",
			ErrNotCanonical, path, MaxDepth)
	}
	if !v.IsValid() {
		e.buf.WriteString("null")
		return nil
	}
	switch v.Kind() {
	case reflect.Pointer, reflect.Interface:
		if v.IsNil() {
			e.buf.WriteString("null")
			return nil
		}
		return e.value(v.Elem(), path, depth+1)
	case reflect.Bool:
		e.buf.WriteString(strconv.FormatBool(v.Bool()))
		return nil
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		e.buf.Write(strconv.AppendInt(nil, v.Int(), 10))
		return nil
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64, reflect.Uintptr:
		e.buf.Write(strconv.AppendUint(nil, v.Uint(), 10))
		return nil
	case reflect.Float32, reflect.Float64:
		return fmt.Errorf("%w: %s is a %s (%v); use baseline.Seconds or an integer",
			ErrFloat, path, v.Kind(), v.Interface())
	case reflect.String:
		return e.str(v.String(), path)
	case reflect.Slice, reflect.Array:
		return e.list(v, path, depth)
	case reflect.Map:
		return e.mapping(v, path, depth)
	case reflect.Struct:
		return e.strct(v, path, depth)
	default:
		return fmt.Errorf("%w: %s is a %s", ErrUnsupportedType, path, v.Kind())
	}
}

func (e *encoder) list(v reflect.Value, path string, depth int) error {
	// []byte and [N]byte are refused deliberately: see Marshal.
	if v.Type().Elem().Kind() == reflect.Uint8 && v.Type().Elem().PkgPath() == "" {
		return fmt.Errorf("%w: %s is a byte sequence; encode it with baseline.Hex",
			ErrUnsupportedType, path)
	}
	e.buf.WriteByte('[')
	for i := 0; i < v.Len(); i++ {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		if err := e.value(v.Index(i), fmt.Sprintf("%s[%d]", path, i), depth+1); err != nil {
			return err
		}
	}
	e.buf.WriteByte(']')
	return nil
}

func (e *encoder) mapping(v reflect.Value, path string, depth int) error {
	if v.Type().Key().Kind() != reflect.String {
		return fmt.Errorf("%w: %s is a map keyed by %s; canonical object keys are strings",
			ErrUnsupportedType, path, v.Type().Key().Kind())
	}
	keys := make([]string, 0, v.Len())
	for iter := v.MapRange(); iter.Next(); {
		keys = append(keys, iter.Key().String())
	}
	sort.Strings(keys) // byte order, which is what a verifier in another language sorts by too
	e.buf.WriteByte('{')
	for i, k := range keys {
		if i > 0 {
			e.buf.WriteByte(',')
		}
		if err := e.str(k, path+"."+k); err != nil {
			return err
		}
		e.buf.WriteByte(':')
		mv := v.MapIndex(reflect.ValueOf(k).Convert(v.Type().Key()))
		if err := e.value(mv, path+"."+k, depth+1); err != nil {
			return err
		}
	}
	e.buf.WriteByte('}')
	return nil
}

type field struct {
	name string
	val  reflect.Value
}

func (e *encoder) strct(v reflect.Value, path string, depth int) error {
	fields, err := structFields(v, path)
	if err != nil {
		return err
	}
	if len(fields) == 0 {
		return fmt.Errorf("%w: %s is a %s with no encodable exported fields; a "+
			"timestamp must cross as baseline.Seconds or a string, not as a struct",
			ErrUnsupportedType, path, v.Type())
	}
	sort.Slice(fields, func(i, j int) bool { return fields[i].name < fields[j].name })
	e.buf.WriteByte('{')
	for i, f := range fields {
		if i > 0 {
			if fields[i-1].name == f.name {
				return fmt.Errorf("%w: %s has two fields named %q",
					ErrDuplicateKey, path, f.name)
			}
			e.buf.WriteByte(',')
		}
		if err := e.str(f.name, path+"."+f.name); err != nil {
			return err
		}
		e.buf.WriteByte(':')
		if err := e.value(f.val, path+"."+f.name, depth+1); err != nil {
			return err
		}
	}
	e.buf.WriteByte('}')
	return nil
}

// structFields collects the encodable fields of a struct, flattening anonymous
// embedded structs that carry no json tag, the way encoding/json does.
func structFields(v reflect.Value, path string) ([]field, error) {
	t := v.Type()
	var out []field
	for i := 0; i < t.NumField(); i++ {
		sf := t.Field(i)
		tag, hasTag := sf.Tag.Lookup("json")
		name, opts, _ := strings.Cut(tag, ",")
		if !sf.IsExported() {
			continue
		}
		if name == "-" && opts == "" {
			continue
		}
		if sf.Anonymous && !hasTag && sf.Type.Kind() == reflect.Struct {
			nested, err := structFields(v.Field(i), path)
			if err != nil {
				return nil, err
			}
			out = append(out, nested...)
			continue
		}
		if name == "" {
			name = sf.Name
		}
		fv := v.Field(i)
		if strings.Contains(opts, "omitempty") && fv.IsZero() {
			continue
		}
		out = append(out, field{name: name, val: fv})
	}
	return out, nil
}

// str writes one canonical JSON string.
func (e *encoder) str(s, path string) error {
	if !utf8.ValidString(s) {
		return fmt.Errorf("%w: %s", ErrNotUTF8, path)
	}
	e.buf.WriteByte('"')
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c == '"':
			e.buf.WriteString(`\"`)
		case c == '\\':
			e.buf.WriteString(`\\`)
		case c == '\b':
			e.buf.WriteString(`\b`)
		case c == '\f':
			e.buf.WriteString(`\f`)
		case c == '\n':
			e.buf.WriteString(`\n`)
		case c == '\r':
			e.buf.WriteString(`\r`)
		case c == '\t':
			e.buf.WriteString(`\t`)
		case c < 0x20:
			e.buf.WriteString(`\u00`)
			const hexdigits = "0123456789abcdef"
			e.buf.WriteByte(hexdigits[c>>4])
			e.buf.WriteByte(hexdigits[c&0xf])
		default:
			// Everything else, including all non-ASCII, goes out as raw UTF-8:
			// no HTML escaping (encoding/json's default would give <, > and &
			// two spellings) and no \u escaping of code points that do not need
			// it.
			e.buf.WriteByte(c)
		}
	}
	e.buf.WriteByte('"')
	return nil
}

// -- decoder ----------------------------------------------------------------

// decodeValue builds a value tree from a token stream, enforcing the canonical
// admission rules as it goes. It is token-based rather than json.Unmarshal into
// `any` because Unmarshal silently keeps the LAST of two duplicate keys, and a
// document whose meaning depends on which parser read it must not be signable.
func decodeValue(dec *json.Decoder, path string, depth int) (any, error) {
	if depth > MaxDepth {
		return nil, fmt.Errorf("%w: %s exceeds the depth limit of %d",
			ErrNotCanonical, path, MaxDepth)
	}
	tok, err := dec.Token()
	if err != nil {
		return nil, fmt.Errorf("%w: %s: %v", ErrNotCanonical, path, err)
	}
	switch t := tok.(type) {
	case json.Delim:
		switch t {
		case '{':
			m := map[string]any{}
			for dec.More() {
				kt, err := dec.Token()
				if err != nil {
					return nil, fmt.Errorf("%w: %s: %v", ErrNotCanonical, path, err)
				}
				k, ok := kt.(string)
				if !ok {
					return nil, fmt.Errorf("%w: %s: object key is not a string", ErrNotCanonical, path)
				}
				kp := path + "." + k
				if _, dup := m[k]; dup {
					return nil, fmt.Errorf("%w: %s", ErrDuplicateKey, kp)
				}
				v, err := decodeValue(dec, kp, depth+1)
				if err != nil {
					return nil, err
				}
				m[k] = v
			}
			if _, err := dec.Token(); err != nil { // consume '}'
				return nil, fmt.Errorf("%w: %s: %v", ErrNotCanonical, path, err)
			}
			return m, nil
		case '[':
			arr := []any{}
			for i := 0; dec.More(); i++ {
				v, err := decodeValue(dec, fmt.Sprintf("%s[%d]", path, i), depth+1)
				if err != nil {
					return nil, err
				}
				arr = append(arr, v)
			}
			if _, err := dec.Token(); err != nil { // consume ']'
				return nil, fmt.Errorf("%w: %s: %v", ErrNotCanonical, path, err)
			}
			return arr, nil
		default:
			return nil, fmt.Errorf("%w: %s: unexpected %q", ErrNotCanonical, path, t)
		}
	case json.Number:
		return decodeNumber(t, path)
	case string, bool, nil:
		return t, nil
	default:
		return nil, fmt.Errorf("%w: %s: unexpected token %T", ErrNotCanonical, path, tok)
	}
}

// decodeNumber accepts only exact 64-bit integers. "1.0" and "1e3" are refused
// even though both have integral values: accepting them would mean two spellings
// of one number, and re-spelling them would mean the bytes that were signed are
// not the bytes that come back out.
func decodeNumber(n json.Number, path string) (any, error) {
	s := n.String()
	if strings.ContainsAny(s, ".eE") {
		return nil, fmt.Errorf("%w: %s is %s", ErrFloat, path, s)
	}
	if i, err := strconv.ParseInt(s, 10, 64); err == nil {
		return i, nil
	}
	if u, err := strconv.ParseUint(s, 10, 64); err == nil {
		return u, nil
	}
	return nil, fmt.Errorf("%w: %s is %s, which is not an exact 64-bit integer",
		ErrFloat, path, s)
}
