// internal/baseline/canon_test.go
//
// These are the tests that make the digest trustworthy, so they are written as
// properties over generated input rather than as hand-picked examples: the
// failure mode being defended against ("two encoders disagree about one
// document") does not show up in three cases someone chose by hand.

package baseline

import (
	"bytes"
	"errors"
	"math"
	"math/rand"
	"reflect"
	"strconv"
	"strings"
	"testing"
)

// -- determinism ------------------------------------------------------------

// Go randomises map iteration, which is the ally here: inserting the same keys
// in different orders and marshalling many times exercises the randomisation
// for real. If the encoder ever leaked iteration order, this fails.
func TestMarshalIsIndependentOfMapInsertionOrder(t *testing.T) {
	keys := []string{"zeta", "alpha", "Mid", "b", "a", "0", "pkg/name", "été"}

	var want []byte
	rng := rand.New(rand.NewSource(1))
	for iter := 0; iter < 500; iter++ {
		order := rng.Perm(len(keys))
		m := make(map[string]any, len(keys))
		for _, i := range order {
			m[keys[i]] = i
		}
		doc := map[string]any{"inner": m, "list": []any{m, m}}
		got, err := Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		if want == nil {
			want = got
			continue
		}
		if !bytes.Equal(want, got) {
			t.Fatalf("iteration %d differs:\n want %s\n  got %s", iter, want, got)
		}
	}
	if !strings.Contains(string(want), `"0":`) {
		t.Fatalf("unexpected encoding: %s", want)
	}
	// Sorted by UTF-8 byte order, so uppercase sorts before lowercase.
	if i, j := bytes.Index(want, []byte(`"Mid"`)), bytes.Index(want, []byte(`"alpha"`)); i > j {
		t.Fatalf("keys not sorted by byte order: %s", want)
	}
}

// Sorting keys means the digest cannot depend on struct declaration order --
// which is the point of "fixed field order": a later refactor that moves a
// field must not invalidate every signature ever made.
func TestMarshalStructFieldOrderIsFixedBySorting(t *testing.T) {
	type a struct {
		Zeta  string `json:"zeta"`
		Alpha string `json:"alpha"`
	}
	type b struct {
		Alpha string `json:"alpha"`
		Zeta  string `json:"zeta"`
	}
	x, err := Marshal(a{Zeta: "z", Alpha: "a"})
	if err != nil {
		t.Fatal(err)
	}
	y, err := Marshal(b{Alpha: "a", Zeta: "z"})
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(x, y) {
		t.Fatalf("declaration order changed the bytes:\n %s\n %s", x, y)
	}
	if string(x) != `{"alpha":"a","zeta":"z"}` {
		t.Fatalf("unexpected encoding: %s", x)
	}
}

func TestMarshalDoesNotEscapeHTML(t *testing.T) {
	got, err := Marshal(map[string]any{"k": `<a href="x">&</a>` + " "})
	if err != nil {
		t.Fatal(err)
	}
	// encoding/json escapes <, > and & to \u003c, \u003e and \u0026 by default,
	// which gives every such string two spellings. Canonical form has one.
	if strings.Contains(string(got), `\u00`) {
		t.Fatalf("HTML escaping leaked in: %s", got)
	}
	if !strings.Contains(string(got), `<a href=`) || !strings.Contains(string(got), `&`) {
		t.Fatalf("raw punctuation not preserved: %s", got)
	}
	if !strings.Contains(string(got), `\"x\"`) {
		t.Fatalf("quote not escaped: %s", got)
	}
}

func TestMarshalEscapesControlCharactersMinimally(t *testing.T) {
	got, err := Marshal("a\tb\nc\x00d\x1fe\\f\"g")
	if err != nil {
		t.Fatal(err)
	}
	want := `"a\tb\nc\u0000d\u001fe\\f\"g"`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

// -- refusals ---------------------------------------------------------------

func TestMarshalRefusesFloatsAndSaysWhere(t *testing.T) {
	type entry struct {
		Path string  `json:"path"`
		Time float64 `json:"time"`
	}
	// The first element carries no float, so a passing test proves the path in
	// the error tracks the actual offender rather than the first thing visited.
	doc := map[string]any{"pkgs": []any{
		map[string]any{"path": "a"},
		entry{Path: "b", Time: 1.5},
	}}
	_, err := Marshal(doc)
	if !errors.Is(err, ErrFloat) {
		t.Fatalf("want ErrFloat, got %v", err)
	}
	if !strings.Contains(err.Error(), "$.pkgs[1].time") {
		t.Fatalf("error does not locate the float: %v", err)
	}

	if _, err := Marshal(map[string]any{"f": float32(2)}); !errors.Is(err, ErrFloat) {
		t.Fatalf("float32 must be refused too, got %v", err)
	}
	// A float with an integral value is refused, not rounded: rounding would
	// hide the defect until a verifier on another Go version disagreed.
	if _, err := Marshal([]any{float64(3)}); !errors.Is(err, ErrFloat) {
		t.Fatalf("integral float must still be refused, got %v", err)
	}
}

func TestMarshalRefusesInvalidUTF8(t *testing.T) {
	// encoding/json would silently substitute U+FFFD, which can make two
	// distinct mtree paths canonicalise to the same bytes -- a collision inside
	// a signed document.
	_, err := Marshal(map[string]any{"path": "./usr/bin/\xff\xfe"})
	if !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("want ErrNotUTF8, got %v", err)
	}
	if !strings.Contains(err.Error(), "$.path") {
		t.Fatalf("error does not locate the string: %v", err)
	}
	if _, err := Marshal(map[string]any{"\xff": 1}); !errors.Is(err, ErrNotUTF8) {
		t.Fatalf("invalid UTF-8 key must be refused, got %v", err)
	}
}

func TestMarshalRefusesUnsupportedTypes(t *testing.T) {
	for name, v := range map[string]any{
		"bytes":   map[string]any{"b": []byte{1, 2}},
		"array":   map[string]any{"d": [2]byte{1, 2}},
		"intkey":  map[int]string{1: "a"},
		"chan":    map[string]any{"c": make(chan int)},
		"complex": map[string]any{"z": complex(1, 2)},
	} {
		if _, err := Marshal(v); !errors.Is(err, ErrUnsupportedType) {
			t.Errorf("%s: want ErrUnsupportedType, got %v", name, err)
		}
	}
}

func TestMarshalRefusesDuplicateKeysFromTags(t *testing.T) {
	// Built with reflect because `go vet`'s structtag check refuses to compile a
	// literal with two identical json tags -- which is a fine thing for vet to
	// do, and no reason for the encoder to trust that vet always ran.
	dup := reflect.StructOf([]reflect.StructField{
		{Name: "A", Type: reflect.TypeOf(""), Tag: `json:"k"`},
		{Name: "B", Type: reflect.TypeOf(""), Tag: `json:"k"`},
	})
	if _, err := Marshal(reflect.New(dup).Elem().Interface()); !errors.Is(err, ErrDuplicateKey) {
		t.Fatalf("want ErrDuplicateKey, got %v", err)
	}
}

func TestMarshalRefusesCycles(t *testing.T) {
	m := map[string]any{}
	m["self"] = m
	if _, err := Marshal(m); err == nil {
		t.Fatal("want an error for a cyclic document")
	}
}

// -- round trip -------------------------------------------------------------

func TestCanonicalRoundTripIsByteIdentical(t *testing.T) {
	rng := rand.New(rand.NewSource(7))
	for i := 0; i < 300; i++ {
		doc := randomDoc(rng, 0)
		first, err := Marshal(doc)
		if err != nil {
			t.Fatalf("Marshal: %v", err)
		}
		second, err := Canonical(first)
		if err != nil {
			t.Fatalf("Canonical(%s): %v", first, err)
		}
		if !bytes.Equal(first, second) {
			t.Fatalf("round trip differs:\n %s\n %s", first, second)
		}
		third, err := Canonical(second)
		if err != nil {
			t.Fatal(err)
		}
		if !bytes.Equal(second, third) {
			t.Fatalf("not idempotent:\n %s\n %s", second, third)
		}
	}
}

func TestCanonicalRewritesNonCanonicalInputAndIsThenStable(t *testing.T) {
	raw := []byte("{ \"b\" : 1,\n \"a\" :\t[ 2 , {\"d\":null,\"c\":true} ] }")
	got, err := Canonical(raw)
	if err != nil {
		t.Fatal(err)
	}
	want := `{"a":[2,{"c":true,"d":null}],"b":1}`
	if string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestCanonicalRefusals(t *testing.T) {
	cases := map[string]struct {
		raw  string
		want error
	}{
		"duplicate key":  {`{"a":1,"a":2}`, ErrDuplicateKey},
		"float":          {`{"t":1.5}`, ErrFloat},
		"exponent":       {`{"t":1e3}`, ErrFloat},
		"minus zero":     {`{"t":-0.0}`, ErrFloat},
		"trailing data":  {`{"a":1} {"b":2}`, ErrNotCanonical},
		"empty":          {``, ErrNotCanonical},
		"invalid utf8":   {"{\"a\":\"\xff\"}", ErrNotUTF8},
		"huge int":       {`{"a":123456789012345678901234567890}`, ErrFloat},
		"not json":       {`{`, ErrNotCanonical},
		"bare truncated": {`[1,`, ErrNotCanonical},
	}
	for name, tc := range cases {
		if _, err := Canonical([]byte(tc.raw)); !errors.Is(err, tc.want) {
			t.Errorf("%s: want %v, got %v", name, tc.want, err)
		}
	}
}

func TestCanonicalRefusesExcessiveDepth(t *testing.T) {
	raw := strings.Repeat("[", MaxDepth+2) + strings.Repeat("]", MaxDepth+2)
	if _, err := Canonical([]byte(raw)); !errors.Is(err, ErrNotCanonical) {
		t.Fatalf("want ErrNotCanonical for over-deep input, got %v", err)
	}
}

// -- timestamps -------------------------------------------------------------

// mtree.Entry.Time is a float64 and every reference value carries a fractional
// part, so a timestamp has to cross into canonical form somehow. It crosses as
// a decimal STRING whose digits round-trip to the identical float64 -- verified
// here by construction, over both real-shaped and adversarial values.
func TestSecondsRoundTripsExactly(t *testing.T) {
	vals := []float64{
		0, 1, -1, 1712345678.1234567, 1699999999.5, 1e-9, 1.0000000001,
		123456789.987654321, math.SmallestNonzeroFloat64, math.MaxFloat64,
		-math.MaxFloat64, 0.1, 1.0 / 3.0,
	}
	rng := rand.New(rand.NewSource(11))
	for i := 0; i < 2000; i++ {
		// The shape pacman actually writes: ~1.7e9 seconds with a fraction.
		vals = append(vals, 1.6e9+rng.Float64()*1e8)
	}
	for i := 0; i < 2000; i++ {
		vals = append(vals, math.Float64frombits(rng.Uint64()))
	}
	for _, v := range vals {
		s, err := SecondsFromFloat(v)
		if math.IsNaN(v) || math.IsInf(v, 0) {
			if err == nil {
				t.Fatalf("non-finite %v accepted", v)
			}
			continue
		}
		if err != nil {
			t.Fatalf("SecondsFromFloat(%v): %v", v, err)
		}
		back, err := s.Float()
		if err != nil {
			t.Fatalf("Seconds(%q).Float: %v", s, err)
		}
		if math.Float64bits(back) != math.Float64bits(v) {
			t.Fatalf("round trip lost %v: %q -> %v", v, s, back)
		}
		// No exponent, no NaN spelling: the canonical form is plain decimal.
		if strings.ContainsAny(string(s), "eEnN") {
			t.Fatalf("non-decimal spelling %q for %v", s, v)
		}
	}
}

func TestSecondsRefusesNonFinite(t *testing.T) {
	for _, v := range []float64{math.NaN(), math.Inf(1), math.Inf(-1)} {
		if _, err := SecondsFromFloat(v); !errors.Is(err, ErrFloat) {
			t.Errorf("%v: want ErrFloat, got %v", v, err)
		}
	}
}

// A Seconds value marshals as a string, so no float reaches the document.
func TestSecondsMarshalsAsAString(t *testing.T) {
	s, err := SecondsFromFloat(1712345678.25)
	if err != nil {
		t.Fatal(err)
	}
	got, err := Marshal(map[string]any{"time": s})
	if err != nil {
		t.Fatal(err)
	}
	if want := `{"time":"1712345678.25"}`; string(got) != want {
		t.Fatalf("got %s want %s", got, want)
	}
}

func TestSecondsRejectsMalformedText(t *testing.T) {
	for _, s := range []Seconds{"", "abc", "1e3", "NaN", " 1", "1 ", "+1", "0x1p3", "Inf"} {
		if _, err := s.Float(); err == nil {
			t.Errorf("%q: want an error", s)
		}
	}
}

// -- digest -----------------------------------------------------------------

func TestDigestMatchesSHA256OfCanonicalBytes(t *testing.T) {
	doc := map[string]any{"a": 1, "b": []any{true, nil, "x"}}
	raw, err := Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	d, err := Digest(doc)
	if err != nil {
		t.Fatal(err)
	}
	if d != DigestBytes(raw) {
		t.Fatal("Digest disagrees with DigestBytes(Marshal(...))")
	}
	if len(Hex(d[:])) != 64 {
		t.Fatalf("unexpected hex length: %q", Hex(d[:]))
	}
}

// Any single-byte change to the canonical bytes changes the digest. This is the
// digest half of the flip-a-byte property; sign_test.go carries the signature
// half.
func TestDigestChangesForEverySingleByteFlip(t *testing.T) {
	rng := rand.New(rand.NewSource(13))
	for i := 0; i < 25; i++ {
		raw, err := Marshal(randomDoc(rng, 0))
		if err != nil {
			t.Fatal(err)
		}
		base := DigestBytes(raw)
		for pos := range raw {
			for _, bit := range []byte{0x01, 0x80} {
				m := append([]byte(nil), raw...)
				m[pos] ^= bit
				if DigestBytes(m) == base {
					t.Fatalf("digest unchanged after flipping byte %d of %s", pos, raw)
				}
			}
		}
	}
}

// -- corpus -----------------------------------------------------------------

// randomDoc builds a document out of exactly the types a canonical document may
// contain. It is seeded, so a failure is reproducible.
func randomDoc(rng *rand.Rand, depth int) any {
	if depth > 3 {
		return randomScalar(rng)
	}
	switch rng.Intn(6) {
	case 0:
		n := rng.Intn(5)
		m := make(map[string]any, n)
		for i := 0; i < n; i++ {
			m[randomKey(rng)] = randomDoc(rng, depth+1)
		}
		return m
	case 1:
		n := rng.Intn(5)
		s := make([]any, n)
		for i := range s {
			s[i] = randomDoc(rng, depth+1)
		}
		return s
	default:
		return randomScalar(rng)
	}
}

func randomScalar(rng *rand.Rand) any {
	switch rng.Intn(6) {
	case 0:
		return nil
	case 1:
		return rng.Intn(2) == 0
	case 2:
		return int64(rng.Int63() - (1 << 40))
	case 3:
		return uint64(rng.Uint64() >> 1)
	case 4:
		return randomKey(rng)
	default:
		return strconv.Itoa(rng.Intn(1000))
	}
}

func randomKey(rng *rand.Rand) string {
	alphabet := []rune{'a', 'B', 'z', '0', '_', '/', '.', '-', 'é', '漢', ' ', '"', '\\', '\n'}
	n := 1 + rng.Intn(6)
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteRune(alphabet[rng.Intn(len(alphabet))])
	}
	return b.String()
}
