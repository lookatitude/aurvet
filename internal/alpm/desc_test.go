// internal/alpm/desc_test.go
package alpm

import (
	"strings"
	"testing"
)

const sampleDesc = `%NAME%
python-pkg_resources

%VERSION%
81.0.0-1

%BASE%
python-pkg_resources

%VALIDATION%
pgp

%DEPENDS%
python
python-packaging

`

func TestParseDescReadsFields(t *testing.T) {
	got, err := ParseDesc(strings.NewReader(sampleDesc))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if v := got["NAME"]; len(v) != 1 || v[0] != "python-pkg_resources" {
		t.Errorf("NAME = %v", v)
	}
	if v := got["DEPENDS"]; len(v) != 2 {
		t.Errorf("DEPENDS = %v, want 2 entries", v)
	}
}

// Measured: %SIZE% is absent on 9 of 1409 packages, %LICENSE% on 1.
// Absent must parse as absent, never as an error.
func TestParseDescToleratesMissingFields(t *testing.T) {
	got, err := ParseDesc(strings.NewReader(sampleDesc))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if _, ok := got["SIZE"]; ok {
		t.Error("SIZE should be absent")
	}
	if _, ok := got["LICENSE"]; ok {
		t.Error("LICENSE should be absent")
	}
}

func TestParseDescMissingFinalNewline(t *testing.T) {
	got, err := ParseDesc(strings.NewReader("%NAME%\nzlib"))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if v := got["NAME"]; len(v) != 1 || v[0] != "zlib" {
		t.Errorf("NAME = %v, want [zlib]", v)
	}
}

func TestParseDescRepeatedKey(t *testing.T) {
	input := "%DEPENDS%\nfoo\nbar\n\n%DEPENDS%\nbaz\n\n"
	got, err := ParseDesc(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	want := []string{"foo", "bar", "baz"}
	v := got["DEPENDS"]
	if len(v) != len(want) {
		t.Fatalf("DEPENDS = %v, want %v", v, want)
	}
	for i := range want {
		if v[i] != want[i] {
			t.Errorf("DEPENDS[%d] = %q, want %q", i, v[i], want[i])
		}
	}
}

func TestParseDescEmptyValueBlock(t *testing.T) {
	input := "%NAME%\nzlib\n\n%XDATA%\n\n"
	got, err := ParseDesc(strings.NewReader(input))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if v := got["NAME"]; len(v) != 1 || v[0] != "zlib" {
		t.Errorf("NAME = %v, want [zlib]", v)
	}
	v, ok := got["XDATA"]
	if !ok {
		t.Fatal("XDATA should be present")
	}
	if len(v) != 0 {
		t.Errorf("XDATA = %v, want empty", v)
	}
}
