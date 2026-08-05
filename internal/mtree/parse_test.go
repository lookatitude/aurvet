// internal/mtree/parse_test.go
package mtree

import (
	"errors"
	"strings"
	"testing"
)

// Shaped after a real installed mtree: the `#mtree` header, a leading `/set`
// that every later line inherits from, `./.`-prefixed package metadata, a
// mid-file `/set` that changes the default mode, per-line overrides, float
// times, a symlink whose target is relative, and a vis-escaped name.
const sampleMtree = `#mtree
/set type=file uid=0 gid=0 mode=644
./.BUILDINFO time=1773995553.0 size=6120 sha256digest=` + shaBuildinfo + `
./.PKGINFO time=1773995553.0 size=406 md5digest=` + md5Pkginfo + ` sha256digest=` + shaPkginfo + `
/set mode=755
./usr time=1773995553.0 type=dir
./usr/bin time=1773995553.0 type=dir
./usr/bin/a52dec time=1773995553.5 size=35504 sha256digest=` + shaA52 + `
/set mode=644
./usr/share/alsa/Librem\0405.conf time=1781523786.0 mode=444 size=700 sha256digest=` + shaConf + `
./usr/lib/liba52.so time=1773995553.0 mode=777 type=link link=liba52.so.0.0.0
./usr/share/x/link time=1773995553.0 type=link link=../../NXP/Librem\0405.conf
`

const (
	shaBuildinfo = "6e9830e4fcd15738983af8ea62d48c6fa44273029d488929863fce40eac78d70"
	shaPkginfo   = "1bd1bab6c3332a19d6f9644d0257d4b4a260543c57ff923ed2554992a6e049d7"
	shaA52       = "6d42b31c0dd39983d06d143ff28fa278c4b52c3513fa030d5076adef6d5f0f12"
	shaConf      = "5326b590a6f015c7fccde8a1e14c1a02b0b62c67e2e0f7f19a17a4e6ba0c7d51"
	md5Pkginfo   = "95c861f10a169da0ca6a32f1da676693"
)

func TestParseSample(t *testing.T) {
	got, err := Parse(strings.NewReader(sampleMtree))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []Entry{
		{Path: "./usr", Type: "dir", Mode: 0o755, Time: 1773995553.0},
		{Path: "./usr/bin", Type: "dir", Mode: 0o755, Time: 1773995553.0},
		{Path: "./usr/bin/a52dec", Type: "file", Mode: 0o755, Time: 1773995553.5, Size: 35504, SHA256: shaA52},
		{Path: "./usr/share/alsa/Librem 5.conf", Type: "file", Mode: 0o444, Time: 1781523786.0, Size: 700, SHA256: shaConf},
		{Path: "./usr/lib/liba52.so", Type: "link", Mode: 0o777, Time: 1773995553.0, Link: "liba52.so.0.0.0"},
		{Path: "./usr/share/x/link", Type: "link", Mode: 0o644, Time: 1773995553.0, Link: "../../NXP/Librem 5.conf"},
	}
	if len(got) != len(want) {
		t.Fatalf("Parse returned %d entries, want %d: %+v", len(got), len(want), got)
	}
	for i := range want {
		if got[i] != want[i] {
			t.Errorf("entry %d =\n %+v\nwant\n %+v", i, got[i], want[i])
		}
	}
}

// `./.BUILDINFO`, `./.PKGINFO` and `./.INSTALL` describe the package, not the
// filesystem: they are the only three `./.` entries across all 1410 installed
// mtrees and none of them exists on disk. Returning them would produce a
// missing-file finding for every package on the system.
func TestParseFiltersPackageMetadata(t *testing.T) {
	got, err := Parse(strings.NewReader(sampleMtree))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	for _, e := range got {
		if strings.HasPrefix(e.Path, "./.") {
			t.Errorf("metadata entry %q was returned", e.Path)
		}
	}
}

// The digest is the whole point of the record, so a metadata entry must not be
// dropped by dropping the line: `./.PKGINFO` carries the md5digest that proves
// the parser reads both digest keywords.
func TestParseReadsMD5(t *testing.T) {
	in := "#mtree\n/set type=file mode=644\n./x time=1.0 size=406 md5digest=" + md5Pkginfo + " sha256digest=" + shaPkginfo + "\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 {
		t.Fatalf("got %d entries, want 1", len(got))
	}
	if got[0].MD5 != md5Pkginfo || got[0].SHA256 != shaPkginfo {
		t.Errorf("digests = %q / %q", got[0].MD5, got[0].SHA256)
	}
}

// /unset appears zero times in the 1410 installed mtrees, which is exactly why
// it is tested: the first mtree that uses it will be one we did not write.
func TestParseUnsetInheritance(t *testing.T) {
	in := "#mtree\n" +
		"/set type=file mode=644 uid=0\n" +
		"./a time=1.0 size=1 sha256digest=" + shaA52 + "\n" +
		"/unset mode\n" +
		"./b time=1.0 size=1 sha256digest=" + shaA52 + "\n" +
		"/unset all\n" +
		"./c time=1.0 type=dir\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if got[0].Mode != 0o644 {
		t.Errorf("a: mode = %o, want 644", got[0].Mode)
	}
	if got[1].Mode != 0 {
		t.Errorf("b: mode = %o, want 0 after /unset mode", got[1].Mode)
	}
	if got[1].Type != "file" {
		t.Errorf("b: type = %q, want file still inherited", got[1].Type)
	}
	// `/unset all` clears the inherited type too; mtree's own default for a
	// record with no type keyword is file, and the line says dir.
	if got[2].Type != "dir" {
		t.Errorf("c: type = %q, want dir", got[2].Type)
	}
}

// An unset type falls back to mtree's documented default rather than to the
// empty string, because a consumer switching on Type would otherwise treat the
// record as a kind it has never heard of.
func TestParseDefaultsTypeToFile(t *testing.T) {
	got, err := Parse(strings.NewReader("#mtree\n./a time=1.0 size=1 sha256digest=" + shaA52 + "\n"))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 || got[0].Type != "file" {
		t.Fatalf("got %+v, want a single file entry", got)
	}
}

// Comments, blank lines and keywords this parser does not model are not
// evidence of tampering -- mtree defines more keywords than pacman emits, and
// refusing the whole subject over `nlink=` would be a coverage gap invented by
// us. A *malformed* value for a keyword we do read is a different matter.
func TestParseIgnoresUnknownKeywordsAndComments(t *testing.T) {
	in := "#mtree\n\n# a comment\n./a nlink=1 flags=none time=1.0 size=1 sha256digest=" + shaA52 + "\n"
	got, err := Parse(strings.NewReader(in))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 1 || got[0].Size != 1 {
		t.Fatalf("got %+v", got)
	}
}

func TestParseRejects(t *testing.T) {
	cases := []struct {
		name string
		in   string
		want error
	}{
		{"no header", "./a time=1.0 size=1\n", ErrHeader},
		{"header is not first", "# hello\n#mtree\n./a size=1\n", ErrHeader},
		{"empty input", "", ErrHeader},
		{"malformed size", "#mtree\n./a size=eleven\n", ErrSyntax},
		{"malformed mode", "#mtree\n./a mode=9999\n", ErrSyntax},
		{"malformed time", "#mtree\n./a time=yesterday\n", ErrSyntax},
		{"keyword without value", "#mtree\n./a size\n", ErrSyntax},
		{"digest is not hex", "#mtree\n./a sha256digest=zz\n", ErrSyntax},
		{"bad escape in path", `#mtree` + "\n" + `./a\q size=1` + "\n", ErrVisEscape},
		{"bad escape in link", `#mtree` + "\n" + `./a type=link link=../b\q` + "\n", ErrVisEscape},
		{"set with a bad value", "#mtree\n/set mode=zzz\n./a size=1\n", ErrSyntax},
		{"traversal", "#mtree\n./../etc/shadow size=1\n", ErrPath},
		{"absolute", "#mtree\n/etc/shadow size=1\n", ErrPath},
		{"not dot-rooted", "#mtree\nusr/bin/x size=1\n", ErrPath},
		{"bare dotdot record", "#mtree\n..\n", ErrPath},
		{"traversal hidden in an escape", `#mtree` + "\n" + `./a/\056\056/etc size=1` + "\n", ErrPath},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, err := Parse(strings.NewReader(c.in))
			if err == nil {
				t.Fatalf("Parse = %+v, want %v", got, c.want)
			}
			if !errors.Is(err, c.want) {
				t.Fatalf("Parse error = %v, want %v", err, c.want)
			}
			if !strings.Contains(err.Error(), "mtree") {
				t.Errorf("error %q does not name the package", err.Error())
			}
		})
	}
}

// INV-4: Parse is a pure function of its reader. It never consults the
// filesystem, so the same bytes give the same entries wherever they came from.
func TestParseIsPure(t *testing.T) {
	a, err := Parse(strings.NewReader(sampleMtree))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	b, err := Parse(strings.NewReader(sampleMtree))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(a) != len(b) {
		t.Fatalf("two parses of identical input differ in length")
	}
	for i := range a {
		if a[i] != b[i] {
			t.Fatalf("entry %d differs between identical parses", i)
		}
	}
}
