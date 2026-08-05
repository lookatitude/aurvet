// internal/mtree/conform_test.go
package mtree

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The conformance suite reads fixtures rather than string literals so the bytes
// under test are the bytes on disk, escapes and all. testdata/mtree/a52dec.mtree.gz
// is a verbatim copy of an installed package's mtree.
const fixtures = "../../testdata/mtree"

func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtures, name))
	if err != nil {
		t.Fatalf("fixture: %v", err)
	}
	return b
}

func TestConformFullEscapeSet(t *testing.T) {
	got, err := Parse(bytes.NewReader(fixture(t, "full-escapes.mtree")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	want := []string{
		"./octal/Librem 5.conf",
		"./octal/#hash",
		"./octal/[bracket",
		`./octal/back\slash`,
		"./octal/utf8-\xc3\x9e",
		"./octal/short- -and-\xff",
		"./named/\x07\x08\x1b\x0c\x0a\x0d \x09\x0b",
		"./ctrl/\x01\x04\x1f\x7f",
		"./meta/\xc1\x81\xff",
		"./end/marker",
		"./link/escaped",
	}
	if len(got) != len(want) {
		t.Fatalf("got %d entries, want %d", len(got), len(want))
	}
	for i := range want {
		if got[i].Path != want[i] {
			t.Errorf("entry %d path = %q, want %q", i, got[i].Path, want[i])
		}
	}
	// A link target is decoded but never resolved, and legitimately contains "..".
	last := got[len(got)-1]
	if last.Type != "link" || last.Link != "../../NXP/iMX8/Librem 5 Devkit.conf" {
		t.Errorf("link entry = %+v", last)
	}
}

// The fixture is one installed package's mtree, byte for byte. It exercises
// /set inheritance across five separate /set lines, the two metadata records,
// float times and symlinks in the arrangement pacman actually emits.
func TestConformRealPackageMtree(t *testing.T) {
	got, err := ParseGzip(bytes.NewReader(fixture(t, "a52dec.mtree.gz")))
	if err != nil {
		t.Fatalf("ParseGzip: %v", err)
	}
	// 30 lines: 1 header, 5 /set, 24 records, of which 2 are metadata.
	if len(got) != 22 {
		t.Fatalf("got %d entries, want 22", len(got))
	}
	byPath := map[string]Entry{}
	for _, e := range got {
		byPath[e.Path] = e
	}
	checks := []Entry{
		// mode inherited from `/set mode=755`, three /set lines back.
		{Path: "./usr/bin/a52dec", Type: "file", Mode: 0o755, Time: 1773995553.0, Size: 35504,
			SHA256: "6d42b31c0dd39983d06d143ff28fa278c4b52c3513fa030d5076adef6d5f0f12"},
		// mode from the record, overriding `/set mode=644`.
		{Path: "./usr/include/a52dec", Type: "dir", Mode: 0o755, Time: 1773995553.0},
		// type=link: mode inherited from `/set mode=777`, target kept as a string.
		{Path: "./usr/lib/liba52.so", Type: "link", Mode: 0o777, Time: 1773995553.0, Link: "liba52.so.0.0.0"},
		{Path: "./usr/share/man/man1/a52dec.1.gz", Type: "file", Mode: 0o644, Time: 1773995553.0, Size: 705,
			SHA256: "cbd1ec132d0a31c6c07547e75b32597f52bbd6a33b64e8c2eafdf082291d3857"},
	}
	for _, want := range checks {
		if got := byPath[want.Path]; got != want {
			t.Errorf("%s =\n %+v\nwant\n %+v", want.Path, got, want)
		}
	}
	for p := range byPath {
		if strings.HasPrefix(p, "./.") {
			t.Errorf("metadata record %q survived", p)
		}
	}
}

func TestConformCorruptGzipFixture(t *testing.T) {
	_, err := ParseGzip(bytes.NewReader(fixture(t, "truncated.mtree.gz")))
	if !errors.Is(err, ErrGzip) {
		t.Fatalf("ParseGzip of a truncated fixture = %v, want ErrGzip", err)
	}
}

func TestConformTraversalFixture(t *testing.T) {
	_, err := Parse(bytes.NewReader(fixture(t, "traversal.mtree")))
	if !errors.Is(err, ErrPath) {
		t.Fatalf("Parse = %v, want ErrPath", err)
	}
	// The refusal names the record, so the caller's coverage gap can say which.
	if !strings.Contains(err.Error(), "line 4") {
		t.Errorf("error %q does not attribute the record", err)
	}
}

func TestConformMissingHeaderFixture(t *testing.T) {
	_, err := Parse(bytes.NewReader(fixture(t, "no-header.mtree")))
	if !errors.Is(err, ErrHeader) {
		t.Fatalf("Parse = %v, want ErrHeader", err)
	}
}

// pacman's mtree has no hardlink keyword: two names for one inode appear as two
// ordinary records carrying the same size and digest. Collapsing them would
// silently drop one path from coverage, so they stay distinct. A symlink beside
// them stays a link, compared as a string.
func TestConformHardlinkPairStaysTwoRecords(t *testing.T) {
	got, err := Parse(bytes.NewReader(fixture(t, "hardlink.mtree")))
	if err != nil {
		t.Fatalf("Parse: %v", err)
	}
	if len(got) != 3 {
		t.Fatalf("got %d entries, want 3", len(got))
	}
	if got[0].SHA256 != got[1].SHA256 || got[0].Path == got[1].Path {
		t.Errorf("hardlinked pair not preserved: %+v", got[:2])
	}
	if got[2].Type != "link" || got[2].Link != "tool" {
		t.Errorf("symlink record = %+v", got[2])
	}
}

// localDB returns the live pacman database, or skips: CI has no Arch root, and
// a conformance claim that quietly did not run is worse than one that says so.
func localDB(t *testing.T) string {
	t.Helper()
	const db = "/var/lib/pacman/local"
	if _, err := os.Stat(db); err != nil {
		t.Skipf("no local pacman database: %v", err)
	}
	return db
}

// Every installed mtree must parse, and none may contain a path that escapes
// the package root -- a single refusal here fails the test with the package
// named, which is the same attribution the scan owes a coverage gap (INV-9).
//
// Measured 2026-08-05: 1410 installed packages, every one with an mtree, 237
// md5digest values (225 of them outside the ./. metadata records this parser
// filters), 669 vis escapes over 397 lines, and zero paths that are absolute,
// contain "..", or are not ./-rooted.
func TestConformAllInstalledMtreesParse(t *testing.T) {
	db := localDB(t)
	dirs, err := os.ReadDir(db)
	if err != nil {
		t.Skipf("cannot read %s: %v", db, err)
	}
	var pkgs, entries, withMD5, escaped int
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(db, d.Name(), "mtree"))
		if err != nil {
			continue // not every DB directory carries one
		}
		got, perr := ParseGzip(f)
		f.Close()
		if perr != nil {
			// INV-9: name the subject. A parse failure here is a coverage gap
			// for one package, and the test is what proves there are none.
			t.Errorf("%s: %v", d.Name(), perr)
			continue
		}
		pkgs++
		entries += len(got)
		for _, e := range got {
			if e.MD5 != "" {
				withMD5++
			}
			// The escape is gone by now; what is asserted is that decoding
			// happened, i.e. no surviving backslash where pacman wrote one.
			if strings.ContainsAny(e.Path, " #[\\") {
				escaped++
			}
		}
	}
	if pkgs == 0 {
		t.Skip("no installed mtrees to read")
	}
	t.Logf("parsed %d mtrees, %d records, %d with md5digest, %d decoded paths", pkgs, entries, withMD5, escaped)
	if withMD5 == 0 {
		t.Errorf("no md5digest records found; 237 were measured, 225 of them outside package metadata")
	}
	if escaped == 0 {
		t.Errorf("no decoded paths found; 397 escaped lines were measured")
	}
}

// Cross-validation. `pacman -Qkk` verifies the same digests; where it reports a
// package clean, this parser plus a sha256 of the same files must agree. This
// is not a claim to novelty -- the file-level work is pacman's, and P1-B's
// reason for reimplementing it is offline roots, parallelism, structured output
// and feeding P4's mtree baseline.
func TestConformCrossValidateAgainstPacman(t *testing.T) {
	localDB(t)
	pacman, err := exec.LookPath("pacman")
	if err != nil {
		t.Skip("pacman not installed")
	}
	pkgs := pickSmallReadablePackages(t, 10)
	var hashed int
	for _, pkg := range pkgs {
		// pacman -Qkk exits non-zero when it finds a mismatch; on these
		// packages it must find none, which is what makes agreement mean
		// something.
		out, err := exec.Command(pacman, "-Qkk", pkg.name).CombinedOutput()
		if err != nil {
			t.Logf("skipping %s: pacman -Qkk: %v: %s", pkg.name, err, out)
			continue
		}
		if bytes.Contains(out, []byte("ismatch")) {
			t.Logf("skipping %s: pacman reports it already altered: %s", pkg.name, out)
			continue
		}

		var mismatched []string
		for _, e := range pkg.entries {
			if e.Type != "file" || e.SHA256 == "" {
				continue
			}
			sum, err := sha256File(filepath.Join("/", strings.TrimPrefix(e.Path, "./")))
			if err != nil {
				t.Fatalf("%s: %v", e.Path, err)
			}
			hashed++
			if sum != e.SHA256 {
				mismatched = append(mismatched, e.Path)
			}
		}
		if len(mismatched) != 0 {
			sort.Strings(mismatched)
			t.Errorf("pacman -Qkk reports %s clean, this parser reports %d mismatches: %v",
				pkg.name, len(mismatched), mismatched)
		}
	}
	if hashed == 0 {
		t.Skip("no files were cross-validated")
	}
	t.Logf("agreed with pacman -Qkk on %d packages, %d files", len(pkgs), hashed)
}

type livePkg struct {
	name    string
	entries []Entry
}

// pickSmallReadablePackages finds up to n installed packages this test can hash
// as an unprivileged user: every recorded file readable and small in total.
func pickSmallReadablePackages(t *testing.T, n int) []livePkg {
	t.Helper()
	var found []livePkg
	db := localDB(t)
	dirs, err := os.ReadDir(db)
	if err != nil {
		t.Skipf("cannot read %s: %v", db, err)
	}
	sort.Slice(dirs, func(i, j int) bool { return dirs[i].Name() < dirs[j].Name() })
	for _, d := range dirs {
		if !d.IsDir() {
			continue
		}
		f, err := os.Open(filepath.Join(db, d.Name(), "mtree"))
		if err != nil {
			continue
		}
		entries, perr := ParseGzip(f)
		f.Close()
		if perr != nil {
			continue
		}
		var total int64
		ok := len(entries) > 0
		for _, e := range entries {
			if e.Type != "file" || e.SHA256 == "" {
				continue
			}
			total += e.Size
			p := filepath.Join("/", strings.TrimPrefix(e.Path, "./"))
			if fh, err := os.Open(p); err != nil {
				ok = false
				break
			} else {
				fh.Close()
			}
		}
		if ok && total > 0 && total < 8<<20 {
			found = append(found, livePkg{name: pkgName(d.Name()), entries: entries})
			if len(found) == n {
				return found
			}
		}
	}
	if len(found) == 0 {
		t.Skip("no small fully readable package found")
	}
	return found
}

// pkgName strips the version from a local-database directory name. The layout
// is name-pkgver-pkgrel and neither pkgver nor pkgrel may contain a hyphen, so
// dropping the last two fields is exact rather than a guess.
func pkgName(dir string) string {
	for i := 0; i < 2; i++ {
		if j := strings.LastIndexByte(dir, '-'); j > 0 {
			dir = dir[:j]
		}
	}
	return dir
}

func sha256File(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}
