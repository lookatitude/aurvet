// internal/pkgmeta/buildinfo_test.go
package pkgmeta

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// TestParseRealBUILDINFO reads a .BUILDINFO taken verbatim out of a package
// archive on the reference system (testdata/pkgmeta/rustdesk.BUILDINFO). Every
// field this package extracts is asserted against what the file actually says,
// because the whole value of .BUILDINFO is that it is a record of one build and
// a reader that reshapes it is not evidence.
func TestParseRealBUILDINFO(t *testing.T) {
	b := parseFixture(t, "rustdesk.BUILDINFO")

	if b.Format != "2" {
		t.Errorf("Format = %q, want 2", b.Format)
	}
	if b.PkgName != "rustdesk" || b.PkgBase != "rustdesk" {
		t.Errorf("PkgName=%q PkgBase=%q", b.PkgName, b.PkgBase)
	}
	if b.PkgVer != "1.4.6-0" || b.PkgArch != "x86_64" {
		t.Errorf("PkgVer=%q PkgArch=%q", b.PkgVer, b.PkgArch)
	}
	if b.PkgBuildSHA256 != "d7f0dbda61f3937a4e8c0a4244c623824d7c7d666fa1b8024af94a86ef918b82" {
		t.Errorf("PkgBuildSHA256 = %q", b.PkgBuildSHA256)
	}
	// %PACKAGER% is Unknown Packager for 38 of 39 foreign packages on the
	// reference system (spec §7), so this is the normal case and not a defect.
	if b.Packager != "Unknown Packager" {
		t.Errorf("Packager = %q", b.Packager)
	}
	// builddir/startdir are the fields that make this file interesting: this
	// -bin package was built in CI, not on the user's machine, so its
	// pkgbuild_sha256sum is over a PKGBUILD in a GitHub workspace.
	if b.BuildDir != "/github/workspace/res" || b.StartDir != "/github/workspace/res" {
		t.Errorf("BuildDir=%q StartDir=%q", b.BuildDir, b.StartDir)
	}
	if b.BuildTool != "makepkg" || b.BuildToolVer != "6.1.0" {
		t.Errorf("BuildTool=%q %q", b.BuildTool, b.BuildToolVer)
	}
	if got := b.BuildDate.UTC().Format(time.RFC3339); got != "2026-03-05T05:38:20Z" {
		t.Errorf("BuildDate = %s", got)
	}
	if len(b.BuildEnv) != 5 || b.BuildEnv[0] != "!distcc" {
		t.Errorf("BuildEnv = %v", b.BuildEnv)
	}
	if len(b.Options) == 0 {
		t.Error("Options empty")
	}
	// The installed list is the build environment's package set: 278 entries in
	// this file, which is what makes a bounded reader necessary.
	if len(b.Installed) != 278 {
		t.Errorf("Installed = %d entries, want 278", len(b.Installed))
	}
	if b.Missing() != nil {
		t.Errorf("Missing() = %v on a complete file", b.Missing())
	}
}

// TestBuildInfoMissingFieldsAreNamed: .BUILDINFO is the only source of
// pkgbuild_sha256sum, and a file without it cannot answer the check that
// compares the built recipe to the published one. Absence must be enumerable,
// not silently zero (INV-6, INV-10).
func TestBuildInfoMissingFieldsAreNamed(t *testing.T) {
	b, err := ParseBuildInfo(strings.NewReader("format = 2\npkgname = x\n"), Limits{})
	if err != nil {
		t.Fatalf("ParseBuildInfo: %v", err)
	}
	missing := b.Missing()
	for _, want := range []string{"pkgbuild_sha256sum", "builddir", "startdir", "pkgbase"} {
		if !contains(missing, want) {
			t.Errorf("Missing() = %v, does not name %s", missing, want)
		}
	}
	gaps := b.Gaps("x")
	if len(gaps) == 0 {
		t.Fatal("Gaps() empty for a .BUILDINFO with no provenance fields")
	}
	for _, g := range gaps {
		if g.RuleID == "" || g.Subject != "x" || g.Reason == "" {
			t.Errorf("incomplete gap %+v", g)
		}
	}
}

// TestBuildInfoPkgBaseFallback: pkgbase is the key everything downstream is
// filed under (spec §7). A .BUILDINFO without one is reported as missing rather
// than silently substituting pkgname -- 432 of 1410 installed packages on the
// reference system have a pkgbase that ships more than one package, so guessing
// pkgbase == pkgname would file 432 snapshots under the wrong key.
func TestBuildInfoPkgBaseFallback(t *testing.T) {
	b, err := ParseBuildInfo(strings.NewReader("pkgname = flutter-tool\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if b.PkgBase != "" {
		t.Errorf("PkgBase = %q; it must not be inferred from pkgname", b.PkgBase)
	}
	if !contains(b.Missing(), "pkgbase") {
		t.Errorf("Missing() = %v", b.Missing())
	}
}

// --- archives -------------------------------------------------------------

// TestBuildInfoFromUncompressedArchive: a plain .pkg.tar is readable with the
// standard library alone, and .BUILDINFO is the first member makepkg writes.
func TestBuildInfoFromUncompressedArchive(t *testing.T) {
	body := mustRead(t, "rustdesk.BUILDINFO")
	archive := tarArchive(t, map[string]string{
		".BUILDINFO": string(body),
		".PKGINFO":   "pkgname = rustdesk\n",
		"usr/bin/x":  "binary",
	})

	b, err := BuildInfoFromArchive("rustdesk-1.4.6-2-x86_64.pkg.tar", bytes.NewReader(archive), Limits{})
	if err != nil {
		t.Fatalf("BuildInfoFromArchive: %v", err)
	}
	if b.PkgBuildSHA256 == "" || b.BuildDir != "/github/workspace/res" {
		t.Errorf("BuildInfo = %+v", b)
	}
}

func TestBuildInfoFromGzipArchive(t *testing.T) {
	archive := gzipBytes(t, tarArchive(t, map[string]string{
		".BUILDINFO": "format = 2\npkgbase = hello\npkgbuild_sha256sum = " + strings.Repeat("a", 64) + "\nbuilddir = /build\nstartdir = /build\n",
	}))
	b, err := BuildInfoFromArchive("hello-1-1-x86_64.pkg.tar.gz", bytes.NewReader(archive), Limits{})
	if err != nil {
		t.Fatalf("BuildInfoFromArchive: %v", err)
	}
	if b.PkgBase != "hello" {
		t.Errorf("PkgBase = %q", b.PkgBase)
	}
}

// TestZstdArchiveIsACoverageGap is the decision this task had to make, written
// down as a test.
//
// Arch's default package compression is zstd and 229 of the 233 archives in the
// reference system's yay cache are .pkg.tar.zst. zstd is NOT in the standard
// library, and the only sanctioned dependency in this module is
// golang.org/x/sys, so decompressing it is not available to this package. The
// choice is therefore between guessing and saying so, and this project's answer
// to that is always the same: an archive that cannot be decompressed is a
// coverage gap (INV-9) that names the algorithm, and the caller reads
// .BUILDINFO from an unpacked copy or from a snapshot (spec §7) instead.
//
// This is also, precisely, why `snapshot` exists: the fact is only reachable
// while the build directory still holds it.
func TestZstdArchiveIsACoverageGap(t *testing.T) {
	for _, tc := range []struct{ name, algo string }{
		{"hello-1-1-x86_64.pkg.tar.zst", "zstd"},
		{"hello-1-1-x86_64.pkg.tar.xz", "xz"},
		{"hello-1-1-x86_64.pkg.tar.bz2", "bzip2"},
		{"hello-1-1-x86_64.pkg.tar.lz4", "lz4"},
		{"hello-1-1-x86_64.pkg.tar.Z", "compress"},
	} {
		_, err := BuildInfoFromArchive(tc.name, strings.NewReader("not really an archive"), Limits{})
		if !errors.Is(err, ErrCompression) {
			t.Errorf("%s: err = %v, want ErrCompression", tc.name, err)
			continue
		}
		if !strings.Contains(err.Error(), tc.algo) {
			t.Errorf("%s: error must name the algorithm, got %v", tc.name, err)
		}
		if !strings.Contains(err.Error(), "snapshot") && !strings.Contains(err.Error(), "unpacked") {
			t.Errorf("%s: error must say where the fact can still be read, got %v", tc.name, err)
		}
	}
}

// TestArchiveWithoutBUILDINFO: an archive built by something other than a
// current makepkg has no .BUILDINFO at all. That is a distinct answer from "I
// could not decompress it".
func TestArchiveWithoutBUILDINFO(t *testing.T) {
	archive := tarArchive(t, map[string]string{".PKGINFO": "pkgname = x\n", "usr/bin/x": "y"})
	_, err := BuildInfoFromArchive("x-1-1-any.pkg.tar", bytes.NewReader(archive), Limits{})
	if !errors.Is(err, ErrNoBuildInfo) {
		t.Fatalf("err = %v, want ErrNoBuildInfo", err)
	}
	if errors.Is(err, ErrCompression) {
		t.Error("a missing member must not be reported as a compression problem")
	}
}

// TestArchiveMemberBounds: the archive is attacker-controlled. A .BUILDINFO
// member claiming a gigabyte, or an archive with a million members before the
// one we want, must both be bounded refusals.
func TestArchiveMemberBounds(t *testing.T) {
	big := "format = 2\n" + strings.Repeat("options = x\n", 20_000)
	archive := tarArchive(t, map[string]string{".BUILDINFO": big})
	if _, err := BuildInfoFromArchive("x-1-1-any.pkg.tar", bytes.NewReader(archive),
		Limits{MaxFileBytes: 1024}); !errors.Is(err, ErrLimit) {
		t.Errorf("oversized member: err = %v, want ErrLimit", err)
	}

	// .BUILDINFO deliberately LAST here: an archive that buries it behind more
	// members than the cap allows must refuse rather than scan on.
	var ordered []tarMember
	for i := 0; i < 50; i++ {
		ordered = append(ordered, tarMember{name: fmt.Sprintf("usr/share/f%d", i), body: "x"})
	}
	ordered = append(ordered, tarMember{name: ".BUILDINFO", body: "format = 2\n"})
	if _, err := BuildInfoFromArchive("x-1-1-any.pkg.tar", bytes.NewReader(tarOrdered(t, ordered)),
		Limits{MaxTarMembers: 3}); !errors.Is(err, ErrLimit) {
		t.Errorf("member count: err = %v, want ErrLimit", err)
	}
}

// TestGzipRatioBounded: a gzip bomb named .pkg.tar.gz would otherwise inflate
// unbounded inside this reader.
func TestGzipRatioBounded(t *testing.T) {
	inner := tarArchive(t, map[string]string{".BUILDINFO": "format = 2\n" + strings.Repeat("options = padding\n", 50_000)})
	archive := gzipBytes(t, inner)
	if len(archive) >= len(inner)/10 {
		t.Fatalf("fixture is not compressible enough to test the bound: %d -> %d", len(inner), len(archive))
	}
	_, err := BuildInfoFromArchive("x-1-1-any.pkg.tar.gz", bytes.NewReader(archive),
		Limits{MaxArchiveBytes: int64(len(inner) / 4)})
	if !errors.Is(err, ErrLimit) {
		t.Fatalf("err = %v, want ErrLimit", err)
	}
}

// TestArchivePathsAreNotUsedAsPaths: nothing here writes a file, but a member
// named ../../etc/passwd must not even be considered a candidate for
// .BUILDINFO -- the match is on the exact member name.
func TestArchivePathsAreNotUsedAsPaths(t *testing.T) {
	archive := tarArchive(t, map[string]string{
		"../.BUILDINFO":     "format = 2\npkgbase = evil\n",
		"./.BUILDINFO/../x": "format = 2\npkgbase = evil2\n",
	})
	_, err := BuildInfoFromArchive("x-1-1-any.pkg.tar", bytes.NewReader(archive), Limits{})
	if !errors.Is(err, ErrNoBuildInfo) {
		t.Fatalf("err = %v, want ErrNoBuildInfo: neither member is .BUILDINFO", err)
	}
}

// TestBuildInfoFromFileIsConfined reads an unpacked .BUILDINFO -- the path this
// package recommends when the archive is zstd -- and refuses a symlinked one,
// because a build directory under a user's home is not a trusted path.
func TestBuildInfoFromFileIsConfined(t *testing.T) {
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "root", "build"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root", "build", ".BUILDINFO"),
		mustRead(t, "rustdesk.BUILDINFO"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "outside"), []byte("format = 2\npkgbase = evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"),
		filepath.Join(dir, "root", "build", "linked.BUILDINFO")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(dir, "root"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	b, err := BuildInfoFromFile(root, "build/.BUILDINFO", Limits{})
	if err != nil {
		t.Fatalf("BuildInfoFromFile: %v", err)
	}
	if b.PkgBase != "rustdesk" {
		t.Errorf("PkgBase = %q", b.PkgBase)
	}
	if _, err := BuildInfoFromFile(root, "build/linked.BUILDINFO", Limits{}); err == nil {
		t.Error("followed a symlinked .BUILDINFO out of the root")
	}
}

// TestCompressionOf documents the dispatch table as data a caller can consult
// BEFORE opening a 200 MB archive it cannot read.
func TestCompressionOf(t *testing.T) {
	cases := map[string]struct {
		algo      string
		supported bool
	}{
		"x.pkg.tar":      {"none", true},
		"x.pkg.tar.gz":   {"gzip", true},
		"x.pkg.tar.zst":  {"zstd", false},
		"x.pkg.tar.xz":   {"xz", false},
		"x.pkg.tar.zstd": {"zstd", false},
		"x.txt":          {"", false},
	}
	for name, want := range cases {
		algo, supported := CompressionOf(name)
		if algo != want.algo || supported != want.supported {
			t.Errorf("CompressionOf(%q) = (%q,%v), want (%q,%v)", name, algo, supported, want.algo, want.supported)
		}
	}
}

// --- parser robustness ----------------------------------------------------

// TestBuildInfoParserRobustness: this file comes out of an attacker's package.
// None of these inputs may panic, hang, or be silently misread.
func TestBuildInfoParserRobustness(t *testing.T) {
	cases := []string{
		"",
		"\n\n\n",
		"no equals sign at all\n",
		"= value with no key\n",
		"pkgbase =\n",
		"pkgbase = \x00nul\n",
		strings.Repeat("a", 4096) + " = x\n",
		"pkgbase = a\rpkgbase = b\n",
		"builddate = not-a-number\n",
		"builddate = 99999999999999999999\n",
		strings.Repeat("installed = x\n", 10_000),
	}
	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			if _, err := ParseBuildInfo(strings.NewReader(in), Limits{}); err != nil {
				// An error is fine; a panic or a hang is not.
				t.Logf("case %d: %v", i, err)
			}
		}()
	}
}

// TestBuildInfoLineBounds proves the per-line and per-key caps fire rather than
// truncating in silence.
func TestBuildInfoLineBounds(t *testing.T) {
	long := "options = " + strings.Repeat("x", 5000) + "\n"
	if _, err := ParseBuildInfo(strings.NewReader(long), Limits{MaxLineBytes: 128}); !errors.Is(err, ErrLimit) {
		t.Errorf("long line: err = %v, want ErrLimit", err)
	}
	many := strings.Repeat("installed = pkg\n", 100)
	if _, err := ParseBuildInfo(strings.NewReader(many), Limits{MaxValuesPerKey: 10}); !errors.Is(err, ErrLimit) {
		t.Errorf("many values: err = %v, want ErrLimit", err)
	}
	if _, err := ParseBuildInfo(strings.NewReader(many), Limits{MaxLines: 10}); !errors.Is(err, ErrLimit) {
		t.Errorf("many lines: err = %v, want ErrLimit", err)
	}
}

// TestBuildInfoUnknownKeysAreKept: the format gains keys (format 1 -> 2 added
// buildtool). An unrecognised key is retained rather than dropped, so a later
// rule can use it without this reader having to know about it first.
func TestBuildInfoUnknownKeysAreKept(t *testing.T) {
	b, err := ParseBuildInfo(strings.NewReader("format = 3\nnewfangled = yes\nnewfangled = also\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if got := b.Other["newfangled"]; len(got) != 2 || got[0] != "yes" {
		t.Errorf("Other = %v", b.Other)
	}
}

// --- helpers --------------------------------------------------------------

func parseFixture(t *testing.T, name string) BuildInfo {
	t.Helper()
	b, err := ParseBuildInfo(bytes.NewReader(mustRead(t, name)), Limits{})
	if err != nil {
		t.Fatalf("ParseBuildInfo(%s): %v", name, err)
	}
	return b
}

func mustRead(t *testing.T, name string) []byte {
	t.Helper()
	data, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pkgmeta", name))
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	return data
}

func contains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// tarMember is one archive member for tarOrdered, which is used where the
// ORDER matters -- an archive that buries .BUILDINFO behind other members.
type tarMember struct {
	name string
	body string
}

func tarOrdered(t *testing.T, members []tarMember) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	for _, m := range members {
		if err := tw.WriteHeader(&tar.Header{
			Name: m.name, Mode: 0o644, Size: int64(len(m.body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(m.body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

// tarArchive builds an uncompressed tar in memory with .BUILDINFO first, as
// makepkg writes it.
func tarArchive(t *testing.T, members map[string]string) []byte {
	t.Helper()
	var buf bytes.Buffer
	tw := tar.NewWriter(&buf)
	names := make([]string, 0, len(members))
	for n := range members {
		names = append(names, n)
	}
	// .BUILDINFO first, as makepkg writes it; the rest in map order is fine
	// because nothing asserts on it.
	sortBuildInfoFirst(names)
	for _, n := range names {
		body := members[n]
		if err := tw.WriteHeader(&tar.Header{
			Name: n, Mode: 0o644, Size: int64(len(body)), Typeflag: tar.TypeReg,
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}

func sortBuildInfoFirst(names []string) {
	for i, n := range names {
		if n == ".BUILDINFO" {
			names[0], names[i] = names[i], names[0]
			return
		}
	}
}

func gzipBytes(t *testing.T, p []byte) []byte {
	t.Helper()
	var buf bytes.Buffer
	zw := gzip.NewWriter(&buf)
	if _, err := zw.Write(p); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	return buf.Bytes()
}
