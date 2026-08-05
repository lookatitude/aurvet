// internal/pkgmeta/srcinfo_test.go
package pkgmeta

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// --- pkgbase keying, and the split-package trap ---------------------------

// TestSRCINFOKeysOnPkgBase reads a real single-package .SRCINFO and pins the
// keying rule: the unit is the pkgbase, and the package names are members of it.
func TestSRCINFOKeysOnPkgBase(t *testing.T) {
	s := parseSRCINFO(t, "kind.SRCINFO")

	if s.PkgBase != "kind" {
		t.Errorf("PkgBase = %q", s.PkgBase)
	}
	if names := s.PkgNames(); len(names) != 1 || names[0] != "kind" {
		t.Errorf("PkgNames = %v", names)
	}
	if s.IsSplit() {
		t.Error("IsSplit = true for a single-package base")
	}
}

// TestSRCINFOSplitPackage reads the flutter recipe from the reference system's
// yay cache: one pkgbase, 17 packages.
//
// This is the definition of splitness that a .SRCINFO can answer, and it is the
// one the roadmap's number comes from. Recording the measurement here because
// getting it wrong costs a wrong conclusion:
//
//	%BASE% != %NAME% in the LOCAL db ..................... 237
//	installed packages sharing a base with another
//	  INSTALLED package .................................. 269
//	either of the above .................................. 296
//	installed packages whose pkgbase ships >1 package
//	  IN THE REPOSITORIES (needs SYNC-db metadata) ....... 432  <- the roadmap's
//
// A splitness test built on the local DB alone reports 237 and misses the 195
// packages whose siblings are simply not installed on this machine. A .SRCINFO
// answers the repository-side question directly -- it lists every pkgname the
// base builds, installed or not -- which is why this is the reader that gets to
// decide, and why TestLiveSplitPackageCount cross-checks it against the sync DB.
func TestSRCINFOSplitPackage(t *testing.T) {
	s := parseSRCINFO(t, "flutter.SRCINFO")

	if s.PkgBase != "flutter" {
		t.Errorf("PkgBase = %q", s.PkgBase)
	}
	names := s.PkgNames()
	if len(names) != 17 {
		t.Fatalf("PkgNames = %d, want 17: %v", len(names), names)
	}
	if names[0] != "flutter" || !contains(names, "flutter-tool") {
		t.Errorf("PkgNames = %v", names)
	}
	if !s.IsSplit() {
		t.Error("IsSplit = false for a 17-package base")
	}
	// A member package resolves to its own section, and the base is not one of
	// the members' keys.
	if _, ok := s.Package("flutter-tool"); !ok {
		t.Error("Package(flutter-tool) not found")
	}
	if _, ok := s.Package("flutter-nonexistent"); ok {
		t.Error("Package returned a section for a name that is not in the file")
	}
}

// TestSRCINFOIndentedPkgnameIsASection is a real-world quirk, found in the
// reference cache and not invented for the test.
//
// nperf-gui-appimage's .SRCINFO writes its `pkgname` line TAB-INDENTED, like a
// field of the pkgbase section, rather than unindented as `makepkg
// --printsrcinfo` does. A parser that treats indentation as the section
// delimiter reads that file as a base with ZERO packages -- and then
// IsSplit(), PkgNames() and any per-package rule are wrong for it, silently.
// The key, not the indentation, decides.
func TestSRCINFOIndentedPkgnameIsASection(t *testing.T) {
	s := parseSRCINFO(t, "nperf-gui-appimage.SRCINFO")

	if s.PkgBase != "nperf-gui-appimage" {
		t.Errorf("PkgBase = %q", s.PkgBase)
	}
	names := s.PkgNames()
	if len(names) != 1 || names[0] != "nperf-gui-appimage" {
		t.Fatalf("PkgNames = %v, want [nperf-gui-appimage]; an indented pkgname is still a package", names)
	}
	if s.IsSplit() {
		t.Error("IsSplit = true")
	}
}

// TestSRCINFOWithoutPkgBaseIsRefused: pkgbase is the key, so a file without one
// cannot be filed anywhere. Inventing a key from the first pkgname would file
// the recipe under a name that is not its unit.
func TestSRCINFOWithoutPkgBaseIsRefused(t *testing.T) {
	_, err := ParseSRCINFO(strings.NewReader("pkgname = orphan\n\tpkgver = 1\n"), Limits{})
	if !errors.Is(err, ErrFormat) {
		t.Fatalf("err = %v, want ErrFormat", err)
	}
}

// --- sources --------------------------------------------------------------

// TestSourcesIncludeArchSuffixed is the 29% blind spot the roadmap names: 10 of
// the 34 cached .SRCINFO files on the reference system declare
// source_x86_64/source_aarch64, and flutter declares 18 of them (12 x86_64,
// 6 aarch64) alongside 25 unsuffixed ones. A reader that looks only at `source`
// misses every one.
func TestSourcesIncludeArchSuffixed(t *testing.T) {
	s := parseSRCINFO(t, "flutter.SRCINFO")
	srcs := s.Sources()

	var plain, x86, arm int
	for _, src := range srcs {
		switch src.Arch {
		case "":
			plain++
		case "x86_64":
			x86++
		case "aarch64":
			arm++
		}
	}
	if x86 != 12 || arm != 6 {
		t.Errorf("arch-suffixed sources = %d x86_64 / %d aarch64, want 12/6", x86, arm)
	}
	if plain != 25 {
		t.Errorf("unsuffixed sources = %d, want 25", plain)
	}
	// Any-arch and per-arch sources must be distinguishable: they are not
	// interchangeable evidence, because only one set was actually fetched.
	for _, src := range srcs {
		if src.Arch != "" && src.Arch != "x86_64" && src.Arch != "aarch64" {
			t.Errorf("unexpected Arch %q on %q", src.Arch, src.Raw)
		}
	}
}

// TestSourceRenameIsSplit: `name::url` is makepkg's rename syntax and both
// halves matter -- the URL is what was fetched, the name is what the build then
// referred to.
func TestSourceRenameIsSplit(t *testing.T) {
	s := parseSRCINFO(t, "flutter.SRCINFO")
	var found bool
	for _, src := range s.Sources() {
		if src.Name == "flutter-3.41.2.tar.xz" {
			found = true
			if src.Location != "https://github.com/flutter/flutter/archive/refs/tags/3.41.2.tar.gz" {
				t.Errorf("Location = %q", src.Location)
			}
			if src.IsVCS {
				t.Error("IsVCS = true for a tarball")
			}
		}
	}
	if !found {
		t.Error("renamed source not parsed")
	}
}

// TestLocalSourcesAreNotURLs: a source with no scheme is a file in the
// repository, and treating it as a URL would report a network fetch that never
// happened.
func TestLocalSourcesAreNotURLs(t *testing.T) {
	s := parseSRCINFO(t, "kind.SRCINFO")
	var remote, local int
	for _, src := range s.Sources() {
		if src.IsRemote {
			remote++
		} else {
			local++
		}
	}
	if remote != 1 || local != 2 {
		t.Errorf("remote=%d local=%d, want 1 remote and 2 local", remote, local)
	}
}

// TestVCSSourceCarriesFragment is what the VCS delta review needs (P2 task 11):
// for a -git package the recipe is stable while the source moves, and the
// fragment is the only thing in the recipe that pins WHICH upstream commit is
// meant.
func TestVCSSourceCarriesFragment(t *testing.T) {
	in := "pkgbase = x\n\tsource = x::git+https://github.com/o/r.git#tag=v2.5.1\n" +
		"\tsource = y::git+https://example.invalid/y#commit=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef\n" +
		"\tsource = z::git+https://example.invalid/z\n" +
		"\tsource = h::hg+https://example.invalid/h\n" +
		"pkgname = x\n"
	s, err := ParseSRCINFO(strings.NewReader(in), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	srcs := s.Sources()
	if len(srcs) != 4 {
		t.Fatalf("sources = %d", len(srcs))
	}
	if !srcs[0].IsVCS || srcs[0].VCS != "git" || srcs[0].Fragment != "tag=v2.5.1" {
		t.Errorf("srcs[0] = %+v", srcs[0])
	}
	if srcs[0].Location != "https://github.com/o/r.git" {
		t.Errorf("VCS Location keeps the scheme prefix or the fragment: %q", srcs[0].Location)
	}
	if srcs[1].Fragment != "commit=deadbeefdeadbeefdeadbeefdeadbeefdeadbeef" {
		t.Errorf("srcs[1].Fragment = %q", srcs[1].Fragment)
	}
	// An unpinned VCS source is the interesting case: nothing in the recipe
	// says which commit will be built, which is exactly why approving the
	// recipe once cannot bless the source.
	if !srcs[2].IsVCS || srcs[2].Fragment != "" {
		t.Errorf("srcs[2] = %+v", srcs[2])
	}
	if srcs[3].VCS != "hg" {
		t.Errorf("srcs[3].VCS = %q", srcs[3].VCS)
	}
}

// TestSourcesPerPackageSection: a split recipe can declare sources inside a
// package section. They belong to that package, and merging them into the base
// would attribute a fetch to the wrong unit.
func TestSourcesPerPackageSection(t *testing.T) {
	in := "pkgbase = b\n\tsource = base.tar.gz\npkgname = p1\n\tsource = p1.tar.gz\npkgname = p2\n"
	s, err := ParseSRCINFO(strings.NewReader(in), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var base, p1 int
	for _, src := range s.Sources() {
		switch src.Package {
		case "":
			base++
		case "p1":
			p1++
		default:
			t.Errorf("source attributed to %q: %+v", src.Package, src)
		}
	}
	if base != 1 || p1 != 1 {
		t.Errorf("base=%d p1=%d", base, p1)
	}
}

// --- dependencies ---------------------------------------------------------

// TestDepsSeparateKindsAndConstraints: the dependency closure (P2 task 9)
// resolves names, and a version constraint is not part of a name. flutter
// declares `dart>=3.11.0` and `dart<3.12.0`, which are one package.
func TestDepsSeparateKindsAndConstraints(t *testing.T) {
	s := parseSRCINFO(t, "flutter.SRCINFO")
	deps := s.Deps(DepMake)

	var sawDart bool
	for _, d := range deps {
		if d.Name == "dart" {
			sawDart = true
			if d.Constraint == "" {
				continue
			}
			if !strings.HasPrefix(d.Constraint, ">=") && !strings.HasPrefix(d.Constraint, "<") {
				t.Errorf("dart Constraint = %q", d.Constraint)
			}
		}
		if strings.ContainsAny(d.Name, "<>=:") {
			t.Errorf("Name %q still carries a constraint or description", d.Name)
		}
	}
	if !sawDart {
		t.Errorf("makedepends did not yield dart: %+v", deps)
	}
	if len(s.Deps(DepRun)) == 0 {
		t.Error("no runtime depends parsed")
	}
	// Kinds are not interchangeable: a makedepend is present at build time and
	// absent afterwards, and the closure review needs both sets separately.
	for _, d := range s.Deps(DepMake) {
		if d.Kind != DepMake {
			t.Errorf("Deps(DepMake) returned kind %q", d.Kind)
		}
	}
}

// TestOptDependsDescriptionIsStripped: optdepends are "name: why", and the
// description is not part of the name.
func TestOptDependsDescriptionIsStripped(t *testing.T) {
	s := parseSRCINFO(t, "kind.SRCINFO")
	deps := s.Deps(DepOpt)
	if len(deps) != 3 {
		t.Fatalf("optdepends = %d, want 3: %+v", len(deps), deps)
	}
	for _, d := range deps {
		if strings.Contains(d.Name, ":") {
			t.Errorf("Name = %q", d.Name)
		}
		if d.Description == "" {
			t.Errorf("Description dropped for %q", d.Name)
		}
	}
}

// TestDepsIncludeArchSuffixed: depends_x86_64 is a dependency, and the closure
// that misses it reviews fewer PKGBUILDs than the build will pull.
func TestDepsIncludeArchSuffixed(t *testing.T) {
	in := "pkgbase = b\n\tdepends = glibc\n\tdepends_x86_64 = lib32-glibc\n\tmakedepends_aarch64 = clang\npkgname = b\n"
	s, err := ParseSRCINFO(strings.NewReader(in), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	var archDeps int
	for _, d := range s.Deps(DepRun) {
		if d.Arch == "x86_64" && d.Name == "lib32-glibc" {
			archDeps++
		}
	}
	if archDeps != 1 {
		t.Errorf("depends_x86_64 not parsed: %+v", s.Deps(DepRun))
	}
	if got := s.Deps(DepMake); len(got) != 1 || got[0].Arch != "aarch64" {
		t.Errorf("makedepends_aarch64 not parsed: %+v", got)
	}
}

// TestDepsAllKinds returns every kind when no filter is given, because the
// closure review wants the union and must not have to enumerate the kinds
// itself.
func TestDepsAllKinds(t *testing.T) {
	s := parseSRCINFO(t, "kind.SRCINFO")
	all := s.Deps()
	if len(all) <= len(s.Deps(DepRun)) {
		t.Errorf("Deps() = %d, Deps(DepRun) = %d; the unfiltered call must be the union",
			len(all), len(s.Deps(DepRun)))
	}
}

// --- robustness -----------------------------------------------------------

// TestSRCINFORobustness: .SRCINFO ships in the attacker's repository.
func TestSRCINFORobustness(t *testing.T) {
	cases := []string{
		"",
		"\t\t\t\n",
		"pkgbase = \n",
		"pkgbase=nospaces\n",
		"pkgbase = x\nsource\n",
		"pkgbase = x\n\tsource = \n",
		"pkgbase = x\n\tsource = a::b::c::d\n",
		"pkgbase = x\n\tsource = ::justacolon\n",
		"pkgbase = x\n\tsource = git+\n",
		"pkgbase = x\n\tdepends = >=1.0\n",
		"pkgbase = x\n\tdepends = " + strings.Repeat("a", 1000) + "\n",
		"pkgbase = x\x00nul\n",
		"pkgbase = x\r\n\tpkgver = 1\r\n",
		strings.Repeat("pkgname = p\n", 5000),
	}
	for i, in := range cases {
		func() {
			defer func() {
				if r := recover(); r != nil {
					t.Errorf("case %d panicked: %v", i, r)
				}
			}()
			s, err := ParseSRCINFO(strings.NewReader(in), Limits{})
			if err != nil {
				t.Logf("case %d: %v", i, err)
				return
			}
			// Whatever came back must be self-consistent enough to use.
			_ = s.Sources()
			_ = s.Deps()
			_ = s.PkgNames()
			_ = s.IsSplit()
		}()
	}
}

// TestSRCINFOCRLFIsHandled: a .SRCINFO committed from Windows has CRLF line
// endings, and a trailing \r silently becomes part of every value.
func TestSRCINFOCRLFIsHandled(t *testing.T) {
	s, err := ParseSRCINFO(strings.NewReader("pkgbase = x\r\n\tsource = a.tar.gz\r\npkgname = x\r\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if s.PkgBase != "x" {
		t.Errorf("PkgBase = %q", s.PkgBase)
	}
	if srcs := s.Sources(); len(srcs) != 1 || srcs[0].Raw != "a.tar.gz" {
		t.Errorf("Sources = %+v", srcs)
	}
	if names := s.PkgNames(); len(names) != 1 || names[0] != "x" {
		t.Errorf("PkgNames = %v", names)
	}
}

// TestSRCINFOCommentsAreIgnored: makepkg --printsrcinfo does not emit comments,
// but a hand-written .SRCINFO can carry them and a '#' line is not a field.
func TestSRCINFOCommentsAreIgnored(t *testing.T) {
	s, err := ParseSRCINFO(strings.NewReader("# generated by hand\npkgbase = x\n\t# a note\n\tsource = a\npkgname = x\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Sources()) != 1 {
		t.Errorf("Sources = %+v", s.Sources())
	}
	if len(s.Unparsed) != 0 {
		t.Errorf("comments recorded as unparsed lines: %v", s.Unparsed)
	}
}

// TestSRCINFOUnparsedLinesAreReported: a line that is neither a comment nor a
// key = value pair is not silently dropped. INV-9 in the small: a reader that
// cannot account for part of its input says so.
func TestSRCINFOUnparsedLinesAreReported(t *testing.T) {
	s, err := ParseSRCINFO(strings.NewReader("pkgbase = x\n\tthis line has no equals sign\npkgname = x\n"), Limits{})
	if err != nil {
		t.Fatal(err)
	}
	if len(s.Unparsed) != 1 || !strings.Contains(s.Unparsed[0], "no equals sign") {
		t.Fatalf("Unparsed = %v", s.Unparsed)
	}
	gaps := s.Gaps("x")
	if len(gaps) != 1 || gaps[0].Subject != "x" {
		t.Fatalf("Gaps = %+v", gaps)
	}
	if !strings.Contains(gaps[0].Reason, "1") {
		t.Errorf("gap must count the unaccounted lines: %q", gaps[0].Reason)
	}
}

// TestSRCINFOBounds proves each cap fires.
func TestSRCINFOBounds(t *testing.T) {
	body := "pkgbase = x\n" + strings.Repeat("\tsource = a\n", 500) + "pkgname = x\n"
	if _, err := ParseSRCINFO(strings.NewReader(body), Limits{MaxLines: 10}); !errors.Is(err, ErrLimit) {
		t.Errorf("MaxLines: err = %v", err)
	}
	if _, err := ParseSRCINFO(strings.NewReader(body), Limits{MaxValuesPerKey: 10}); !errors.Is(err, ErrLimit) {
		t.Errorf("MaxValuesPerKey: err = %v", err)
	}
	long := "pkgbase = x\n\tsource = " + strings.Repeat("u", 9000) + "\npkgname = x\n"
	if _, err := ParseSRCINFO(strings.NewReader(long), Limits{MaxLineBytes: 128}); !errors.Is(err, ErrLimit) {
		t.Errorf("MaxLineBytes: err = %v", err)
	}
	many := "pkgbase = x\n" + strings.Repeat("pkgname = p\n", 500)
	if _, err := ParseSRCINFO(strings.NewReader(many), Limits{MaxPackages: 10}); !errors.Is(err, ErrLimit) {
		t.Errorf("MaxPackages: err = %v", err)
	}
	if _, err := ParseSRCINFO(bytes.NewReader(mustRead(t, "flutter.SRCINFO")),
		Limits{MaxFileBytes: 1024}); !errors.Is(err, ErrLimit) {
		t.Errorf("MaxFileBytes: err = %v", err)
	}
}

// TestSRCINFOFromFileIsConfined: a .SRCINFO lives in an attacker-controlled
// clone, so the read is confined and a symlinked file is refused unresolved.
func TestSRCINFOFromFileIsConfined(t *testing.T) {
	root, dir := srcinfoRoot(t)
	defer root.Close()
	_ = dir

	s, err := SRCINFOFromFile(root, "clone/.SRCINFO", Limits{})
	if err != nil {
		t.Fatalf("SRCINFOFromFile: %v", err)
	}
	if s.PkgBase != "kind" {
		t.Errorf("PkgBase = %q", s.PkgBase)
	}
	if _, err := SRCINFOFromFile(root, "clone/linked.SRCINFO", Limits{}); err == nil {
		t.Error("followed a symlinked .SRCINFO out of the root")
	}
}

// --- helpers --------------------------------------------------------------

func parseSRCINFO(t *testing.T, name string) *SRCINFO {
	t.Helper()
	s, err := ParseSRCINFO(bytes.NewReader(mustRead(t, name)), Limits{})
	if err != nil {
		t.Fatalf("ParseSRCINFO(%s): %v", name, err)
	}
	return s
}

// srcinfoRoot materializes a clone holding a real .SRCINFO plus a symlinked one
// pointing out of the root, which is the shape the confinement test needs and
// the shape a checked-in fixture cannot carry.
func srcinfoRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	if err := os.MkdirAll(filepath.Join(dir, "root", "clone"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "root", "clone", ".SRCINFO"),
		mustRead(t, "kind.SRCINFO"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "outside"), []byte("pkgbase = evil\npkgname = evil\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside"),
		filepath.Join(dir, "root", "clone", "linked.SRCINFO")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(dir, "root"))
	if err != nil {
		t.Fatal(err)
	}
	return root, dir
}
