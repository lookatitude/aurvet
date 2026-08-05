// internal/pkgmeta/srcinfo.go
package pkgmeta

import (
	"fmt"
	"io"
	"os"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// DepKind is which dependency array a dependency came from. The kinds are NOT
// interchangeable: a makedepend is present while the build runs and gone
// afterwards, and a closure review that merges them cannot tell the operator
// which packages will execute code on their machine at build time.
type DepKind string

const (
	DepRun   DepKind = "depends"
	DepMake  DepKind = "makedepends"
	DepCheck DepKind = "checkdepends"
	DepOpt   DepKind = "optdepends"
)

// allDepKinds is the order Deps() returns when unfiltered.
var allDepKinds = []DepKind{DepRun, DepMake, DepCheck, DepOpt}

// Section is one section of a .SRCINFO: the pkgbase section, or one pkgname
// section. Fields keeps every key with its values in file order.
type Section struct {
	// Name is the pkgbase for the global section and the pkgname for a package
	// section.
	Name string

	// Fields maps a lowercased key (including any _arch suffix, verbatim) to
	// its values in order.
	Fields map[string][]string

	// Keys is the key order as the file wrote it, so output can follow the
	// recipe rather than a map iteration.
	Keys []string
}

func (s *Section) add(key, value string) {
	if s.Fields == nil {
		s.Fields = map[string][]string{}
	}
	if _, seen := s.Fields[key]; !seen {
		s.Keys = append(s.Keys, key)
	}
	s.Fields[key] = append(s.Fields[key], value)
}

// Get returns the values for one key, or nil.
func (s Section) Get(key string) []string { return s.Fields[key] }

// First returns the first value for one key, or "".
func (s Section) First(key string) string {
	if v := s.Fields[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// Source is one declared source.
type Source struct {
	// Raw is the value exactly as written, which is what review output shows.
	Raw string

	// Name is the local filename from makepkg's `name::location` rename
	// syntax, empty when the source was not renamed.
	Name string

	// Location is the part after any rename and, for a VCS source, with the
	// vcs+ prefix and #fragment removed.
	Location string

	// Arch is the architecture suffix from source_x86_64 / source_aarch64, and
	// "" for the plain source array. Measured on the reference system: 10 of 34
	// cached recipes use arch-suffixed sources (18 entries in one), so folding
	// them together would misreport which sources a build actually fetched.
	Arch string

	// Package is the pkgname whose section declared this source, "" for the
	// pkgbase section. A per-package source belongs to that package.
	Package string

	// IsRemote reports a location with a URL scheme. A local source is a file
	// in the repository, and calling it a fetch would report network access
	// that never happened.
	IsRemote bool

	// IsVCS and VCS report a vcs+url source ("git", "hg", "svn", "bzr", "fossil").
	IsVCS bool
	VCS   string

	// Fragment is the part after '#' on a VCS source -- "tag=v2.5.1",
	// "commit=<sha>", "branch=main" -- and is the ONLY thing in a recipe that
	// pins which upstream revision is meant. An empty Fragment on a VCS source
	// is the case the VCS delta review exists for: nothing in the recipe says
	// what will be built, so approving the recipe cannot approve the source.
	Fragment string
}

// Dep is one declared dependency.
type Dep struct {
	// Raw is the value as written, constraint and description included.
	Raw string

	// Name is the package name alone, with any version constraint and any
	// optdepends description removed. This is what a closure resolver keys on.
	Name string

	// Constraint is the version constraint (">=3.11.0", "<3.12.0", "=1.2") or
	// "".
	Constraint string

	// Description is an optdepends description, or "".
	Description string

	Kind    DepKind
	Arch    string
	Package string
}

// SRCINFO is a parsed .SRCINFO, keyed on its pkgbase.
type SRCINFO struct {
	// PkgBase is the unit everything is filed under (spec §7).
	PkgBase string

	// Global is the pkgbase section.
	Global Section

	// Packages are the pkgname sections in file order. A base with more than
	// one is a split package.
	Packages []Section

	// Unparsed holds a bounded sample of lines that were neither a comment nor
	// a key = value pair, with a trailing "(and N more)" entry when the sample
	// was capped. A reader that cannot account for part of its input says so
	// (INV-9) rather than silently proceeding.
	Unparsed []string
}

// ParseSRCINFO parses .SRCINFO content.
//
// Section structure is decided by the KEY, not by indentation. `makepkg
// --printsrcinfo` writes pkgbase/pkgname unindented and fields with a leading
// tab, but that is a convention and not a guarantee:
// testdata/pkgmeta/nperf-gui-appimage.SRCINFO, taken verbatim off the reference
// system, writes its `pkgname` line TAB-INDENTED. A parser that split sections
// on indentation reads that real file as a base with zero packages, and then
// IsSplit, PkgNames and every per-package rule are wrong for it without
// anything reporting a problem.
func ParseSRCINFO(r io.Reader, lim Limits) (*SRCINFO, error) {
	lim = lim.withDefaults()
	fields, unparsed, err := scanFields(r, lim)
	if err != nil {
		return nil, err
	}

	s := &SRCINFO{Unparsed: unparsed}
	var cur *Section
	for _, f := range fields {
		switch f.key {
		case "pkgbase":
			if f.value == "" {
				return nil, fmt.Errorf("%w: pkgbase is empty", ErrFormat)
			}
			if s.PkgBase != "" {
				return nil, fmt.Errorf("%w: a second pkgbase (%q) -- one file describes one base", ErrFormat, f.value)
			}
			s.PkgBase = f.value
			s.Global = Section{Name: f.value}
			cur = &s.Global
		case "pkgname":
			if s.PkgBase == "" {
				// No key to file this under. Inventing one from the first
				// pkgname would file the recipe under a name that is not its
				// unit, which is the mis-keying spec §7 exists to prevent.
				return nil, fmt.Errorf("%w: pkgname %q appears before any pkgbase", ErrFormat, f.value)
			}
			if f.value == "" {
				return nil, fmt.Errorf("%w: pkgname is empty", ErrFormat)
			}
			if len(s.Packages) >= lim.MaxPackages {
				return nil, fmt.Errorf("%w: more than %d pkgname sections", ErrLimit, lim.MaxPackages)
			}
			s.Packages = append(s.Packages, Section{Name: f.value})
			cur = &s.Packages[len(s.Packages)-1]
		default:
			if cur == nil {
				return nil, fmt.Errorf("%w: %q appears before any pkgbase", ErrFormat, f.key)
			}
			cur.add(f.key, f.value)
		}
	}
	if s.PkgBase == "" {
		return nil, fmt.Errorf("%w: no pkgbase; there is no key to file this recipe under", ErrFormat)
	}
	return s, nil
}

// SRCINFOFromFile reads a .SRCINFO under root, confined and refusing a symlink
// leaf unresolved: the file came out of an AUR clone.
func SRCINFOFromFile(root *os.Root, rel string, lim Limits) (*SRCINFO, error) {
	lim = lim.withDefaults()
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > lim.MaxFileBytes {
		return nil, fmt.Errorf("%w: %s is %d bytes", ErrLimit, rel, st.Size)
	}
	return ParseSRCINFO(f, lim)
}

// PkgNames returns the pkgnames this base builds, in file order.
func (s *SRCINFO) PkgNames() []string {
	out := make([]string, 0, len(s.Packages))
	for _, p := range s.Packages {
		out = append(out, p.Name)
	}
	return out
}

// IsSplit reports whether this base builds more than one package.
//
// This is the recipe-side definition of splitness, and it is the same definition
// as the roadmap's number: a base that ships more than one package in the
// repositories. It is NOT the local-database definition (%BASE% != %NAME%),
// which reports 237 for the reference system's 432 -- see TestSRCINFOSplitPackage
// for all four measurements and the trap between them.
func (s *SRCINFO) IsSplit() bool { return len(s.Packages) > 1 }

// Package returns one pkgname's section.
func (s *SRCINFO) Package(name string) (Section, bool) {
	for _, p := range s.Packages {
		if p.Name == name {
			return p, true
		}
	}
	return Section{}, false
}

// Gaps reports what this reader could not account for, as coverage gaps for
// subject (a pkgbase).
func (s *SRCINFO) Gaps(subject string) []finding.Gap {
	if len(s.Unparsed) == 0 {
		return nil
	}
	sample := strings.Join(s.Unparsed, "; ")
	if len(sample) > 400 {
		sample = sample[:400] + "..."
	}
	return []finding.Gap{{
		RuleID:  RuleSRCINFO,
		Subject: subject,
		Reason: fmt.Sprintf("%d line(s) of .SRCINFO were neither a comment nor a key = value pair and were "+
			"not interpreted, so the declared sources and dependencies may be incomplete: %s",
			len(s.Unparsed), sample),
	}}
}

// Sources returns every declared source, from the pkgbase section and from each
// package section, including arch-suffixed arrays.
//
// Order is: pkgbase section first (in file order), then each package section.
func (s *SRCINFO) Sources() []Source {
	var out []Source
	collect := func(sec Section, pkg string) {
		for _, key := range sec.Keys {
			arch, ok := archSuffix(key, "source")
			if !ok {
				continue
			}
			for _, v := range sec.Fields[key] {
				out = append(out, parseSource(v, arch, pkg))
			}
		}
	}
	collect(s.Global, "")
	for _, p := range s.Packages {
		collect(p, p.Name)
	}
	return out
}

// Deps returns every declared dependency of the given kinds, or of all kinds
// when none are given -- the closure review wants the union and must not have
// to enumerate the kinds itself and risk missing one.
func (s *SRCINFO) Deps(kinds ...DepKind) []Dep {
	if len(kinds) == 0 {
		kinds = allDepKinds
	}
	var out []Dep
	collect := func(sec Section, pkg string) {
		for _, key := range sec.Keys {
			for _, kind := range kinds {
				arch, ok := archSuffix(key, string(kind))
				if !ok {
					continue
				}
				for _, v := range sec.Fields[key] {
					out = append(out, parseDep(v, kind, arch, pkg))
				}
			}
		}
	}
	collect(s.Global, "")
	for _, p := range s.Packages {
		collect(p, p.Name)
	}
	return out
}

// archSuffix matches key against base and base_<arch>, returning the
// architecture ("" for the unsuffixed form).
//
// The suffix is not validated against a list of architectures on purpose: a new
// one (loong64, riscv64) must not read as "no sources declared", which is the
// silent failure this project treats as worse than a false positive.
func archSuffix(key, base string) (arch string, ok bool) {
	if key == base {
		return "", true
	}
	rest, ok := strings.CutPrefix(key, base+"_")
	if !ok || rest == "" {
		return "", false
	}
	return rest, true
}

// vcsSchemes are makepkg's VCS source prefixes.
var vcsSchemes = []string{"git", "hg", "svn", "bzr", "fossil"}

// parseSource splits one source value without resolving or fetching anything.
func parseSource(raw, arch, pkg string) Source {
	src := Source{Raw: raw, Arch: arch, Package: pkg}
	loc := raw
	// makepkg's rename syntax is name::location, and only the FIRST "::"
	// separates them -- a URL may legitimately contain another.
	if name, rest, ok := strings.Cut(raw, "::"); ok {
		src.Name = name
		loc = rest
	}
	for _, vcs := range vcsSchemes {
		if rest, ok := strings.CutPrefix(loc, vcs+"+"); ok {
			src.IsVCS = true
			src.VCS = vcs
			loc = rest
			break
		}
	}
	if src.IsVCS {
		// The fragment pins the revision, and only a VCS source has one. A '#'
		// in a plain URL is a URL fragment and is left in place.
		if before, frag, ok := strings.Cut(loc, "#"); ok {
			loc = before
			src.Fragment = frag
		}
	}
	src.Location = loc
	src.IsRemote = hasURLScheme(loc)
	return src
}

// hasURLScheme reports whether loc starts with "scheme://", or is one of the
// scp-like or protocol-relative forms makepkg accepts. It parses the shape and
// never resolves anything.
func hasURLScheme(loc string) bool {
	i := strings.Index(loc, "://")
	if i <= 0 {
		return false
	}
	for j := 0; j < i; j++ {
		c := loc[j]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c >= '0' && c <= '9', c == '+', c == '-', c == '.':
		default:
			return false
		}
	}
	return true
}

// parseDep splits a dependency value into name, constraint and description.
//
// The description split comes first because an optdepends description can
// contain any character at all, including '>' and '=': "docker: use >= 20.10"
// would otherwise contribute a constraint that the recipe never declared.
func parseDep(raw string, kind DepKind, arch, pkg string) Dep {
	d := Dep{Raw: raw, Kind: kind, Arch: arch, Package: pkg}
	rest := raw
	if kind == DepOpt {
		if name, desc, ok := strings.Cut(raw, ":"); ok {
			rest = name
			d.Description = strings.TrimSpace(desc)
		}
	}
	// Constraint operators, longest first so ">=" is not read as ">".
	for _, op := range []string{">=", "<=", "=", ">", "<"} {
		if i := strings.Index(rest, op); i > 0 {
			d.Name = strings.TrimSpace(rest[:i])
			d.Constraint = strings.TrimSpace(rest[i:])
			return d
		}
	}
	d.Name = strings.TrimSpace(rest)
	return d
}
