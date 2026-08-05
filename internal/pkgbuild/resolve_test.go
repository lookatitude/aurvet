// internal/pkgbuild/resolve_test.go
package pkgbuild

import (
	"fmt"
	"os"
	"strings"
	"testing"
)

func resolveFixture(t *testing.T, name string, cfg ResolveConfig) Resolution {
	t.Helper()
	return Resolve(Lex(fixture(t, name)), cfg)
}

func srcURLs(r Resolution) []string {
	var out []string
	for _, s := range r.Sources {
		if s.Value.Status == Resolved {
			out = append(out, s.Arch+"|"+s.Value.Text)
		} else {
			out = append(out, s.Arch+"|UNRESOLVABLE")
		}
	}
	return out
}

// The 29% blind spot, resolved. rustdesk-bin has no unsuffixed source= at all:
// a scanner that reads only `source` sees this package fetch nothing.
func TestResolveArchSuffixedSources(t *testing.T) {
	r := resolveFixture(t, "rustdesk-bin.pkgbuild", ResolveConfig{})
	if len(r.Sources) != 2 {
		t.Fatalf("sources = %v, want 2 (x86_64 and aarch64)", srcURLs(r))
	}
	want := map[string]string{
		"x86_64":  "rustdesk-1.4.9-1-x86_64.pkg.tar.zst::https://github.com/rustdesk/rustdesk/releases/download/1.4.9/rustdesk-1.4.9-0-x86_64.pkg.tar.zst",
		"aarch64": "rustdesk-1.4.9-1-aarch64.rpm::https://github.com/rustdesk/rustdesk/releases/download/1.4.9/rustdesk-1.4.9-0.aarch64.rpm",
	}
	for _, s := range r.Sources {
		if s.Value.Status != Resolved {
			t.Fatalf("source %s unresolvable: %s", s.Arch, s.Value.Reason)
		}
		if s.Value.Text != want[s.Arch] {
			t.Fatalf("source %s =\n  %q\nwant\n  %q", s.Arch, s.Value.Text, want[s.Arch])
		}
		if s.Host != "github.com" {
			t.Fatalf("source %s host = %q", s.Arch, s.Host)
		}
		if len(s.Integrity) != 1 || s.Integrity[0].Algo != "sha256" {
			t.Fatalf("source %s integrity = %+v", s.Arch, s.Integrity)
		}
	}
	if fmt.Sprint(r.Targets) != fmt.Sprint([]string{"x86_64", "aarch64"}) {
		t.Fatalf("targets = %v, want both declared arches", r.Targets)
	}
}

// The architecture is a parameter, not runtime.GOARCH (INV-4): reviewing an
// aarch64-only payload from an x86_64 host is the whole point.
func TestResolveArchIsAParameter(t *testing.T) {
	r := resolveFixture(t, "rustdesk-bin.pkgbuild", ResolveConfig{Arches: []string{"aarch64"}})
	if len(r.Sources) != 1 || r.Sources[0].Arch != "aarch64" {
		t.Fatalf("sources = %v, want only aarch64", srcURLs(r))
	}
	if !strings.Contains(r.Sources[0].Value.Text, "aarch64.rpm") {
		t.Fatalf("aarch64 source = %q", r.Sources[0].Value.Text)
	}
	// And an architecture the recipe never declares yields no sources rather
	// than the host's.
	r = resolveFixture(t, "rustdesk-bin.pkgbuild", ResolveConfig{Arches: []string{"riscv64"}})
	if len(r.Sources) != 0 {
		t.Fatalf("riscv64 sources = %v, want none", srcURLs(r))
	}
}

// dart-sdk-dev is the corpus's only strict ${var//x/y} inside a source URL.
func TestResolveSubstitutionInSourceURL(t *testing.T) {
	r := resolveFixture(t, "dart-sdk-dev.pkgbuild", ResolveConfig{})
	if len(r.Sources) != 1 {
		t.Fatalf("sources = %v", srcURLs(r))
	}
	s := r.Sources[0]
	if s.Value.Status != Resolved {
		t.Fatalf("unresolvable: %s", s.Value.Reason)
	}
	if s.Name != "dartsdk-linux-x64-release-3.12.0_203.0.dev.zip" {
		t.Fatalf("rename target = %q", s.Name)
	}
	wantURL := "https://storage.googleapis.com/dart-archive/channels/dev/release/3.12.0-203.0.dev/sdk/dartsdk-linux-x64-release.zip"
	if s.URL != wantURL {
		t.Fatalf("url = %q, want %q", s.URL, wantURL)
	}
}

// Never a partially expanded string presented as resolved: "https:///x.tar.gz"
// is a URL that looks analysable and is not.
func TestUnknownVariableIsUnresolvableNotPartial(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=x\nsource=(\"https://${_host}/x.tar.gz\")\n")), ResolveConfig{})
	if len(r.Sources) != 1 {
		t.Fatalf("sources = %v", srcURLs(r))
	}
	s := r.Sources[0]
	if s.Value.Status != Unresolvable {
		t.Fatalf("status = %v, want Unresolvable", s.Value.Status)
	}
	if s.Value.Text != "" {
		t.Fatalf("unresolvable value carries text %q; a half-expanded URL must never be emitted", s.Value.Text)
	}
	if s.URL != "" || s.Host != "" {
		t.Fatalf("unresolvable source has url=%q host=%q", s.URL, s.Host)
	}
	if !strings.Contains(s.Value.Reason, "_host") {
		t.Fatalf("reason does not name the variable: %q", s.Value.Reason)
	}
	if len(r.Unresolved) != 1 {
		t.Fatalf("Unresolved = %+v, want 1", r.Unresolved)
	}
}

// INV-4: pure function of its input. The recipe's $HOME is not the process's.
func TestResolveReadsNoProcessEnvironment(t *testing.T) {
	t.Setenv("_aurvet_probe", "leaked")
	t.Setenv("HOME", "/home/leaked")
	r := Resolve(Lex([]byte("pkgname=x\nsource=(\"$HOME/$_aurvet_probe/x.tar.gz\")\n")), ResolveConfig{})
	s := r.Sources[0]
	if s.Value.Status != Unresolvable {
		t.Fatalf("process environment leaked into resolution: %+v", s.Value)
	}
	if strings.Contains(s.Value.Text, "leaked") {
		t.Fatalf("value carries process env: %q", s.Value.Text)
	}
}

func TestCommandSubstitutionIsUnresolvable(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=x\npkgver=$(date +%s)\nsource=(\"https://x.example/$pkgver.tar.gz\")\n")), ResolveConfig{})
	s := r.Sources[0]
	if s.Value.Status != Unresolvable {
		t.Fatalf("a command substitution resolved to %q", s.Value.Text)
	}
	if !strings.Contains(s.Value.Reason, "command substitution") {
		t.Fatalf("reason = %q", s.Value.Reason)
	}
}

// For a -git package the recipe is stable while pkgver is computed at build
// time, so a URL built from pkgver is not knowable from the text.
func TestPkgverFunctionMakesPkgverDynamic(t *testing.T) {
	src := []byte("pkgname=x-git\npkgver=r1.abc\nsource=(\"https://x.example/v$pkgver.tar.gz\")\n" +
		"pkgver() {\n  git describe --tags\n}\n")
	r := Resolve(Lex(src), ResolveConfig{})
	if !r.PkgverDynamic {
		t.Fatal("pkgver() present but PkgverDynamic false")
	}
	if r.Sources[0].Value.Status != Unresolvable {
		t.Fatalf("value built from a computed pkgver resolved to %q", r.Sources[0].Value.Text)
	}
}

func TestVCSSourceParsing(t *testing.T) {
	src := []byte("pkgname=x\nsource=(\"x::git+https://github.com/a/b.git#tag=v1.2\" 'y::hg+https://h.example/r' 'git://old.example/z')\n" +
		"sha256sums=('SKIP' 'SKIP' 'SKIP')\n")
	r := Resolve(Lex(src), ResolveConfig{})
	if len(r.Sources) != 3 {
		t.Fatalf("sources = %v", srcURLs(r))
	}
	got := make([]string, 0, 3)
	for _, s := range r.Sources {
		got = append(got, fmt.Sprintf("%s|%s|%s|%s|%v", s.Name, s.VCS, s.Host, s.Fragment, s.Integrity[0].Skip))
	}
	want := []string{
		"x|git|github.com|tag=v1.2|true",
		"y|hg|h.example||true",
		"z|git|old.example||true",
	}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("parsed sources =\n  %v\nwant\n  %v", got, want)
	}
}

func TestLocalFileSourceHasNoURL(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=x\nsource=('x.install' 'patch-1.diff')\nmd5sums=('d41d8cd98f00b204e9800998ecf8427e' 'SKIP')\n")), ResolveConfig{})
	if len(r.Sources) != 2 {
		t.Fatalf("sources = %v", srcURLs(r))
	}
	for i, s := range r.Sources {
		if !s.Local || s.URL != "" || s.Host != "" {
			t.Fatalf("source %d = %+v, want a local file", i, s)
		}
	}
	if r.Sources[0].Integrity[0].Algo != "md5" || r.Sources[0].Integrity[0].Skip {
		t.Fatalf("integrity = %+v", r.Sources[0].Integrity)
	}
	if !r.Sources[1].Integrity[0].Skip {
		t.Fatalf("SKIP not recognised: %+v", r.Sources[1].Integrity)
	}
}

func TestIntegrityPairingIsPositional(t *testing.T) {
	src := []byte("pkgname=x\nsource=('a' 'b')\nsha256sums=('aa' 'bb')\nb2sums=('cc' 'dd')\n")
	r := Resolve(Lex(src), ResolveConfig{})
	for i, want := range [][2]string{{"aa", "cc"}, {"bb", "dd"}} {
		s := r.Sources[i]
		if len(s.Integrity) != 2 {
			t.Fatalf("source %d integrity = %+v", i, s.Integrity)
		}
		got := map[string]string{}
		for _, in := range s.Integrity {
			got[in.Algo] = in.Value.Text
		}
		if got["sha256"] != want[0] || got["b2"] != want[1] {
			t.Fatalf("source %d integrity = %v, want %v", i, got, want)
		}
	}
}

// A sums array shorter than its source array leaves entries with no integrity
// at all -- reported as absent, never as passing.
func TestShortIntegrityArrayLeavesEntriesUncovered(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=x\nsource=('a' 'b')\nsha256sums=('aa')\n")), ResolveConfig{})
	if len(r.Sources[0].Integrity) != 1 {
		t.Fatalf("source 0 integrity = %+v", r.Sources[0].Integrity)
	}
	if len(r.Sources[1].Integrity) != 0 {
		t.Fatalf("source 1 invented an integrity entry: %+v", r.Sources[1].Integrity)
	}
}

func TestAppendedSourceArray(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=x\nsource=('a')\nsource+=('b')\nsource_x86_64=('c')\narch=('x86_64')\n")), ResolveConfig{})
	if got := srcURLs(r); fmt.Sprint(got) != fmt.Sprint([]string{"|a", "|b", "x86_64|c"}) {
		t.Fatalf("sources = %v", got)
	}
}

func TestArrayExpansionJoinAndIndex(t *testing.T) {
	src := []byte("_p=(alpha beta)\npkgname=(\"${_p[@]}\")\nx=\"${_p[1]}\"\ny=\"${_p[9]}\"\n")
	r := Resolve(Lex(src), ResolveConfig{})
	if v := r.Vars["x"].Values[0]; v.Status != Resolved || v.Text != "beta" {
		t.Fatalf("x = %+v, want beta", v)
	}
	if v := r.Vars["y"].Values[0]; v.Status != Unresolvable {
		t.Fatalf("y = %+v, want Unresolvable (index out of range)", v)
	}
	if v := r.Vars["pkgname"].Values[0]; v.Status != Resolved || v.Text != "alpha beta" {
		t.Fatalf("pkgname = %+v", v)
	}
}

func TestParameterExpansionOperators(t *testing.T) {
	src := []byte(strings.Join([]string{
		"v=1.2.3-4",
		"a=\"${v//./_}\"",    // global literal substitution
		"b=\"${v/-/.}\"",     // first-match substitution
		"c=\"${v%%-*}\"",     // longest suffix strip, glob
		"d=\"${v#*.}\"",      // shortest prefix strip, glob
		"e=\"${v##*.}\"",     // longest prefix strip
		"f=\"${undef:-fb}\"", // default when unset
		"g=\"${v^^}\"",       // upper-case
		"h=\"${#v}\"",        // length: not computed
		"i=\"${!v}\"",        // indirect: not resolvable
		"j=\"${v:2:3}\"",     // substring
		"k=\"${v::3}\"",      // substring, offset omitted (hyprshade's PyPI URL)
		"",
	}, "\n"))
	r := Resolve(Lex([]byte(src)), ResolveConfig{})
	want := map[string]string{
		"a": "1_2_3-4", "b": "1.2.3.4", "c": "1.2.3", "d": "2.3-4",
		"e": "3-4", "f": "fb", "g": "1.2.3-4", "j": "2.3", "k": "1.2",
	}
	for k, w := range want {
		v := r.Vars[k].Values[0]
		if v.Status != Resolved || v.Text != w {
			t.Fatalf("%s = %+v, want %q", k, v, w)
		}
	}
	for _, k := range []string{"h", "i"} {
		if v := r.Vars[k].Values[0]; v.Status != Unresolvable {
			t.Fatalf("%s = %+v, want Unresolvable", k, v)
		}
	}
}

// CARCH is set by makepkg to the architecture being built for, so it is bound
// to the target under analysis rather than to the host.
func TestCARCHIsBoundToTheTargetArchitecture(t *testing.T) {
	src := []byte("pkgname=x\narch=('x86_64' 'aarch64')\nsource_x86_64=(\"https://x.example/$CARCH.tar.gz\")\nsource_aarch64=(\"https://x.example/$CARCH.tar.gz\")\n")
	r := Resolve(Lex(src), ResolveConfig{})
	got := map[string]string{}
	for _, s := range r.Sources {
		got[s.Arch] = s.Value.Text
	}
	if got["x86_64"] != "https://x.example/x86_64.tar.gz" || got["aarch64"] != "https://x.example/aarch64.tar.gz" {
		t.Fatalf("CARCH-built sources = %v", got)
	}
}

// An arch-independent source must be emitted once, not once per architecture:
// duplicating it would double-count every finding against it.
func TestArchIndependentSourceEmittedOnce(t *testing.T) {
	src := []byte("pkgname=x\narch=('x86_64' 'aarch64')\nsource=('common.patch')\nsource_x86_64=('a')\nsource_aarch64=('b')\n")
	r := Resolve(Lex(src), ResolveConfig{})
	var common int
	for _, s := range r.Sources {
		if s.Arch == "" {
			common++
		}
	}
	if common != 1 || len(r.Sources) != 3 {
		t.Fatalf("sources = %v, want one common plus two arch-specific", srcURLs(r))
	}
}

func TestPkgbaseAndPkgnames(t *testing.T) {
	r := resolveFixture(t, "flutter-eval-excerpt.pkgbuild", ResolveConfig{})
	if r.Pkgbase != "flutter" {
		t.Fatalf("pkgbase = %q", r.Pkgbase)
	}
	if len(r.Pkgnames) != 17 {
		t.Fatalf("pkgnames = %d, want 17", len(r.Pkgnames))
	}
	if r.Pkgnames[0].Status != Resolved || r.Pkgnames[0].Text != "flutter" {
		t.Fatalf("pkgnames[0] = %+v", r.Pkgnames[0])
	}
	if r.Pkgnames[1].Text != "flutter-common" {
		t.Fatalf("pkgnames[1] = %+v", r.Pkgnames[1])
	}
}

func TestPkgbaseFallsBackToFirstPkgname(t *testing.T) {
	r := Resolve(Lex([]byte("pkgname=(a b)\n")), ResolveConfig{})
	if r.Pkgbase != "a" {
		t.Fatalf("pkgbase = %q, want a", r.Pkgbase)
	}
}

// Bounds again: resolution must not become a way to make the tool spin.
func TestResolveBoundsOversizedValues(t *testing.T) {
	long := strings.Repeat("a.", 200000)
	src := []byte("pkgname=x\nv=" + long + "\nw=\"${v//./_}\"\nsource=(\"https://x.example/$w\")\n")
	done := make(chan Resolution, 1)
	go func() {
		defer func() {
			if p := recover(); p != nil {
				t.Errorf("panic: %v", p)
				done <- Resolution{}
			}
		}()
		done <- Resolve(Lex(src), ResolveConfig{})
	}()
	r := <-done
	if r.Sources[0].Value.Status != Unresolvable {
		t.Fatalf("an oversized value was resolved; bound not enforced")
	}
}

func TestResolveEmptyFile(t *testing.T) {
	r := Resolve(Lex(nil), ResolveConfig{})
	if len(r.Sources) != 0 || len(r.Unresolved) != 0 || r.Pkgbase != "" {
		t.Fatalf("empty resolution = %+v", r)
	}
}

// TestLiveCorpusParameterExpansion measures parameter expansion in the real
// corpus, counted by the tokeniser rather than by a regex, because the roadmap's
// "7 of 34" is definition-sensitive and could not be reproduced. Four
// definitions are reported so that any future claim can name the one it means:
//
//	strict-substitution  a ${v//x/y} anywhere in the file
//	any-modifier         a ${v OP ...} with any operator, anywhere
//	source-modifier      a ${v OP ...} inside a source array
//	source-any-expansion any ${v} at all inside a source array
//
// Gated; see TestLiveCorpusLex.
func TestLiveCorpusParameterExpansion(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGBUILD") != "1" {
		t.Skip("set AURVET_LIVE_PKGBUILD=1 to measure against the live helper cache")
	}
	counts := map[string]int{}
	for _, p := range livePKGBUILDs(t) {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f := Lex(src)
		var strict, anyMod, srcMod, srcAny bool
		walk := func(w Word, inSource bool) {
			for _, s := range w.Segs {
				if s.Kind != SegVar {
					continue
				}
				if inSource {
					srcAny = true
				}
				if s.Op == "" {
					continue
				}
				anyMod = true
				if s.Op == "//" {
					strict = true
				}
				if inSource {
					srcMod = true
				}
			}
		}
		for _, a := range f.Assignments {
			inSource := a.Base == "source"
			for _, w := range a.Values {
				walk(w, inSource)
			}
		}
		for _, c := range f.Commands {
			for _, w := range c.Words {
				walk(w, false)
			}
		}
		for name, hit := range map[string]bool{
			"strict-substitution":  strict,
			"any-modifier":         anyMod,
			"source-modifier":      srcMod,
			"source-any-expansion": srcAny,
		} {
			if hit {
				counts[name]++
			}
		}
	}
	for _, k := range []string{"strict-substitution", "any-modifier", "source-modifier", "source-any-expansion"} {
		t.Logf("%-22s %d of 34", k, counts[k])
	}
}

// TestLiveCorpusResolve reports how much of the real corpus resolves. Gated:
// see TestLiveCorpusLex.
func TestLiveCorpusResolve(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGBUILD") != "1" {
		t.Skip("set AURVET_LIVE_PKGBUILD=1 to measure against the live helper cache")
	}
	var (
		files, sources, resolved, unresolvable int
		reasons                                = map[string]int{}
		withUnresolvable                       int
		// noSources is the load-bearing number for arch-suffix handling: with
		// source_x86_64 / source_aarch64 unhandled, 10 of the 34 recipes have no
		// sources at all and the tool reviews nothing while reporting complete.
		noSources int
	)
	for _, p := range livePKGBUILDs(t) {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		r := Resolve(Lex(src), ResolveConfig{})
		files++
		if len(r.Sources) == 0 {
			noSources++
			t.Logf("%-44s NO SOURCES RESOLVED", pkgOf(p))
		}
		bad := 0
		for _, s := range r.Sources {
			sources++
			if s.Value.Status == Resolved {
				resolved++
			} else {
				unresolvable++
				bad++
				reasons[reasonClass(s.Value.Reason)]++
			}
		}
		if bad > 0 {
			withUnresolvable++
			t.Logf("%-44s %d/%d source entries unresolvable", pkgOf(p), bad, len(r.Sources))
		}
	}
	t.Logf("corpus=%d source-entries=%d resolved=%d unresolvable=%d recipes-with-unresolvable=%d recipes-with-no-sources=%d",
		files, sources, resolved, unresolvable, withUnresolvable, noSources)
	for k, n := range reasons {
		t.Logf("unresolvable because %-40s %d", k, n)
	}
}
