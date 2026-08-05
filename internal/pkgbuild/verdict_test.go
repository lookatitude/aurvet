// internal/pkgbuild/verdict_test.go
package pkgbuild

import (
	"os"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
)

func assessFixture(t *testing.T, name string, cfg ResolveConfig) Verdict {
	t.Helper()
	f := Lex(fixture(t, name))
	return Assess(name, f, Resolve(f, cfg))
}

func gapReasons(v Verdict) string {
	var b strings.Builder
	for _, g := range v.Gaps {
		b.WriteString(g.RuleID + ": " + g.Reason + "\n")
	}
	return b.String()
}

// The ordinary corpus must not gap. A tool that reports "could not analyse" for
// a normal recipe teaches its user that the verdict means nothing.
func TestOrdinaryRecipesAreCompletelyAnalysed(t *testing.T) {
	for _, name := range []string{"gdm-settings.pkgbuild", "dart-sdk-dev.pkgbuild", "rustdesk-bin.pkgbuild"} {
		v := assessFixture(t, name, ResolveConfig{})
		if !v.Complete() {
			t.Fatalf("%s reported coverage gaps:\n%s", name, gapReasons(v))
		}
		// INV-6: a clean verdict still states what it cannot prove.
		if len(v.Limits) == 0 {
			t.Fatalf("%s: a complete verdict with no stated limits", name)
		}
	}
}

// INV-9 made concrete, on the recipe that motivated it. eval is in 3 of 34
// legitimate recipes, so it is a coverage gap -- never a critical, and never
// silence.
func TestEvalIsAGapNeverACriticalAndNeverSilence(t *testing.T) {
	v := assessFixture(t, "flutter-eval-excerpt.pkgbuild", ResolveConfig{})
	if v.Complete() {
		t.Fatal("a recipe that generates its package functions with eval reported complete coverage")
	}
	if !strings.Contains(gapReasons(v), "eval") {
		t.Fatalf("no gap mentions eval:\n%s", gapReasons(v))
	}
	// Rendered into a Result, the verdict must read as incomplete-but-not-severe:
	// exit 3 territory (INV-3), not exit 1.
	res := finding.Result{Gaps: v.Gaps}
	if res.Complete() {
		t.Fatal("Result.Complete() true despite gaps")
	}
	if res.MaxSeverity() != finding.SevInfo {
		t.Fatalf("MaxSeverity = %v; an unresolvable recipe must not manufacture severity", res.MaxSeverity())
	}
	for _, g := range v.Gaps {
		if g.Subject == "" || g.RuleID == "" || g.Reason == "" {
			t.Fatalf("gap is not actionable: %+v", g)
		}
	}
}

// 31% of installed packages are split, and zero cached PKGBUILDs contain a
// literal package_*() -- because the functions are generated. A verdict that
// treats generated structure as ABSENT would report those recipes clean.
func TestGeneratedPackageFunctionsAreAGap(t *testing.T) {
	v := assessFixture(t, "flutter-eval-excerpt.pkgbuild", ResolveConfig{})
	var found bool
	for _, g := range v.Gaps {
		if strings.Contains(g.Reason, "package function") {
			found = true
			if !strings.Contains(g.Reason, "flutter-common") {
				t.Fatalf("gap does not name a package whose function is missing: %q", g.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("split package with generated functions produced no gap:\n%s", gapReasons(v))
	}
}

// ... and a split package that DOES define its functions in the text is fully
// analysed. This is the false-positive half of the same rule.
func TestSplitPackageWithLiteralFunctionsIsComplete(t *testing.T) {
	src := []byte("pkgbase=x\npkgname=(x-a x-b)\npkgver=1\narch=(any)\nsource=('f.tar.gz')\nsha256sums=('aa')\n" +
		"package_x-a() {\n  install -d \"$pkgdir/usr\"\n}\npackage_x-b() {\n  install -d \"$pkgdir/usr\"\n}\n")
	f := Lex(src)
	v := Assess("x", f, Resolve(f, ResolveConfig{}))
	if !v.Complete() {
		t.Fatalf("a split package defining both package functions gapped:\n%s", gapReasons(v))
	}
}

// A single-package recipe uses package(), not package_name().
func TestSinglePackageFunctionIsComplete(t *testing.T) {
	src := []byte("pkgname=x\npkgver=1\narch=(any)\nsource=('f.tar.gz')\nsha256sums=('aa')\npackage() {\n  true\n}\n")
	f := Lex(src)
	if v := Assess("x", f, Resolve(f, ResolveConfig{})); !v.Complete() {
		t.Fatalf("single package gapped:\n%s", gapReasons(v))
	}
}

func TestUnresolvableSourceIsAGap(t *testing.T) {
	f := Lex([]byte("pkgname=x\npkgver=1\nsource=(\"https://${_mirror}/x-$pkgver.tar.gz\")\npackage() {\n true\n}\n"))
	v := Assess("x", f, Resolve(f, ResolveConfig{}))
	if v.Complete() {
		t.Fatal("an unresolvable source URL reported complete coverage")
	}
	reasons := gapReasons(v)
	if !strings.Contains(reasons, "_mirror") || !strings.Contains(reasons, "source") {
		t.Fatalf("gap does not say which source or why:\n%s", reasons)
	}
}

// Restricting the analysed architectures is legitimate, but the architectures
// left out are coverage that was not obtained, and saying so is the difference
// between a scoped review and a false clean.
func TestDeclaredButUnanalysedArchitectureIsAGap(t *testing.T) {
	v := assessFixture(t, "rustdesk-bin.pkgbuild", ResolveConfig{Arches: []string{"x86_64"}})
	if v.Complete() {
		t.Fatal("analysing only x86_64 of an x86_64+aarch64 recipe reported complete coverage")
	}
	if !strings.Contains(gapReasons(v), "aarch64") {
		t.Fatalf("gap does not name the unanalysed architecture:\n%s", gapReasons(v))
	}
}

func TestExternalSourceBuiltinIsAGap(t *testing.T) {
	f := Lex([]byte("pkgname=x\nsource=('a')\nbuild() {\n  source /usr/share/nvm/init-nvm.sh\n  make\n}\n"))
	v := Assess("x", f, Resolve(f, ResolveConfig{}))
	if v.Complete() {
		t.Fatal("a recipe sourcing an external file reported complete coverage")
	}
	if !strings.Contains(gapReasons(v), "init-nvm.sh") {
		t.Fatalf("gap does not name the sourced file:\n%s", gapReasons(v))
	}
}

func TestTruncatedInputIsAGap(t *testing.T) {
	src := append([]byte("pkgname=a\n"), []byte(strings.Repeat("x=1\n", 2<<20))...)
	f := Lex(src)
	v := Assess("a", f, Resolve(f, ResolveConfig{}))
	if v.Complete() {
		t.Fatal("a truncated recipe reported complete coverage")
	}
}

func TestUnterminatedQuoteIsAGap(t *testing.T) {
	f := Lex([]byte("pkgname=x\nsource=('unclosed\n"))
	v := Assess("x", f, Resolve(f, ResolveConfig{}))
	if v.Complete() {
		t.Fatalf("an unterminated quote reported complete coverage")
	}
}

// An empty or non-PKGBUILD file is not clean: it is unexamined.
func TestNothingToAnalyseIsAGap(t *testing.T) {
	for _, src := range []string{"", "\n\n# just a comment\n", "\x00\x00\x00"} {
		f := Lex([]byte(src))
		v := Assess("x", f, Resolve(f, ResolveConfig{}))
		if v.Complete() {
			t.Fatalf("input %q reported complete coverage", src)
		}
	}
}

// Gap output is bounded: a crafted recipe must not be able to turn one report
// into a hundred thousand lines, and the truncation itself must be visible.
func TestGapsAreBounded(t *testing.T) {
	var b strings.Builder
	b.WriteString("pkgname=x\n")
	for i := 0; i < 5000; i++ {
		b.WriteString("eval \"x=1\"\n")
	}
	f := Lex([]byte(b.String()))
	v := Assess("x", f, Resolve(f, ResolveConfig{}))
	if len(v.Gaps) > maxGaps {
		t.Fatalf("gaps = %d, want at most %d", len(v.Gaps), maxGaps)
	}
	if v.Complete() {
		t.Fatal("5000 evals reported complete coverage")
	}
}

// The verdict is a pure function of its input, so two runs must be identical --
// including order, which map iteration would randomise.
func TestVerdictIsDeterministic(t *testing.T) {
	f := Lex(fixture(t, "flutter-eval-excerpt.pkgbuild"))
	first := gapReasons(Assess("flutter", f, Resolve(f, ResolveConfig{})))
	for i := 0; i < 20; i++ {
		if got := gapReasons(Assess("flutter", f, Resolve(f, ResolveConfig{}))); got != first {
			t.Fatalf("verdict differs between runs:\n%s\n---\n%s", first, got)
		}
	}
}

func TestSubjectDefaultsToPkgbase(t *testing.T) {
	f := Lex([]byte("pkgbase=zzz\npkgname=(zzz)\neval 'x=1'\n"))
	v := Assess("", f, Resolve(f, ResolveConfig{}))
	if v.Subject != "zzz" {
		t.Fatalf("subject = %q, want zzz", v.Subject)
	}
	for _, g := range v.Gaps {
		if g.Subject != "zzz" {
			t.Fatalf("gap subject = %q", g.Subject)
		}
	}
}

// TestLiveCorpusVerdict is the number that matters for INV-9's calibration: how
// much of an honest corpus this phase admits it cannot fully analyse, and what
// defeated it. Gated; see TestLiveCorpusLex.
func TestLiveCorpusVerdict(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGBUILD") != "1" {
		t.Skip("set AURVET_LIVE_PKGBUILD=1 to measure against the live helper cache")
	}
	var (
		files, complete int
		byRule          = map[string]int{}
	)
	for _, p := range livePKGBUILDs(t) {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f := Lex(src)
		r := Resolve(f, ResolveConfig{})
		v := Assess(pkgOf(p), f, r)
		files++
		if v.Complete() {
			complete++
			continue
		}
		seen := map[string]bool{}
		for _, g := range v.Gaps {
			if !seen[g.RuleID] {
				seen[g.RuleID] = true
				byRule[g.RuleID]++
			}
		}
		var rules []string
		for _, g := range v.Gaps {
			rules = append(rules, g.RuleID)
		}
		t.Logf("%-44s gaps=%d %v", pkgOf(p), len(v.Gaps), rules)
	}
	t.Logf("corpus=%d fully-analysed=%d gapped=%d", files, complete, files-complete)
	for rule, n := range byRule {
		t.Logf("gap rule %-34s in %d recipes", rule, n)
	}
}
