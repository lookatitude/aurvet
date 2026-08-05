// internal/helper/detect_test.go
package helper

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/finding"
)

// fixtureRoot materializes a root-relative tree and opens it as an os.Root.
// Fixtures are built here rather than checked in for the reason
// testdata/helper/README.md states: the interesting inputs are directory
// SHAPES, and one of them (a cache directory that cannot be read) has to be
// created with a mode git cannot carry.
func fixtureRoot(t *testing.T, files map[string]string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		abs := filepath.Join(dir, rel)
		if strings.HasSuffix(rel, "/") {
			if err := os.MkdirAll(abs, 0o755); err != nil {
				t.Fatalf("mkdir %s: %v", rel, err)
			}
			continue
		}
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", filepath.Dir(rel), err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatalf("write %s: %v", rel, err)
		}
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

// cloneFiles returns the three files a real helper clone carries, so every
// layout fixture is built from the same shape.
func cloneFiles(dir string) map[string]string {
	return map[string]string{
		dir + "/PKGBUILD":               "pkgname=x\n",
		dir + "/.SRCINFO":               "pkgbase = x\n",
		dir + "/.git/HEAD":              "ref: refs/heads/master\n",
		dir + "/.git/objects/":          "",
		dir + "/.git/refs/heads/master": "0123456789abcdef0123456789abcdef01234567\n",
	}
}

func merge(ms ...map[string]string) map[string]string {
	out := map[string]string{}
	for _, m := range ms {
		for k, v := range m {
			out[k] = v
		}
	}
	return out
}

func gapReasons(d Detection, rule string) []string {
	var out []string
	for _, g := range d.Gaps {
		if g.RuleID == rule {
			out = append(out, g.Subject+": "+g.Reason)
		}
	}
	return out
}

func hasGap(d Detection, rule, subject string) bool {
	for _, g := range d.Gaps {
		if g.RuleID == rule && g.Subject == subject {
			return true
		}
	}
	return false
}

// --- the four layouts -----------------------------------------------------

// TestDetectsAllFourLayouts exercises every supported helper shape, not just
// the one installed on the development machine. yay keys clones directly off
// its cache directory; paru, pikaur and aurutils each interpose a differently
// named subdirectory, and a detector that had only ever seen yay would report
// three coverage gaps on a system that has full evidence.
func TestDetectsAllFourLayouts(t *testing.T) {
	cases := []struct {
		helper string
		dir    string
	}{
		{"yay", "home/u/.cache/yay"},
		{"paru", "home/u/.cache/paru/clone"},
		{"pikaur", "home/u/.cache/pikaur/aur_repos"},
		{"aurutils", "home/u/.cache/aurutils/sync"},
	}
	for _, tc := range cases {
		t.Run(tc.helper, func(t *testing.T) {
			root := fixtureRoot(t, cloneFiles(tc.dir+"/hello-git"))
			d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

			cache, ok := d.Cache(tc.helper)
			if !ok {
				t.Fatalf("helper %s not detected; caches=%v gaps=%v", tc.helper, d.Caches, d.Gaps)
			}
			if cache.Dir != tc.dir {
				t.Errorf("clones dir = %q, want %q", cache.Dir, tc.dir)
			}
			if len(cache.Clones) != 1 {
				t.Fatalf("clones = %d, want 1: %+v", len(cache.Clones), cache.Clones)
			}
			c := cache.Clones[0]
			if c.PkgBase != "hello-git" {
				t.Errorf("PkgBase = %q, want hello-git", c.PkgBase)
			}
			if !c.HasPKGBUILD || !c.HasSRCINFO || !c.HasGitDir {
				t.Errorf("clone markers = %+v, want all true", c)
			}
			if c.Dir != tc.dir+"/hello-git" {
				t.Errorf("clone dir = %q", c.Dir)
			}
		})
	}
}

// TestDetectKeysClonesOnPkgBase pins the keying rule. 432 of 1410 installed
// packages on the reference system have a pkgbase that ships more than one
// package, so a lookup keyed on a package name misses the clone that holds
// the recipe for it.
func TestDetectKeysClonesOnPkgBase(t *testing.T) {
	root := fixtureRoot(t, cloneFiles("home/u/.cache/yay/electron-base"))
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	if got := d.Clones("electron-base"); len(got) != 1 {
		t.Fatalf("Clones(pkgbase) = %+v, want 1 entry", got)
	}
	// A member package of that base is NOT a key into the cache.
	if got := d.Clones("electron-base-headers"); len(got) != 0 {
		t.Fatalf("Clones(pkgname) = %+v, want none: lookups must be pkgbase-keyed", got)
	}
}

// --- absent caches are coverage gaps, never silence -----------------------

// TestAbsentCacheIsCoverageGap is the load-bearing assertion of this file.
// "I found no helper cache" and "there is no evidence of AUR activity" are
// different statements and only the first is true (INV-9).
func TestAbsentCacheIsCoverageGap(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/u/.cache/": ""})
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	if len(d.Caches) != 0 {
		t.Fatalf("caches = %+v, want none", d.Caches)
	}
	if d.Covered() {
		t.Fatal("Covered() = true with no cache present")
	}
	if len(d.Gaps) == 0 {
		t.Fatal("no gaps for four absent caches: an absent cache must not be silence")
	}
	absent := gapReasons(d, RuleCacheAbsent)
	if len(absent) != len(DefaultLayouts()) {
		t.Errorf("absent gaps = %d, want one per layout (%d): %v",
			len(absent), len(DefaultLayouts()), absent)
	}
	// And one gap that states the consequence for the run as a whole.
	if !hasGap(d, RuleNoCache, subjectRun) {
		t.Errorf("no %s gap; gaps=%v", RuleNoCache, d.Gaps)
	}
	for _, g := range d.Gaps {
		if g.RuleID != RuleNoCache {
			continue
		}
		if !strings.Contains(g.Reason, "unavailable") {
			t.Errorf("run-level gap must say the evidence is unavailable, got %q", g.Reason)
		}
	}
}

// TestPresentCacheEmitsNoRunLevelGap is the other half: the run-level gap must
// not fire when a cache was found, or it degrades into noise that gets ignored.
func TestPresentCacheEmitsNoRunLevelGap(t *testing.T) {
	root := fixtureRoot(t, cloneFiles("home/u/.cache/yay/hello"))
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	if !d.Covered() {
		t.Fatal("Covered() = false with a yay cache present")
	}
	if hasGap(d, RuleNoCache, subjectRun) {
		t.Errorf("run-level gap fired with a cache present: %v", d.Gaps)
	}
	// The three absent helpers are still gaps: yay's clones say nothing about
	// what a paru user built.
	if got := len(gapReasons(d, RuleCacheAbsent)); got != len(DefaultLayouts())-1 {
		t.Errorf("absent gaps = %d, want %d", got, len(DefaultLayouts())-1)
	}
}

// TestUnreadableCacheIsDistinctFromAbsent — "not there" and "there and I could
// not read it" are different evidence states (INV-6) and a caller that cannot
// tell them apart cannot tell a fresh install from a permissions problem.
func TestUnreadableCacheIsDistinctFromAbsent(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0 does not deny access")
	}
	root := fixtureRoot(t, map[string]string{"home/u/.cache/yay/": ""})
	if err := os.Chmod(filepath.Join(rootName(t, root), "home/u/.cache/yay"), 0); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() {
		_ = os.Chmod(filepath.Join(rootName(t, root), "home/u/.cache/yay"), 0o755)
	})

	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})
	if !hasGap(d, RuleCacheUnreadable, "home/u/.cache/yay") {
		t.Fatalf("no %s gap for a mode-0 cache; gaps=%v", RuleCacheUnreadable, d.Gaps)
	}
	if hasGap(d, RuleCacheAbsent, "home/u/.cache/yay") {
		t.Errorf("unreadable cache reported as absent; gaps=%v", d.Gaps)
	}
}

// TestNoCacheDirsConfiguredIsAGap: a caller that resolved no home directories
// inspected nothing, which is not the same as finding nothing.
func TestNoCacheDirsConfiguredIsAGap(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/": ""})
	d := Detect(root, Config{})
	if !hasGap(d, RuleNoCacheDirs, subjectRun) {
		t.Fatalf("no %s gap with an empty Config; gaps=%v", RuleNoCacheDirs, d.Gaps)
	}
	if len(d.Caches) != 0 {
		t.Errorf("caches = %+v with no search dirs", d.Caches)
	}
}

// TestEmptyCacheDirectoryIsAGap: the directory exists (the helper ran) but
// holds no clone, so the evidence was cleaned. That is a third state again.
func TestEmptyCacheDirectoryIsAGap(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/u/.cache/yay/": ""})
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	if !hasGap(d, RuleCacheEmpty, "home/u/.cache/yay") {
		t.Fatalf("no %s gap for a present-but-empty cache; gaps=%v", RuleCacheEmpty, d.Gaps)
	}
	if !d.Covered() {
		t.Error("Covered() = false: the cache directory was found and read")
	}
}

// --- what is and is not a clone -------------------------------------------

// TestNonDirectoryEntriesAreNotClones: measured in ~/.cache/yay on the
// reference system, 36 entries are 34 clones plus completion.cache and
// vcs.json. Those two are yay's own state, not packages, and reporting them as
// clones with no recipe would be two false gaps on every yay system.
func TestNonDirectoryEntriesAreNotClones(t *testing.T) {
	root := fixtureRoot(t, merge(cloneFiles("home/u/.cache/yay/hello"), map[string]string{
		"home/u/.cache/yay/completion.cache": "hello\tAUR\n",
		"home/u/.cache/yay/vcs.json":         "{}\n",
	}))
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	cache, ok := d.Cache("yay")
	if !ok {
		t.Fatal("yay not detected")
	}
	if len(cache.Clones) != 1 || cache.Clones[0].PkgBase != "hello" {
		t.Fatalf("clones = %+v, want just hello", cache.Clones)
	}
	if len(d.Gaps) != len(DefaultLayouts())-1 {
		t.Errorf("gaps = %v; the two state files must not produce gaps", d.Gaps)
	}
}

// TestCloneWithoutRecipeIsRecordedAndGapped: a directory in the cache with no
// PKGBUILD is a clone whose recipe is gone. It is reported (so the caller can
// still read its git history) and gapped (so nobody reads the absence of rule
// hits as a clean recipe).
func TestCloneWithoutRecipeIsRecordedAndGapped(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/u/.cache/yay/hello/.git/HEAD": "ref: refs/heads/master\n"})
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	got := d.Clones("hello")
	if len(got) != 1 {
		t.Fatalf("Clones = %+v, want 1", got)
	}
	if got[0].HasPKGBUILD {
		t.Error("HasPKGBUILD = true with no PKGBUILD on disk")
	}
	if !hasGap(d, RuleCloneNoRecipe, "home/u/.cache/yay/hello") {
		t.Errorf("no %s gap; gaps=%v", RuleCloneNoRecipe, d.Gaps)
	}
}

// --- configuration, not hardcoding ----------------------------------------

// TestLayoutsAreConfigurable proves the layout table is data. A helper that
// changes its cache layout, or one this project has never heard of, is a
// configuration change and not a code change — the failure mode of a hardcoded
// list is a scanner that silently stops finding anything.
func TestLayoutsAreConfigurable(t *testing.T) {
	root := fixtureRoot(t, cloneFiles("home/u/.cache/newhelper/repos/hello"))

	if d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}}); len(d.Caches) != 0 {
		t.Fatalf("default layouts matched an unknown helper: %+v", d.Caches)
	}

	d := Detect(root, Config{
		CacheDirs: []string{"home/u/.cache"},
		Layouts:   []Layout{{Name: "newhelper", CacheRel: "newhelper", ClonesRel: "repos"}},
	})
	if _, ok := d.Cache("newhelper"); !ok {
		t.Fatalf("configured layout not detected: caches=%+v gaps=%v", d.Caches, d.Gaps)
	}
	if len(gapReasons(d, RuleCacheAbsent)) != 0 {
		t.Errorf("configured layouts replace the defaults, got absent gaps: %v", gapReasons(d, RuleCacheAbsent))
	}
}

// TestDefaultLayoutsCoverTheFourNamedHelpers guards the roadmap's list against
// a silent deletion.
func TestDefaultLayoutsCoverTheFourNamedHelpers(t *testing.T) {
	want := map[string]bool{"yay": false, "paru": false, "pikaur": false, "aurutils": false}
	for _, l := range DefaultLayouts() {
		if _, ok := want[l.Name]; !ok {
			t.Errorf("unexpected default layout %q", l.Name)
			continue
		}
		want[l.Name] = true
		if l.CacheRel == "" {
			t.Errorf("layout %q has no CacheRel", l.Name)
		}
	}
	for name, seen := range want {
		if !seen {
			t.Errorf("default layouts do not cover %q", name)
		}
	}
	// paru's clone/ layout specifically — the roadmap calls it out.
	for _, l := range DefaultLayouts() {
		if l.Name == "paru" && l.ClonesRel != "clone" {
			t.Errorf("paru ClonesRel = %q, want clone", l.ClonesRel)
		}
	}
}

// TestDefaultCacheDirsAreRootRelative: INV-4. A cache directory is derived
// from a home directory the caller resolved from the target's passwd, never
// from $HOME and never absolute, or --offline-root silently reads the live
// machine.
func TestDefaultCacheDirsAreRootRelative(t *testing.T) {
	for _, got := range DefaultCacheDirs([]string{"home/u", "/root", "root"}) {
		if filepath.IsAbs(got) {
			t.Errorf("DefaultCacheDirs returned absolute %q", got)
		}
	}
	got := DefaultCacheDirs([]string{"home/u"})
	if len(got) != 1 || got[0] != "home/u/.cache" {
		t.Errorf("DefaultCacheDirs = %v, want [home/u/.cache]", got)
	}
}

// --- hostile input --------------------------------------------------------

// TestDetectRefusesToLeaveTheRoot: a cache directory is under a user's home
// and is not a trusted path. A symlinked cache pointing out of the scanned
// tree must be a gap, not a read of the live filesystem.
func TestDetectRefusesToLeaveTheRoot(t *testing.T) {
	dir := t.TempDir()
	outside := filepath.Join(dir, "outside", "yay", "evil")
	if err := os.MkdirAll(outside, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(outside, "PKGBUILD"), []byte("x\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(dir, "root", "home", "u", ".cache"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Join(dir, "outside", "yay"),
		filepath.Join(dir, "root", "home", "u", ".cache", "yay")); err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot(filepath.Join(dir, "root"))
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})
	for _, c := range d.Caches {
		for _, cl := range c.Clones {
			if cl.PkgBase == "evil" {
				t.Fatalf("followed a symlink out of the root: %+v", cl)
			}
		}
	}
	if len(d.Gaps) == 0 {
		t.Fatal("escaping symlink produced no gap")
	}
}

// TestUnsafeCacheDirIsRefused: the search path itself is configuration, and a
// caller that composed it wrongly must get a refusal rather than a scan of
// something else.
func TestUnsafeCacheDirIsRefused(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/u/.cache/yay/": ""})
	for _, bad := range []string{"/home/u/.cache", "../etc", "home/../../etc", ""} {
		d := Detect(root, Config{CacheDirs: []string{bad}})
		if len(d.Caches) != 0 {
			t.Errorf("Detect(%q) returned caches %+v", bad, d.Caches)
		}
		if !hasGap(d, RuleCacheDirUnsafe, bad) {
			t.Errorf("Detect(%q): no %s gap; gaps=%v", bad, RuleCacheDirUnsafe, d.Gaps)
		}
	}
}

// TestClonesBoundedPerCache proves the entry cap fires and is reported rather
// than truncating silently.
func TestClonesBoundedPerCache(t *testing.T) {
	files := map[string]string{}
	for _, n := range []string{"a", "b", "c", "d"} {
		files["home/u/.cache/yay/"+n+"/PKGBUILD"] = "x\n"
	}
	root := fixtureRoot(t, files)
	d := Detect(root, Config{CacheDirs: []string{"home/u/.cache"}, Limits: Limits{MaxClones: 2}})

	cache, ok := d.Cache("yay")
	if !ok {
		t.Fatal("yay not detected")
	}
	if len(cache.Clones) != 2 {
		t.Errorf("clones = %d, want the cap of 2", len(cache.Clones))
	}
	if !hasGap(d, RuleCacheTruncated, "home/u/.cache/yay") {
		t.Errorf("cap fired without a gap; gaps=%v", d.Gaps)
	}
}

// TestDetectIsPure runs the same detection twice and requires identical
// results, and requires the ordering to be deterministic (INV-4).
func TestDetectIsPure(t *testing.T) {
	root := fixtureRoot(t, merge(
		cloneFiles("home/u/.cache/yay/b"),
		cloneFiles("home/u/.cache/yay/a"),
		cloneFiles("home/v/.cache/paru/clone/c"),
	))
	cfg := Config{CacheDirs: []string{"home/v/.cache", "home/u/.cache"}}
	first := Detect(root, cfg)
	second := Detect(root, cfg)

	if len(first.Caches) != 2 {
		t.Fatalf("caches = %+v, want 2", first.Caches)
	}
	if first.Caches[0].Helper != "paru" {
		t.Errorf("cache order follows Config.CacheDirs; got %q first", first.Caches[0].Helper)
	}
	yay, _ := first.Cache("yay")
	if len(yay.Clones) != 2 || yay.Clones[0].PkgBase != "a" {
		t.Errorf("clones are not name-sorted: %+v", yay.Clones)
	}
	if len(first.Gaps) != len(second.Gaps) || len(first.Caches) != len(second.Caches) {
		t.Errorf("Detect is not pure: %v vs %v", first, second)
	}
}

// TestDetectWritesNothing: INV-5. These are readers, and one of them runs
// under --offline-root against a mounted rescue target.
func TestDetectWritesNothing(t *testing.T) {
	root := fixtureRoot(t, cloneFiles("home/u/.cache/yay/hello"))
	base := rootName(t, root)
	before := treeSnapshot(t, base)

	Detect(root, Config{CacheDirs: []string{"home/u/.cache"}})

	if after := treeSnapshot(t, base); after != before {
		t.Errorf("Detect mutated the tree:\nbefore %s\nafter  %s", before, after)
	}
}

// TestGapsAreFindingGaps keeps the type contract with internal/report: gaps
// travel as finding.Gap so a caller cannot forget to merge them.
func TestGapsAreFindingGaps(t *testing.T) {
	root := fixtureRoot(t, map[string]string{"home/u/.cache/": ""})
	var gaps []finding.Gap = Detect(root, Config{CacheDirs: []string{"home/u/.cache"}}).Gaps
	if len(gaps) == 0 {
		t.Fatal("no gaps")
	}
	for _, g := range gaps {
		if g.RuleID == "" || g.Subject == "" || g.Reason == "" {
			t.Errorf("incomplete gap %+v", g)
		}
	}
}

// --- helpers --------------------------------------------------------------

// rootName recovers the filesystem path of an os.Root for the few tests that
// must chmod or walk it from outside.
func rootName(t *testing.T, root *os.Root) string {
	t.Helper()
	return root.Name()
}

func treeSnapshot(t *testing.T, base string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.WalkDir(base, func(p string, de fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		info, err := de.Info()
		if err != nil {
			return err
		}
		b.WriteString(p)
		b.WriteString(" ")
		b.WriteString(info.Mode().String())
		if !de.IsDir() {
			b.WriteString(" ")
			b.WriteString(info.ModTime().UTC().Format("20060102150405.000000000"))
		}
		b.WriteString("\n")
		return nil
	})
	if err != nil && !errors.Is(err, fs.ErrPermission) {
		t.Fatalf("walk: %v", err)
	}
	return b.String()
}

// --- live measurement -----------------------------------------------------

// TestLiveHelperCaches runs the detector against the machine the tests run on.
// Skipped by default: it reads / and a real home directory, which no unit test
// may depend on. AURVET_LIVE_HELPER=1 reproduces the numbers in the P2 receipt.
//
// The home directory is passed as a root-relative path (INV-4) rather than being
// read from the environment inside Detect: this test resolves it, Detect does
// not go looking.
func TestLiveHelperCaches(t *testing.T) {
	if os.Getenv("AURVET_LIVE_HELPER") != "1" {
		t.Skip("set AURVET_LIVE_HELPER=1 to measure against the live system")
	}
	home := os.Getenv("HOME")
	if !filepath.IsAbs(home) {
		t.Skip("no absolute HOME")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	d := Detect(root, Config{CacheDirs: DefaultCacheDirs([]string{home})})
	for _, c := range d.Caches {
		withRecipe, withGit := 0, 0
		for _, cl := range c.Clones {
			if cl.HasPKGBUILD {
				withRecipe++
			}
			if cl.HasGitDir {
				withGit++
			}
		}
		t.Logf("cache %-9s %-40s clones=%d with-PKGBUILD=%d with-.git=%d",
			c.Helper, c.Dir, len(c.Clones), withRecipe, withGit)
	}
	for _, g := range d.Gaps {
		t.Logf("gap   %-30s %s: %s", g.RuleID, g.Subject, g.Reason)
	}
	t.Logf("caches=%d gaps=%d covered=%v", len(d.Caches), len(d.Gaps), d.Covered())
}
