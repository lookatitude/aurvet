// internal/snapshot/snapshot_test.go
//
// Fixtures here are built byte by byte -- git objects included. Nothing in this
// file runs `git`, `makepkg` or `pacman` (INV-2), for the same reason
// internal/vcs's tests do not: a suite that shells out to the binary the code
// exists to avoid cannot prove the code avoids it.
package snapshot

import (
	"bytes"
	"compress/zlib"
	"crypto/sha1"
	"encoding/hex"
	"errors"
	"fmt"
	"go/build"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/helper"
)

// --- fixture --------------------------------------------------------------

// tree builds a scanned root holding one user's yay cache.
type tree struct {
	dir  string // absolute path of the scanned root
	root *os.Root
}

func newTree(t *testing.T) *tree {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return &tree{dir: dir, root: root}
}

func (tr *tree) write(t *testing.T, rel, body string) {
	t.Helper()
	abs := filepath.Join(tr.dir, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// cacheDirs is the one search directory every fixture uses.
func cacheDirs() []string { return []string{"home/u/.cache"} }

func (tr *tree) detect(t *testing.T) helper.Detection {
	t.Helper()
	return helper.Detect(tr.root, helper.Config{
		CacheDirs: cacheDirs(),
		Layouts:   []helper.Layout{{Name: "yay", CacheRel: "yay"}},
	})
}

// clonePath is the root-relative clone directory for one pkgbase.
func clonePath(pkgbase string) string { return "home/u/.cache/yay/" + pkgbase }

// gitFixture writes a loose-object git repository. Bare when gitRel == the
// directory itself.
type gitFixture struct {
	git  string // absolute git directory
	tree string
}

func (tr *tree) newGit(t *testing.T, rel string, bare bool) *gitFixture {
	t.Helper()
	git := filepath.Join(tr.dir, rel)
	if !bare {
		git = filepath.Join(git, ".git")
	}
	g := &gitFixture{git: git}
	for _, d := range []string{"objects", "refs/heads"} {
		if err := os.MkdirAll(filepath.Join(git, d), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	g.file(t, "HEAD", "ref: refs/heads/master\n")
	g.file(t, "config", "[core]\n\trepositoryformatversion = 0\n")
	g.tree = g.loose(t, "tree", nil)
	return g
}

func (g *gitFixture) file(t *testing.T, rel, body string) {
	t.Helper()
	abs := filepath.Join(g.git, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func (g *gitFixture) remote(t *testing.T, url string) {
	t.Helper()
	g.file(t, "config", "[core]\n\trepositoryformatversion = 0\n[remote \"origin\"]\n\turl = "+url+"\n")
}

const fixtureEpoch = 1785924000

func (g *gitFixture) commit(t *testing.T, msg string, parent string, secs int) string {
	t.Helper()
	var b bytes.Buffer
	fmt.Fprintf(&b, "tree %s\n", g.tree)
	if parent != "" {
		fmt.Fprintf(&b, "parent %s\n", parent)
	}
	when := fixtureEpoch + secs
	fmt.Fprintf(&b, "author A U Thor <author@example.com> %d +0200\n", when)
	fmt.Fprintf(&b, "committer C O Mitter <committer@example.com> %d +0200\n", when)
	b.WriteString("\n")
	b.WriteString(msg + "\n")
	return g.loose(t, "commit", b.Bytes())
}

func (g *gitFixture) head(t *testing.T, sha string) {
	t.Helper()
	g.file(t, "refs/heads/master", sha+"\n")
}

func (g *gitFixture) loose(t *testing.T, typ string, body []byte) string {
	t.Helper()
	h := sha1.New()
	fmt.Fprintf(h, "%s %d", typ, len(body))
	h.Write([]byte{0})
	h.Write(body)
	sha := hex.EncodeToString(h.Sum(nil))

	var raw bytes.Buffer
	fmt.Fprintf(&raw, "%s %d", typ, len(body))
	raw.WriteByte(0)
	raw.Write(body)
	var z bytes.Buffer
	w := zlib.NewWriter(&z)
	if _, err := w.Write(raw.Bytes()); err != nil {
		t.Fatal(err)
	}
	if err := w.Close(); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(g.git, "objects", sha[:2])
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, sha[2:]), z.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	return sha
}

// splitRecipe is a split base: one recipe, two output packages. 433 of 1409
// installed packages on the reference system have this shape.
const splitRecipe = `pkgbase=foo
pkgname=(foo-a foo-b)
pkgver=1.0
pkgrel=1
arch=(x86_64)
source=("https://example.com/foo-$pkgver.tar.gz")
sha256sums=('SKIP')
`

const splitSRCINFO = `pkgbase = foo
	pkgver = 1.0
	pkgrel = 1
	source = https://example.com/foo-1.0.tar.gz

pkgname = foo-a

pkgname = foo-b
`

func capture(t *testing.T, tr *tree, pkgbase string) Record {
	t.Helper()
	d := tr.detect(t)
	rec, err := Capture(tr.root, Config{
		PkgBase:    pkgbase,
		Clones:     d.Clones(pkgbase),
		CapturedAt: time.Unix(fixtureEpoch, 0).UTC(),
	})
	if err != nil {
		t.Fatalf("Capture(%q): %v", pkgbase, err)
	}
	return rec
}

func gapRules(rec Record) []string {
	var out []string
	for _, g := range rec.Gaps {
		out = append(out, g.RuleID)
	}
	return out
}

func hasGap(rec Record, rule string) bool {
	for _, g := range rec.Gaps {
		if g.RuleID == rule {
			return true
		}
	}
	return false
}

// --- pkgbase keying -------------------------------------------------------

// TestCaptureKeysOnPkgBase: one recipe, one record, both output packages named
// inside it. The trap this guards is recorded in the lane brief: keying on
// pkgname would file one recipe under two keys, and the two records would then
// disagree about their own provenance while describing the same PKGBUILD.
func TestCaptureKeysOnPkgBase(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/.SRCINFO", splitSRCINFO)

	rec := capture(t, tr, "foo")
	if rec.PkgBase != "foo" {
		t.Errorf("PkgBase = %q, want foo", rec.PkgBase)
	}
	if len(rec.Clones) != 1 {
		t.Fatalf("Clones = %d, want 1 (one recipe is one record)", len(rec.Clones))
	}
	c := rec.Clones[0]
	if got := strings.Join(c.PkgNames, ","); got != "foo-a,foo-b" {
		t.Errorf("PkgNames = %q, want foo-a,foo-b", got)
	}
	if c.SRCINFOPkgBase != "foo" {
		t.Errorf("SRCINFOPkgBase = %q, want foo", c.SRCINFOPkgBase)
	}

	// The load-bearing half: the same system, keyed on either output package
	// name, finds nothing to capture. A pkgname-keyed snapshot store is not a
	// store with duplicate entries -- it is a store that misses the recipe.
	for _, name := range []string{"foo-a", "foo-b"} {
		got := capture(t, tr, name)
		if len(got.Clones) != 0 {
			t.Errorf("Capture(%q) found %d clones; a pkgname is not a cache key", name, len(got.Clones))
		}
		if !hasGap(got, RuleNoClone) {
			t.Errorf("Capture(%q) gaps = %v, want %s", name, gapRules(got), RuleNoClone)
		}
	}
}

// TestCaptureRefusesAHostileKey: the refusal is at the capture boundary too, not
// only at the write. A record built under a hostile key would be handed to a
// caller that might do something else with it.
func TestCaptureRefusesAHostileKey(t *testing.T) {
	tr := newTree(t)
	for _, name := range []string{"../../etc/cron.d/x", "/abs", "foo\x00bar", "", strings.Repeat("a", 4096)} {
		if _, err := Capture(tr.root, Config{PkgBase: name}); !errors.Is(err, ErrUnsafePkgBase) {
			t.Errorf("Capture(%q) error = %v, want ErrUnsafePkgBase", firstN(name, 20), err)
		}
	}
}

// TestCaptureRequiresARoot: no root means nothing was examined, which is an
// error and never an empty record.
func TestCaptureRequiresARoot(t *testing.T) {
	if _, err := Capture(nil, Config{PkgBase: "foo"}); err == nil {
		t.Error("Capture(nil, ...) succeeded")
	}
}

// TestCaptureRecordsPkgBaseMismatchAndNeverRekeys: a .SRCINFO declaring a
// different pkgbase than the directory it sits in is a fact to report, not a
// key to adopt. Adopting it would let a hostile recipe choose which record it
// overwrites.
func TestCaptureRecordsPkgBaseMismatchAndNeverRekeys(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", "pkgbase=elsewhere\npkgname=elsewhere\n")
	tr.write(t, clonePath("foo")+"/.SRCINFO", "pkgbase = elsewhere\n\npkgname = elsewhere\n")

	rec := capture(t, tr, "foo")
	if rec.PkgBase != "foo" {
		t.Errorf("PkgBase = %q; the record must stay keyed on the requested base", rec.PkgBase)
	}
	if got := rec.Clones[0].SRCINFOPkgBase; got != "elsewhere" {
		t.Errorf("SRCINFOPkgBase = %q, want elsewhere (recorded verbatim)", got)
	}
	if !hasGap(rec, RuleKeyMismatch) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleKeyMismatch)
	}
}

// --- coverage gaps (INV-9) ------------------------------------------------

// TestNoCloneIsAGapNotSilence: an absent cache is a coverage gap. "I found no
// clone" and "there is nothing to find" are different statements.
func TestNoCloneIsAGapNotSilence(t *testing.T) {
	tr := newTree(t)
	rec := capture(t, tr, "absent")
	if len(rec.Clones) != 0 {
		t.Fatalf("Clones = %d, want 0", len(rec.Clones))
	}
	if rec.Complete() {
		t.Error("Complete() = true for a snapshot that captured nothing")
	}
	if !hasGap(rec, RuleNoClone) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleNoClone)
	}
}

// TestMissingBuildInfoIsAGap: INV-6. A record that silently omits .BUILDINFO
// reads later as "there was none", which is a claim this capture cannot make.
func TestMissingBuildInfoIsAGap(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	rec := capture(t, tr, "foo")
	if rec.Clones[0].BuildInfo != nil {
		t.Error("BuildInfo recorded where none exists")
	}
	if !hasGap(rec, RuleBuildInfo) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleBuildInfo)
	}
}

// TestUnreadableArchiveCompressionIsANamedGap: the reference system's clones
// hold .pkg.tar.zst archives and .BUILDINFO lives only inside them. zstd is not
// in the standard library, so the honest answer is a gap naming the algorithm,
// never an absent .BUILDINFO.
func TestUnreadableArchiveCompressionIsANamedGap(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/foo-1.0-1-x86_64.pkg.tar.zst", "not really zstd")

	rec := capture(t, tr, "foo")
	var reason string
	for _, g := range rec.Gaps {
		if g.RuleID == RuleBuildInfo {
			reason += g.Reason + "\n"
		}
	}
	if !strings.Contains(reason, "zstd") {
		t.Errorf("no gap naming zstd; got:\n%s", reason)
	}
	if got := rec.Clones[0].Archives; len(got) != 1 || !strings.HasSuffix(got[0], ".zst") {
		t.Errorf("Archives = %v, want the one archive recorded", got)
	}
}

// TestBuildInfoFromPkgDirIsCaptured: a build directory left behind carries
// .BUILDINFO under pkg/<pkgname>/, and pkgbuild_sha256sum is the only local
// evidence that the recipe on disk is the recipe that was built.
func TestBuildInfoFromPkgDirIsCaptured(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/pkg/foo-a/.BUILDINFO", strings.Join([]string{
		"format = 2",
		"pkgname = foo-a",
		"pkgbase = foo",
		"pkgver = 1.0-1",
		"pkgbuild_sha256sum = " + strings.Repeat("a", 64),
		"builddir = /build",
		"startdir = /build/foo",
		"installed = glibc-2.41-1-x86_64",
		"installed = bash-5.2-1-x86_64",
	}, "\n")+"\n")

	rec := capture(t, tr, "foo")
	bi := rec.Clones[0].BuildInfo
	if bi == nil {
		t.Fatal("BuildInfo not captured from pkg/foo-a/.BUILDINFO")
	}
	if bi.PkgBuildSHA256 != strings.Repeat("a", 64) {
		t.Errorf("PkgBuildSHA256 = %q", bi.PkgBuildSHA256)
	}
	if bi.PkgBase != "foo" {
		t.Errorf("PkgBase = %q, want foo", bi.PkgBase)
	}
	// Size discipline: the installed list is the bulk of a .BUILDINFO (~120 KiB
	// on a desktop build) and is counted, not retained. The count is what makes
	// the omission visible instead of silent.
	if bi.InstalledCount != 2 {
		t.Errorf("InstalledCount = %d, want 2", bi.InstalledCount)
	}
	if !hasNote(rec, "installed") {
		t.Errorf("notes = %v, want one stating the installed list is not retained", rec.Notes)
	}
}

func hasNote(rec Record, substr string) bool {
	for _, n := range rec.Notes {
		if strings.Contains(n, substr) {
			return true
		}
	}
	return false
}

// --- git provenance -------------------------------------------------------

func TestCaptureReadsHeadRemoteAndLog(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	g := tr.newGit(t, clonePath("foo"), false)
	g.remote(t, "https://aur.archlinux.org/foo.git")
	c1 := g.commit(t, "initial", "", 0)
	c2 := g.commit(t, "bump to 1.0", c1, 60)
	g.head(t, c2)

	rec := capture(t, tr, "foo")
	git := rec.Clones[0].Git
	if git == nil {
		t.Fatal("Git not captured")
	}
	if git.Head != c2 {
		t.Errorf("Head = %q, want %q", git.Head, c2)
	}
	if git.Remote != "https://aur.archlinux.org/foo.git" {
		t.Errorf("Remote = %q", git.Remote)
	}
	if len(git.Log) != 2 {
		t.Fatalf("Log = %d commits, want 2", len(git.Log))
	}
	if git.Log[0].Subject != "bump to 1.0" {
		t.Errorf("Log[0].Subject = %q", git.Log[0].Subject)
	}
	if !strings.Contains(git.Log[0].Author, "author@example.com") {
		t.Errorf("Log[0].Author = %q", git.Log[0].Author)
	}
	// The commit's own offset, never the reader's zone.
	if !strings.HasSuffix(git.Log[0].Date, "+02:00") {
		t.Errorf("Log[0].Date = %q, want the commit's own +0200 offset", git.Log[0].Date)
	}
}

// TestNoGitDirIsAGap: a clone whose history has been removed is a gap, because
// the remote and the recipe's own history are the provenance.
func TestNoGitDirIsAGap(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	rec := capture(t, tr, "foo")
	if rec.Clones[0].Git != nil {
		t.Error("Git recorded for a clone with no .git")
	}
	if !hasGap(rec, RuleGit) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleGit)
	}
}

// --- the upstream commit built --------------------------------------------

const vcsRecipe = `pkgbase=bar-git
pkgname=bar-git
pkgver=r1
pkgrel=1
arch=(x86_64)
source=("bar::git+https://example.com/bar.git")
sha256sums=('SKIP')
`

// TestUpstreamCommitFromSrcdirClone: for a -git package the recipe is stable
// while the source moves, so the commit that was built is the fact an approval
// has to be measured against. makepkg leaves that clone beside the PKGBUILD.
func TestUpstreamCommitFromSrcdirClone(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("bar-git")+"/PKGBUILD", vcsRecipe)
	up := tr.newGit(t, clonePath("bar-git")+"/bar", true)
	up.remote(t, "https://example.com/bar.git")
	sha := up.commit(t, "upstream work", "", 0)
	up.head(t, sha)

	rec := capture(t, tr, "bar-git")
	ups := rec.Clones[0].Upstream
	if len(ups) != 1 {
		t.Fatalf("Upstream = %d entries, want 1: %+v", len(ups), ups)
	}
	if ups[0].Commit != sha {
		t.Errorf("Commit = %q, want %q", ups[0].Commit, sha)
	}
	if ups[0].Origin != OriginSrcdirClone {
		t.Errorf("Origin = %q, want %q", ups[0].Origin, OriginSrcdirClone)
	}
}

// TestUpstreamCommitFromHelperVCSState: yay records the built commit per
// pkgbase in vcs.json, which survives a cleaned srcdir. It is keyed on pkgbase
// -- reading it under a package name finds nothing.
func TestUpstreamCommitFromHelperVCSState(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("bar-git")+"/PKGBUILD", vcsRecipe)
	tr.write(t, "home/u/.cache/yay/vcs.json", `{
	"bar-git": {
		"example.com/bar.git": {"protocols": ["https"], "branch": "HEAD", "sha": "`+strings.Repeat("b", 40)+`"}
	}
}`)

	d := tr.detect(t)
	rec, err := Capture(tr.root, Config{
		PkgBase:       "bar-git",
		Clones:        d.Clones("bar-git"),
		VCSStateFiles: []string{"home/u/.cache/yay/vcs.json"},
		CapturedAt:    time.Unix(fixtureEpoch, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	ups := rec.Clones[0].Upstream
	if len(ups) != 1 {
		t.Fatalf("Upstream = %d entries, want 1: %+v", len(ups), ups)
	}
	if ups[0].Commit != strings.Repeat("b", 40) {
		t.Errorf("Commit = %q", ups[0].Commit)
	}
	if !strings.HasPrefix(ups[0].Origin, OriginHelperVCSState) {
		t.Errorf("Origin = %q, want %s...", ups[0].Origin, OriginHelperVCSState)
	}
}

// TestUpstreamDisagreementIsRecordedNotReconciled: two sources, two answers.
// Picking one would manufacture a fact; both are recorded and the disagreement
// is a gap.
func TestUpstreamDisagreementIsRecordedNotReconciled(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("bar-git")+"/PKGBUILD", vcsRecipe)
	up := tr.newGit(t, clonePath("bar-git")+"/bar", true)
	sha := up.commit(t, "upstream work", "", 0)
	up.head(t, sha)
	tr.write(t, "home/u/.cache/yay/vcs.json", `{"bar-git":{"example.com/bar.git":{"sha":"`+strings.Repeat("c", 40)+`"}}}`)

	d := tr.detect(t)
	rec, err := Capture(tr.root, Config{
		PkgBase:       "bar-git",
		Clones:        d.Clones("bar-git"),
		VCSStateFiles: []string{"home/u/.cache/yay/vcs.json"},
		CapturedAt:    time.Unix(fixtureEpoch, 0).UTC(),
	})
	if err != nil {
		t.Fatal(err)
	}
	if len(rec.Clones[0].Upstream) != 2 {
		t.Fatalf("Upstream = %+v, want both answers recorded", rec.Clones[0].Upstream)
	}
	if !hasGap(rec, RuleUpstream) {
		t.Errorf("gaps = %v, want %s for the disagreement", gapRules(rec), RuleUpstream)
	}
}

// TestVCSSourceWithNoRecordedCommitIsAGap: an unknowable upstream commit is
// the whole reason -git approvals cannot be granted once and forever.
func TestVCSSourceWithNoRecordedCommitIsAGap(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("bar-git")+"/PKGBUILD", vcsRecipe)
	rec := capture(t, tr, "bar-git")
	if len(rec.Clones[0].Upstream) != 0 {
		t.Errorf("Upstream = %+v, want none", rec.Clones[0].Upstream)
	}
	if !hasGap(rec, RuleUpstream) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleUpstream)
	}
}

// --- resolved sources ------------------------------------------------------

func TestResolvedSourceURLsAreCaptured(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/.SRCINFO", splitSRCINFO)

	rec := capture(t, tr, "foo")
	var fromRecipe, fromSRCINFO int
	for _, s := range rec.Clones[0].Sources {
		switch s.Origin {
		case OriginPKGBUILD:
			fromRecipe++
			if s.URL != "https://example.com/foo-1.0.tar.gz" {
				t.Errorf("pkgbuild source URL = %q, want the $pkgver-resolved URL", s.URL)
			}
		case OriginSRCINFO:
			fromSRCINFO++
		}
	}
	if fromRecipe != 1 || fromSRCINFO != 1 {
		t.Errorf("sources: pkgbuild=%d srcinfo=%d, want 1 and 1 (%+v)", fromRecipe, fromSRCINFO, rec.Clones[0].Sources)
	}
}

func TestUnresolvableSourceIsAGap(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", "pkgbase=foo\npkgname=foo\nsource=(\"https://example.com/${undefined}.tar.gz\")\n")
	rec := capture(t, tr, "foo")
	if !hasGap(rec, RuleRecipe) {
		t.Errorf("gaps = %v, want %s for an unresolvable source", gapRules(rec), RuleRecipe)
	}
}

// --- retention and size ----------------------------------------------------

// TestPKGBUILDIsRetainedVerbatimWithDigest: the diff against the last approved
// recipe needs the bytes, and the digest is what an approval keys on.
func TestPKGBUILDIsRetainedVerbatimWithDigest(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	rec := capture(t, tr, "foo")
	f := rec.Clones[0].PKGBUILD
	if f == nil {
		t.Fatal("PKGBUILD not captured")
	}
	if f.Text != splitRecipe {
		t.Errorf("Text = %q, want the recipe verbatim", f.Text)
	}
	if !f.Retained {
		t.Error("Retained = false for a retained file")
	}
	if want := sha256hex([]byte(splitRecipe)); f.SHA256 != want {
		t.Errorf("SHA256 = %q, want %q", f.SHA256, want)
	}
}

// TestOversizedFileIsDigestedNotRetained: a hostile recipe must not be able to
// grow the state directory to its own size, and a record that dropped the text
// silently would read as an empty recipe.
func TestOversizedFileIsDigestedNotRetained(t *testing.T) {
	tr := newTree(t)
	big := "pkgbase=foo\npkgname=foo\n# " + strings.Repeat("x", 4096) + "\n"
	tr.write(t, clonePath("foo")+"/PKGBUILD", big)

	d := tr.detect(t)
	rec, err := Capture(tr.root, Config{
		PkgBase:    "foo",
		Clones:     d.Clones("foo"),
		CapturedAt: time.Unix(fixtureEpoch, 0).UTC(),
		Limits:     Limits{MaxRetainBytes: 1024},
	})
	if err != nil {
		t.Fatal(err)
	}
	f := rec.Clones[0].PKGBUILD
	if f == nil {
		t.Fatal("PKGBUILD not captured at all")
	}
	if f.Text != "" || f.Retained {
		t.Errorf("Retained = %v, Text = %d bytes; want the text dropped above the cap", f.Retained, len(f.Text))
	}
	if f.SHA256 != sha256hex([]byte(big)) {
		t.Error("digest must still be over the full file")
	}
	if !hasGap(rec, RuleNotRetained) {
		t.Errorf("gaps = %v, want %s", gapRules(rec), RuleNotRetained)
	}
}

// --- purity ----------------------------------------------------------------

// TestCaptureWritesNothing: INV-4/INV-5. Capture is the pure half; the write is
// the store's business and only ever lands in the state directory.
func TestCaptureWritesNothing(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/.SRCINFO", splitSRCINFO)
	g := tr.newGit(t, clonePath("foo"), false)
	g.remote(t, "https://aur.archlinux.org/foo.git")
	g.head(t, g.commit(t, "initial", "", 0))

	before := treeSnapshot(t, tr.dir)
	capture(t, tr, "foo")
	if after := treeSnapshot(t, tr.dir); after != before {
		t.Errorf("Capture mutated the scanned tree:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// TestCaptureIsDeterministic: the same (root, cfg) produces the same record,
// which is what makes the content digest usable as an idempotence key.
func TestCaptureIsDeterministic(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/.SRCINFO", splitSRCINFO)
	g := tr.newGit(t, clonePath("foo"), false)
	g.head(t, g.commit(t, "initial", "", 0))

	a := capture(t, tr, "foo")
	b := capture(t, tr, "foo")
	if a.Digest() != b.Digest() {
		t.Errorf("Digest differs across identical captures: %s != %s", a.Digest(), b.Digest())
	}
}

// TestPackageImportsNoExec: INV-2 reaches this package too. A snapshot that
// ran `makepkg --printsrcinfo` to fill in a missing .SRCINFO would execute the
// recipe it is capturing.
func TestPackageImportsNoExec(t *testing.T) {
	pkg, err := build.ImportDir(".", 0)
	if err != nil {
		t.Fatal(err)
	}
	for _, imp := range append(pkg.Imports, pkg.TestImports...) {
		if imp == "os/exec" {
			t.Errorf("package imports %s; INV-2 forbids executing anything here", imp)
		}
	}
}

// treeSnapshot renders every path under dir with its size and mode, so any
// creation, deletion or modification changes the string.
func treeSnapshot(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		fmt.Fprintf(&b, "%s %d %s\n", rel, fi.Size(), fi.Mode())
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
