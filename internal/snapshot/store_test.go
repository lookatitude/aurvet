// internal/snapshot/store_test.go
//
// This is the one package in the provenance path that writes, so these tests
// are about refusals as much as about records: INV-5 (never under
// --offline-root), and a pkgbase -- an attacker-influenced string -- never
// reaching a path.
package snapshot

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/config"
)

func testRecord(pkgbase string) Record {
	return Record{
		SchemaVersion: SchemaVersion,
		PkgBase:       pkgbase,
		CapturedAt:    "2026-08-05T10:00:00Z",
		Clones: []CloneRecord{{
			Helper:   "yay",
			Dir:      "home/u/.cache/yay/" + pkgbase,
			PKGBUILD: &FileRecord{Path: "PKGBUILD", Bytes: 3, SHA256: sha256hex([]byte("abc")), Text: "abc", Retained: true},
		}},
	}
}

// --- hostile pkgbase -------------------------------------------------------

// TestHostilePkgBaseIsRefused: a PKGBUILD's pkgbase reaches this package's
// filesystem layout. Every name below is refused before any syscall, and the
// state directory is checked afterwards to prove nothing landed anywhere --
// refusing to write the record is not the same as not having written it.
func TestHostilePkgBaseIsRefused(t *testing.T) {
	names := map[string]string{
		"traversal":        "../../etc/cron.d/x",
		"parent":           "..",
		"dot":              ".",
		"absolute":         "/etc/cron.d/x",
		"nul":              "foo\x00bar",
		"slash":            "foo/bar",
		"backslash":        `foo\bar`,
		"empty":            "",
		"leading-hyphen":   "-foo",
		"leading-dot":      ".foo",
		"newline":          "foo\nbar",
		"space":            "foo bar",
		"long":             strings.Repeat("a", 4096),
		"non-ascii":        "fooé",
		"shell":            "foo;rm -rf /",
		"dollar":           "$(id)",
		"tilde":            "~/foo",
		"double-traversal": "..%2f..%2fetc",
	}
	for label, name := range names {
		t.Run(label, func(t *testing.T) {
			dir := t.TempDir()
			s := StoreAt(dir)
			if _, _, err := s.Save(testRecord(name), "20260805T100000Z"); !errors.Is(err, ErrUnsafePkgBase) {
				t.Fatalf("Save(%q) error = %v, want ErrUnsafePkgBase", name, err)
			}
			if got := treeSnapshot(t, dir); strings.Count(got, "\n") != 1 {
				t.Errorf("Save(%q) touched the state directory:\n%s", name, got)
			}
			if _, err := os.Stat(filepath.Join(dir, "..", "etc")); err == nil {
				t.Fatalf("Save(%q) created something outside the state directory", name)
			}
			if _, _, err := s.Latest(name); !errors.Is(err, ErrUnsafePkgBase) {
				t.Errorf("Latest(%q) error = %v, want ErrUnsafePkgBase", name, err)
			}
		})
	}
}

// TestRealPkgBasesAreAccepted: the refusal must not be so broad that it rejects
// the names the AUR actually ships. All of these are live pkgbases.
func TestRealPkgBasesAreAccepted(t *testing.T) {
	for _, name := range []string{
		"yay", "brave-bin", "visual-studio-code-bin", "python-pywalfox",
		"binder_linux-dkms", "flutter-artifacts-google-bin", "nperf-gui-appimage",
		"unionfs-fuse", "libc++", "gtk2+extra", "foo.bar", "a",
	} {
		if err := ValidPkgBase(name); err != nil {
			t.Errorf("ValidPkgBase(%q) = %v, want nil", name, err)
		}
	}
}

// --- INV-5 ----------------------------------------------------------------

// TestOfflineRootRefusesEveryWrite: a snapshot taken while examining someone
// else's disk must not write into it. The assertion is over the whole target
// tree, so a write anywhere under it fails the test -- not just a write to the
// path this test predicted.
func TestOfflineRootRefusesEveryWrite(t *testing.T) {
	target := t.TempDir()
	if err := os.MkdirAll(filepath.Join(target, "var/lib/pacman/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	cfg, err := config.Resolve(target, 1000)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.HasPrefix(cfg.StateDir, target) {
		t.Fatalf("fixture assumption broken: StateDir %q is not inside %q", cfg.StateDir, target)
	}

	s := New(cfg, "")
	if ok, why := s.Writable(); ok {
		t.Fatalf("Writable() = true under --offline-root (%q)", why)
	}

	before := treeSnapshot(t, target)
	_, _, err = s.Save(testRecord("foo"), "20260805T100000Z")
	if !errors.Is(err, ErrOfflineRoot) {
		t.Fatalf("Save error = %v, want ErrOfflineRoot", err)
	}
	if after := treeSnapshot(t, target); after != before {
		t.Errorf("a write escaped into the examined tree:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// TestOfflineRootWithAnExternalStateDirIsAllowed: the invariant is about the
// examined tree, not about the mode. A destination outside it is a legitimate
// write, and refusing it would mean --offline-root could never capture anything.
func TestOfflineRootWithAnExternalStateDirIsAllowed(t *testing.T) {
	target := t.TempDir()
	outside := t.TempDir()
	cfg, err := config.Resolve(target, 1000)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, outside)
	if ok, why := s.Writable(); !ok {
		t.Fatalf("Writable() = false for a state dir outside the target: %s", why)
	}
	before := treeSnapshot(t, target)
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); err != nil {
		t.Fatal(err)
	}
	if after := treeSnapshot(t, target); after != before {
		t.Error("the examined tree was modified")
	}
}

// TestStateDirInsideTargetIsRefusedEvenWhenExplicit: an explicit --state-dir
// pointing back into the examined tree is still a write into the examined tree.
func TestStateDirInsideTargetIsRefusedEvenWhenExplicit(t *testing.T) {
	target := t.TempDir()
	cfg, err := config.Resolve(target, 1000)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, filepath.Join(target, "some/where"))
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); !errors.Is(err, ErrOfflineRoot) {
		t.Errorf("Save error = %v, want ErrOfflineRoot", err)
	}
}

// TestUnwritableFallbackStateDirIsRefusedUpFront: config.Resolve's
// fallback-unwritable case hands an unprivileged run /var/lib/aurvet. Failing at
// the mkdir would read as a bug in snapshot; saying so up front reads as what it
// is.
func TestUnwritableFallbackStateDirIsRefusedUpFront(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")
	cfg, err := config.Resolve("/", 1000)
	if err != nil {
		t.Fatal(err)
	}
	s := New(cfg, "")
	ok, why := s.Writable()
	if ok {
		t.Fatal("Writable() = true for the known-degraded resolution")
	}
	if !strings.Contains(why, "XDG_STATE_HOME") {
		t.Errorf("reason = %q, want it to name the cause", why)
	}
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); !errors.Is(err, ErrStateUnwritable) {
		t.Errorf("Save error = %v, want ErrStateUnwritable", err)
	}
}

// --- writing --------------------------------------------------------------

func TestSaveThenLatestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	s := StoreAt(dir)
	rec := testRecord("foo")
	path, wrote, err := s.Save(rec, "20260805T100000Z")
	if err != nil {
		t.Fatal(err)
	}
	if !wrote {
		t.Error("wrote = false for a first save")
	}
	if fi, err := os.Stat(path); err != nil {
		t.Fatal(err)
	} else if fi.Mode().Perm() != 0o600 {
		t.Errorf("mode = %v, want 0600: a snapshot names a package and its build paths", fi.Mode().Perm())
	}

	got, ok, err := s.Latest("foo")
	if err != nil || !ok {
		t.Fatalf("Latest = (_, %v, %v)", ok, err)
	}
	if got.Digest() != rec.Digest() {
		t.Errorf("round trip changed the record: %s != %s", got.Digest(), rec.Digest())
	}
	if got.Clones[0].PKGBUILD.Text != "abc" {
		t.Errorf("PKGBUILD text = %q", got.Clones[0].PKGBUILD.Text)
	}
}

// TestSaveIsIdempotentOnUnchangedContent: capture runs from a PostTransaction
// hook and from every scan, so an unchanged record must not add a file per run.
// A few KB per package is the claim; a few KB per package per scan is not.
func TestSaveIsIdempotentOnUnchangedContent(t *testing.T) {
	dir := t.TempDir()
	s := StoreAt(dir)
	first, _, err := s.Save(testRecord("foo"), "20260805T100000Z")
	if err != nil {
		t.Fatal(err)
	}
	// A later stamp, identical content.
	again := testRecord("foo")
	again.CapturedAt = "2026-08-06T10:00:00Z"
	second, wrote, err := s.Save(again, "20260806T100000Z")
	if err != nil {
		t.Fatal(err)
	}
	if wrote {
		t.Error("wrote = true for an unchanged record")
	}
	if second != first {
		t.Errorf("path = %q, want the existing %q", second, first)
	}
	ents, err := os.ReadDir(filepath.Dir(first))
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 1 {
		t.Errorf("%d files after two identical captures, want 1", len(ents))
	}
}

// TestSaveWritesANewRecordWhenTheRecipeChanges: the opposite failure. A store
// that deduplicated on pkgbase alone would bless a changed recipe.
func TestSaveWritesANewRecordWhenTheRecipeChanges(t *testing.T) {
	dir := t.TempDir()
	s := StoreAt(dir)
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); err != nil {
		t.Fatal(err)
	}
	changed := testRecord("foo")
	changed.Clones[0].PKGBUILD = &FileRecord{Path: "PKGBUILD", Bytes: 4, SHA256: sha256hex([]byte("abcd")), Text: "abcd", Retained: true}
	if _, wrote, err := s.Save(changed, "20260806T100000Z"); err != nil || !wrote {
		t.Fatalf("Save = (_, %v, %v), want a write", wrote, err)
	}
	got, ok, err := s.Latest("foo")
	if err != nil || !ok {
		t.Fatalf("Latest = (_, %v, %v)", ok, err)
	}
	if got.Clones[0].PKGBUILD.Text != "abcd" {
		t.Errorf("Latest returned the older record (%q)", got.Clones[0].PKGBUILD.Text)
	}
}

// TestNoTempFileSurvives: an interrupted write must not leave a half-written
// record that a later read treats as authoritative.
func TestNoTempFileSurvives(t *testing.T) {
	dir := t.TempDir()
	s := StoreAt(dir)
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); err != nil {
		t.Fatal(err)
	}
	got := treeSnapshot(t, dir)
	if strings.Contains(got, ".tmp") {
		t.Errorf("a temp file survived:\n%s", got)
	}
}

// TestLatestIgnoresUnreadableAndForeignSchemas: a damaged newest record must not
// hide a healthy older one, and it must never read as "no snapshot".
func TestLatestIgnoresUnreadableAndForeignSchemas(t *testing.T) {
	dir := t.TempDir()
	s := StoreAt(dir)
	if _, _, err := s.Save(testRecord("foo"), "20260805T100000Z"); err != nil {
		t.Fatal(err)
	}
	pkgDir := filepath.Join(dir, snapshotsSubdir, "foo")
	if err := os.WriteFile(filepath.Join(pkgDir, "20260806T100000Z.json"), []byte("{truncated"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "20260807T100000Z.json"), []byte(`{"schema_version":999}`), 0o600); err != nil {
		t.Fatal(err)
	}
	got, ok, err := s.Latest("foo")
	if err != nil || !ok {
		t.Fatalf("Latest = (_, %v, %v), want the healthy older record", ok, err)
	}
	if got.CapturedAt != "2026-08-05T10:00:00Z" {
		t.Errorf("CapturedAt = %q", got.CapturedAt)
	}
}

func TestLatestAbsentIsNotAnError(t *testing.T) {
	s := StoreAt(t.TempDir())
	rec, ok, err := s.Latest("nothing-here")
	if err != nil {
		t.Fatalf("err = %v, want nil", err)
	}
	if ok {
		t.Errorf("ok = true, record %+v", rec)
	}
}

// TestListReportsWhatIsStored: keyed on pkgbase, so the listing is a list of
// bases and never of package names.
func TestListReportsWhatIsStored(t *testing.T) {
	s := StoreAt(t.TempDir())
	for _, b := range []string{"foo", "bar-git"} {
		if _, _, err := s.Save(testRecord(b), "20260805T100000Z"); err != nil {
			t.Fatal(err)
		}
	}
	got, err := s.List()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Join(got, ",") != "bar-git,foo" {
		t.Errorf("List = %v, want [bar-git foo]", got)
	}
}

// TestRecordSizeIsAFewKB: the design claim is "a few KB per package against the
// 88 GB the cache occupies to hold the same facts". A record that grew to
// hundreds of KB would defeat the reason this command exists, so the ceiling is
// asserted rather than assumed.
func TestRecordSizeIsAFewKB(t *testing.T) {
	tr := newTree(t)
	tr.write(t, clonePath("foo")+"/PKGBUILD", splitRecipe)
	tr.write(t, clonePath("foo")+"/.SRCINFO", splitSRCINFO)
	g := tr.newGit(t, clonePath("foo"), false)
	g.remote(t, "https://aur.archlinux.org/foo.git")
	sha := g.commit(t, "initial", "", 0)
	g.head(t, g.commit(t, "bump", sha, 60))

	rec := capture(t, tr, "foo")
	dir := t.TempDir()
	path, _, err := StoreAt(dir).Save(rec, "20260805T100000Z")
	if err != nil {
		t.Fatal(err)
	}
	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Logf("record size: %d bytes", fi.Size())
	if fi.Size() > 32<<10 {
		t.Errorf("record is %d bytes; the design claim is a few KB per package", fi.Size())
	}
}
