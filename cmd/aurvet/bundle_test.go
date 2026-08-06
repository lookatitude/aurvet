// cmd/aurvet/bundle_test.go
//
// `bundle` end to end, and the test that makes the feature real is the ROUND
// TRIP: bundle a finding, scan the bundle, and require the same finding with the
// same fingerprint. Without that, "reproducing the finding" is a claim.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// cruftRoot is the false-positive fixture: a real desktop five years in. It is
// used rather than a synthetic tree because the round trip has to survive real
// shapes -- an enablement symlink with a relative target, a hook in a
// non-default HookDir, an autostart entry inside a home.
const cruftRoot = "../../testdata/roots/cruft"

func runBundleCmd(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var out, errb bytes.Buffer
	code := run(args, &out, &errb)
	return code, out.String(), errb.String()
}

// -- the round trip, per finding class ----------------------------------------

// Each case is a finding class the bundle CLAIMS to reproduce. The fingerprint
// is not hard-coded: it is read out of the scan, so a change to the fingerprint
// scheme cannot make this test pass by comparing two constants.
func TestBundleRoundTripsTheClassesItClaimsToReproduce(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	for _, rule := range []string{
		"wants-link-unowned-target",
		"unit-execstart-unowned",
		"hook-unowned",
		"surface-profiled-unowned",
		"surface-autostart-unowned-exec",
	} {
		fp, ok := ids[rule]
		if !ok {
			t.Fatalf("the cruft fixture no longer produces a %s finding, so this round trip "+
				"proves nothing. Fixture rules: %v", rule, ruleKeys(ids))
		}
		t.Run(rule, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "bundle")
			code, stdout, stderr := runBundleCmd(t, "bundle", fp, dir,
				"--offline-root", cruftRoot, "--no-network")
			if code != exitClean {
				t.Fatalf("bundle = %d, want %d (this class claims to reproduce)\nstdout: %s\nstderr: %s",
					code, exitClean, stdout, stderr)
			}
			if !strings.Contains(stdout, "should reappear with the same id") {
				t.Fatalf("the bundle does not claim reproduction:\n%s", stdout)
			}

			// The round trip itself.
			again := scanIDs(t, dir)
			got, present := again[rule]
			if !present {
				t.Fatalf("scanning the bundle produced no %s finding at all. Rules found: %v",
					rule, ruleKeys(again))
			}
			if got != fp {
				t.Fatalf("the bundle reproduces %s with fingerprint %s, not %s: the SUBJECT changed, "+
					"so a maintainer cannot match the report to the fixture", rule, got, fp)
			}
		})
	}
}

// scanIDs runs the real scan against a root and returns one finding id per rule.
func scanIDs(t *testing.T, root string) map[string]string {
	t.Helper()
	var out, errb bytes.Buffer
	code := run([]string{"scan", "--offline-root", root, "--no-network",
		"--min-severity", "info", "--json"}, &out, &errb)
	if code == exitUsage {
		t.Fatalf("scan %s = %d (usage)\n%s", root, code, errb.String())
	}
	var doc struct {
		Findings []struct {
			ID     string `json:"id"`
			RuleID string `json:"rule_id"`
		} `json:"findings"`
	}
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("scan %s: stdout is not JSON: %v\n%s", root, err, out.String())
	}
	ids := make(map[string]string, len(doc.Findings))
	for _, f := range doc.Findings {
		if _, seen := ids[f.RuleID]; !seen {
			ids[f.RuleID] = f.ID
		}
	}
	return ids
}

func ruleKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	return out
}

// -- attack: the operator publishes their own machine -------------------------

// The reference machine's live scan reports a unit pointing at
// /home/<user>/Projects/<employer>/..., and the cruft fixture reproduces that
// shape with /home/alice. A directory layout is not something a false-positive
// report should carry.
func TestBundleDoesNotPublishTheHomeDirectoryLayout(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	fp, ok := ids["unit-execstart-unowned"]
	if !ok {
		t.Fatal("the fixture no longer produces the finding whose evidence names a home path")
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	if code, _, se := runBundleCmd(t, "bundle", fp, dir,
		"--offline-root", cruftRoot, "--no-network"); code != exitClean {
		t.Fatalf("bundle = %d: %s", code, se)
	}
	all := allBytes(t, dir)
	if strings.Contains(all, "/home/alice") || strings.Contains(all, "home/alice") {
		t.Fatalf("the bundle carries the home directory named only in an evidence ARGUMENT:\n%s",
			grepIn(t, dir, "alice"))
	}
	// The unit still carries the directive the finding is about, and carries only
	// its PROGRAM.
	unit, err := os.ReadFile(filepath.Join(dir, "etc/systemd/system/local-backup.service"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(unit), "ExecStart=/usr/local/bin/hand-built-tool") {
		t.Fatalf("the ExecStart the finding is about did not survive:\n%s", unit)
	}
	if strings.Contains(string(unit), "--backup") {
		t.Errorf("the rebuilt unit carries the command's ARGUMENTS:\n%s", unit)
	}
	// Positive proof that the withholding fired, rather than the home path merely
	// being absent because the unit failed to emit at all. This replaces a canary
	// that asserted "/home/redacted/redacted" appears somewhere in the bundle --
	// which README.md always satisfies by documenting the placeholder, so it could
	// not fail even with redaction disabled.
	if !strings.Contains(allBytes(t, dir), "command argument(s) withheld") {
		t.Error("no manifest entry records withholding a command argument, so this test cannot " +
			"tell a redacted argument from a unit that never emitted")
	}
}

// -- attack: a bundle that quietly does not reproduce -------------------------

// A maintainer who runs a bundle, sees nothing and closes the report is the
// failure the classification table exists to prevent. The class is labelled and
// the exit code says so.
func TestBundleLabelsAClassItCannotReproduceAndExitsIncomplete(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	fp, ok := ids["unit-execstart-hijackable"]
	if !ok {
		t.Skip("the fixture produces no reproducible-class finding to contrast against")
	}
	_ = fp

	// aur-provenance and friends need a network response the bundle cannot carry.
	// The malicious fixture carries a correlated cluster, whose reproduction
	// depends on when the bundle is opened.
	mids := scanIDs(t, "../../testdata/roots/malicious")
	target, rule := "", ""
	for _, candidate := range []string{"correlated-cluster", "surface-preload-unowned"} {
		if id, present := mids[candidate]; present && candidate == "correlated-cluster" {
			target, rule = id, candidate
			break
		}
	}
	if target == "" {
		t.Skipf("no non-reproducible class in the malicious fixture; rules: %v", ruleKeys(mids))
	}

	dir := filepath.Join(t.TempDir(), "bundle")
	code, stdout, stderr := runBundleCmd(t, "bundle", target, dir,
		"--offline-root", "../../testdata/roots/malicious", "--no-network")
	if code != exitIncomplete {
		t.Fatalf("bundling a %s = %d, want %d (it cannot be reproduced from a fixture)\n%s\n%s",
			rule, code, exitIncomplete, stdout, stderr)
	}
	if !strings.Contains(stdout, "DOES NOT REPRODUCE") {
		t.Fatalf("the bundle does not say it will not reproduce:\n%s", stdout)
	}
	readme, err := os.ReadFile(filepath.Join(dir, "README.md"))
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(readme), "does NOT reproduce") {
		t.Fatalf("the README does not carry the label, so a maintainer who reads only the "+
			"attachment is misled:\n%s", readme)
	}
}

// -- attack: writing into the evidence ----------------------------------------

func TestBundleRefusesADestinationInsideTheExaminedTree(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	fp := ids["surface-profiled-unowned"]
	if fp == "" {
		t.Fatal("no finding to bundle")
	}
	inside := filepath.Join(cruftRoot, "tmp-bundle")
	code, _, stderr := runBundleCmd(t, "bundle", fp, inside,
		"--offline-root", cruftRoot, "--no-network")
	if code != exitUsage {
		t.Fatalf("a destination inside --offline-root = %d, want %d\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "INV-5") {
		t.Fatalf("the refusal does not cite the invariant:\n%s", stderr)
	}
	if _, err := os.Stat(inside); !os.IsNotExist(err) {
		os.RemoveAll(inside)
		t.Fatal("the refused bundle was written into the examined tree anyway")
	}
}

func TestBundleRefusesAPopulatedDestination(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	fp := ids["surface-profiled-unowned"]
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "mine.txt"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	code, _, stderr := runBundleCmd(t, "bundle", fp, dir, "--offline-root", cruftRoot, "--no-network")
	if code != exitUsage {
		t.Fatalf("a populated destination = %d, want %d\n%s", code, exitUsage, stderr)
	}
	if !strings.Contains(stderr, "self-contained") {
		t.Fatalf("the refusal does not say why:\n%s", stderr)
	}
}

// -- usage --------------------------------------------------------------------

func TestBundleRefusesAnUnknownFingerprintAndSaysWhereIdsComeFrom(t *testing.T) {
	code, _, stderr := runBundleCmd(t, "bundle", strings.Repeat("a", 32),
		filepath.Join(t.TempDir(), "b"), "--offline-root", cruftRoot, "--no-network")
	if code != exitUsage {
		t.Fatalf("unknown fingerprint = %d, want %d\n%s", code, exitUsage, stderr)
	}
	for _, want := range []string{"aurvet explain", "INV-3"} {
		if !strings.Contains(stderr, want) {
			t.Errorf("the refusal does not name %q:\n%s", want, stderr)
		}
	}
	// And no argument at all is a usage error naming the synopsis, not a panic.
	if code, _, se := runBundleCmd(t, "bundle"); code != exitUsage {
		t.Fatalf("`bundle` with no argument = %d, want %d", code, exitUsage)
	} else if !strings.Contains(se, "usage: aurvet bundle") {
		t.Fatalf("the usage line is missing:\n%s", se)
	}
	if code, _, _ := runBundleCmd(t, "bundle", "a", "b", "c"); code != exitUsage {
		t.Fatalf("three positionals = %d, want %d", code, exitUsage)
	}
}

// -- json ---------------------------------------------------------------------

func TestBundleJSONCarriesTheDispositionOfEveryFile(t *testing.T) {
	ids := scanIDs(t, cruftRoot)
	fp := ids["hook-unowned"]
	if fp == "" {
		t.Fatal("no hook finding to bundle")
	}
	dir := filepath.Join(t.TempDir(), "bundle")
	code, stdout, stderr := runBundleCmd(t, "bundle", fp, dir,
		"--offline-root", cruftRoot, "--no-network", "--json")
	if code != exitClean {
		t.Fatalf("bundle -json = %d\n%s", code, stderr)
	}
	var doc struct {
		Reproduces bool `json:"reproduces"`
		Files      []struct {
			Path        string `json:"path"`
			Disposition string `json:"disposition"`
		} `json:"files"`
	}
	if err := json.Unmarshal([]byte(stdout), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, stdout)
	}
	if !doc.Reproduces || len(doc.Files) == 0 {
		t.Fatalf("the document says nothing useful: %+v", doc)
	}
	for _, f := range doc.Files {
		switch f.Disposition {
		case "filtered", "placeholder", "symlink", "directory", "synthesised":
		default:
			t.Errorf("%s has disposition %q, which a maintainer cannot interpret", f.Path, f.Disposition)
		}
	}
}

// -- helpers ------------------------------------------------------------------

func allBytes(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		b.WriteString(p + "\n")
		switch {
		case info.Mode()&os.ModeSymlink != 0:
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return rerr
			}
			b.WriteString(target + "\n")
		case info.Mode().IsRegular():
			raw, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			b.Write(raw)
			b.WriteString("\n")
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	if b.Len() == 0 {
		t.Fatal("the bundle is empty; every assertion would be vacuous")
	}
	return b.String()
}

func grepIn(t *testing.T, dir, needle string) string {
	t.Helper()
	var hits []string
	_ = filepath.Walk(dir, func(p string, info os.FileInfo, err error) error {
		if err != nil {
			return nil
		}
		if strings.Contains(p, needle) {
			hits = append(hits, "  (path) "+p)
		}
		if info.Mode().IsRegular() {
			if raw, rerr := os.ReadFile(p); rerr == nil && strings.Contains(string(raw), needle) {
				hits = append(hits, "  "+p)
			}
		}
		if info.Mode()&os.ModeSymlink != 0 {
			if tgt, rerr := os.Readlink(p); rerr == nil && strings.Contains(tgt, needle) {
				hits = append(hits, "  (link) "+p+" -> "+tgt)
			}
		}
		return nil
	})
	return strings.Join(hits, "\n")
}
