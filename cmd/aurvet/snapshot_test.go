// cmd/aurvet/snapshot_test.go
//
// Every test here runs against a FIXTURE root. None of them reads the live
// pacman configuration, the live helper cache or the live state directory.
package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// snapshotRoot builds a scanned root with one account and one yay clone.
func snapshotRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	write := func(rel, body string) {
		abs := filepath.Join(root, rel)
		if err := os.MkdirAll(filepath.Dir(abs), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(abs, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.MkdirAll(filepath.Join(root, "var/lib/pacman/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	write("etc/passwd", "root:x:0:0::/root:/usr/bin/bash\nu:x:1000:1000::/home/u:/usr/bin/bash\n")
	write("home/u/.cache/yay/foo/PKGBUILD", "pkgbase=foo\npkgname=(foo-a foo-b)\npkgver=1.0\npkgrel=1\n"+
		"source=(\"https://example.com/foo-$pkgver.tar.gz\")\nsha256sums=('SKIP')\n")
	write("home/u/.cache/yay/foo/.SRCINFO", "pkgbase = foo\n\tpkgver = 1.0\n\npkgname = foo-a\n\npkgname = foo-b\n")
	return root
}

func TestSnapshotRequiresAPkgBase(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"snapshot"}, &stdout, &stderr); code != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "usage: aurvet snapshot") {
		t.Errorf("stderr = %q, want a usage line", stderr.String())
	}
}

// TestSnapshotRefusesAHostilePkgBase: the argument reaches a filesystem layout,
// so it is refused as an invocation error and nothing is captured or written.
func TestSnapshotRefusesAHostilePkgBase(t *testing.T) {
	root := snapshotRoot(t)
	state := t.TempDir()
	t.Setenv("AURVET_STATE_DIR", state)
	for _, name := range []string{"../../etc/cron.d/x", "/abs", "foo/bar", "", "-foo"} {
		var stdout, stderr bytes.Buffer
		if code := run([]string{"-offline-root", root, "snapshot", name}, &stdout, &stderr); code != exitUsage {
			t.Errorf("run(snapshot %q) = %d, want %d", name, code, exitUsage)
		}
		if ents, err := os.ReadDir(state); err != nil || len(ents) != 0 {
			t.Fatalf("state directory is not empty after refusing %q: %v %v", name, ents, err)
		}
	}
}

// TestSnapshotUnderOfflineRootDoesNotPersistByDefault: INV-5. The capture still
// runs and still reports -- the evidence is the point -- but the default state
// directory is inside the examined tree, so nothing is written.
func TestSnapshotUnderOfflineRootDoesNotPersistByDefault(t *testing.T) {
	root := snapshotRoot(t)
	before := walkTree(t, root)

	var stdout, stderr bytes.Buffer
	code := run([]string{"-offline-root", root, "snapshot", "foo"}, &stdout, &stderr)
	if code != exitIncomplete {
		t.Fatalf("run = %d, want %d (the fixture has no .BUILDINFO)\nstdout: %s\nstderr: %s",
			code, exitIncomplete, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "foo-a") {
		t.Errorf("output does not name the split package set:\n%s", stdout.String())
	}
	if !strings.Contains(stderr.String(), "offline-root") {
		t.Errorf("stderr does not say why nothing was persisted:\n%s", stderr.String())
	}
	if after := walkTree(t, root); after != before {
		t.Errorf("a write escaped into the examined tree:\nbefore\n%s\nafter\n%s", before, after)
	}
}

// TestSnapshotPersistsToAnExternalStateDir: with a destination outside the
// examined tree the record is written, keyed on the pkgbase.
func TestSnapshotPersistsToAnExternalStateDir(t *testing.T) {
	root := snapshotRoot(t)
	state := t.TempDir()
	t.Setenv("AURVET_STATE_DIR", state)

	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "snapshot", "foo"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitIncomplete, stderr.String())
	}
	dir := filepath.Join(state, "snapshots", "foo")
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatalf("no record under %s: %v", dir, err)
	}
	if len(ents) != 1 {
		t.Fatalf("%d records, want 1", len(ents))
	}

	// A second identical capture must not add a file: the store keys on content.
	var out2, err2 bytes.Buffer
	if code := run([]string{"-offline-root", root, "snapshot", "foo"}, &out2, &err2); code != exitIncomplete {
		t.Fatalf("second run = %d\nstderr: %s", code, err2.String())
	}
	if ents, _ := os.ReadDir(dir); len(ents) != 1 {
		t.Errorf("%d records after two identical captures, want 1", len(ents))
	}

	// The output must not be keyed on a package name.
	if _, err := os.Stat(filepath.Join(state, "snapshots", "foo-a")); err == nil {
		t.Error("a record was filed under a package name")
	}
}

func TestSnapshotJSONIsParseable(t *testing.T) {
	root := snapshotRoot(t)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "-json", "snapshot", "foo"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d\nstderr: %s", code, stderr.String())
	}
	var rec struct {
		SchemaVersion int    `json:"schema_version"`
		PkgBase       string `json:"pkgbase"`
		Clones        []struct {
			PkgNames []string `json:"pkgnames"`
			PKGBUILD *struct {
				SHA256 string `json:"sha256"`
			} `json:"pkgbuild"`
		} `json:"clones"`
		Gaps []struct {
			RuleID string `json:"RuleID"`
		} `json:"gaps"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &rec); err != nil {
		t.Fatalf("stdout is not parseable JSON: %v\n%s", err, stdout.String())
	}
	if rec.PkgBase != "foo" {
		t.Errorf("pkgbase = %q", rec.PkgBase)
	}
	if len(rec.Clones) != 1 || rec.Clones[0].PKGBUILD == nil || rec.Clones[0].PKGBUILD.SHA256 == "" {
		t.Errorf("record does not carry the captured recipe digest: %+v", rec)
	}
	if len(rec.Gaps) == 0 {
		t.Error("gaps are absent from the JSON record")
	}
}

// TestSnapshotWithNoCacheIsIncompleteNotClean: an absent cache is a coverage
// gap. Exit 3, and the reason names the pkgbase.
func TestSnapshotWithNoCacheIsIncompleteNotClean(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"), []byte("u:x:1000:1000::/home/u:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "snapshot", "nothing"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstdout: %s", code, exitIncomplete, stdout.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "snapshot-no-clone") {
		t.Errorf("output does not report the missing clone as a gap:\n%s", out)
	}
}

// TestSnapshotSearchCoverageIsReportedButNotStored: an unreadable cache
// belonging to another account is a real shortfall in the SEARCH -- it is
// reported and it drives the exit code -- but it is not a fact about the pkgbase
// whose clone was found, so it does not go into that record. On a live
// unprivileged run there are twenty of these.
func TestSnapshotSearchCoverageIsReportedButNotStored(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0000 directory is still readable")
	}
	root := snapshotRoot(t)
	locked := filepath.Join(root, "home/other/.cache/yay")
	if err := os.MkdirAll(locked, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(locked, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(locked, 0o755) })
	if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
		[]byte("u:x:1000:1000::/home/u:/bin/sh\nother:x:1001:1001::/home/other:/bin/sh\n"), 0o644); err != nil {
		t.Fatal(err)
	}

	state := t.TempDir()
	t.Setenv("AURVET_STATE_DIR", state)
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", root, "snapshot", "foo"}, &stdout, &stderr); code != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstderr: %s", code, exitIncomplete, stderr.String())
	}
	if !strings.Contains(stdout.String(), "helper-cache-unreadable") {
		t.Errorf("the unreadable cache is not reported:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "search coverage") {
		t.Errorf("output does not separate search coverage from the record:\n%s", stdout.String())
	}

	ents, err := os.ReadDir(filepath.Join(state, "snapshots", "foo"))
	if err != nil || len(ents) != 1 {
		t.Fatalf("records = %v, err = %v", ents, err)
	}
	blob, err := os.ReadFile(filepath.Join(state, "snapshots", "foo", ents[0].Name()))
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(blob), "helper-cache-unreadable") {
		t.Errorf("another account's permissions problem was stored inside this pkgbase's record:\n%s", blob)
	}
}

// TestSnapshotRejectsTrailingArguments: one pkgbase, not a list -- a list would
// make the exit code ambiguous across subjects.
func TestSnapshotRejectsTrailingArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"snapshot", "foo", "bar"}, &stdout, &stderr); code != exitUsage {
		t.Errorf("run = %d, want %d", code, exitUsage)
	}
}

func walkTree(t *testing.T, dir string) string {
	t.Helper()
	var b strings.Builder
	err := filepath.Walk(dir, func(p string, fi os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		rel, _ := filepath.Rel(dir, p)
		b.WriteString(rel)
		b.WriteString("\n")
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	return b.String()
}
