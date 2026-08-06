package main

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// ---------------------------------------------------------------------------
// --pkg N (repeatable), spec §14's `[--pkg N]...`
//
// The failure mode this guards is a typo. `aurvet scan --pkg zilb` that scanned
// nothing and exited 0 would be a false clean produced by a keystroke, so an
// unknown name is a usage error naming what was not found.
// ---------------------------------------------------------------------------

// twoPackageRoot has a clean package and a tampered one, so a restriction that
// did nothing and a restriction that worked have different exit codes.
func twoPackageRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writePackageRoot(t, root, "zlib", "1.3.1-2", []mtreeFile{
		{Rel: "usr/bin/zlib", Recorded: "clean\n", OnDisk: "clean\n"},
	})
	writePackageRoot(t, root, "acl", "2.4.0-1", []mtreeFile{
		{Rel: "usr/bin/acl", Recorded: "shipped\n", OnDisk: "tampered\n"},
	})
	// writePackageRoot writes a single-package sync database each time, so the
	// second call leaves the first package looking FOREIGN -- which would send
	// these tests to the real AUR over the network. One sync database naming both.
	writeSyncDB(t, filepath.Join(root, "var/lib/pacman/sync"), "core",
		map[string]string{"zlib": "1.3.1-2", "acl": "2.4.0-1"})
	return root
}

// reportsOn says whether the text report carries a finding or a gap about this
// package. Two spellings, because the subject of an integrity finding is the PATH
// and the package appears as evidence, while a provenance finding's subject is the
// package itself. A bare strings.Contains(out, "acl") cannot be used: "oracle"
// appears in the scope line, and a substring collision that makes a test pass is
// worse than one that makes it fail.
func reportsOn(out, pkg string) bool {
	return strings.Contains(out, "] "+pkg+":") ||
		strings.Contains(out, "] "+pkg+" (") ||
		strings.Contains(out, "evidence: package="+pkg)
}

func TestPkgRestrictsTheScanToTheNamedPackage(t *testing.T) {
	root := twoPackageRoot(t)
	// Without the flag the tampered package is reported: otherwise the
	// assertion below would pass on a root with nothing to find.
	code, stdout, _ := scanOut(t, "scan", "-offline-root", root)
	if code != exitFindings || !reportsOn(stdout, "acl") {
		t.Fatalf("the unrestricted scan did not report acl (exit %d), so the restriction below "+
			"would assert nothing:\n%s", code, stdout)
	}

	code, stdout, stderr := scanOut(t, "scan", "-pkg", "zlib", "-offline-root", root)
	if reportsOn(stdout, "acl") {
		t.Errorf("--pkg zlib reported a finding about acl:\n%s", stdout)
	}
	if !strings.Contains(stdout, "1 finding") && !strings.Contains(stdout, "0 finding") {
		t.Errorf("no header to read:\n%s", stdout)
	}
	if code != exitClean {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitClean, stdout, stderr)
	}
	// The scope is stated where the verdict is, above the findings: a report
	// that covered one package out of 1409 and did not say so is a report that
	// will be read as a system verdict.
	if !strings.Contains(stdout, "scope: 1 named package") {
		t.Errorf("the report does not state its scope:\n%s", stdout)
	}
}

// Repeatable, per §14's `[--pkg N]...`.
func TestPkgIsRepeatable(t *testing.T) {
	root := twoPackageRoot(t)
	code, stdout, stderr := scanOut(t, "scan", "-pkg", "zlib", "-pkg", "acl", "-offline-root", root)
	if !reportsOn(stdout, "acl") {
		t.Errorf("the second -pkg was dropped:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}
	if !strings.Contains(stdout, "scope: 2 named package") {
		t.Errorf("the scope line does not count both packages:\n%s", stdout)
	}
}

// The deliverable: a typo must not scan nothing and exit 0.
func TestUnknownPkgIsAUsageErrorNotAnEmptyResult(t *testing.T) {
	root := twoPackageRoot(t)
	code, stdout, stderr := scanOut(t, "scan", "-pkg", "zilb", "-offline-root", root)
	if code != exitUsage {
		t.Fatalf("exit = %d, want %d: a typo'd package name that scans nothing and exits 0 is a "+
			"false clean\nstdout:\n%s\nstderr:\n%s", code, exitUsage, stdout, stderr)
	}
	if !strings.Contains(stderr, "zilb") {
		t.Errorf("the refusal does not name the package it could not find:\n%s", stderr)
	}
	if stdout != "" {
		t.Errorf("a usage error wrote a report to stdout:\n%s", stdout)
	}
}

// A --pkg run must not become the --since-last baseline. Its result covers a
// handful of subjects, and storing it would truncate the next run's baseline so
// that every finding on the system re-reported as new on the run after that --
// the same reasoning that keeps runScan from persisting a FILTERED view.
func TestAPkgRunDoesNotPersistItsScopedReport(t *testing.T) {
	root := twoPackageRoot(t)
	state := t.TempDir()
	var stdout, stderr strings.Builder
	code := runScan(scanOpts{offlineRoot: root, only: []string{"zlib"}, stateDir: state},
		&stdout, &stderr)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\n%s", code, exitClean, stderr.String())
	}
	ents, err := os.ReadDir(state)
	if err != nil {
		t.Fatal(err)
	}
	if len(ents) != 0 {
		t.Errorf("a --pkg run persisted %d entry/entries under the state dir; the next --since-last "+
			"would diff the whole system against a one-package report", len(ents))
	}
	if !strings.Contains(stderr.String(), "--pkg") {
		t.Errorf("the run did not say why it did not persist:\n%s", stderr.String())
	}
}

// Why the whole-system passes are skipped, stated as a test because the reason is
// structural and easy to "fix" back into a defect: with --pkg the ownership
// oracle is built from the named packages alone, so every file on the system
// belongs to no package as far as this run can tell. Running the unowned-file and
// correlation checks against that oracle would fabricate findings.
func TestAPkgRunSkipsTheWholeSystemPassesAndSaysSo(t *testing.T) {
	root := suidRoot(t)
	code, stdout, stderr := scanOut(t, "scan", "-tier", "paranoid", "-pkg", "util-linux",
		"-offline-root", root)
	for _, rule := range []string{"integrity-unowned-setuid", "correlated-cluster", "surface-"} {
		if strings.Contains(stdout, rule) {
			t.Errorf("a --pkg run reported %s against a deliberately partial ownership oracle:\n%s",
				rule, stdout)
		}
	}
	if !strings.Contains(stdout, "surface") || !strings.Contains(stdout, "correlation") {
		t.Errorf("the scope line does not say that the system-wide passes did not run:\n%s\nstderr:\n%s",
			stdout, stderr)
	}
	if code != exitClean {
		t.Errorf("exit = %d, want %d\nstdout:\n%s", code, exitClean, stdout)
	}
}

// A package the restriction keeps must still be verified: the flag narrows the
// subject set, it does not weaken the analysis.
func TestPkgStillVerifiesTheNamedPackage(t *testing.T) {
	root := twoPackageRoot(t)
	code, stdout, stderr := scanOut(t, "scan", "-pkg", "acl", "-offline-root", root)
	if !strings.Contains(stdout, "does not match the digest its package recorded") {
		t.Fatalf("--pkg acl did not verify acl's contents:\n%s\nstderr:\n%s", stdout, stderr)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d", code, exitFindings)
	}
}
