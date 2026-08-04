package main

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/report"
)

// Spec §14: the exit code is the machine-readable result. Automation branches on
// it, so each class is pinned here rather than left to the switch's shape.
func TestRunExitCodes(t *testing.T) {
	for _, tc := range []struct {
		name string
		args []string
		want int
	}{
		{"doctor succeeds", []string{"doctor"}, exitClean},
		{"doctor under offline-root succeeds", []string{"-offline-root", "/mnt/target", "doctor"}, exitClean},
		{"no command is a usage error", nil, exitUsage},
		{"unknown command is a usage error", []string{"rummage"}, exitUsage},
		{"unknown flag is a usage error", []string{"-nope", "doctor"}, exitUsage},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var stdout, stderr bytes.Buffer
			if got := run(tc.args, &stdout, &stderr); got != tc.want {
				t.Errorf("run(%q) = %d, want %d\nstderr: %s", tc.args, got, tc.want, stderr.String())
			}
		})
	}
}

// doctor must write its report to stdout, not stderr: it is data, and callers
// pipe it.
func TestDoctorWritesReportToStdout(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if code := run([]string{"-offline-root", "/mnt/target", "doctor"}, &stdout, &stderr); code != exitClean {
		t.Fatalf("run = %d, stderr: %s", code, stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "/mnt/target/var/lib/pacman/local") {
		t.Errorf("doctor output missing rooted db_path:\n%s", out)
	}
	if stderr.Len() != 0 {
		t.Errorf("doctor wrote to stderr: %s", stderr.String())
	}
	// Provenance is the point of doctor; a bare value dump is not enough.
	if !strings.Contains(out, "(derived)") {
		t.Errorf("doctor output missing provenance:\n%s", out)
	}
}

// writeMinimalRoot builds a --offline-root tree with one installed, readable
// package and no sync database at all. That absence is deliberate: it drives
// the sync-coverage guard in sweep (main.go) so every scan against this root
// is deterministically incomplete without ever touching the network.
func writeMinimalRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	pkgDir := filepath.Join(root, "var/lib/pacman/local", "zlib-1.3.1-2")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n%BASE%\nzlib\n\n%VALIDATION%\npgp\n\n"
	if err := os.WriteFile(filepath.Join(pkgDir, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pkgDir, "files"), []byte("%FILES%\nusr/lib/libz.so\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return root
}

// TestScanMinimalRootIsIncomplete covers scan step order 1-9: a root with a
// real package and no sync DB must gap on the absent name oracle and, under
// --no-network, gap again on the unattempted provenance check -- coverage is
// incomplete either way, so the run must exit 3.
func TestScanMinimalRootIsIncomplete(t *testing.T) {
	root := writeMinimalRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "-offline-root", root}, &stdout, &stderr)
	if got != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstdout: %s\nstderr: %s", got, exitIncomplete, stdout.String(), stderr.String())
	}
	out := stdout.String()
	if !strings.Contains(out, "coverage") || !strings.Contains(out, "incomplete") {
		t.Errorf("stdout missing coverage/incomplete markers:\n%s", out)
	}
}

// TestScanEmptyOfflineRootIsNotClean pins P1-A success criterion 1 (.guild/plan/aurvet-p1a.md):
// scan must exit 0, 1, or 3 -- never a bare success when coverage is
// incomplete or when nothing was analysed at all. A bare empty temp
// directory has no pacman local DB directory to read, so this hits the
// hard-error path in sweep (LoadLocalDB) rather than the zero-population
// guard below; both must refuse to report exitClean.
func TestScanEmptyOfflineRootIsNotClean(t *testing.T) {
	root := t.TempDir()
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "-offline-root", root}, &stdout, &stderr)
	if got == exitClean {
		t.Fatalf("run = %d, want anything but %d (success criterion 1): an empty/unreadable root must never report a clean bill of health", got, exitClean)
	}
	if got != exitUsage {
		t.Errorf("run = %d, want %d: a missing local DB means nothing was analysed", got, exitUsage)
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// TestScanZeroPackagesGuardsAgainstFalseAllClear exercises the guard directly:
// the local DB directory exists and is fully readable, but contains zero
// package entries. Without the len(pkgs) == 0 guard in sweep this would
// produce zero findings, zero gaps and exit 0 -- a confident all-clear on a
// scan that read nothing.
func TestScanZeroPackagesGuardsAgainstFalseAllClear(t *testing.T) {
	root := t.TempDir()
	if err := os.MkdirAll(filepath.Join(root, "var/lib/pacman/local"), 0o755); err != nil {
		t.Fatal(err)
	}
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "-offline-root", root}, &stdout, &stderr)
	if got != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstdout: %s\nstderr: %s", got, exitIncomplete, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "nothing to analyse") {
		t.Errorf("stdout missing the zero-population gap reason:\n%s", stdout.String())
	}
}

// TestFlagPositionIsPermutationInvariant covers the trap in the plan's own
// step 4 (`go run ./cmd/aurvet scan --no-network`): flags after the
// subcommand must parse identically to flags before it, or --no-network
// silently fails to suppress the network dial it exists to suppress.
func TestFlagPositionIsPermutationInvariant(t *testing.T) {
	root := writeMinimalRoot(t)

	var beforeOut, beforeErr bytes.Buffer
	before := run([]string{"-no-network", "scan", "-offline-root", root}, &beforeOut, &beforeErr)

	var afterOut, afterErr bytes.Buffer
	after := run([]string{"scan", "-no-network", "-offline-root", root}, &afterOut, &afterErr)

	if before != after {
		t.Fatalf("flag before subcommand = %d, flag after = %d, want equal", before, after)
	}
	if beforeOut.String() != afterOut.String() {
		t.Errorf("stdout differs by flag position:\nbefore: %s\nafter:  %s", beforeOut.String(), afterOut.String())
	}
}

// TestUnknownFlagAfterSubcommandIsUsageError guards the other half of the
// permutation loop: a genuinely bad flag placed after the subcommand must
// still be caught, not swallowed as a stray positional.
func TestUnknownFlagAfterSubcommandIsUsageError(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"scan", "--nope"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("run = %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// TestJSONFlagDoubleDashEmitsParseableSchema covers the spec synopsis's
// double-dash spelling and pins the equality that keeps the JSON document and
// the process's actual exit status honest: exit_code in the document must
// equal the code run() returned, because JSON computes both by calling the
// same report.ExitCode.
func TestJSONFlagDoubleDashEmitsParseableSchema(t *testing.T) {
	root := writeMinimalRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "--json", "-offline-root", root}, &stdout, &stderr)

	var doc struct {
		SchemaVersion int `json:"schema_version"`
		ExitCode      int `json:"exit_code"`
	}
	if err := json.Unmarshal(stdout.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not valid JSON: %v\nstdout: %s\nstderr: %s", err, stdout.String(), stderr.String())
	}
	if doc.SchemaVersion == 0 {
		t.Errorf("schema_version missing or zero: %+v", doc)
	}
	if doc.ExitCode != got {
		t.Errorf("document exit_code = %d, process exit code = %d, want equal", doc.ExitCode, got)
	}
}

// TestMinSeverityRejectsUnknownValue: a typo'd floor must never silently
// become "info" and change a scan's verdict class -- it is a usage error
// naming the values ParseSeverity accepts.
func TestMinSeverityRejectsUnknownValue(t *testing.T) {
	root := writeMinimalRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "-offline-root", root, "-min-severity=criticl"}, &stdout, &stderr)
	if got != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
	}
	for _, want := range []string{"info", "suspicious", "critical"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing accepted value %q:\n%s", want, stderr.String())
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// The floor-vs-coverage precedence itself (a below-floor finding rendered but
// not raising the exit code above what Complete() dictates) cannot be
// exercised at this layer without a live or faked network call: check.Provenance
// never emits a Finding on the --no-network path (only Gaps), and cmd/aurvet's
// scan always builds its aur.Client against the real AUR endpoint, with no
// seam to inject a fake one. That logic is exercised directly against
// report.ExitCode instead -- see internal/report/report_test.go's
// TestExitCodeFindingsBelowFloorNoGaps and TestGapOutranksFindings, which
// cover exactly this floor-vs-gap precedence.

// TestExplainRequiresAnArgument covers the missing-fingerprint usage error.
func TestExplainRequiresAnArgument(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"explain"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("run = %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// TestExplainUnknownFingerprintIsAUsageError covers the unknown-id path: the
// error from report.Explain must reach stderr, exit 2, and stdout must stay
// empty -- report.Explain never partially writes before returning its error.
func TestExplainUnknownFingerprintIsAUsageError(t *testing.T) {
	root := writeMinimalRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"explain", "-no-network", "-offline-root", root, "deadbeef"}, &stdout, &stderr)
	if got != exitUsage {
		t.Fatalf("run = %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
	}
	if !strings.Contains(stderr.String(), "deadbeef") {
		t.Errorf("stderr missing the unknown id:\n%s", stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// TestScanRejectsTrailingArguments: scan takes no positional operands, and
// trailing garbage must not be silently ignored.
func TestScanRejectsTrailingArguments(t *testing.T) {
	var stdout, stderr bytes.Buffer
	if got := run([]string{"scan", "extra-arg"}, &stdout, &stderr); got != exitUsage {
		t.Errorf("run = %d, want %d\nstderr: %s", got, exitUsage, stderr.String())
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// Ported from report-sec's demonstration suite (item (b)), verbatim from
// /tmp/aurvet-sec/cmd/aurvet/sec_main_test.go:22-133. No committed tarball:
// open item O-1 asked for a runtime-generated one, and this is that generator.
// ---------------------------------------------------------------------------

// writeSyncDB writes syncPath/<repo>.db as a gzipped tar in the shape pacman
// actually ships: one `<name>-<ver>-<rel>/` directory entry per package plus its
// `desc` member. Verified against /var/lib/pacman/sync/core.db on the reference
// system, whose first entries are `acl-2.4.0-1/` and `acl-2.4.0-1/desc`.
func writeSyncDB(t *testing.T, syncPath, repo string, pkgs map[string]string) {
	t.Helper()
	if err := os.MkdirAll(syncPath, 0o755); err != nil {
		t.Fatal(err)
	}
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for name, ver := range pkgs {
		dir := name + "-" + ver + "/"
		if err := tw.WriteHeader(&tar.Header{Name: dir, Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		body := "%FILENAME%\n" + name + "-" + ver + "-x86_64.pkg.tar.zst\n\n%NAME%\n" + name + "\n\n%VERSION%\n" + ver + "\n\n"
		if err := tw.WriteHeader(&tar.Header{
			Name: dir + "desc", Typeflag: tar.TypeReg, Mode: 0o644, Size: int64(len(body)),
		}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write([]byte(body)); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(syncPath, repo+".db"), buf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
}

// writeLocalPkg writes one readable local-DB package entry.
func writeLocalPkg(t *testing.T, dbPath, dir, name, base string) string {
	t.Helper()
	full := filepath.Join(dbPath, dir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "%NAME%\n" + name + "\n\n%VERSION%\n1.0-1\n\n%BASE%\n" + base + "\n\n%VALIDATION%\npgp\n\n"
	if err := os.WriteFile(filepath.Join(full, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "files"), []byte("%FILES%\nusr/bin/"+name+"\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	return full
}

// coveredRoot builds an --offline-root whose every installed package is named by
// the sync DB, i.e. len(foreign) == 0 with a POPULATED name oracle. That is the
// one population that reaches check.Provenance's first early return, and the
// only fixture from which scan can legitimately reach exit 0 without touching
// the network -- Provenance returns before any aur.Client method is called.
func coveredRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	db := filepath.Join(root, "var/lib/pacman/local")
	writeLocalPkg(t, db, "zlib-1.3.1-2", "zlib", "zlib")
	writeLocalPkg(t, db, "acl-2.4.0-1", "acl", "acl")
	writeSyncDB(t, filepath.Join(root, "var/lib/pacman/sync"), "core",
		map[string]string{"zlib": "1.3.1-2", "acl": "2.4.0-1"})
	return root
}

// TestNoNetworkWithZeroForeignPackagesStillExitsIncomplete pins the isolated
// case that makes "--no-network never exits 0" structurally true: zero foreign
// packages against a POPULATED name oracle, where check.Provenance returns at
// its len(foreign) == 0 early return and contributes no gap of its own. Without
// sweep's unconditional !network gap this run would exit 0 having deliberately
// skipped every network check. The sync DB is generated at runtime (open item
// O-1) in the shape pacman ships -- verified against /var/lib/pacman/sync/core.db,
// whose first entries are `acl-2.4.0-1/` and `acl-2.4.0-1/desc`.
func TestNoNetworkWithZeroForeignPackagesStillExitsIncomplete(t *testing.T) {
	root := coveredRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-no-network", "-offline-root", root}, &stdout, &stderr)
	if got != exitIncomplete {
		t.Fatalf("run = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, exitIncomplete, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "0 foreign / 2 total") {
		t.Errorf("fixture did not reach len(foreign) == 0:\n%s", stdout.String())
	}
	if !strings.Contains(stdout.String(), "no AUR provenance check was attempted") {
		t.Errorf("sweep-level --no-network gap missing:\n%s", stdout.String())
	}
}

// TestCoveredRootExitsCleanWithoutTouchingTheNetwork is its control and the
// only hermetic exit-0 path in cmd/aurvet: Provenance returns before any
// aur.Client method is called, so no request is made.
func TestCoveredRootExitsCleanWithoutTouchingTheNetwork(t *testing.T) {
	root := coveredRoot(t)
	var stdout, stderr bytes.Buffer
	got := run([]string{"scan", "-offline-root", root}, &stdout, &stderr)
	if got != exitClean {
		t.Fatalf("run = %d, want %d\nstdout:\n%s\nstderr:\n%s", got, exitClean, stdout.String(), stderr.String())
	}
	if !strings.Contains(stdout.String(), "coverage: complete") {
		t.Errorf("expected complete coverage:\n%s", stdout.String())
	}
}

// failingWriter succeeds n times, then always returns err. Used to simulate a
// broken stdout (closed pipe, full disk) partway through rendering.
type failingWriter struct {
	n   int
	err error
}

func (w *failingWriter) Write(p []byte) (int, error) {
	if w.n > 0 {
		w.n--
		return len(p), nil
	}
	return 0, w.err
}

// TestRenderFailureMasksTheIncompleteExitCode (finding 5, report-sec). Ported
// from sec_main_test.go, inverted to assert the FIXED behaviour: a rendering
// failure must not downgrade the analysis's own contractual exit code. The
// analysis behind this fixture is complete-but-gapped (exitIncomplete == 3);
// a broken stdout must still report 3, not 2 -- 2 says "fix your command
// line", 3 says "this host was not fully checked", and a wrapper that retries
// on 2 and pages on 3 does exactly the wrong thing if rendering silently
// downgrades the second into the first.
func TestRenderFailureMasksTheIncompleteExitCode(t *testing.T) {
	root := coveredRoot(t)
	var stderr bytes.Buffer
	// Sanity: with a working writer this invocation is exit 3.
	var ok bytes.Buffer
	if got := run([]string{"scan", "-no-network", "-offline-root", root}, &ok, &stderr); got != exitIncomplete {
		t.Fatalf("precondition: run = %d, want %d", got, exitIncomplete)
	}
	w := &failingWriter{n: 0, err: errors.New("broken pipe")}
	got := run([]string{"scan", "-no-network", "-offline-root", root}, w, &stderr)
	if got != exitIncomplete {
		t.Fatalf("run with a failing stdout = %d, want %d: the analysis was complete and "+
			"incomplete-coverage is its contractual code; a rendering failure must not "+
			"downgrade it to a usage error\nstderr: %s", got, exitIncomplete, stderr.String())
	}
}

// TestInvalidMinSeverityIsAcceptedOutsideScan (finding 6, the half that is
// ours; report-sec). Ported from sec_main_test.go, inverted to assert the
// FIXED behaviour: -min-severity is parsed and validated once in run, before
// any subcommand dispatch, so a typo'd floor is rejected identically whether
// the command is scan, doctor or explain. A typo in a wrapper that smoke-tests
// against `doctor` must not silently pass and then change the verdict class of
// every `scan`.
func TestInvalidMinSeverityIsAcceptedOutsideScan(t *testing.T) {
	var stdout, stderr bytes.Buffer
	got := run([]string{"-min-severity", "criticl", "doctor"}, &stdout, &stderr)
	if got != exitUsage {
		t.Fatalf("run = %d, want %d (doctor must reject an invalid -min-severity too)\nstderr: %s",
			got, exitUsage, stderr.String())
	}
	for _, want := range []string{"info", "suspicious", "critical"} {
		if !strings.Contains(stderr.String(), want) {
			t.Errorf("stderr missing accepted value %q:\n%s", want, stderr.String())
		}
	}
	if stdout.Len() != 0 {
		t.Errorf("stdout not empty on a usage-error path: %s", stdout.String())
	}
}

// ---------------------------------------------------------------------------
// Task 4 (finding coverage hole, report-sec): sweep hardcoded aur.NewHTTP with
// no seam, so no hermetic test could reach scan's exit-0 path through a
// network check -- which is why report-sec findings 1 and 4 survived task 9's
// own suite, and why explain-with-a-finding was untestable. sweep now takes an
// aur.Client parameter (nil means "build the real one"); run's own signature
// is untouched, so these tests call sweep directly, the same way runScan and
// runExplain do internally, and drive report.ExitCode/report.Explain the same
// way those callers do.
// ---------------------------------------------------------------------------

// evilRoot builds on coveredRoot by adding one more installed package, "evil",
// that is absent from the sync DB -- i.e. genuinely foreign -- so Provenance
// has something to ask the injected client about.
func evilRoot(t *testing.T) string {
	t.Helper()
	root := coveredRoot(t)
	writeLocalPkg(t, filepath.Join(root, "var/lib/pacman/local"), "evil-1.0-1", "evil", "evil")
	return root
}

// TestScanWithInjectedFakeProducesRealFinding: a foreign package the injected
// aur.Fake has never heard of, and no tombstone for it either, resolves to the
// ordinary aur-absent finding at SevSuspicious -- exit 1, the finding
// rendered, coverage complete. This is the exit-1 path through a network
// check that no test could reach before the seam existed.
func TestScanWithInjectedFakeProducesRealFinding(t *testing.T) {
	root := evilRoot(t)
	cfg, err := config.Resolve(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	cl := aur.Fake{Known: map[string]aur.Pkg{}, Tombstones: map[string]string{}}
	res, summary, err := sweep(context.Background(), cfg, false, cl)
	if err != nil {
		t.Fatalf("sweep error: %v", err)
	}
	if !res.Complete() {
		t.Fatalf("expected complete coverage; got gaps %+v", res.Gaps)
	}
	floor, err := report.ParseSeverity(cfg.MinSeverity)
	if err != nil {
		t.Fatal(err)
	}
	if code := report.ExitCode(res, floor); code != exitFindings {
		t.Fatalf("ExitCode = %d, want %d", code, exitFindings)
	}
	var buf bytes.Buffer
	if err := report.Text(&buf, res, summary); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(buf.String(), "evil") {
		t.Errorf("finding for evil not rendered:\n%s", buf.String())
	}
}

// TestExplainResolvesFindingFromInjectedFake: the fingerprint report.Text
// renders for the finding above must resolve through report.Explain, exactly
// as runExplain does, and the rendered rationale must carry the Limits text
// (INV-6: every finding states what it cannot prove).
func TestExplainResolvesFindingFromInjectedFake(t *testing.T) {
	root := evilRoot(t)
	cfg, err := config.Resolve(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	cl := aur.Fake{Known: map[string]aur.Pkg{}, Tombstones: map[string]string{}}
	res, _, err := sweep(context.Background(), cfg, false, cl)
	if err != nil {
		t.Fatalf("sweep error: %v", err)
	}
	if len(res.Findings) != 1 {
		t.Fatalf("expected exactly one finding; got %+v", res.Findings)
	}
	id := report.FindingID(res.Findings[0])
	var buf bytes.Buffer
	if err := report.Explain(&buf, res, id); err != nil {
		t.Fatalf("explain failed to resolve a real finding: %v", err)
	}
	if !strings.Contains(buf.String(), res.Findings[0].Limits) {
		t.Errorf("explain output missing the finding's Limits text:\n%s", buf.String())
	}
}

// TestScanWithFakeErrProducesGapsNeverAbsent: an RPC failure on a foreign
// package must produce coverage gaps, never an aur-absent finding -- a
// transport hiccup must never be able to trigger a finding. Exit 3, not 1.
func TestScanWithFakeErrProducesGapsNeverAbsent(t *testing.T) {
	root := evilRoot(t)
	cfg, err := config.Resolve(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	cl := aur.Fake{Err: errors.New("dial tcp: no route to host")}
	res, _, err := sweep(context.Background(), cfg, false, cl)
	if err != nil {
		t.Fatalf("sweep error: %v", err)
	}
	for _, f := range res.Findings {
		if f.RuleID == "aur-absent" {
			t.Fatalf("an RPC failure produced an aur-absent finding: %+v", f)
		}
	}
	if res.Complete() {
		t.Fatal("an RPC failure must leave coverage incomplete")
	}
	floor, err := report.ParseSeverity(cfg.MinSeverity)
	if err != nil {
		t.Fatal(err)
	}
	if code := report.ExitCode(res, floor); code != exitIncomplete {
		t.Fatalf("ExitCode = %d, want %d", code, exitIncomplete)
	}
}
