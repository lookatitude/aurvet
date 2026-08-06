package main

import (
	"bytes"
	"compress/gzip"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/config"
)

// ---------------------------------------------------------------------------
// Fixtures for the wired scan.
//
// Everything here builds a WHOLE OFFLINE ROOT -- a local database, a sync
// database naming its packages (so foreignness is decided from a populated
// oracle and no network check is attempted), an mtree, and the files the mtree
// records. That combination is the minimum a full-tier scan needs: a root with
// a database and no files on disk exercises nothing but the missing-file rule.
// ---------------------------------------------------------------------------

// mtreeFile is one recorded path: what the mtree claims, and what is written to
// disk. Recorded and OnDisk differ exactly when a test wants a mismatch.
type mtreeFile struct {
	Rel      string // root-relative, no leading slash
	Recorded string // the content the mtree records the digest of
	OnDisk   string // the content actually written; "" writes nothing
}

// writePackageRoot writes one package: its local-DB entry (desc, files, mtree),
// a sync-DB entry naming it, and the files themselves.
func writePackageRoot(t *testing.T, root, name, version string, files []mtreeFile) {
	t.Helper()
	db := filepath.Join(root, "var/lib/pacman/local", name+"-"+version)
	if err := os.MkdirAll(db, 0o755); err != nil {
		t.Fatal(err)
	}
	desc := "%NAME%\n" + name + "\n\n%VERSION%\n" + version + "\n\n%BASE%\n" + name + "\n\n%VALIDATION%\npgp\n\n"
	var list strings.Builder
	list.WriteString("%FILES%\n")

	// The mtree, in the spelling pacman writes: a #mtree header, a /set line,
	// and one "./"-rooted record per path.
	var mt strings.Builder
	mt.WriteString("#mtree\n/set type=file uid=0 gid=0 mode=644\n")
	for _, f := range files {
		list.WriteString(f.Rel + "\n")
		sum := sha256.Sum256([]byte(f.Recorded))
		fmt.Fprintf(&mt, "./%s time=1700000000.0 size=%d sha256digest=%s\n",
			f.Rel, len(f.Recorded), hex.EncodeToString(sum[:]))
		if f.OnDisk == "" {
			continue
		}
		full := filepath.Join(root, f.Rel)
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(f.OnDisk), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	list.WriteString("\n")

	if err := os.WriteFile(filepath.Join(db, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "files"), []byte(list.String()), 0o644); err != nil {
		t.Fatal(err)
	}
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	if _, err := zw.Write([]byte(mt.String())); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(db, "mtree"), gzbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	writeSyncDB(t, filepath.Join(root, "var/lib/pacman/sync"), "core",
		map[string]string{name: version})

	// etc/passwd: without it the per-user surface scan cannot enumerate accounts
	// and raises a coverage gap, which would make every exit code below 3 for a
	// reason that has nothing to do with what the test is asserting.
	if _, err := os.Stat(filepath.Join(root, "etc/passwd")); err != nil {
		if err := os.MkdirAll(filepath.Join(root, "etc"), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(filepath.Join(root, "etc/passwd"),
			[]byte("root:x:0:0::/root:/usr/bin/bash\n"), 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

// integrityRoot is a root with one package whose single file is on disk with
// onDisk content while its mtree records recorded.
func integrityRoot(t *testing.T, recorded, onDisk string) string {
	t.Helper()
	root := t.TempDir()
	writePackageRoot(t, root, "zlib", "1.3.1-2", []mtreeFile{
		{Rel: "usr/bin/zlib", Recorded: recorded, OnDisk: onDisk},
	})
	return root
}

// resolveForTest resolves the configuration for an offline root the way run()
// does, so a test that calls the pipeline directly gets the same paths a CLI
// invocation would.
func resolveForTest(t *testing.T, root string) config.Config {
	t.Helper()
	cfg, err := config.Resolve(root, os.Geteuid())
	if err != nil {
		t.Fatal(err)
	}
	return cfg
}

func scanOut(t *testing.T, args ...string) (int, string, string) {
	t.Helper()
	var stdout, stderr bytes.Buffer
	code := run(args, &stdout, &stderr)
	return code, stdout.String(), stderr.String()
}

// ---------------------------------------------------------------------------
// The --tier flag
// ---------------------------------------------------------------------------

// A typo'd tier must be refused, never silently defaulted: a wrong tier name in
// a systemd unit would otherwise downgrade verification permanently and
// invisibly.
func TestUnknownTierIsAUsageErrorAndNeverADefault(t *testing.T) {
	code, stdout, stderr := scanOut(t, "scan", "-tier", "fuII", "-offline-root", t.TempDir())
	if code != exitUsage {
		t.Fatalf("run = %d, want %d\nstdout: %s\nstderr: %s", code, exitUsage, stdout, stderr)
	}
	if !strings.Contains(stderr, "meta") || !strings.Contains(stderr, "paranoid") {
		t.Errorf("the refusal does not name the accepted tiers: %s", stderr)
	}
	if stdout != "" {
		t.Errorf("a usage error wrote to stdout: %s", stdout)
	}
}

// The tier is validated before dispatch, like -min-severity: a wrapper that
// smoke-tests its flags against `doctor` must not pass with a tier `scan` would
// reject.
func TestUnknownTierIsRejectedOutsideScanToo(t *testing.T) {
	code, _, _ := scanOut(t, "doctor", "-tier", "fuII")
	if code != exitUsage {
		t.Fatalf("doctor with a bad tier = %d, want %d", code, exitUsage)
	}
}

// ---------------------------------------------------------------------------
// Integrity: internal/collect -> mtree -> Tier.Verify -> check.Integrity
// ---------------------------------------------------------------------------

// The whole point of the lane: `aurvet scan` must actually compare file
// contents against the digests the package recorded.
func TestScanVerifiesFileContentsAgainstTheRecordedDigest(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered\n")
	code, stdout, stderr := scanOut(t, "scan", "-offline-root", root)
	if !strings.Contains(stdout, "does not match the digest its package recorded") {
		t.Fatalf("no digest mismatch reported for a file that does not match its mtree\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}
	if !strings.Contains(stdout, "observed sha256=") {
		t.Errorf("the finding does not carry the digest it observed:\n%s", stdout)
	}
	if code != exitFindings {
		t.Errorf("exit = %d, want %d (a suspicious finding, complete coverage)\nstdout:\n%s\nstderr:\n%s",
			code, exitFindings, stdout, stderr)
	}
}

// The other direction, which is the one that makes the finding above mean
// something: a file that DOES match must produce no finding and exit 0.
func TestScanIsCleanWhenContentsMatchTheRecordedDigest(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "the packaged bytes\n")
	code, stdout, stderr := scanOut(t, "scan", "-offline-root", root)
	if code != exitClean {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitClean, stdout, stderr)
	}
	if strings.Contains(stdout, "integrity-") || strings.Contains(stdout, "digest its package recorded") {
		t.Errorf("an integrity rule fired on a matching file:\n%s", stdout)
	}
}

// Tier meta reads no contents, so it must NOT report a mismatch it could not
// have seen -- and must say that it did not look (INV-3).
func TestMetaTierDoesNotHashAndReportsTheHoleAsCoverage(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered!!!!!!!!!!!\n")
	code, stdout, stderr := scanOut(t, "scan", "-tier", "meta", "-offline-root", root)
	if strings.Contains(stdout, "observed sha256") {
		t.Errorf("tier meta reported a hashed comparison it never performed:\n%s", stdout)
	}
	if !strings.Contains(stdout, "integrity-coverage") {
		t.Errorf("tier meta did not report its own blindness as a coverage gap:\n%s\nstderr: %s", stdout, stderr)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d: a scan that verified nothing is not a clean scan", code, exitIncomplete)
	}
}

// The tier reported is the tier EXECUTED. A --tier full over a root whose
// packages carry no mtree hashes nothing, and must say meta rather than repeat
// the flag back.
func TestReportedTierIsTheTierExecutedNotTheTierRequested(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	// Remove the one mtree, leaving a database entry that cannot be verified.
	if err := os.Remove(filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/mtree")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := scanOut(t, "scan", "-tier", "full", "-offline-root", root)
	if !strings.Contains(stdout+stderr, `tier meta`) {
		t.Errorf("a scan that hashed nothing reported a tier it did not execute\nstdout:\n%s\nstderr:\n%s",
			stdout, stderr)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
}

// A live scan states the tier it ran at, because every verdict below it is
// qualified by that one word.
func TestScanStatesItsTier(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	_, stdout, _ := scanOut(t, "scan", "-offline-root", root)
	if !strings.Contains(stdout, "tier full") {
		t.Errorf("the report does not state the tier it ran at:\n%s", stdout)
	}
}

// An mtree that cannot be parsed is a coverage gap naming the package, never
// silence: a hostile local database is exactly where a parser is attacked, and a
// package nobody could verify must not read as a package that verified clean
// (INV-9).
func TestUnparseableMtreeIsAGapNamingThePackage(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	// Valid gzip framing, garbage inside: this reaches the mtree parser rather
	// than failing in the collector, which is the path under test.
	var gzbuf bytes.Buffer
	zw := gzip.NewWriter(&gzbuf)
	if _, err := zw.Write([]byte("not an mtree at all\n")); err != nil {
		t.Fatal(err)
	}
	if err := zw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/mtree"),
		gzbuf.Bytes(), 0o644); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := scanOut(t, "scan", "-json", "-offline-root", root)
	rep := decodeReport(t, stdout)
	found := false
	for _, g := range rep.CoverageGaps {
		if g.RuleID == "integrity-mtree" && g.Subject == "zlib" {
			found = true
		}
	}
	if !found {
		t.Errorf("an unparseable mtree produced no gap naming the package: %+v", rep.CoverageGaps)
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
}

// The derived exemptions must be WIRED, not merely derivable. A %BACKUP% file
// that differs from its recorded digest is what pacman itself expects, so it must
// not be reported at full tier -- and must be re-examined at paranoid, where the
// exemption itself is what is under audit.
func TestBackupFileIsExemptAtFullAndAuditedAtParanoid(t *testing.T) {
	root := t.TempDir()
	writePackageRoot(t, root, "zlib", "1.3.1-2", []mtreeFile{
		{Rel: "etc/zlib.conf", Recorded: "shipped\n", OnDisk: "edited by the administrator\n"},
	})
	// The %BACKUP% entry, in the local database's own spelling: path<TAB>md5.
	files := filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/files")
	body, err := os.ReadFile(files)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(files, append(body,
		[]byte("%BACKUP%\netc/zlib.conf\td41d8cd98f00b204e9800998ecf8427e\n\n")...), 0o644); err != nil {
		t.Fatal(err)
	}

	code, stdout, stderr := scanOut(t, "scan", "-offline-root", root)
	if strings.Contains(stdout, "digest its package recorded") {
		t.Errorf("a %%BACKUP%% file was reported at tier full; pacman itself expects it to differ\n%s", stdout)
	}
	if code != exitClean {
		t.Errorf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitClean, stdout, stderr)
	}

	// Paranoid re-examines it, at info, with the exemption named -- so the hole
	// can be audited rather than trusted.
	code, stdout, _ = scanOut(t, "scan", "-json", "-tier", "paranoid", "-offline-root", root)
	rep := decodeReport(t, stdout)
	found := false
	for _, f := range rep.Findings {
		if f.RuleID == "integrity-digest-mismatch" && f.Severity == "info" {
			found = true
		}
	}
	if !found {
		t.Errorf("tier paranoid did not re-examine the exempt path: %+v", rep.Findings)
	}
	if code != exitClean {
		t.Errorf("paranoid exit = %d, want %d: an expected difference must not raise the verdict class",
			code, exitClean)
	}
}

// ---------------------------------------------------------------------------
// Surfaces and correlation
// ---------------------------------------------------------------------------

// The INV-8 gate, through the CLI and with every rule family running together.
// Rules calibrated in isolation can interact; a clean machine that produces
// criticals once they are combined is a calibration failure.
func TestBenignRootsProduceNoCriticalsThroughTheCLI(t *testing.T) {
	for _, name := range []string{"stock", "cruft"} {
		t.Run(name, func(t *testing.T) {
			root := filepath.Join("..", "..", "testdata", "roots", name)
			_, stdout, stderr := scanOut(t, "scan", "-no-network", "-offline-root", root)
			if strings.Contains(stdout, "CRITICAL") {
				t.Errorf("critical finding on the %s root:\n%s\nstderr:\n%s", name, stdout, stderr)
			}
		})
	}
}

// The acceptance shape: the malicious fixture must yield exactly one critical,
// and it must be the correlated cluster rather than any single surface rule.
func TestMaliciousRootYieldsOneCorrelatedCriticalThroughTheCLI(t *testing.T) {
	root := maliciousCLIRoot(t)
	// -json, because rule IDs are what this asserts and the text view prints a
	// finding's fingerprint rather than its rule.
	code, stdout, stderr := scanOut(t, "scan", "-json", "-no-network", "-offline-root", root)
	rep := decodeReport(t, stdout)
	var crit []string
	for _, f := range rep.Findings {
		if f.Severity == "critical" {
			crit = append(crit, f.RuleID+" on "+f.Subject)
		}
	}
	if len(crit) != 1 {
		t.Fatalf("criticals = %v, want exactly one correlated cluster\nstderr:\n%s", crit, stderr)
	}
	if !strings.HasPrefix(crit[0], "correlated-cluster ") {
		t.Errorf("the one critical is %q, want the correlated cluster: a single surface rule reaching "+
			"critical means correlation was bypassed", crit[0])
	}
	// --no-network gaps the AUR check, so 3 outranks 1 here. That is INV-3 and
	// is asserted rather than worked around.
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
}

// A surface check's own coverage gap must reach the report. It is the half of
// INV-3 that a findings-only merge silently loses: the surface scans would still
// report what they found and stop reporting what they could not look at.
func TestSurfaceCoverageGapsReachTheReport(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	// No account list: the per-user surfaces cannot be enumerated, which is a
	// gap and not an absence.
	if err := os.Remove(filepath.Join(root, "etc/passwd")); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := scanOut(t, "scan", "-json", "-offline-root", root)
	rep := decodeReport(t, stdout)
	found := false
	for _, g := range rep.CoverageGaps {
		if g.RuleID == "surface-misc-coverage" {
			found = true
		}
	}
	if !found {
		t.Errorf("no surface coverage gap in the report: %+v", rep.CoverageGaps)
	}
	if rep.CoverageComplete {
		t.Error("coverage_complete is true on a scan that could not enumerate the accounts")
	}
	if code != exitIncomplete {
		t.Errorf("exit = %d, want %d", code, exitIncomplete)
	}
}

// maliciousCLIRoot is testdata/roots/malicious copied to a temp dir with the
// planted mtimes restored (git does not preserve them) and a sync database
// written, so that librewolf-fix-bin reads as foreign against a POPULATED
// oracle. Both are required for the temporal attribution key; without them the
// cluster is real but unattributed, and an unattributed cluster is not critical.
func maliciousCLIRoot(t *testing.T) string {
	t.Helper()
	src := filepath.Join("..", "..", "testdata", "roots", "malicious")
	dst := t.TempDir()
	if err := copyTree(src, dst); err != nil {
		t.Fatalf("copy malicious root: %v", err)
	}
	// The offsets are correlate's own fixture calibration, kept in step with
	// internal/correlate/correlate_test.go's maliciousPlanted: the planted files
	// sit just after librewolf-fix-bin's %INSTALLDATE% of 1770099000, which is
	// what the temporal key joins on.
	const installDate int64 = 1770099000
	for rel, sec := range map[string]int64{
		"usr/lib/systemd/inert-marker-initd":             installDate + 60,
		"etc/systemd/system/systemd-initd-inert.service": installDate + 61,
		"usr/lib/systemd/libinert-marker-preload.so":     installDate + 62,
		"etc/pacman.d/hooks/60-depmod.hook":              installDate + 63,
	} {
		p := filepath.Join(dst, rel)
		if _, err := os.Lstat(p); err != nil {
			continue
		}
		ts := time.Unix(sec, 0)
		if err := os.Chtimes(p, ts, ts); err != nil {
			t.Fatal(err)
		}
	}
	writeSyncDB(t, filepath.Join(dst, "var/lib/pacman/sync"), "core",
		map[string]string{"systemd": "257.2-1", "kmod": "33-1"})
	return dst
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(p string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		case d.Type()&os.ModeSymlink != 0:
			target, rerr := os.Readlink(p)
			if rerr != nil {
				return rerr
			}
			return os.Symlink(target, out)
		default:
			data, rerr := os.ReadFile(p)
			if rerr != nil {
				return rerr
			}
			info, ierr := d.Info()
			if ierr != nil {
				return ierr
			}
			return os.WriteFile(out, data, info.Mode().Perm())
		}
	})
}

// ---------------------------------------------------------------------------
// Privilege staging
// ---------------------------------------------------------------------------

// The staged-privilege model, asserted by ORDER rather than by the mere fact
// that the calls exist: a reduction after the first read protects nothing, and a
// drop before the last read turns coverage into gaps.
//
// The reads all live in phase 1 now, so the window they have to fall inside is
// the one between beforeCollectForTest and beforeVerifyForTest. Asserting
// against the COMPARISON phase instead would be asserting nothing: it performs
// no I/O, so its position relative to the drop cannot fail.
func TestPrivilegeIsReducedBeforeTheFirstReadAndDroppedAfterTheLast(t *testing.T) {
	var seq atomic.Int64
	var reduced, dropped int64
	origReduce, origDrop := privReduceToRead, privDropAll
	t.Cleanup(func() { privReduceToRead, privDropAll = origReduce, origDrop })
	privReduceToRead = func() error { reduced = seq.Add(1); return nil }
	privDropAll = func() error { dropped = seq.Add(1); return nil }

	var collectStart, firstCompare, lastCompare int64
	origCollect, origVerify := beforeCollectForTest, beforeVerifyForTest
	t.Cleanup(func() { beforeCollectForTest, beforeVerifyForTest = origCollect, origVerify })
	beforeCollectForTest = func() { collectStart = seq.Add(1) }
	beforeVerifyForTest = func() {
		n := seq.Add(1)
		if firstCompare == 0 {
			firstCompare = n
		}
		lastCompare = n
	}

	root := integrityRoot(t, "x", "x")
	if _, err := fullScan(t.Context(), pipeline{
		cfg:  resolveForTest(t, root),
		tier: check.TierFull,
		euid: 0, // the privileged path, without being root
	}); err != nil {
		t.Fatal(err)
	}
	if reduced == 0 || dropped == 0 {
		t.Fatalf("privilege was not staged: reduced=%d dropped=%d", reduced, dropped)
	}
	if collectStart == 0 || firstCompare == 0 {
		t.Fatalf("a phase did not run; the ordering assertion would pass vacuously: collect=%d compare=%d",
			collectStart, firstCompare)
	}
	if reduced > collectStart {
		t.Errorf("privilege was reduced (%d) after phase 1 began reading (%d)", reduced, collectStart)
	}
	if collectStart > firstCompare {
		t.Errorf("a comparison (%d) preceded the collection it compares against (%d)", firstCompare, collectStart)
	}
	if dropped < lastCompare {
		t.Errorf("privilege was dropped (%d) before the last comparison (%d)", dropped, lastCompare)
	}
}

// An unprivileged scan must not silently do less: it stages nothing, and every
// read it is refused becomes a gap.
func TestUnprivilegedScanStagesNothing(t *testing.T) {
	called := false
	origReduce := privReduceToRead
	t.Cleanup(func() { privReduceToRead = origReduce })
	privReduceToRead = func() error { called = true; return nil }

	root := integrityRoot(t, "x", "x")
	if _, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierFull, euid: 1000}); err != nil {
		t.Fatal(err)
	}
	if called {
		t.Error("an unprivileged scan called ReduceToRead; there is nothing to reduce and the failure would be reported as a refusal")
	}
}

// A refused reduction is not a scan that proceeds anyway. It exits 3: the
// analysis could not be performed under the model it promises.
func TestARefusedPrivilegeReductionIsNotASilentFullPrivilegeScan(t *testing.T) {
	origReduce := privReduceToRead
	t.Cleanup(func() { privReduceToRead = origReduce })
	privReduceToRead = func() error { return fmt.Errorf("capset refused") }

	root := integrityRoot(t, "x", "x")
	_, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierFull, euid: 0})
	if err == nil {
		t.Fatal("a refused reduction did not stop the scan")
	}
}

// ---------------------------------------------------------------------------
// Gaps and severity floors
// ---------------------------------------------------------------------------

// INV-3: exit 3 outranks exit 1 when four analysers' gaps are merged.
func TestGapsFromAnyAnalyserOutrankFindings(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered\n")
	// A second package whose mtree cannot be read: one gap, alongside the
	// finding the first package produces.
	writePackageRoot(t, root, "acl", "2.4.0-1", []mtreeFile{
		{Rel: "usr/bin/acl", Recorded: "a", OnDisk: "a"},
	})
	if err := os.Remove(filepath.Join(root, "var/lib/pacman/local/acl-2.4.0-1/mtree")); err != nil {
		t.Fatal(err)
	}
	code, stdout, stderr := scanOut(t, "scan", "-offline-root", root)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d (gaps outrank findings)\nstdout:\n%s\nstderr:\n%s",
			code, exitIncomplete, stdout, stderr)
	}
}

// --min-severity gates findings only. A gap must still force exit 3 with the
// floor at critical.
func TestMinSeverityNeverGatesAGap(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered\n")
	if err := os.Remove(filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/mtree")); err != nil {
		t.Fatal(err)
	}
	code, stdout, _ := scanOut(t, "scan", "-min-severity", "critical", "-offline-root", root)
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d: -min-severity gated a coverage gap\n%s", code, exitIncomplete, stdout)
	}
}

// ---------------------------------------------------------------------------
// baseline init's permitted path
// ---------------------------------------------------------------------------

// The evidence `baseline init` stands on must now come from a scan that
// verified contents and enumerated surfaces. Both of w5-bootstrap's structural
// refusals -- "tier meta" and "surfaces not collected" -- must be gone, and
// gone because the work happened.
func TestLiveEvidenceCarriesAFullTierAndASurfacesInventory(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	// One hook and one unit, so "the inventory is empty" cannot pass for "there
	// was nothing to inventory".
	writeFile(t, filepath.Join(root, "usr/share/libalpm/hooks/90-local.hook"),
		"[Trigger]\nOperation = Install\nType = Package\nTarget = *\n\n[Action]\nWhen = PostTransaction\nExec = /usr/bin/true\n")
	writeFile(t, filepath.Join(root, "etc/systemd/system/local.service"),
		"[Unit]\nDescription=local\n\n[Service]\nExecStart=/usr/bin/true\n")
	ev, err := liveEvidence(baselineEnv{
		cfg:      resolveForTest(t, root),
		euid:     1000,
		stateDir: t.TempDir(),
		noNet:    true,
		now:      time.Now(),
	}, check.TierFull)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tier != "full" {
		t.Errorf("tier = %q, want full", ev.Tier)
	}
	for _, g := range ev.Result.Gaps {
		if g.RuleID == "baseline-surfaces-not-collected" {
			t.Errorf("the surfaces gap is still declared: %s", g.Reason)
		}
		if g.RuleID == "integrity-coverage" && g.Subject == "files" {
			t.Errorf("the integrity gap is still declared wholesale: %s", g.Reason)
		}
	}
	if len(ev.Surfaces) == 0 {
		t.Error("no surfaces inventory was collected")
	}
	if len(ev.Packages) == 0 || ev.Packages[0].MtreeSHA256 == "" {
		t.Errorf("no mtree digest recorded: %+v", ev.Packages)
	}
}

// cliReport is the subset of the JSON document these tests read.
type cliReport struct {
	CoverageComplete bool `json:"coverage_complete"`
	Findings         []struct {
		RuleID   string `json:"rule_id"`
		Subject  string `json:"subject"`
		Severity string `json:"severity"`
	} `json:"findings"`
	CoverageGaps []struct {
		RuleID  string `json:"rule_id"`
		Subject string `json:"subject"`
	} `json:"coverage_gaps"`
}

func decodeReport(t *testing.T, out string) cliReport {
	t.Helper()
	var rep cliReport
	if err := json.Unmarshal([]byte(out), &rep); err != nil {
		t.Fatalf("stdout is not the JSON document (%v):\n%s", err, out)
	}
	return rep
}

// The other half of the same property, on the path that matters most: the tier a
// SIGNED baseline records is the tier the scan executed. A relabelling here would
// sign a manifest over contents nothing verified, which is the exact failure
// w5-bootstrap's refusal exists to prevent.
func TestLiveEvidenceReportsTheAchievedTierNotTheRequestedOne(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	if err := os.Remove(filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/mtree")); err != nil {
		t.Fatal(err)
	}
	ev, err := liveEvidence(baselineEnv{
		cfg:      resolveForTest(t, root),
		euid:     1000,
		stateDir: t.TempDir(),
		noNet:    true,
		now:      time.Now(),
	}, check.TierFull)
	if err != nil {
		t.Fatal(err)
	}
	if ev.Tier != "meta" {
		t.Errorf("tier = %q, want meta: nothing was verified, and `--tier full` must not relabel that", ev.Tier)
	}
}

func writeFile(t *testing.T, path, body string) {
	t.Helper()
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// ---------------------------------------------------------------------------
// The staged privilege model, as a property of what the phases can see
// ---------------------------------------------------------------------------

// TestIntegrityReadsNothingAfterPhaseOne is spec §11.1 asserted by CONSEQUENCE
// rather than by inspection: if the comparison phase still touched the
// filesystem, restoring the tampered file between the two phases would make the
// finding disappear.
//
// It has to be asserted this way. "The parse happens after the drop" is not
// observable from a test that cannot become root, but "the verdict does not
// change when the tree changes underneath the analyser" is, and it is the
// property that actually matters: after the drop this process holds nothing, so
// an analyser that re-read would be reading as an ordinary user and silently
// reporting less on exactly the files that need privilege.
func TestIntegrityReadsNothingAfterPhaseOne(t *testing.T) {
	root := integrityRoot(t, "the packaged bytes\n", "tampered\n")
	target := filepath.Join(root, "usr/bin/zlib")

	orig := beforeVerifyForTest
	t.Cleanup(func() { beforeVerifyForTest = orig })
	var once sync.Once
	beforeVerifyForTest = func() {
		// Between collection and comparison, put the file back exactly as the
		// package recorded it. A phase 2 that reads would now find a match.
		once.Do(func() {
			if err := os.WriteFile(target, []byte("the packaged bytes\n"), 0o644); err != nil {
				t.Error(err)
			}
		})
	}

	run, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierFull, euid: 1000})
	if err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range run.Result.Findings {
		if f.RuleID == "integrity-digest-mismatch" {
			found = true
		}
	}
	if !found {
		t.Fatalf("the mismatch vanished when the file was restored between the phases: the comparison "+
			"phase re-read the filesystem, which after the capability drop it cannot do\n%+v %+v",
			run.Result.Findings, run.Result.Gaps)
	}
}

// The evidence the comparison rests on comes from phase 1, so a file phase 1
// never opened produces no verdict at all rather than a fabricated one.
func TestAPathPhaseOneNeverOpenedYieldsNoVerdict(t *testing.T) {
	root := integrityRoot(t, "x", "x")
	// A path the mtree records and `files` does not: phase 1 learns what to open
	// from `files`, so this path is never opened and must become a gap.
	db := filepath.Join(root, "var/lib/pacman/local/zlib-1.3.1-2/files")
	body, err := os.ReadFile(db)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(db, []byte("%FILES%\n\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	_ = body

	run, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierFull, euid: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range run.Result.Findings {
		if strings.HasPrefix(f.RuleID, "integrity-") {
			t.Errorf("a path that was never opened produced a finding: %+v", f)
		}
	}
	found := false
	for _, g := range run.Result.Gaps {
		if g.RuleID == "integrity-digest-mismatch" && strings.Contains(g.Reason, "no observation") {
			found = true
		}
	}
	if !found {
		t.Fatalf("an unexamined path was not reported as a coverage gap (INV-3): %+v", run.Result.Gaps)
	}
}

// ---------------------------------------------------------------------------
// The unowned setuid sweep
// ---------------------------------------------------------------------------

// suidRoot builds a root with one package-owned setuid helper and one setuid
// binary no package claims.
func suidRoot(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	writePackageRoot(t, root, "util-linux", "2.41-1", []mtreeFile{
		{Rel: "usr/bin/mount", Recorded: "owned helper\n", OnDisk: "owned helper\n"},
	})
	// os.ModeSetuid, not 0o4755: Go's FileMode does not carry the Unix setuid bit
	// in its permission word, so the octal spelling would silently set 0o755 and
	// the fixture would assert nothing.
	if err := os.Chmod(filepath.Join(root, "usr/bin/mount"), 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	planted := filepath.Join(root, "usr/local/bin/backdoor")
	if err := os.MkdirAll(filepath.Dir(planted), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(planted, []byte("#!/bin/sh\nid\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(planted, 0o755|os.ModeSetuid); err != nil {
		t.Fatal(err)
	}
	return root
}

// integrity-unowned-setuid is a declared rule, so it must be able to fire. It
// fires at paranoid, which is the tier spec §13 assigns the unowned walk and the
// full SUID sweep to.
func TestUnownedSetuidFiresAtParanoid(t *testing.T) {
	root := suidRoot(t)
	run, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierParanoid, euid: 1000})
	if err != nil {
		t.Fatal(err)
	}
	var got []string
	for _, f := range run.Result.Findings {
		if f.RuleID == "integrity-unowned-setuid" {
			got = append(got, f.Subject)
		}
	}
	if len(got) != 1 || got[0] != "./usr/local/bin/backdoor" {
		t.Fatalf("unowned setuid subjects = %v, want exactly [./usr/local/bin/backdoor]\n%+v", got, run.Result.Findings)
	}
	// A package-owned setuid binary is ordinary and must not be reported: sudo,
	// ping and mount all look like this on every system.
	for _, f := range run.Result.Findings {
		if f.RuleID == "integrity-unowned-setuid" && strings.Contains(f.Subject, "mount") {
			t.Errorf("a package-owned setuid helper was reported: %+v", f)
		}
	}
}

// The same rule at the default tier says NOTHING, and that is by design rather
// than by accident: the metadata sweep it needs is what paranoid buys. Stated
// here because a rule that only fires at a non-default tier is otherwise
// indistinguishable from one that never fires.
func TestUnownedSetuidDoesNotFireBelowParanoid(t *testing.T) {
	root := suidRoot(t)
	for _, tier := range []check.Tier{check.TierMeta, check.TierTriage, check.TierFull} {
		t.Run(tier.String(), func(t *testing.T) {
			run, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: tier, euid: 1000})
			if err != nil {
				t.Fatal(err)
			}
			for _, f := range run.Result.Findings {
				if f.RuleID == "integrity-unowned-setuid" {
					t.Errorf("tier %s reported an unowned setuid file without the sweep that finds one: %+v", tier, f)
				}
			}
		})
	}
}

// The rule's limits must name the trees the sweep cannot see. "Full SUID sweep"
// is not full, and the limits text is where that gets said rather than a silent
// pass: a setuid binary in /tmp or a user's home is invisible at every tier.
func TestUnownedSetuidStatesWhatTheSweepCannotSee(t *testing.T) {
	root := suidRoot(t)
	run, err := fullScan(t.Context(), pipeline{cfg: resolveForTest(t, root), tier: check.TierParanoid, euid: 1000})
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range run.Result.Findings {
		if f.RuleID != "integrity-unowned-setuid" {
			continue
		}
		for _, want := range []string{"home", "tmp", "paranoid"} {
			if !strings.Contains(f.Limits, want) {
				t.Errorf("the limits do not mention %q, so the rule's blindness reaches nobody:\n%s", want, f.Limits)
			}
		}
		return
	}
	t.Fatal("no finding to inspect")
}
