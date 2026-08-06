// internal/collect/collect_test.go
package collect

import (
	"bytes"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/safe"
)

// payloadSHA256 is the digest of testdata/collect/payload.txt as reported by
// sha256sum(1). Computed outside Go on purpose: a bug in this package must not
// be able to define its own expected answer.
const (
	payloadSHA256 = "ed6656b46899bda2eaddcecf19edb370b456c526f9c929b2cdd081dfbb07fa97"
	payloadPath   = "../../testdata/collect/payload.txt"
	payloadSize   = 95

	mtreeFixture     = "../../testdata/mtree/a52dec.mtree.gz"
	truncatedFixture = "../../testdata/mtree/truncated.mtree.gz"
)

// fixtureRoot materializes the tree described in testdata/collect/README.md and
// returns the absolute path of the tree to scan plus the temp dir that contains
// it (the latter so a test can assert that nothing outside the tree was read).
//
//	<tmp>/outside/secret.txt              never to be read
//	<tmp>/root/usr/bin/hello              regular file, payload bytes
//	<tmp>/root/usr/share/doc/readme       regular file, payload bytes
//	<tmp>/root/usr/lib/liba.so         -> ../../lib/liba.so.1  (".." in target)
//	<tmp>/root/usr/escdir              -> ../../outside        (escaping dir link)
//	<tmp>/root/usr/bin/pipe               fifo
//	<tmp>/root/usr/bin/locked             mode 0000
//	<tmp>/root/proc/kmsg                  in the default skip list
//	<tmp>/root/var/lib/pacman/local/a52dec-0.8.0-1/{desc,files,mtree}
//	<tmp>/root/var/lib/pacman/local/corrupt-1-1/{desc,files,mtree}   truncated gz
//	<tmp>/root/var/lib/pacman/local/ALPM_DB_VERSION
func fixtureRoot(t *testing.T) (root, tmp string) {
	t.Helper()
	tmp = t.TempDir()
	root = filepath.Join(tmp, "root")

	mkdir := func(p string) {
		t.Helper()
		if err := os.MkdirAll(filepath.Join(tmp, p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	write := func(p string, b []byte, mode os.FileMode) {
		t.Helper()
		if err := os.WriteFile(filepath.Join(tmp, p), b, mode); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	link := func(target, p string) {
		t.Helper()
		if err := os.Symlink(target, filepath.Join(tmp, p)); err != nil {
			t.Fatalf("symlink %s: %v", p, err)
		}
	}

	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read payload fixture: %v", err)
	}
	mtreeGz, err := os.ReadFile(mtreeFixture)
	if err != nil {
		t.Fatalf("read mtree fixture: %v", err)
	}
	truncatedGz, err := os.ReadFile(truncatedFixture)
	if err != nil {
		t.Fatalf("read truncated mtree fixture: %v", err)
	}

	mkdir("outside")
	write("outside/secret.txt", []byte("SECRET-OUTSIDE-THE-ROOT\n"), 0o644)

	mkdir("root/usr/bin")
	mkdir("root/usr/share/doc")
	mkdir("root/usr/lib")
	mkdir("root/proc")
	write("root/usr/bin/hello", payload, 0o755)
	write("root/usr/share/doc/readme", payload, 0o644)
	write("root/usr/bin/locked", payload, 0o000)
	write("root/proc/kmsg", []byte("pseudo\n"), 0o644)
	link("../../lib/liba.so.1", "root/usr/lib/liba.so")
	link("../../outside", "root/usr/escdir")
	if err := syscall.Mkfifo(filepath.Join(tmp, "root/usr/bin/pipe"), 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	db := "root/var/lib/pacman/local"
	mkdir(db + "/a52dec-0.8.0-1")
	write(db+"/a52dec-0.8.0-1/desc", []byte("%NAME%\na52dec\n"), 0o644)
	write(db+"/a52dec-0.8.0-1/files", []byte("%FILES%\nusr/bin/hello\n"), 0o644)
	write(db+"/a52dec-0.8.0-1/mtree", mtreeGz, 0o644)
	mkdir(db + "/corrupt-1-1")
	write(db+"/corrupt-1-1/desc", []byte("%NAME%\ncorrupt\n"), 0o644)
	write(db+"/corrupt-1-1/files", []byte("%FILES%\n"), 0o644)
	write(db+"/corrupt-1-1/mtree", truncatedGz, 0o644)
	write(db+"/ALPM_DB_VERSION", []byte("9\n"), 0o644)

	return root, tmp
}

// testConfig is the fixture configuration: the whole tree, one worker unless the
// test says otherwise, and a timeout long enough not to fire by accident.
func testConfig(root string) Config {
	cfg := DefaultConfig(root)
	cfg.Workers = 4
	cfg.SubjectTimeout = 30 * time.Second
	return cfg
}

func mustCollect(t *testing.T, cfg Config) Raw {
	t.Helper()
	raw, err := Collect(cfg)
	if err != nil {
		t.Fatalf("Collect: %v", err)
	}
	return raw
}

func fileFor(t *testing.T, raw Raw, path string) File {
	t.Helper()
	for _, f := range raw.Files {
		if f.Path == path {
			return f
		}
	}
	t.Fatalf("no evidence for %q; have %s", path, pathsOf(raw))
	return File{}
}

func pathsOf(raw Raw) string {
	var b strings.Builder
	for _, f := range raw.Files {
		b.WriteString(f.Path)
		b.WriteString(" ")
	}
	return b.String()
}

func gapFor(raw Raw, subject string) (finding.Gap, bool) {
	for _, g := range raw.Gaps {
		if g.Subject == subject {
			return g, true
		}
	}
	return finding.Gap{}, false
}

func TestCollectHashesRegularFilesFromTheConfinedFd(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	for _, path := range []string{"./usr/bin/hello", "./usr/share/doc/readme"} {
		f := fileFor(t, raw, path)
		if f.Kind != KindFile {
			t.Errorf("%s: Kind = %q, want %q", path, f.Kind, KindFile)
		}
		if f.SHA256 != payloadSHA256 {
			t.Errorf("%s: SHA256 = %q, want %q", path, f.SHA256, payloadSHA256)
		}
		if f.Size != payloadSize {
			t.Errorf("%s: Size = %d, want %d", path, f.Size, payloadSize)
		}
		if f.Ino == 0 || f.Dev == 0 {
			t.Errorf("%s: identity not recorded (dev=%d ino=%d)", path, f.Dev, f.Ino)
		}
	}
	if got := fileFor(t, raw, "./usr/bin/hello").Mode; got != 0o755 {
		t.Errorf("hello: Mode = %#o, want 0755 (permission bits only, comparable with mtree mode=)", got)
	}
}

// The one shape that must never be resolved: 4,145 legitimate link targets on
// the reference system contain "..", so a collector that resolved them would
// manufacture findings. The target is recorded as bytes and the link is not read.
func TestCollectRecordsSymlinkTargetsUnresolved(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	f := fileFor(t, raw, "./usr/lib/liba.so")
	if f.Kind != KindLink {
		t.Fatalf("Kind = %q, want %q", f.Kind, KindLink)
	}
	if f.Link != "../../lib/liba.so.1" {
		t.Errorf("Link = %q, want the recorded target verbatim", f.Link)
	}
	if f.SHA256 != "" {
		t.Errorf("SHA256 = %q: a symlink must not be resolved and hashed", f.SHA256)
	}
}

// An escaping directory symlink is recorded as what it is and not descended.
// Descending it would put content from outside the tree into the evidence under
// an in-tree path, which is worse than missing it.
func TestCollectDoesNotDescendDirectorySymlinks(t *testing.T) {
	root, tmp := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	f := fileFor(t, raw, "./usr/escdir")
	if f.Kind != KindLink {
		t.Errorf("Kind = %q, want %q", f.Kind, KindLink)
	}
	for _, got := range raw.Files {
		if strings.Contains(got.Path, "secret") {
			t.Fatalf("evidence %q reaches outside the tree (%s)", got.Path, tmp)
		}
		if got.SHA256 != "" && strings.HasPrefix(got.Path, "./usr/escdir/") {
			t.Fatalf("descended an escaping symlink: %q", got.Path)
		}
	}
}

// A fifo where a regular file might have been is refused by the S_ISREG gate,
// and -- the property worth asserting -- without hanging. A blocking open on a
// fifo is denial of tool with no panic to recover from.
func TestCollectRefusesAFifoWithoutHanging(t *testing.T) {
	root, _ := fixtureRoot(t)
	done := make(chan Raw, 1)
	go func() {
		raw, err := Collect(testConfig(root))
		if err == nil {
			done <- raw
		}
	}()
	select {
	case raw := <-done:
		f := fileFor(t, raw, "./usr/bin/pipe")
		if f.Kind != KindOther {
			t.Errorf("Kind = %q, want %q", f.Kind, KindOther)
		}
		if f.SHA256 != "" {
			t.Errorf("SHA256 = %q: a fifo has no content to hash", f.SHA256)
		}
	case <-time.After(20 * time.Second):
		t.Fatal("Collect hung on a fifo")
	}
}

func TestCollectGapsAnUnreadableFile(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is not a refusal for uid 0, so this asserts nothing")
	}
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	g, ok := gapFor(raw, "./usr/bin/locked")
	if !ok {
		t.Fatalf("no gap for an unreadable file; gaps=%v", raw.Gaps)
	}
	if !strings.Contains(g.Reason, "permission denied") {
		t.Errorf("gap reason = %q, want the refusal named", g.Reason)
	}
	// And it must not also appear as examined: a file cannot be both.
	for _, f := range raw.Files {
		if f.Path == "./usr/bin/locked" {
			t.Errorf("unreadable file also reported as examined: %+v", f)
		}
	}
	if raw.Complete() {
		t.Error("Complete() = true with an unreadable file present")
	}
}

// Raw DB bytes are buffered VERBATIM. The gzip magic assertion is the phase
// boundary made testable: had collect decompressed anything, these bytes would
// not be a gzip member any more.
func TestCollectBuffersDatabaseBytesWithoutInterpretingThem(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	want, err := os.ReadFile(mtreeFixture)
	if err != nil {
		t.Fatal(err)
	}
	var got *Package
	for i := range raw.Packages {
		if raw.Packages[i].Dir == "a52dec-0.8.0-1" {
			got = &raw.Packages[i]
		}
	}
	if got == nil {
		t.Fatalf("package not buffered; have %d packages", len(raw.Packages))
	}
	if !bytes.Equal(got.MTree, want) {
		t.Errorf("MTree buffered %d bytes, want the %d fixture bytes verbatim", len(got.MTree), len(want))
	}
	if !bytes.HasPrefix(got.MTree, []byte{0x1f, 0x8b}) {
		t.Error("MTree does not start with the gzip magic: collect decompressed it, which belongs after the privilege drop")
	}
	if !bytes.Contains(got.Desc, []byte("%NAME%")) {
		t.Errorf("Desc = %q, want the raw desc bytes", got.Desc)
	}
	if !bytes.Contains(got.FileList, []byte("%FILES%")) {
		t.Errorf("FileList = %q, want the raw files bytes", got.FileList)
	}
}

// A corrupt gzip is not collect's problem. It buffers the bytes and returns no
// error: refusing here would make a parse-time failure into a privileged-phase
// failure, and the whole point of the split is that a parser bug is an
// unprivileged bug.
func TestCollectBuffersACorruptArchiveWithoutError(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	for _, p := range raw.Packages {
		if p.Dir != "corrupt-1-1" {
			continue
		}
		if len(p.MTree) == 0 {
			t.Fatal("corrupt archive not buffered")
		}
		if g, ok := gapFor(raw, "corrupt-1-1"); ok {
			t.Errorf("collect gapped a corrupt archive it was not asked to read: %q", g.Reason)
		}
		return
	}
	t.Fatalf("corrupt-1-1 absent from %d buffered packages", len(raw.Packages))
}

// ALPM_DB_VERSION is a file, not a package directory. It must not become a
// package, and must not become a gap either -- it is the entire benign
// non-directory population of that directory (measured: 1410 dirs, one such
// file).
func TestCollectIgnoresTheDatabaseVersionFile(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	for _, p := range raw.Packages {
		if p.Dir == "ALPM_DB_VERSION" {
			t.Error("ALPM_DB_VERSION buffered as a package")
		}
	}
	if g, ok := gapFor(raw, "ALPM_DB_VERSION"); ok {
		t.Errorf("ALPM_DB_VERSION gapped: %q", g.Reason)
	}
}

func TestCollectSkipsConfiguredSubtreesAndSaysSo(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	for _, f := range raw.Files {
		if strings.HasPrefix(f.Path, "./proc/") {
			t.Errorf("walked a skipped subtree: %q", f.Path)
		}
	}
	found := false
	for _, s := range raw.Skipped {
		if s == "./proc" {
			found = true
		}
	}
	if !found {
		t.Errorf("Raw.Skipped = %v, want ./proc listed: a skip the report cannot see is a silent hole", raw.Skipped)
	}
}

// A file rewritten between its open and its digest is a fact about the scan's
// timing, not about the package. It must be a gap naming that, never a digest
// mismatch and never a published hash.
func TestCollectReportsMidScanMutationAsAGap(t *testing.T) {
	root, _ := fixtureRoot(t)
	target := filepath.Join(root, "usr/bin/hello")

	cfg := testConfig(root)
	cfg.Workers = 1
	beforeHashForTest = func(rel string) {
		if rel != "./usr/bin/hello" {
			return
		}
		if err := os.WriteFile(target, []byte("REWRITTEN UNDER THE DESCRIPTOR\n"), 0o755); err != nil {
			t.Errorf("mutating fixture: %v", err)
		}
	}
	t.Cleanup(func() { beforeHashForTest = nil })

	raw := mustCollect(t, cfg)
	g, ok := gapFor(raw, "./usr/bin/hello")
	if !ok {
		t.Fatalf("no gap for a mutated file; gaps=%v", raw.Gaps)
	}
	if !strings.Contains(g.Reason, "mutated during scan") {
		t.Errorf("gap reason = %q, want it to name the mutation", g.Reason)
	}
	for _, f := range raw.Files {
		if f.Path == "./usr/bin/hello" && f.SHA256 != "" {
			t.Errorf("published a digest for a file that moved underneath us: %q", f.SHA256)
		}
	}
}

// The case that kills processes. A panic raised inside a worker goroutine must
// become one gap attributed to its subject, the other subjects must still be
// examined, and the scan must complete at exit 3 -- with 3 outranking the
// finding that is also present.
func TestCollectContainsAPanicInAWorkerGoroutine(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.Workers = 4
	beforeHashForTest = func(rel string) {
		if rel == "./usr/bin/hello" {
			panic("crafted metadata")
		}
	}
	t.Cleanup(func() { beforeHashForTest = nil })

	raw := mustCollect(t, cfg)

	g, ok := gapFor(raw, "./usr/bin/hello")
	if !ok {
		t.Fatalf("no gap for a panicking subject; gaps=%v", raw.Gaps)
	}
	if !strings.Contains(g.Reason, "panicked during analysis") || !strings.Contains(g.Reason, "crafted metadata") {
		t.Errorf("gap reason = %q, want the contained panic named", g.Reason)
	}
	// The scan completed: the sibling file was still examined.
	if f := fileFor(t, raw, "./usr/share/doc/readme"); f.SHA256 != payloadSHA256 {
		t.Errorf("sibling subject not examined after the panic: %+v", f)
	}

	res := finding.Result{
		Gaps: raw.Gaps,
		Findings: []finding.Finding{{
			RuleID: "TEST-001", SubjectKind: "package", Subject: "pkg-c",
			Severity: finding.SevCritical, Summary: "fixture finding", Limits: "fixture only",
		}},
	}
	if code := report.ExitCode(res, finding.SevSuspicious); code != 3 {
		t.Errorf("ExitCode = %d, want 3 (incomplete coverage outranks findings)", code)
	}
}

func TestCollectBoundsAHangingSubject(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.Workers = 2
	cfg.SubjectTimeout = 100 * time.Millisecond

	release := make(chan struct{})
	t.Cleanup(func() { close(release) })
	beforeHashForTest = func(rel string) {
		if rel == "./usr/bin/hello" {
			<-release
		}
	}
	t.Cleanup(func() { beforeHashForTest = nil })

	start := time.Now()
	raw := mustCollect(t, cfg)
	if elapsed := time.Since(start); elapsed > 30*time.Second {
		t.Fatalf("Collect took %v: the per-subject deadline did not bound the hang", elapsed)
	}
	g, ok := gapFor(raw, "./usr/bin/hello")
	if !ok {
		t.Fatalf("no gap for a hanging subject; gaps=%v", raw.Gaps)
	}
	if !strings.Contains(g.Reason, safe.ErrTimeout.Error()) {
		t.Errorf("gap reason = %q, want it to name the timeout", g.Reason)
	}
	if f := fileFor(t, raw, "./usr/share/doc/readme"); f.SHA256 != payloadSHA256 {
		t.Errorf("sibling subject not examined despite the hang: %+v", f)
	}
}

// INV-4: Collect is a pure function of (root, cfg). The same tree at two
// different absolute locations must yield identical evidence, which is only true
// if nothing consulted the process working directory or an ambient path.
func TestCollectIsAPureFunctionOfRootAndConfig(t *testing.T) {
	rootA, _ := fixtureRoot(t)
	rootB, _ := fixtureRoot(t)

	a := mustCollect(t, testConfig(rootA))
	b := mustCollect(t, testConfig(rootB))

	if len(a.Files) != len(b.Files) {
		t.Fatalf("%d vs %d files from identical trees", len(a.Files), len(b.Files))
	}
	for i := range a.Files {
		x, y := a.Files[i], b.Files[i]
		if x.Path != y.Path || x.Kind != y.Kind || x.SHA256 != y.SHA256 || x.Link != y.Link {
			t.Errorf("entry %d differs: %+v vs %+v", i, x, y)
		}
	}
	if len(a.Gaps) != len(b.Gaps) {
		t.Errorf("%d vs %d gaps from identical trees", len(a.Gaps), len(b.Gaps))
	}
}

// Order is part of the evidence: a report diffed against a previous run must not
// churn because the kernel returned dirents in another order.
func TestCollectEvidenceIsSorted(t *testing.T) {
	root, _ := fixtureRoot(t)
	raw := mustCollect(t, testConfig(root))

	for i := 1; i < len(raw.Files); i++ {
		if raw.Files[i-1].Path >= raw.Files[i].Path {
			t.Fatalf("files not sorted ascending at %d: %q then %q", i, raw.Files[i-1].Path, raw.Files[i].Path)
		}
	}
	for i := 1; i < len(raw.Packages); i++ {
		if raw.Packages[i-1].Dir >= raw.Packages[i].Dir {
			t.Fatalf("packages not sorted ascending at %d", i)
		}
	}
}

func TestCollectRefusesARelativeRoot(t *testing.T) {
	cfg := DefaultConfig("testdata")
	if _, err := Collect(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig: a relative root is an ambient path (INV-4)", err)
	}
}

func TestCollectRefusesADatabasePathOutsideTheRoot(t *testing.T) {
	root, tmp := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.DBPath = filepath.Join(tmp, "outside")
	if _, err := Collect(cfg); !errors.Is(err, ErrConfig) {
		t.Fatalf("err = %v, want ErrConfig for a DB path outside the tree", err)
	}
}

// The buffer ceiling is what keeps a hostile local database from being a memory
// exhaustion primitive against the privileged phase. Exceeding it is a gap, not
// an abort: the packages that fit are still evidence.
func TestCollectEnforcesTheBufferCeiling(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.MaxBufferBytes = 512

	raw := mustCollect(t, cfg)
	if raw.BufferedBytes > cfg.MaxBufferBytes {
		t.Errorf("BufferedBytes = %d, over the %d ceiling", raw.BufferedBytes, cfg.MaxBufferBytes)
	}
	if raw.Complete() {
		t.Fatal("Complete() = true after refusing to buffer: that is a silent hole")
	}
	var named bool
	for _, g := range raw.Gaps {
		if strings.Contains(g.Reason, "buffer") {
			named = true
		}
	}
	if !named {
		t.Errorf("gaps %v do not say the buffer ceiling stopped the collection", raw.Gaps)
	}
	// Files are streamed, never buffered, so hashing is unaffected by the cap.
	if f := fileFor(t, raw, "./usr/bin/hello"); f.SHA256 != payloadSHA256 {
		t.Errorf("file hashing affected by the metadata buffer ceiling: %+v", f)
	}
}

// The per-file ceiling: one absurd DB file must not consume the whole budget.
func TestCollectRefusesAnOversizedDatabaseFile(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.MaxDBFileBytes = 16

	raw := mustCollect(t, cfg)
	if _, ok := gapFor(raw, "a52dec-0.8.0-1/mtree"); !ok {
		t.Errorf("no gap for an oversized DB file; gaps=%v", raw.Gaps)
	}
	for _, p := range raw.Packages {
		if len(p.MTree) > int(cfg.MaxDBFileBytes) {
			t.Errorf("%s: buffered %d bytes over the %d per-file ceiling", p.Dir, len(p.MTree), cfg.MaxDBFileBytes)
		}
	}
}

// A missing local database is a gap for the whole subject, not a crash: an
// offline root handed to the tool may not have one.
func TestCollectGapsAMissingDatabase(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.DBPath = filepath.Join(root, "var/lib/pacman/nonexistent")

	raw := mustCollect(t, cfg)
	if len(raw.Packages) != 0 {
		t.Errorf("%d packages from a nonexistent database", len(raw.Packages))
	}
	if _, ok := gapFor(raw, "var/lib/pacman/nonexistent"); !ok {
		t.Errorf("no gap for a missing database; gaps=%v", raw.Gaps)
	}
}

// Extra raw files (P1-C's surface files: unit files, hooks) are buffered by the
// privileged phase too, because anything phase 1 did not buffer is unavailable
// to analysis by construction. A missing one is a gap, not an error.
func TestCollectBuffersRequestedExtraFiles(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := testConfig(root)
	cfg.BufferPaths = []string{"./usr/share/doc/readme", "./usr/nonexistent"}

	raw := mustCollect(t, cfg)
	if got := raw.Buffered["./usr/share/doc/readme"]; len(got) != payloadSize {
		t.Errorf("buffered %d bytes for readme, want %d", len(got), payloadSize)
	}
	if _, ok := gapFor(raw, "./usr/nonexistent"); !ok {
		t.Errorf("no gap for a requested file that is absent; gaps=%v", raw.Gaps)
	}
}

// ---------------------------------------------------------------------------
// The recorded paths: phase 1's hash set, learned from the plain-text `files`
// ---------------------------------------------------------------------------

// recordedPaths is the whole of what phase 1 is permitted to interpret, so what
// it accepts and what it refuses is asserted directly rather than inferred from
// a scan's output. Every refusal below is measured to have a population of zero
// on the reference system: 386,645 recorded non-directory entries, none of them
// absolute, none containing a ".." component, none carrying a NUL.
func TestRecordedPathsIsANameListAndNothingMore(t *testing.T) {
	list := "%FILES%\n" +
		"usr/bin/hello\n" +
		"usr/lib/\n" + // a directory: nothing to open it for
		"usr/share/doc/read me.txt\n" + // a literal space; `files` does not vis-escape
		"\n" +
		"%BACKUP%\n" +
		"etc/foo.conf\td41d8cd98f00b204e9800998ecf8427e\n" +
		"%FILES%\n" +
		"usr/bin/second\n"

	paths, bad := recordedPaths([]byte(list))
	want := []string{"usr/bin/hello", "usr/share/doc/read me.txt", "usr/bin/second"}
	if strings.Join(paths, "|") != strings.Join(want, "|") {
		t.Errorf("paths = %q, want %q", paths, want)
	}
	if len(bad) != 0 {
		t.Errorf("a benign list produced refusals: %q", bad)
	}
	// A %BACKUP% line carries a second tab-separated field. Reading it as a path
	// would produce a name no open can ever match, which is a manufactured
	// "missing file" finding on every %BACKUP% entry on the system.
	for _, p := range paths {
		if strings.Contains(p, "\t") {
			t.Errorf("a %%BACKUP%% line was read as a path: %q", p)
		}
	}
}

func TestRecordedPathsRefusesEveryHostileShape(t *testing.T) {
	hostile := []string{
		"/etc/passwd",
		"usr/../../etc/passwd",
		"./../etc/passwd",
		"usr//bin/x",
		"usr/bin/\x00foo",
		".",
		"..",
	}
	for _, h := range hostile {
		paths, bad := recordedPaths([]byte("%FILES%\n" + h + "\n"))
		if len(paths) != 0 {
			t.Errorf("%q was accepted as a path: %q", h, paths)
		}
		if len(bad) != 1 || bad[0] != h {
			t.Errorf("%q was not reported as refused: %q", h, bad)
		}
	}
}

// A path outside the %FILES% section is not a path. `files` has no nesting and
// no escaping, but it does have sections, and reading a %BACKUP% digest as a
// filename would be interpreting a field.
func TestRecordedPathsIgnoresEverythingOutsideTheFilesSection(t *testing.T) {
	paths, bad := recordedPaths([]byte("%BACKUP%\netc/foo.conf\tdeadbeef\nusr/bin/never\n"))
	if len(paths) != 0 || len(bad) != 0 {
		t.Errorf("paths=%q bad=%q, want neither: nothing outside %%FILES%% is a path", paths, bad)
	}
}

// recordedConfig scans the fixture root's recorded paths at the given policy,
// walking nothing but the database (which is what a scan below paranoid does).
func recordedConfig(root string, policy RecordedPolicy) Config {
	cfg := testConfig(root)
	cfg.Walk = []string{"var/lib/pacman/local"}
	cfg.Recorded = policy
	return cfg
}

// writeFileList replaces one fixture package's `files` with an explicit list.
func writeFileList(t *testing.T, root, pkgDir string, paths ...string) {
	t.Helper()
	body := "%FILES%\n" + strings.Join(paths, "\n") + "\n"
	p := filepath.Join(root, "var/lib/pacman/local", pkgDir, "files")
	if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

// The recorded paths are opened even though the walk never enters their
// subtree. This is the property the staged model rests on: phase 1 knows what to
// read without decompressing an mtree, so the gzip and the vis(3) unescaping
// stay on the unprivileged side of the drop.
func TestCollectOpensRecordedPathsWithoutWalkingThem(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello", "usr/lib/liba.so", "usr/share/doc/gone")

	raw := mustCollect(t, recordedConfig(root, RecordedAll))

	hello := fileFor(t, raw, "./usr/bin/hello")
	if hello.Kind != KindFile || hello.SHA256 != payloadSHA256 {
		t.Errorf("recorded regular file: kind=%s sha256=%s", hello.Kind, hello.SHA256)
	}
	// A recorded symlink: O_NOFOLLOW refuses the open, readlinkat reads the
	// target, and the target is never resolved.
	link := fileFor(t, raw, "./usr/lib/liba.so")
	if link.Kind != KindLink || link.Link != "../../lib/liba.so.1" {
		t.Errorf("recorded symlink: kind=%s link=%q", link.Kind, link.Link)
	}
	// A recorded path that is not there is an ANSWER, established from a
	// confined open, and must not be a coverage gap.
	gone := fileFor(t, raw, "./usr/share/doc/gone")
	if gone.Kind != KindAbsent {
		t.Errorf("absent recorded path: kind=%s, want %s", gone.Kind, KindAbsent)
	}
	if g, ok := gapFor(raw, "./usr/share/doc/gone"); ok {
		t.Errorf("an observed absence was reported as a coverage gap: %+v", g)
	}
}

// A recorded path that could not be examined is a gap AND carries KindUnread, so
// the analyse phase can consume the one gap instead of raising a second.
func TestCollectMarksAnUnreadableRecordedPath(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is readable and the refusal cannot be provoked")
	}
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/locked")

	raw := mustCollect(t, recordedConfig(root, RecordedAll))
	locked := fileFor(t, raw, "./usr/bin/locked")
	if locked.Kind != KindUnread {
		t.Fatalf("kind = %s, want %s", locked.Kind, KindUnread)
	}
	if locked.Unread == "" {
		t.Error("KindUnread carries no reason")
	}
	if _, ok := gapFor(raw, "./usr/bin/locked"); !ok {
		t.Errorf("an unreadable recorded path produced no gap: %+v", raw.Gaps)
	}
}

// RecordedSecurity decides from the fstat of the descriptor it would hash, not
// from anything a package recorded. usr/bin/hello is 0755 and is read;
// usr/share/doc/readme is 0644 and is not.
func TestRecordedSecurityKeysOnTheDescriptorsOwnMode(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello", "usr/share/doc/readme")

	raw := mustCollect(t, recordedConfig(root, RecordedSecurity))
	if got := fileFor(t, raw, "./usr/bin/hello").SHA256; got != payloadSHA256 {
		t.Errorf("an executable was not hashed at RecordedSecurity: sha256=%q", got)
	}
	readme := fileFor(t, raw, "./usr/share/doc/readme")
	if readme.SHA256 != "" {
		t.Errorf("a non-executable was hashed at RecordedSecurity: %s", readme.SHA256)
	}
	if readme.Kind != KindFile || readme.Size != payloadSize {
		t.Errorf("the unhashed file lost its metadata: kind=%s size=%d", readme.Kind, readme.Size)
	}

	// Same file, made executable: the answer changes, because the mode that
	// decides what runs is the one on disk.
	if err := os.Chmod(filepath.Join(root, "usr/share/doc/readme"), 0o755); err != nil {
		t.Fatal(err)
	}
	raw = mustCollect(t, recordedConfig(root, RecordedSecurity))
	if got := fileFor(t, raw, "./usr/share/doc/readme").SHA256; got != payloadSHA256 {
		t.Errorf("a file made executable after installation was not hashed: sha256=%q", got)
	}
}

// A watched path is hashed at RecordedSecurity whatever its mode: a unit file
// decides what runs without being runnable itself.
func TestRecordedSecurityHashesWatchedPathsWhateverTheirMode(t *testing.T) {
	root, _ := fixtureRoot(t)
	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(filepath.Join(root, "usr/lib/systemd/system"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(root, "usr/lib/systemd/system/foo.service"), payload, 0o644); err != nil {
		t.Fatal(err)
	}
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/lib/systemd/system/foo.service")

	raw := mustCollect(t, recordedConfig(root, RecordedSecurity))
	if got := fileFor(t, raw, "./usr/lib/systemd/system/foo.service").SHA256; got != payloadSHA256 {
		t.Errorf("a mode-0644 unit file was not hashed at RecordedSecurity: sha256=%q", got)
	}
}

// RecordedStat is tier meta: every recorded path is still opened once, confined,
// and fstat'd, and nothing at all is read.
func TestRecordedStatOpensEverythingAndHashesNothing(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello", "usr/bin/pipe")

	raw := mustCollect(t, recordedConfig(root, RecordedStat))
	hello := fileFor(t, raw, "./usr/bin/hello")
	if hello.SHA256 != "" {
		t.Errorf("RecordedStat hashed a file: %s", hello.SHA256)
	}
	if hello.Size != payloadSize || hello.Mode != 0o755 {
		t.Errorf("RecordedStat lost the descriptor's own metadata: size=%d mode=%o", hello.Size, hello.Mode)
	}
	// A fifo standing where a file was recorded is still established from a
	// descriptor rather than guessed at, and the open must not block.
	if got := fileFor(t, raw, "./usr/bin/pipe").Kind; got != KindOther {
		t.Errorf("fifo kind = %s, want %s", got, KindOther)
	}
}

// RecordedIgnore is the zero value: a caller that does not ask for the recorded
// paths does not silently get them, and does not silently pay for them.
func TestRecordedIgnoreVisitsNoRecordedPath(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello")

	raw := mustCollect(t, recordedConfig(root, RecordedIgnore))
	for _, f := range raw.Files {
		if f.Path == "./usr/bin/hello" {
			t.Fatalf("RecordedIgnore opened a recorded path anyway: %+v", f)
		}
	}
}

// The sweep enumerates without reading: it is what the setuid and unowned checks
// need, and making it hash would silently turn a metadata question into a
// whole-tree read (28,239 MiB on the reference system against 20,497 MiB of
// recorded content).
func TestSweepEnumeratesWithoutHashing(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := recordedConfig(root, RecordedIgnore)
	cfg.Sweep = []string{"usr"}

	raw := mustCollect(t, cfg)
	hello := fileFor(t, raw, "./usr/bin/hello")
	if hello.SHA256 != "" {
		t.Errorf("the sweep hashed a file: %s", hello.SHA256)
	}
	if hello.Mode != 0o755 || hello.Size != payloadSize {
		t.Errorf("the sweep did not describe the file from its descriptor: mode=%o size=%d", hello.Mode, hello.Size)
	}
}

// A sweep subtree that does not exist is an answer, not a hole. usr, etc, opt,
// boot and srv are a standard set and not every root has every one; gapping the
// missing ones would put a permanent exit 3 on every machine without /opt.
// A subtree that EXISTS and cannot be opened is still a gap.
func TestAMissingSweepSubtreeIsNotAGap(t *testing.T) {
	root, _ := fixtureRoot(t)
	cfg := recordedConfig(root, RecordedIgnore)
	cfg.Sweep = []string{"usr", "opt", "srv"}

	raw := mustCollect(t, cfg)
	for _, g := range raw.Gaps {
		if g.Subject == "./opt" || g.Subject == "./srv" {
			t.Errorf("a sweep subtree that simply does not exist was gapped: %+v", g)
		}
	}
	if _, ok := gapFor(raw, "./usr/escdir"); ok {
		t.Log("escaping directory link recorded, as expected")
	}
}

// A recorded path the walk already found is opened ONCE. Two leaves for one path
// would be a second resolution of the same name, which is exactly the TOCTOU
// window internal/fsx exists to close.
func TestARecordedPathIsNotOpenedTwiceWhenTheSweepAlsoFindsIt(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello", "usr/lib/liba.so")
	cfg := recordedConfig(root, RecordedAll)
	cfg.Sweep = []string{"usr"}

	raw := mustCollect(t, cfg)
	seen := map[string]int{}
	for _, f := range raw.Files {
		seen[f.Path]++
	}
	for _, p := range []string{"./usr/bin/hello", "./usr/lib/liba.so"} {
		if seen[p] != 1 {
			t.Errorf("%s produced %d evidence records, want 1", p, seen[p])
		}
	}
	// The recorded policy still wins over the sweep's: a path the sweep would
	// only stat is hashed because the database records it.
	if got := fileFor(t, raw, "./usr/bin/hello").SHA256; got != payloadSHA256 {
		t.Errorf("the sweep downgraded a recorded path to metadata only: sha256=%q", got)
	}
}

// A hostile recorded path is refused before any syscall, and the refusal is
// attributed to the PACKAGE that recorded it rather than to whichever errno the
// kernel happened to produce.
func TestAHostileRecordedPathIsAGapAgainstItsPackage(t *testing.T) {
	root, _ := fixtureRoot(t)
	writeFileList(t, root, "a52dec-0.8.0-1", "usr/bin/hello", "../../../etc/shadow")

	raw := mustCollect(t, recordedConfig(root, RecordedAll))
	g, ok := gapFor(raw, "a52dec-0.8.0-1")
	if !ok {
		t.Fatalf("a hostile recorded path produced no gap: %+v", raw.Gaps)
	}
	if !strings.Contains(g.Reason, "../../../etc/shadow") {
		t.Errorf("the gap does not name the path it refused: %q", g.Reason)
	}
	// The rest of the package is still examined: one crafted record costs one
	// coverage gap, not the package (INV-9).
	if got := fileFor(t, raw, "./usr/bin/hello").SHA256; got != payloadSHA256 {
		t.Errorf("a hostile record cost the rest of the package: sha256=%q", got)
	}
}
