// internal/check/tier_test.go
package check

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/mtree"
	"github.com/lookatitude/aurvet/internal/safe"
	"golang.org/x/sys/unix"
)

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// tierRoot builds a fixture root and returns it opened as an os.Root, which is
// the only handle Verify ever gets: --offline-root is a parameter, not a second
// code path (INV-4).
func tierRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	dir := t.TempDir()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root, dir
}

func writeAt(t *testing.T, dir, rel, content string, mode os.FileMode) string {
	t.Helper()
	p := filepath.Join(dir, rel)
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(p, []byte(content), mode); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(p, mode); err != nil {
		t.Fatal(err)
	}
	return p
}

// mtimeOf reads the mtime an mtree record would have to carry to agree with the
// file on disk.
func mtimeOf(t *testing.T, p string) float64 {
	t.Helper()
	var st unix.Stat_t
	if err := unix.Lstat(p, &st); err != nil {
		t.Fatal(err)
	}
	return float64(st.Mtim.Sec) + float64(st.Mtim.Nsec)/1e9
}

func TestParseTierDefaultsToFull(t *testing.T) {
	cases := map[string]Tier{
		"":         TierFull,
		"full":     TierFull,
		"meta":     TierMeta,
		"triage":   TierTriage,
		"paranoid": TierParanoid,
	}
	for in, want := range cases {
		got, err := ParseTier(in)
		if err != nil {
			t.Errorf("ParseTier(%q): %v", in, err)
			continue
		}
		if got != want {
			t.Errorf("ParseTier(%q) = %v, want %v", in, got, want)
		}
		if got.String() == "unknown" {
			t.Errorf("ParseTier(%q).String() = unknown", in)
		}
	}
	if _, err := ParseTier("quick"); err == nil {
		t.Error("ParseTier(\"quick\") returned no error; an unknown tier must not silently become a default")
	}
	if DefaultTier != TierFull {
		t.Errorf("DefaultTier = %v, want full", DefaultTier)
	}
}

func TestVerifyFullHashesTheFileItOpened(t *testing.T) {
	root, dir := tierRoot(t)
	writeAt(t, dir, "usr/bin/foo", "hello", 0o755)
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 5, SHA256: sha256Of("hello")}}

	obs := TierFull.Verify(root, entries, Exemptions{})
	o := obs["./usr/bin/foo"]
	if o.Kind != ObsHashed {
		t.Fatalf("kind = %v, want ObsHashed (err=%v)", o.Kind, o.Err)
	}
	if o.SHA256 != sha256Of("hello") {
		t.Errorf("sha256 = %s", o.SHA256)
	}
	if o.Size != 5 || o.Mode != 0o755 {
		t.Errorf("size/mode from the descriptor's fstat = %d/%o", o.Size, o.Mode)
	}
	if o.MtimeAssisted {
		t.Error("tier full marked an observation mtime-assisted")
	}
	if res := Integrity("foo", entries, obs, Exemptions{}, TierFull); len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("clean root produced output: %+v %+v", res.Findings, res.Gaps)
	}

	// Now the content diverges from the record: the same code path must report
	// it. (A check whose test passes with the check deleted is not a check.)
	writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	obs = TierFull.Verify(root, entries, Exemptions{})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/bin/foo")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v: %s", f.Severity, formatFinding(f))
	}
}

// A symlink standing where a regular file was recorded is refused unresolved,
// and that refusal is a coverage gap rather than a hash of the swap target.
func TestVerifyRefusesASymlinkWhereAFileWasRecorded(t *testing.T) {
	root, dir := tierRoot(t)
	writeAt(t, dir, "real/secret", "sensitive", 0o644)
	if err := os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../real/secret", filepath.Join(dir, "usr/bin/foo")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 5, SHA256: sha256Of("hello")}}

	obs := TierFull.Verify(root, entries, Exemptions{})
	o := obs["./usr/bin/foo"]
	if o.Kind != ObsUnreadable {
		t.Fatalf("kind = %v, want ObsUnreadable", o.Kind)
	}
	if !errors.Is(o.Err, fsx.ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", o.Err)
	}
	if o.SHA256 == sha256Of("sensitive") {
		t.Fatal("the swap target was hashed")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("a refusal produced a finding rather than a gap (INV-9): %+v", res.Findings)
	}
	if len(res.Gaps) != 1 {
		t.Errorf("want one gap, got %+v", res.Gaps)
	}
}

// A fifo where a file was recorded must not hang the scan: that would turn a
// hostile filesystem into a denial of the tool with no panic to recover from.
func TestVerifyRefusesAFifoWithoutBlocking(t *testing.T) {
	root, dir := tierRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "var/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "var/run/pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	entries := []mtree.Entry{{Path: "./var/run/pipe", Type: "file", SHA256: sha256Of("x")}}
	obs := TierFull.Verify(root, entries, Exemptions{})
	if got := obs["./var/run/pipe"].Kind; got != ObsUnreadable {
		t.Fatalf("kind = %v, want ObsUnreadable", got)
	}
	if !errors.Is(obs["./var/run/pipe"].Err, fsx.ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular", obs["./var/run/pipe"].Err)
	}
}

// Link targets are READ, never resolved. The dangling target here is the point:
// a resolving implementation would fail or manufacture a finding, and 4,145
// legitimate targets on the reference system contain "..".
func TestVerifyReadsLinkTargetsWithoutResolvingThem(t *testing.T) {
	root, dir := tierRoot(t)
	const target = "../../../nonexistent/../usr/lib/libfoo.so.1"
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{{Path: "./usr/lib/libfoo.so", Type: "link", Link: target}}

	obs := TierFull.Verify(root, entries, Exemptions{})
	o := obs["./usr/lib/libfoo.so"]
	if o.Kind != ObsLink {
		t.Fatalf("kind = %v, want ObsLink (err=%v)", o.Kind, o.Err)
	}
	if o.Link != target {
		t.Errorf("link = %q, want %q", o.Link, target)
	}
	if res := Integrity("foo", entries, obs, Exemptions{}, TierFull); len(res.Findings) != 0 {
		t.Fatalf("a dangling dot-dot link matching its record produced findings: %+v", res.Findings)
	}

	// Repoint it: the same code path must now report the disagreement.
	if err := os.Remove(filepath.Join(dir, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../tmp/evil.so", filepath.Join(dir, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	obs = TierFull.Verify(root, entries, Exemptions{})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if _, ok := findingForSubject(res, "integrity-link-target", "./usr/lib/libfoo.so"); !ok {
		t.Fatalf("a repointed symlink produced no finding: %+v %+v", res.Findings, res.Gaps)
	}
}

func TestVerifyReportsAMissingPath(t *testing.T) {
	root, _ := tierRoot(t)
	entries := []mtree.Entry{{Path: "./usr/share/doc/foo", Type: "file", SHA256: sha256Of("x")}}
	obs := TierFull.Verify(root, entries, Exemptions{})
	if got := obs["./usr/share/doc/foo"].Kind; got != ObsMissing {
		t.Fatalf("kind = %v, want ObsMissing (err=%v)", got, obs["./usr/share/doc/foo"].Err)
	}
}

func TestMetaTierNeverHashes(t *testing.T) {
	root, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	entries := []mtree.Entry{{
		Path: "./usr/bin/foo", Type: "file", Mode: 0o755,
		Size: int64(len("tampered")), Time: mtimeOf(t, p), SHA256: sha256Of("original"),
	}}
	obs := TierMeta.Verify(root, entries, Exemptions{})
	o := obs["./usr/bin/foo"]
	if o.Kind != ObsMetadataOnly {
		t.Fatalf("kind = %v, want ObsMetadataOnly", o.Kind)
	}
	if o.SHA256 != "" {
		t.Errorf("tier meta computed a digest: %s", o.SHA256)
	}
	if !o.MtimeAssisted {
		t.Error("tier meta did not mark its observation mtime-assisted (INV-6)")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierMeta)
	if len(res.Findings) != 0 {
		t.Errorf("tier meta produced a content finding it cannot support: %+v", res.Findings)
	}
	if len(res.Gaps) != 1 || res.Gaps[0].RuleID != "integrity-coverage" {
		t.Fatalf("tier meta did not report its own blindness as a gap (INV-3): %+v", res.Gaps)
	}
}

// TestTriageAlwaysHashesTheSecurityRelevantSubset is the property that is easy
// to miss and required: trusting mtime to decide what to hash is trusting the
// attacker who can set mtime. Both files below agree with their record on size
// AND mtime while their contents differ; the executable must still be hashed.
func TestTriageAlwaysHashesTheSecurityRelevantSubset(t *testing.T) {
	root, dir := tierRoot(t)
	quiet := writeAt(t, dir, "usr/share/doc/foo/README", "tampered", 0o644)
	exe := writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	entries := []mtree.Entry{
		{Path: "./usr/share/doc/foo/README", Type: "file", Mode: 0o644,
			Size: int64(len("tampered")), Time: mtimeOf(t, quiet), SHA256: sha256Of("original")},
		{Path: "./usr/bin/foo", Type: "file", Mode: 0o755,
			Size: int64(len("tampered")), Time: mtimeOf(t, exe), SHA256: sha256Of("original")},
	}

	obs := TierTriage.Verify(root, entries, Exemptions{})

	quietObs := obs["./usr/share/doc/foo/README"]
	if quietObs.Kind != ObsMetadataOnly {
		t.Errorf("a quiet non-executable was hashed at tier triage (kind=%v); the prefilter bought nothing",
			quietObs.Kind)
	}
	if !quietObs.MtimeAssisted {
		t.Error("the skipped file is not marked mtime-assisted")
	}

	exeObs := obs["./usr/bin/foo"]
	if exeObs.Kind != ObsHashed {
		t.Fatalf("an executable was NOT hashed at tier triage (kind=%v): mtime decided what to look at, "+
			"which is the attacker's decision to make", exeObs.Kind)
	}
	if exeObs.MtimeAssisted {
		t.Error("an unconditionally hashed observation was marked mtime-assisted")
	}

	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/bin/foo")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v: %s", f.Severity, formatFinding(f))
	}
	if _, ok := gapForSubject(res, "integrity-coverage", "foo"); !ok {
		t.Errorf("triage did not gap the paths it skipped (INV-3): %+v", res.Gaps)
	}
}

// When stat DOES disagree, triage hashes -- and the resulting finding says that
// stat is what selected it.
func TestTriageHashesWhenStatDisagreesAndMarksIt(t *testing.T) {
	root, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/share/foo.dat", "much longer content", 0o644)
	entries := []mtree.Entry{{
		Path: "./usr/share/foo.dat", Type: "file", Mode: 0o644,
		Size: 4, Time: mtimeOf(t, p), SHA256: sha256Of("orig"),
	}}
	obs := TierTriage.Verify(root, entries, Exemptions{})
	o := obs["./usr/share/foo.dat"]
	if o.Kind != ObsHashed {
		t.Fatalf("kind = %v, want ObsHashed", o.Kind)
	}
	if !o.MtimeAssisted {
		t.Error("a stat-selected observation is not marked mtime-assisted (INV-6)")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/share/foo.dat")
	if !containsString(f.Evidence, "mtime-assisted") {
		t.Errorf("finding does not carry the marker: %v", f.Evidence)
	}
}

func TestExemptPathIsNotOpenedBelowParanoid(t *testing.T) {
	root, dir := tierRoot(t)
	writeAt(t, dir, "etc/ld.so.cache", "regenerated", 0o644)
	ex := DeriveExemptions([]Hook{{
		Name: "11-glibc-remove-ldconfig-cache.hook", When: "PreTransaction",
		Exec: "/usr/bin/rm --force /etc/ld.so.cache",
	}}, nil)
	entries := []mtree.Entry{{Path: "./etc/ld.so.cache", Type: "file", Mode: 0o644, SHA256: sha256Of("as-shipped")}}

	if got := TierFull.Verify(root, entries, ex)["./etc/ld.so.cache"].Kind; got != ObsExempt {
		t.Errorf("tier full kind = %v, want ObsExempt", got)
	}
	par := TierParanoid.Verify(root, entries, ex)["./etc/ld.so.cache"]
	if par.Kind != ObsHashed {
		t.Fatalf("tier paranoid kind = %v, want ObsHashed", par.Kind)
	}
	res := Integrity("glibc", entries, TierParanoid.Verify(root, entries, ex), ex, TierParanoid)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./etc/ld.so.cache")
	if f.Severity != finding.SevInfo {
		t.Errorf("severity = %v, want info: %s", f.Severity, formatFinding(f))
	}
}

func TestSecurityRelevant(t *testing.T) {
	cases := []struct {
		e    mtree.Entry
		want bool
	}{
		{mtree.Entry{Type: "file", Mode: 0o755}, true},
		{mtree.Entry{Type: "file", Mode: 0o4755}, true},
		{mtree.Entry{Type: "file", Mode: 0o2755}, true},
		{mtree.Entry{Type: "file", Mode: 0o4644}, true},
		{mtree.Entry{Type: "file", Mode: 0o644}, false},
		{mtree.Entry{Type: "file", Mode: 0o444}, false},
		{mtree.Entry{Type: "link", Mode: 0o777}, true},
	}
	for _, c := range cases {
		if got := SecurityRelevant(c.e); got != c.want {
			t.Errorf("SecurityRelevant(%+v) = %v, want %v", c.e, got, c.want)
		}
	}
}

// A path an mtree should never contain must never reach a syscall.
func TestVerifyRefusesHostilePaths(t *testing.T) {
	root, _ := tierRoot(t)
	for _, p := range []string{"/etc/passwd", "./usr/../../etc/passwd", "", "./usr/bin/\x00foo"} {
		entries := []mtree.Entry{{Path: p, Type: "file", SHA256: sha256Of("x")}}
		obs := TierFull.Verify(root, entries, Exemptions{})
		o, ok := obs[p]
		if !ok {
			t.Errorf("path %q produced no observation at all; a refusal must be attributable", p)
			continue
		}
		if o.Kind != ObsUnreadable {
			t.Errorf("path %q: kind = %v, want ObsUnreadable", p, o.Kind)
		}
	}
}

// TestFPGateIntegrityIsQuietOnABenignRoot is this lane's half of the INV-8
// gate, and it runs the real mtree parser over a real fixture root rather than
// hand-built Entry literals -- the vis(3) escape, the dot-dot link target and
// the hook-regenerated cache below are the three shapes measured to dominate
// false positives on the reference system (382 spurious missing files, 4,145
// dot-dot targets, and the pacman-rewritten caches respectively).
//
// A benign root must produce nothing at or above the default reporting floor.
// If a check ever fires here, the check is wrong, not the fixture.
func TestFPGateIntegrityIsQuietOnABenignRoot(t *testing.T) {
	root, dir := tierRoot(t)

	// The installed hook set: what pacman itself regenerates on this system.
	writeAt(t, dir, "usr/share/libalpm/hooks/11-glibc-remove-ldconfig-cache.hook", hookLdconfigRemove, 0o644)
	writeAt(t, dir, "usr/share/libalpm/hooks/11-glibc-ldconfig.hook", hookLdconfig, 0o644)

	// Regenerated by a hook after the transaction that installed it: differs
	// from the shipped digest on every system, forever.
	writeAt(t, dir, "etc/ld.so.cache", "regenerated by ldconfig", 0o644)
	// A %BACKUP% config the administrator edited.
	writeAt(t, dir, "etc/foo.conf", "edited by the administrator\n", 0o644)
	// A digest-covered .pyc. 103 packages ship these; a blanket __pycache__
	// exemption would drop all of them out of coverage.
	pyc := writeAt(t, dir, "usr/lib/python3.13/site-packages/foo/__pycache__/bar.cpython-313.pyc", "bytecode", 0o644)
	// A path with a space: vis(3) writes it as \040, and 379 lines on the
	// reference system carry one.
	spaced := writeAt(t, dir, "usr/share/doc/foo/read me.txt", "docs\n", 0o644)
	exe := writeAt(t, dir, "usr/bin/foo", "#!/bin/sh\ntrue\n", 0o755)
	// A relative dot-dot symlink target, matching its record exactly.
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../usr/lib/libfoo.so.1", filepath.Join(dir, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}

	text := "#mtree\n" +
		"/set type=file uid=0 gid=0 mode=644\n" +
		"./.PKGINFO time=1773995553.0 size=1 sha256digest=" + sha256Of("x") + "\n" +
		"./etc time=1773995553.0 type=dir mode=755\n" +
		fmt.Sprintf("./etc/ld.so.cache time=%.1f size=1 sha256digest=%s\n", mtimeOf(t, filepath.Join(dir, "etc/ld.so.cache")), sha256Of("as shipped")) +
		fmt.Sprintf("./etc/foo.conf time=%.1f size=1 sha256digest=%s\n", mtimeOf(t, filepath.Join(dir, "etc/foo.conf")), sha256Of("as shipped")) +
		fmt.Sprintf("./usr/lib/python3.13/site-packages/foo/__pycache__/bar.cpython-313.pyc time=%.1f size=%d sha256digest=%s\n",
			mtimeOf(t, pyc), len("bytecode"), sha256Of("bytecode")) +
		fmt.Sprintf("./usr/share/doc/foo/read\\040me.txt time=%.1f size=%d sha256digest=%s\n",
			mtimeOf(t, spaced), len("docs\n"), sha256Of("docs\n")) +
		fmt.Sprintf("./usr/bin/foo time=%.1f mode=755 size=%d sha256digest=%s\n",
			mtimeOf(t, exe), len("#!/bin/sh\ntrue\n"), sha256Of("#!/bin/sh\ntrue\n")) +
		"./usr/lib/libfoo.so time=1773995553.0 type=link mode=777 link=../../usr/lib/libfoo.so.1\n"

	entries, err := mtree.Parse(strings.NewReader(text))
	if err != nil {
		t.Fatalf("mtree.Parse: %v", err)
	}
	if len(entries) != 7 {
		t.Fatalf("fixture parsed to %d entries, want 7 (./.PKGINFO is package metadata): %+v", len(entries), entries)
	}

	hooks, hookGaps := LoadHooks(root.FS(), DefaultHookDirs)
	if len(hookGaps) != 0 {
		t.Fatalf("hook load gaps: %+v", hookGaps)
	}
	ex := DeriveExemptions(hooks, []alpm.Package{{
		Name:   "glibc",
		Backup: map[string]string{"etc/foo.conf": "d41d8cd98f00b204e9800998ecf8427e"},
	}})

	for _, tier := range []Tier{TierMeta, TierTriage, TierFull} {
		t.Run(tier.String(), func(t *testing.T) {
			obs := tier.Verify(root, entries, ex)
			res := Integrity("glibc", entries, obs, ex, tier)
			for _, f := range res.Findings {
				if f.Severity >= finding.SevSuspicious {
					t.Errorf("benign root produced a finding at or above the default floor at tier %s:\n  %s",
						tier, formatFinding(f))
				}
			}
			for _, g := range res.Gaps {
				if g.RuleID != "integrity-coverage" {
					t.Errorf("benign root produced an unexpected coverage gap at tier %s: %+v", tier, g)
				}
			}
			if got := obs["./etc/ld.so.cache"].Kind; got != ObsExempt {
				t.Errorf("etc/ld.so.cache kind = %v, want ObsExempt (derived from the installed hook)", got)
			}
			if got := obs["./etc/foo.conf"].Kind; got != ObsExempt {
				t.Errorf("etc/foo.conf kind = %v, want ObsExempt (%%BACKUP%%)", got)
			}
			// The .pyc must be examined at full: a blanket __pycache__
			// exemption would show up here as ObsExempt.
			if tier == TierFull {
				pycObs := obs["./usr/lib/python3.13/site-packages/foo/__pycache__/bar.cpython-313.pyc"]
				if pycObs.Kind != ObsHashed {
					t.Errorf("a digest-covered .pyc was not hashed (kind=%v); 103 packages ship these", pycObs.Kind)
				}
			}
		})
	}

	// Liveness floor: the same benign fixture, with one byte of tampering,
	// must still speak. A quiet scanner satisfies "no findings" trivially.
	writeAt(t, dir, "usr/bin/foo", "#!/bin/sh\ncurl\n", 0o755)
	res := Integrity("glibc", entries, TierFull.Verify(root, entries, ex), ex, TierFull)
	if _, ok := findingForSubject(res, "integrity-digest-mismatch", "./usr/bin/foo"); !ok {
		t.Fatalf("the benign root went quiet after tampering: %+v %+v", res.Findings, res.Gaps)
	}
}

// TestPanicOnOnePathIsAGapAndTheScanContinues is INV-9 at this layer: a bug in
// the observation of one recorded path costs exactly one coverage gap. If it
// aborted the pass instead, every path after it would go unexamined and the run
// would never report that it had not -- which is a working instruction for
// becoming invisible.
func TestPanicOnOnePathIsAGapAndTheScanContinues(t *testing.T) {
	root, dir := tierRoot(t)
	writeAt(t, dir, "usr/bin/a", "a", 0o755)
	writeAt(t, dir, "usr/bin/b", "b", 0o755)
	entries := []mtree.Entry{
		{Path: "./usr/bin/a", Type: "file", Mode: 0o755, Size: 1, SHA256: sha256Of("a")},
		{Path: "./usr/bin/b", Type: "file", Mode: 0o755, Size: 1, SHA256: sha256Of("b")},
	}

	beforeObserveForTest = func(p string) {
		if p == "./usr/bin/a" {
			panic("crafted record")
		}
	}
	t.Cleanup(func() { beforeObserveForTest = nil })

	obs := TierFull.Verify(root, entries, Exemptions{})
	if got := obs["./usr/bin/a"].Kind; got != ObsUnreadable {
		t.Fatalf("panicking path kind = %v, want ObsUnreadable", got)
	}
	if !errors.Is(obs["./usr/bin/a"].Err, safe.ErrPanic) {
		t.Errorf("err = %v, want safe.ErrPanic", obs["./usr/bin/a"].Err)
	}
	if got := obs["./usr/bin/b"].Kind; got != ObsHashed {
		t.Errorf("the path after the panic was not examined (kind=%v): the pass aborted", got)
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("a panic produced a finding rather than a gap: %+v", res.Findings)
	}
	if _, ok := gapForSubject(res, "integrity-digest-mismatch", "./usr/bin/a"); !ok {
		t.Fatalf("a contained panic produced no gap: %+v", res.Gaps)
	}
}

func containsString(ss []string, want string) bool {
	for _, s := range ss {
		if s == want {
			return true
		}
	}
	return false
}
