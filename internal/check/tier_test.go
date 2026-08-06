// internal/check/tier_test.go
package check

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/collect"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/hook"
	"github.com/lookatitude/aurvet/internal/mtree"
	"github.com/lookatitude/aurvet/internal/safe"
	"golang.org/x/sys/unix"
)

func sha256Of(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])
}

// tierRoot builds a fixture root and returns it opened as an os.Root, which is
// the only handle phase 1 ever gets: --offline-root is a parameter, not a second
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

// phase1 runs the REAL privileged phase over the fixture root: it writes the
// plain-text `files` a package would record, then lets internal/collect discover
// the paths from it, open each one confined, fstat it and hash what the tier
// asks for. Nothing here hands collect a path list directly, because the
// newline split of `files` is the part spec §11.1 permits phase 1 to do and a
// test that bypassed it would be testing a shape the binary never runs.
func phase1(t *testing.T, dir string, tier Tier, entries []mtree.Entry) collect.Raw {
	t.Helper()
	var list strings.Builder
	list.WriteString("%FILES%\n")
	for _, e := range entries {
		if e.Type == "dir" {
			continue
		}
		list.WriteString(strings.TrimPrefix(e.Path, "./") + "\n")
	}
	pkgDir := filepath.Join(dir, "var/lib/pacman/local/fixture-1-1")
	if err := os.MkdirAll(pkgDir, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, content := range map[string]string{
		"desc":  "%NAME%\nfixture\n",
		"files": list.String(),
		"mtree": "",
	} {
		if err := os.WriteFile(filepath.Join(pkgDir, name), []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}

	raw, err := collect.Collect(collect.Config{
		Root:     dir,
		DBPath:   filepath.Join(dir, "var/lib/pacman/local"),
		Walk:     []string{"var/lib/pacman/local"},
		Recorded: tier.CollectPolicy(),
		Workers:  4,
	})
	if err != nil {
		t.Fatalf("collect: %v", err)
	}
	return raw
}

// observeRaw is the whole two-phase path a scan takes, in one call: collect,
// then join. It returns the collector's evidence too, because several
// properties below are statements about which phase reported a shortfall.
func observeRaw(t *testing.T, dir string, tier Tier, entries []mtree.Entry, ex Exemptions) (map[string]Observed, collect.Raw) {
	t.Helper()
	raw := phase1(t, dir, tier, entries)
	// The index rather than the map, because that is the join a scan runs; the
	// map path is pinned to this one by
	// TestObserveIsTheSameThroughAMapAndAnIndex.
	return tier.ObserveFiles(entries, raw.Index(), ex), raw
}

func observe(t *testing.T, dir string, tier Tier, entries []mtree.Entry, ex Exemptions) map[string]Observed {
	t.Helper()
	obs, _ := observeRaw(t, dir, tier, entries, ex)
	return obs
}

// collectGapFor reports whether phase 1 raised a gap naming this subject.
func collectGapFor(raw collect.Raw, subject string) (finding.Gap, bool) {
	for _, g := range raw.Gaps {
		if g.Subject == subject {
			return g, true
		}
	}
	return finding.Gap{}, false
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
	_, dir := tierRoot(t)
	writeAt(t, dir, "usr/bin/foo", "hello", 0o755)
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 5, SHA256: sha256Of("hello")}}

	obs := observe(t, dir, TierFull, entries, Exemptions{})
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
	if o.StatOnly {
		t.Error("tier full marked an observation stat-only")
	}
	if res := Integrity("foo", entries, obs, Exemptions{}, TierFull); len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("clean root produced output: %+v %+v", res.Findings, res.Gaps)
	}

	// Now the content diverges from the record: the same code path must report
	// it. (A check whose test passes with the check deleted is not a check.)
	writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	obs = observe(t, dir, TierFull, entries, Exemptions{})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/bin/foo")
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v: %s", f.Severity, formatFinding(f))
	}
}

// A symlink standing where a regular file was recorded is refused unresolved,
// and that refusal is a coverage gap rather than a hash of the swap target.
//
// Phase 1 learns it is a symlink from O_NOFOLLOW refusing the open, then reads
// the target with readlinkat and never resolves it -- so the evidence can say
// where the link claims to point without a single byte of the swap target being
// read. Integrity sees the record and the observation disagree about type and
// gaps it: it cannot verify contents it deliberately did not read.
func TestVerifyRefusesASymlinkWhereAFileWasRecorded(t *testing.T) {
	_, dir := tierRoot(t)
	writeAt(t, dir, "real/secret", "sensitive", 0o644)
	if err := os.MkdirAll(filepath.Join(dir, "usr/bin"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../real/secret", filepath.Join(dir, "usr/bin/foo")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{{Path: "./usr/bin/foo", Type: "file", Mode: 0o755, Size: 5, SHA256: sha256Of("hello")}}

	obs := observe(t, dir, TierFull, entries, Exemptions{})
	o := obs["./usr/bin/foo"]
	if o.Kind != ObsLink {
		t.Fatalf("kind = %v, want ObsLink (err=%v)", o.Kind, o.Err)
	}
	if o.SHA256 != "" {
		t.Fatalf("the swap target was hashed: %s", o.SHA256)
	}
	if o.SHA256 == sha256Of("sensitive") {
		t.Fatal("the swap target was hashed")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("a refusal produced a finding rather than a gap (INV-9): %+v", res.Findings)
	}
	if len(res.Gaps) != 1 {
		t.Fatalf("want one gap, got %+v", res.Gaps)
	}
	if !strings.Contains(res.Gaps[0].Reason, "refused") {
		t.Errorf("the gap does not say the contents were not verified: %q", res.Gaps[0].Reason)
	}
}

// A fifo where a file was recorded must not hang the scan: that would turn a
// hostile filesystem into a denial of the tool with no panic to recover from.
func TestVerifyRefusesAFifoWithoutBlocking(t *testing.T) {
	_, dir := tierRoot(t)
	if err := os.MkdirAll(filepath.Join(dir, "var/run"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := unix.Mkfifo(filepath.Join(dir, "var/run/pipe"), 0o644); err != nil {
		t.Skipf("mkfifo unavailable: %v", err)
	}
	entries := []mtree.Entry{{Path: "./var/run/pipe", Type: "file", SHA256: sha256Of("x")}}
	obs := observe(t, dir, TierFull, entries, Exemptions{})
	if got := obs["./var/run/pipe"].Kind; got != ObsUnreadable {
		t.Fatalf("kind = %v, want ObsUnreadable", got)
	}
	if !errors.Is(obs["./var/run/pipe"].Err, errRecordKind) {
		t.Errorf("err = %v, want errRecordKind", obs["./var/run/pipe"].Err)
	}
}

// Link targets are READ, never resolved. The dangling target here is the point:
// a resolving implementation would fail or manufacture a finding, and 4,145
// legitimate targets on the reference system contain "..".
func TestVerifyReadsLinkTargetsWithoutResolvingThem(t *testing.T) {
	_, dir := tierRoot(t)
	const target = "../../../nonexistent/../usr/lib/libfoo.so.1"
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "usr/lib/libfoo.so")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{{Path: "./usr/lib/libfoo.so", Type: "link", Link: target}}

	obs := observe(t, dir, TierFull, entries, Exemptions{})
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
	obs = observe(t, dir, TierFull, entries, Exemptions{})
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if _, ok := findingForSubject(res, "integrity-link-target", "./usr/lib/libfoo.so"); !ok {
		t.Fatalf("a repointed symlink produced no finding: %+v %+v", res.Findings, res.Gaps)
	}
}

func TestVerifyReportsAMissingPath(t *testing.T) {
	_, dir := tierRoot(t)
	entries := []mtree.Entry{{Path: "./usr/share/doc/foo", Type: "file", SHA256: sha256Of("x")}}
	obs := observe(t, dir, TierFull, entries, Exemptions{})
	if got := obs["./usr/share/doc/foo"].Kind; got != ObsMissing {
		t.Fatalf("kind = %v, want ObsMissing (err=%v)", got, obs["./usr/share/doc/foo"].Err)
	}
}

func TestMetaTierNeverHashes(t *testing.T) {
	_, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	entries := []mtree.Entry{{
		Path: "./usr/bin/foo", Type: "file", Mode: 0o755,
		Size: int64(len("tampered")), Time: mtimeOf(t, p), SHA256: sha256Of("original"),
	}}
	obs := observe(t, dir, TierMeta, entries, Exemptions{})
	o := obs["./usr/bin/foo"]
	if o.Kind != ObsMetadataOnly {
		t.Fatalf("kind = %v, want ObsMetadataOnly", o.Kind)
	}
	if o.SHA256 != "" {
		t.Errorf("tier meta computed a digest: %s", o.SHA256)
	}
	if !o.StatOnly {
		t.Error("tier meta did not mark its observation stat-only (INV-6)")
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
//
// The subset is decided in phase 1 from the fstat of the descriptor that would
// be read. Note what the record says here and what it does not have to say: the
// mode below could claim anything at all and the executable would still be
// hashed, because it is the kernel's mode that decides what runs.
func TestTriageAlwaysHashesTheSecurityRelevantSubset(t *testing.T) {
	_, dir := tierRoot(t)
	quiet := writeAt(t, dir, "usr/share/doc/foo/README", "tampered", 0o644)
	exe := writeAt(t, dir, "usr/bin/foo", "tampered", 0o755)
	entries := []mtree.Entry{
		{Path: "./usr/share/doc/foo/README", Type: "file", Mode: 0o644,
			Size: int64(len("tampered")), Time: mtimeOf(t, quiet), SHA256: sha256Of("original")},
		{Path: "./usr/bin/foo", Type: "file", Mode: 0o755,
			Size: int64(len("tampered")), Time: mtimeOf(t, exe), SHA256: sha256Of("original")},
	}

	obs := observe(t, dir, TierTriage, entries, Exemptions{})

	quietObs := obs["./usr/share/doc/foo/README"]
	if quietObs.Kind != ObsMetadataOnly {
		t.Errorf("a quiet non-executable was hashed at tier triage (kind=%v); the prefilter bought nothing",
			quietObs.Kind)
	}
	if !quietObs.StatOnly {
		t.Error("the skipped file is not marked stat-only")
	}

	exeObs := obs["./usr/bin/foo"]
	if exeObs.Kind != ObsHashed {
		t.Fatalf("an executable was NOT hashed at tier triage (kind=%v): mtime decided what to look at, "+
			"which is the attacker's decision to make", exeObs.Kind)
	}
	if exeObs.StatOnly {
		t.Error("an unconditionally hashed observation was marked stat-only")
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

// TestTriageDoesNotHashOutsideTheSubsetAndStatesTheLoss is the deliberate
// weakening of tier triage, asserted rather than left implicit.
//
// Triage's hash set has to be decidable in phase 1, because after the capability
// drop the process cannot read a root-only file at all. So a file outside the
// security-relevant subset is opened, fstat'd and NOT read, whatever its size
// and mtime say. A size disagreement is still reported -- metadata can
// contradict a record even though it can never confirm one -- and the paths that
// went unhashed are gapped with the limit spelled out, because a limit an
// operator only meets in the source is a limit they never meet.
func TestTriageDoesNotHashOutsideTheSubsetAndStatesTheLoss(t *testing.T) {
	_, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/share/foo.dat", "much longer content", 0o644)
	entries := []mtree.Entry{{
		Path: "./usr/share/foo.dat", Type: "file", Mode: 0o644,
		Size: 4, Time: mtimeOf(t, p), SHA256: sha256Of("orig"),
	}}
	obs := observe(t, dir, TierTriage, entries, Exemptions{})
	o := obs["./usr/share/foo.dat"]
	if o.Kind != ObsMetadataOnly {
		t.Fatalf("kind = %v, want ObsMetadataOnly: a stat disagreement must not make triage read a "+
			"file it could not have decided to read while it still held the capability", o.Kind)
	}
	if !o.StatOnly {
		t.Error("a metadata-only observation is not marked stat-only (INV-6)")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./usr/share/foo.dat")
	if !containsString(f.Evidence, "stat-only") {
		t.Errorf("finding does not carry the marker: %v", f.Evidence)
	}
	if !containsString(f.Evidence, "contents not hashed") {
		t.Errorf("a size-only finding does not say the contents were not read: %v", f.Evidence)
	}
	g, ok := gapForSubject(res, "integrity-coverage", "foo")
	if !ok {
		t.Fatalf("triage did not gap the path it left unhashed: %+v", res.Gaps)
	}
	if !strings.Contains(g.Reason, "NOT detected at this tier") {
		t.Errorf("the triage coverage gap does not state the tier's blindness: %q", g.Reason)
	}
}

// The same file at tier full IS read, so the weakening above is a property of
// triage rather than of the whole pipeline.
func TestFullHashesWhatTriageSkips(t *testing.T) {
	_, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/share/foo.dat", "tampered", 0o644)
	entries := []mtree.Entry{{
		Path: "./usr/share/foo.dat", Type: "file", Mode: 0o644,
		Size: int64(len("tampered")), Time: mtimeOf(t, p), SHA256: sha256Of("orig"),
	}}
	if got := observe(t, dir, TierTriage, entries, Exemptions{})["./usr/share/foo.dat"].Kind; got != ObsMetadataOnly {
		t.Fatalf("triage kind = %v, want ObsMetadataOnly", got)
	}
	obs := observe(t, dir, TierFull, entries, Exemptions{})
	if got := obs["./usr/share/foo.dat"].Kind; got != ObsHashed {
		t.Fatalf("full kind = %v, want ObsHashed", got)
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if _, ok := findingForSubject(res, "integrity-digest-mismatch", "./usr/share/foo.dat"); !ok {
		t.Fatalf("tier full did not report a size-identical content change: %+v %+v", res.Findings, res.Gaps)
	}
}

// A watched path is hashed at triage even though nothing about it is
// executable: a unit file decides what runs without being runnable itself.
func TestTriageHashesWatchedPathsWhateverTheirMode(t *testing.T) {
	_, dir := tierRoot(t)
	p := writeAt(t, dir, "usr/lib/systemd/system/foo.service", "[Service]\nExecStart=/usr/bin/evil\n", 0o644)
	entries := []mtree.Entry{{
		Path: "./usr/lib/systemd/system/foo.service", Type: "file", Mode: 0o644,
		Size: int64(len("[Service]\nExecStart=/usr/bin/evil\n")), Time: mtimeOf(t, p),
		SHA256: sha256Of("[Service]\nExecStart=/usr/bin/true\n"),
	}}
	obs := observe(t, dir, TierTriage, entries, Exemptions{})
	o := obs["./usr/lib/systemd/system/foo.service"]
	if o.Kind != ObsHashed {
		t.Fatalf("a non-executable unit file was not hashed at tier triage (kind=%v); its contents "+
			"decide what runs and its mode says nothing about that", o.Kind)
	}
	if o.StatOnly {
		t.Error("an unconditionally hashed observation was marked stat-only")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierTriage)
	if _, ok := findingForSubject(res, "integrity-digest-mismatch", "./usr/lib/systemd/system/foo.service"); !ok {
		t.Fatalf("no finding for a rewritten unit file: %+v %+v", res.Findings, res.Gaps)
	}
}

// An exempt path IS opened and hashed by phase 1 -- exemptions are derived from
// PARSED hooks and do not exist while the capability is held -- and is then not
// COMPARED below paranoid. Phase 1 hashes; phase 2 alone decides what a mismatch
// means. Measured cost of hashing the exempt set on the reference system: 321
// files, 1.3 MiB.
func TestExemptPathIsNotComparedBelowParanoid(t *testing.T) {
	_, dir := tierRoot(t)
	writeAt(t, dir, "etc/ld.so.cache", "regenerated", 0o644)
	ex := DeriveExemptions([]hook.Hook{{
		Name: "11-glibc-remove-ldconfig-cache.hook", When: "PreTransaction",
		Exec: "/usr/bin/rm --force /etc/ld.so.cache",
	}}, nil)
	entries := []mtree.Entry{{Path: "./etc/ld.so.cache", Type: "file", Mode: 0o644, SHA256: sha256Of("as-shipped")}}

	if got := observe(t, dir, TierFull, entries, ex)["./etc/ld.so.cache"].Kind; got != ObsExempt {
		t.Errorf("tier full kind = %v, want ObsExempt", got)
	}
	par := observe(t, dir, TierParanoid, entries, ex)["./etc/ld.so.cache"]
	if par.Kind != ObsHashed {
		t.Fatalf("tier paranoid kind = %v, want ObsHashed", par.Kind)
	}
	res := Integrity("glibc", entries, observe(t, dir, TierParanoid, entries, ex), ex, TierParanoid)
	f := integrityFor(t, res, "integrity-digest-mismatch", "./etc/ld.so.cache")
	if f.Severity != finding.SevInfo {
		t.Errorf("severity = %v, want info: %s", f.Severity, formatFinding(f))
	}
}

// TestVerifyRefusesALinkReachedThroughAnEscapingDirectory is the assertion with
// teeth behind reading link targets through fsx.ReadLinkConfined rather than a
// plain readlink: a DIRECTORY component that is a symlink out of the tree must
// refuse the whole read.
//
// It is written as an escape rather than as a malformed path because malformed
// paths refuse for boring reasons -- ENOENT, EINVAL -- and a test they satisfy
// cannot distinguish a confined implementation from an unconfined one. This one
// can: pointed at os.Readlink instead, it reports the target and fails.
func TestVerifyRefusesALinkReachedThroughAnEscapingDirectory(t *testing.T) {
	outside := t.TempDir()
	if err := os.Symlink("../../../etc/shadow", filepath.Join(outside, "bait")); err != nil {
		t.Fatal(err)
	}
	_, dir := tierRoot(t)
	// "usr" inside the root is a symlink to a directory outside it.
	if err := os.Symlink(outside, filepath.Join(dir, "usr")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{{Path: "./usr/bait", Type: "link", Link: "../../../etc/shadow"}}

	obs, raw := observeRaw(t, dir, TierFull, entries, Exemptions{})
	o := obs["./usr/bait"]
	if o.Kind != ObsUnreadable {
		t.Fatalf("a link reached through an escaping directory was read (kind=%v, link=%q); the "+
			"directory components must resolve through os.Root", o.Kind, o.Link)
	}
	if o.Link != "" {
		t.Errorf("refused, yet a target was reported: %q", o.Link)
	}
	// The shortfall is reported ONCE. Phase 1 is the phase that met the refusal,
	// so phase 1 is the phase that names it; Integrity consumes that gap rather
	// than restating it under a second rule ID.
	if _, ok := collectGapFor(raw, "./usr/bait"); !ok {
		t.Fatalf("phase 1 did not gap the refused path: %+v", raw.Gaps)
	}
	if !o.Gapped {
		t.Error("the observation does not record that phase 1 already gapped it")
	}
	res := Integrity("foo", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 {
		t.Errorf("an escape produced a finding rather than a gap (INV-9): %+v", res.Findings)
	}
	if len(res.Gaps) != 0 {
		t.Errorf("the same shortfall was gapped twice, once by each phase: %+v", res.Gaps)
	}
}

// A path a package database should never contain must never reach a syscall.
// The refusal now happens in phase 1, on the plain-text name list, before the
// path is ever handed to fsx -- and it is attributed to the package that
// recorded it rather than to whichever errno the kernel happened to produce.
//
// Measured on the reference system: zero of 386,645 recorded paths are
// absolute, contain a ".." component, or carry a NUL. There is no legitimate
// population to accommodate, so any occurrence is damning.
func TestVerifyRefusesHostilePaths(t *testing.T) {
	_, dir := tierRoot(t)
	hostile := []string{"/etc/passwd", "./usr/../../etc/passwd", "./usr/bin/\x00foo", "./usr//bin/x"}
	for _, kind := range []string{"file", "link"} {
		for _, p := range hostile {
			e := mtree.Entry{Path: p, Type: kind, SHA256: sha256Of("x")}
			if kind == "link" {
				e.Link = "somewhere"
			}
			obs, raw := observeRaw(t, dir, TierFull, []mtree.Entry{e}, Exemptions{})
			if o, ok := obs[p]; ok {
				t.Errorf("type=%s path %q was observed (kind=%v, link=%q); it must never have been opened",
					kind, p, o.Kind, o.Link)
			}
			if _, ok := collectGapFor(raw, "fixture-1-1"); !ok {
				t.Errorf("type=%s path %q: phase 1 refused it without saying so: %+v", kind, p, raw.Gaps)
			}
			// An unexamined path is never a clean path: the package carries a
			// coverage gap for it (INV-3).
			res := Integrity("fixture", []mtree.Entry{e}, obs, Exemptions{}, TierFull)
			if len(res.Findings) != 0 {
				t.Errorf("type=%s path %q produced a finding rather than a gap: %+v", kind, p, res.Findings)
			}
			if _, ok := gapForSubject(res, ruleForEntry(e), p); !ok {
				t.Errorf("type=%s path %q produced no coverage gap: %+v", kind, p, res.Gaps)
			}
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

	hooks, hookGaps := hook.LoadHooks(root.FS(), hook.DefaultHookDirs)
	if len(hookGaps) != 0 {
		t.Fatalf("hook load gaps: %+v", hookGaps)
	}
	ex := DeriveExemptions(hooks, []alpm.Package{{
		Name:   "glibc",
		Backup: map[string]string{"etc/foo.conf": "d41d8cd98f00b204e9800998ecf8427e"},
	}})

	for _, tier := range []Tier{TierMeta, TierTriage, TierFull} {
		t.Run(tier.String(), func(t *testing.T) {
			obs := observe(t, dir, tier, entries, ex)
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
	res := Integrity("glibc", entries, observe(t, dir, TierFull, entries, ex), ex, TierFull)
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
	_, dir := tierRoot(t)
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

	obs := observe(t, dir, TierFull, entries, Exemptions{})
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

// --------------------------------------------------------- evidence lookup ----

// Observe's two entry points must be the same function. ObserveFiles is what a
// scan runs -- it reads phase 1's evidence in place rather than through a copy
// of it -- and Observe is the map-shaped convenience over the top; a divergence
// between them would make a verdict depend on which index the caller happened to
// build, which is not a property anyone would think to check when reading a
// finding.
func TestObserveIsTheSameThroughAMapAndAnIndex(t *testing.T) {
	root, dir := tierRoot(t)
	_ = root
	p := writeAt(t, dir, "usr/bin/tool", "payload", 0o755)
	writeAt(t, dir, "usr/share/doc/readme", "docs", 0o644)
	if err := os.MkdirAll(filepath.Join(dir, "usr/lib"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../elsewhere", filepath.Join(dir, "usr/lib/liba.so")); err != nil {
		t.Fatal(err)
	}
	entries := []mtree.Entry{
		{Path: "./usr/bin/tool", Type: "file", SHA256: sha256Of("payload"), Size: 7, Time: mtimeOf(t, p)},
		{Path: "./usr/share/doc/readme", Type: "file", SHA256: sha256Of("docs"), Size: 4},
		{Path: "./usr/lib/liba.so", Type: "link", Link: "../../elsewhere"},
		{Path: "./usr/bin/gone", Type: "file", SHA256: sha256Of("x"), Size: 1},
		{Path: "./usr", Type: "dir"},
	}
	raw := phase1(t, dir, TierFull, entries)

	viaMap := TierFull.Observe(entries, raw.ByPath(), Exemptions{})
	viaIndex := TierFull.ObserveFiles(entries, raw.Index(), Exemptions{})

	if len(viaMap) != len(viaIndex) {
		t.Fatalf("%d observations through the map, %d through the index: one of them dropped a path\nmap=%v\nindex=%v",
			len(viaMap), len(viaIndex), keysOf(viaMap), keysOf(viaIndex))
	}
	for path, want := range viaMap {
		got, ok := viaIndex[path]
		if !ok {
			t.Errorf("%q was observed through the map and not through the index", path)
			continue
		}
		if got.Kind != want.Kind || got.SHA256 != want.SHA256 || got.Link != want.Link ||
			got.Size != want.Size || got.Mode != want.Mode || got.Gapped != want.Gapped ||
			got.StatOnly != want.StatOnly || errText(got.Err) != errText(want.Err) {
			t.Errorf("%q: index = %+v, map = %+v", path, got, want)
		}
	}
}

// A path phase 1 could not examine carries the ONLY statement of why. If the
// lookup loses Unread, the observation degrades from "refused because X" to a
// bare unreadable, the gap stops naming the cause, and Gapped stops merging the
// double gap -- three regressions from one dropped string, none of which changes
// a count.
func TestTheUnreadReasonSurvivesTheEvidenceLookup(t *testing.T) {
	raw := collect.Raw{Files: []collect.File{
		{Path: "./usr/bin/locked", Kind: collect.KindUnread, Unread: "mutated during scan"},
	}}
	entries := []mtree.Entry{{Path: "./usr/bin/locked", Type: "file", SHA256: sha256Of("x"), Size: 1}}

	obs := TierFull.ObserveFiles(entries, raw.Index(), Exemptions{})
	o, ok := obs["./usr/bin/locked"]
	if !ok {
		t.Fatal("the recorded path produced no observation")
	}
	if o.Kind != ObsUnreadable {
		t.Fatalf("Kind = %v, want ObsUnreadable", o.Kind)
	}
	if !o.Gapped {
		t.Error("Gapped is false: integrity will raise a second gap for a shortfall phase 1 already reported")
	}
	if o.Err == nil || o.Err.Error() != "mutated during scan" {
		t.Errorf("Err = %v, want the collector's reason verbatim", o.Err)
	}
}

// Every recorded path a package names must reach the comparison. A lookup that
// silently answered "not found" for some of them would turn a verified file into
// an unobserved one -- which Integrity does report as a gap, so the loss is
// visible, but the package would stop being covered without anything having gone
// wrong on the filesystem.
func TestEveryRecordedPathReachesTheComparison(t *testing.T) {
	const n = 512
	var files []collect.File
	var entries []mtree.Entry
	for i := range n {
		p := fmt.Sprintf("./usr/lib/pkg/%04d.so", i)
		files = append(files, collect.File{Path: p, Kind: collect.KindFile, SHA256: sha256Of(p), Size: 3})
		entries = append(entries, mtree.Entry{Path: p, Type: "file", SHA256: sha256Of(p), Size: 3})
	}
	raw := collect.Raw{Files: files}

	obs := TierFull.ObserveFiles(entries, raw.Index(), Exemptions{})
	if len(obs) != n {
		t.Fatalf("%d observations for %d recorded paths: the lookup dropped %d", len(obs), n, n-len(obs))
	}
	res := Integrity("pkg", entries, obs, Exemptions{}, TierFull)
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Errorf("a package whose every path matches produced %d finding(s) and %d gap(s): %+v %+v",
			len(res.Findings), len(res.Gaps), res.Findings, res.Gaps)
	}
}

func keysOf(m map[string]Observed) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func errText(err error) string {
	if err == nil {
		return ""
	}
	return err.Error()
}
