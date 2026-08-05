// internal/check/fpgate_test.go
package check

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/correlate"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/hook"
	"github.com/lookatitude/aurvet/internal/own"
	"github.com/lookatitude/aurvet/internal/report"
)

// This file is the P1-A release gate for INV-8 / success criterion 5: zero
// critical findings on both benign fixture roots (testdata/gate/stock and
// testdata/gate/cruft). It is deliberately a PAIR, never a single assertion:
//
//  1. TestFPGateNoCriticalsOnBenignSystems — zero SevCritical on "stock" and
//     "cruft".
//  2. TestFPGateStillCatchesMalware — the SAME Provenance code path, in the
//     same run, still reaches SevCritical (via rule aur-tombstone, on the
//     expected subject) against "malicious".
//
// If half 1 passes while half 2 fails, THE GATE MUST FAIL: a scanner that
// reports nothing at all satisfies "zero criticals" trivially, and that is
// the exact condition this gate exists to catch (the design review measured
// ~1,860 findings / ~427 criticals / zero actionable on a reference system —
// the countermeasure is the pair, not either half alone). This is made
// structurally true, not just asserted in a comment: both halves are
// top-level Test functions living in this one file, so the release-gate
// invocation `go test ./internal/check/` exits non-zero if EITHER fails,
// independent of what the other one did. Neither half can short-circuit or
// suppress the other's result.
//
// TestFPGateBenignRootsAreNotSilent adds a liveness floor on top of that
// pair: "cruft" must still produce at least one SevSuspicious finding. Zero
// criticals AND zero findings of any kind on "cruft" would be the silent
// scanner failure wearing a benign root as a disguise — cruft's messy
// fixtures exist precisely so "alarming-looking but not critical" has
// something to land on.

// gateRoot returns the on-disk path of one fixture root under testdata/gate.
// Repo-root testdata, relative to this package directory (internal/check) —
// the same convention internal/alpm and internal/aur's tests use for
// ../../testdata/roots and ../../testdata/aur.
func gateRoot(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "gate", name)
}

// gateFixture is what one fixture root loads into: the packages and gaps
// alpm.LoadLocalDB reports, and the sync-name oracle alpm.LoadSyncNames
// reports once the checked-in sync-names.txt has been materialized into a
// real gzipped-tar sync DB and loaded back through the real loader.
type gateFixture struct {
	pkgs              []alpm.Package
	localGaps         []string
	syncNames         map[string]bool
	unreadableSyncDBs []string
}

// loadGateFixture drives the real loaders end to end: alpm.LoadLocalDB
// against the checked-in desc/files tree, and alpm.LoadSyncNames against a
// sync DB materialized at runtime from sync-names.txt. No hand-built
// map[string]bool shortcut — the point of these fixtures is to exercise the
// same code path `scan` uses, not a stand-in for it.
func loadGateFixture(t *testing.T, root string) gateFixture {
	t.Helper()
	localDB := filepath.Join(root, "var", "lib", "pacman", "local")
	pkgs, localGaps, err := alpm.LoadLocalDB(localDB)
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", localDB, err)
	}
	names := readGateSyncNames(t, filepath.Join(root, "sync-names.txt"))
	syncDir := t.TempDir()
	writeGateSyncDB(t, syncDir, "core", names)
	syncNames, unreadableSyncDBs, err := alpm.LoadSyncNames(syncDir)
	if err != nil {
		t.Fatalf("LoadSyncNames(%s): %v", syncDir, err)
	}
	return gateFixture{
		pkgs:              pkgs,
		localGaps:         localGaps,
		syncNames:         syncNames,
		unreadableSyncDBs: unreadableSyncDBs,
	}
}

// readGateSyncNames reads sync-names.txt: one repository package name per
// non-blank line.
func readGateSyncNames(t *testing.T, path string) []string {
	t.Helper()
	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read sync-names fixture %s: %v", path, err)
	}
	var names []string
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		names = append(names, line)
	}
	return names
}

// writeGateSyncDB materializes a gzipped tar sync DB from a plain
// package-name list, in the same shape cmd/aurvet's writeSyncDB (main_test.go
// lines 282-314) uses and verified against a real pacman sync DB: one
// <name>-<ver>/ directory entry plus its desc member per package. The version
// is fixed and arbitrary — alpm.stripVersion only strips the trailing two
// hyphen-delimited fields regardless of their content, and LoadSyncNames
// keys sync names on NAME alone, so no test here depends on it.
func writeGateSyncDB(t *testing.T, syncPath, repo string, names []string) {
	t.Helper()
	const ver = "1-1"
	var buf bytes.Buffer
	gz := gzip.NewWriter(&buf)
	tw := tar.NewWriter(gz)
	for _, name := range names {
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

// cruftAURClient is the network-side fixture for testdata/gate/cruft. It
// stays in Go, not on disk, because it is the AUR RPC/cgit side of the
// fixture, not the filesystem side.
func cruftAURClient() aur.Fake {
	return aur.Fake{
		Known: map[string]aur.Pkg{
			// Cleanly present, maintainer == submitter.
			"brave-bin": {Name: "brave-bin", PackageBase: "brave-bin", Maintainer: "brave", Submitter: "brave"},
			// Orphaned: maintainer unset.
			"tty-clock": {Name: "tty-clock", PackageBase: "tty-clock", Maintainer: "", Submitter: "someone"},
			// Maintainer differs from submitter: a legitimate handoff.
			"handoff-pkg": {Name: "handoff-pkg", PackageBase: "handoff-pkg", Maintainer: "alice", Submitter: "bob"},
			// Present, but the AUR record carries no submitter: a coverage gap,
			// not a finding.
			"nosubmitter-pkg": {Name: "nosubmitter-pkg", PackageBase: "nosubmitter-pkg", Maintainer: "carol", Submitter: ""},
			// A split package: name differs from pkgbase, resolves cleanly.
			"foo-headers": {Name: "foo-headers", PackageBase: "foo-common", Maintainer: "maint", Submitter: "maint"},
			// dropped-pkg and brave-bin-debug are deliberately absent from Known:
			// both are the "absent from the AUR, no tombstone" shape.
		},
		Tombstones: map[string]string{},
	}
}

// maliciousAURClient is the network-side fixture for testdata/gate/malicious:
// one base with a cgit removal tombstone whose message satisfies
// aur.IsMalwareRemoval, taken verbatim from provenance_test.go's
// TestTombstonedPackageIsCritical so it is known-good against the real
// IsMalwareRemoval implementation.
func maliciousAURClient() aur.Fake {
	return aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"},
	}
}

// formatFinding renders everything needed to triage a regression from CI
// output alone: FindingID, rule, subject, evidence and limits.
func formatFinding(f finding.Finding) string {
	return fmt.Sprintf("id=%s rule=%s subject=%s severity=%s evidence=%v limits=%q",
		report.FindingID(f), f.RuleID, f.Subject, f.Severity, f.Evidence, f.Limits)
}

// TestFPGateNoCriticalsOnBenignSystems is half 1 of the gate: zero
// SevCritical findings on "stock" and "cruft".
func TestFPGateNoCriticalsOnBenignSystems(t *testing.T) {
	cases := []struct {
		name string
		cl   aur.Client
	}{
		{"stock", aur.Fake{}},
		{"cruft", cruftAURClient()},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			fx := loadGateFixture(t, gateRoot(t, c.name))
			res := Provenance(context.Background(), fx.pkgs, fx.syncNames, fx.unreadableSyncDBs, c.cl, true)
			for _, f := range res.Findings {
				if f.Severity == finding.SevCritical {
					t.Errorf("critical finding on benign root %q:\n  %s", c.name, formatFinding(f))
				}
			}
		})
	}
}

// TestFPGateStillCatchesMalware is half 2 of the gate, the acceptance
// counterpart to TestFPGateNoCriticalsOnBenignSystems: without this test,
// "zero criticals" would be trivially satisfiable by a scanner that reports
// nothing at all. MaxSeverity() alone would also be satisfied by a critical
// raised by the wrong rule for the wrong reason, so this pins both the rule
// and the subject.
func TestFPGateStillCatchesMalware(t *testing.T) {
	fx := loadGateFixture(t, gateRoot(t, "malicious"))
	res := Provenance(context.Background(), fx.pkgs, fx.syncNames, fx.unreadableSyncDBs, maliciousAURClient(), true)
	if res.MaxSeverity() != finding.SevCritical {
		t.Fatalf("malicious root did not reach SevCritical: findings=%+v gaps=%+v", res.Findings, res.Gaps)
	}
	f, ok := findingFor(res, "aur-tombstone")
	if !ok {
		t.Fatalf("no aur-tombstone finding on malicious root:\n  findings=%+v", res.Findings)
	}
	if f.Subject != "librewolf-fix-bin" {
		t.Errorf("aur-tombstone finding subject = %q, want %q\n  %s", f.Subject, "librewolf-fix-bin", formatFinding(f))
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("aur-tombstone finding severity = %v, want critical\n  %s", f.Severity, formatFinding(f))
	}
}

// TestFPGateBenignRootsAreNotSilent is the liveness floor: cruft must
// produce at least one SevSuspicious finding. Zero criticals with zero
// findings of any kind is the silent-scanner failure wearing a benign root
// as a disguise.
func TestFPGateBenignRootsAreNotSilent(t *testing.T) {
	fx := loadGateFixture(t, gateRoot(t, "cruft"))
	res := Provenance(context.Background(), fx.pkgs, fx.syncNames, fx.unreadableSyncDBs, cruftAURClient(), true)
	n := 0
	for _, f := range res.Findings {
		if f.Severity == finding.SevSuspicious {
			n++
		}
	}
	if n == 0 {
		t.Fatalf("cruft root produced zero SevSuspicious findings — liveness floor failed "+
			"(a silent scanner disguised as a benign root): findings=%+v gaps=%+v", res.Findings, res.Gaps)
	}
}

// TestFPGateFixtureRootsLoad guards against a typo in a fixture path making
// the whole gate vacuous: LoadLocalDB on a wrong path errors, but on an
// EMPTY directory it succeeds with zero packages, and every test above would
// then pass having scanned nothing.
func TestFPGateFixtureRootsLoad(t *testing.T) {
	for _, name := range []string{"stock", "cruft", "malicious"} {
		t.Run(name, func(t *testing.T) {
			fx := loadGateFixture(t, gateRoot(t, name))
			if len(fx.pkgs) == 0 {
				t.Fatalf("root %q loaded zero packages", name)
			}
			if len(fx.localGaps) != 0 {
				t.Errorf("root %q: local DB had unreadable entries: %v", name, fx.localGaps)
			}
			if len(fx.unreadableSyncDBs) != 0 {
				t.Errorf("root %q: materialized sync DB had unreadable entries: %v", name, fx.unreadableSyncDBs)
			}
		})
	}
}

// TestFPGateFindingIDIsVersionIndependent is the O-6 caller check.
// finding.Fingerprint's contract requires its subjectIdentity argument to be
// version-independent and says it cannot enforce that itself (finding.go's
// Fingerprint doc comment) — this pins the caller, Provenance, to that
// contract: the same package at two different Version values must produce
// the identical report.FindingID for the same rule. If this fails, the bug
// is in provenance.go's choice of Subject, not here — this test reports it,
// it does not fix it.
func TestFPGateFindingIDIsVersionIndependent(t *testing.T) {
	cl := aur.Fake{Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"}}
	older := alpm.Package{Name: "librewolf-fix-bin", Base: "librewolf-fix-bin", Version: "1.0-1", Validation: "none"}
	newer := alpm.Package{Name: "librewolf-fix-bin", Base: "librewolf-fix-bin", Version: "2.0-1", Validation: "none"}

	rOld := Provenance(context.Background(), []alpm.Package{older}, map[string]bool{}, nil, cl, true)
	rNew := Provenance(context.Background(), []alpm.Package{newer}, map[string]bool{}, nil, cl, true)

	fOld, okOld := findingFor(rOld, "aur-tombstone")
	fNew, okNew := findingFor(rNew, "aur-tombstone")
	if !okOld || !okNew {
		t.Fatalf("expected an aur-tombstone finding at both versions: okOld=%v okNew=%v", okOld, okNew)
	}
	idOld, idNew := report.FindingID(fOld), report.FindingID(fNew)
	if idOld != idNew {
		t.Errorf("O-6: report.FindingID differs across versions of the same package: "+
			"version %s -> %s, version %s -> %s (Provenance's Subject must be version-independent)",
			older.Version, idOld, newer.Version, idNew)
	}
}

// findingForSubject selects a finding by rule AND subject. findingFor
// (provenance_test.go) is rule-only, which is fine when a scenario has a
// single foreign package; the cruft root has several, so a rule-only lookup
// could silently pick a different subject's finding of the same rule and let
// a per-subject assertion pass having checked nothing about the subject it
// names.
func findingForSubject(res finding.Result, ruleID, subject string) (finding.Finding, bool) {
	for _, f := range res.Findings {
		if f.RuleID == ruleID && f.Subject == subject {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// gapForSubject mirrors findingForSubject for Gaps.
func gapForSubject(res finding.Result, ruleID, subject string) (finding.Gap, bool) {
	for _, g := range res.Gaps {
		if g.RuleID == ruleID && g.Subject == subject {
			return g, true
		}
	}
	return finding.Gap{}, false
}

// TestFPGateSubmitterMismatchIsBelowDefaultFloor pins, as release-gate
// behaviour, the checks lane's 2026-08-05 decision to downgrade
// aur-submitter-mismatch from SevSuspicious to SevInfo (lead decision, plan
// Risk #1 "cries wolf": measured on the reference system this rule fired on
// 13 of 39 foreign packages -- 33% -- every one a verified-benign maintainer
// handoff, and dominated the default `suspicious` floor with 13 of 14 total
// findings). provenance_test.go pins the same decision through hand-built
// literals; this test pins it through the SAME cruft fixture and the SAME
// Provenance call the rest of this release gate exercises, so a future
// change cannot pass the unit-level pin while still shipping the noise on a
// realistic system.
//
// It also closes the hole this gate shipped with: cruftAURClient already
// defines handoff-pkg and nosubmitter-pkg specifically to exercise this rule
// (33% of foreign packages on the reference system, the highest-volume rule
// in the tool), and until this test nothing in the gate asserted on either.
func TestFPGateSubmitterMismatchIsBelowDefaultFloor(t *testing.T) {
	fx := loadGateFixture(t, gateRoot(t, "cruft"))
	res := Provenance(context.Background(), fx.pkgs, fx.syncNames, fx.unreadableSyncDBs, cruftAURClient(), true)

	// (1) handoff-pkg: maintainer alice != submitter bob, both present ->
	// aur-submitter-mismatch must fire at exactly SevInfo. Asserted twice
	// deliberately: the exact-enum check pins the token, and the
	// floor-comparison check states the *operator-visible* consequence the
	// downgrade exists for -- that it no longer clears the default
	// `suspicious` reporting floor. Before 2026-08-05 this rule fired at
	// SevSuspicious here, which satisfies neither line below.
	f, ok := findingForSubject(res, "aur-submitter-mismatch", "handoff-pkg")
	if !ok {
		t.Fatalf("no aur-submitter-mismatch finding for handoff-pkg on the cruft root:\n  findings=%+v", res.Findings)
	}
	if f.Severity != finding.SevInfo {
		t.Errorf("handoff-pkg aur-submitter-mismatch severity = %v, want info "+
			"(2026-08-05 downgrade, plan Risk #1 -- 33%% noise on the reference system):\n  %s",
			f.Severity, formatFinding(f))
	}
	if f.Severity >= finding.SevSuspicious {
		t.Errorf("handoff-pkg aur-submitter-mismatch severity %v reaches the default reporting floor "+
			"(SevSuspicious) on the release-gate cruft root -- this is exactly the 33%%-noise regression "+
			"the 2026-08-05 downgrade exists to prevent:\n  %s", f.Severity, formatFinding(f))
	}

	// (3) INV-6: a downgrade to info must not become a downgrade to
	// uninformative -- the finding still has to name what it found. NOTE ON
	// THIS ASSERTION'S HISTORY (see the qa-fp-gate receipt): Evidence and
	// Limits were non-empty on this rule before the 2026-08-05 downgrade too
	// (only the Severity field and the Limits *text* changed, per
	// `git diff` on provenance.go); this block alone could not have failed
	// against the pre-downgrade code and is a forward-looking regression pin,
	// not a red/green TDD assertion for this lane.
	if f.Limits == "" {
		t.Errorf("handoff-pkg aur-submitter-mismatch has empty Limits (INV-6): %s", formatFinding(f))
	}
	evidence := strings.Join(f.Evidence, " ")
	if !strings.Contains(evidence, "submitter=bob") || !strings.Contains(evidence, "maintainer=alice") {
		t.Errorf("handoff-pkg aur-submitter-mismatch evidence does not name both identities: %v", f.Evidence)
	}

	// (2) INV-10 pin: nosubmitter-pkg (maintainer carol, no submitter on the
	// AUR record) must produce an aur-submitter-mismatch Gap and NEVER an
	// aur-submitter-mismatch finding. An absent submitter must never read as
	// "maintainer and submitter agree" -- that would silently disable the
	// takeover signal this rule exists to raise. provenance_test.go's
	// TestMissingSubmitterIsAGap pins the same shape on a hand-built literal;
	// this pins it through the release-gate fixture and the real
	// alpm.LoadLocalDB parse.
	if _, ok := findingForSubject(res, "aur-submitter-mismatch", "nosubmitter-pkg"); ok {
		t.Fatalf("nosubmitter-pkg produced an aur-submitter-mismatch finding despite no submitter on the " +
			"AUR record (INV-10 violation: an absent submitter must never read as agreement)")
	}
	if _, ok := gapForSubject(res, "aur-submitter-mismatch", "nosubmitter-pkg"); !ok {
		t.Errorf("no aur-submitter-mismatch Gap for nosubmitter-pkg on the cruft root; got gaps=%+v", res.Gaps)
	}

	// (4) Severity-inflation regression floor, stated over the whole cruft
	// sweep rather than one subject: no aur-submitter-mismatch finding may
	// reach >= SevSuspicious anywhere on this root. If this ever fails, the
	// rule has drifted back toward (or past) the default floor and will
	// again dominate default `scan` output the way it measurably did before
	// the 2026-08-05 downgrade (13 of 14 total findings on the reference
	// system were this rule, at SevSuspicious).
	for _, sf := range res.Findings {
		if sf.RuleID == "aur-submitter-mismatch" && sf.Severity >= finding.SevSuspicious {
			t.Errorf("aur-submitter-mismatch finding at or above the default floor on the cruft root "+
				"(2026-08-05 downgrade regression, plan Risk #1 -- historically 33%% of foreign packages, "+
				"13 of 14 total findings, on the reference system): %s", formatFinding(sf))
		}
	}
}

// ---------------------------------------------------------------------------
// P1-C: the SYSTEM-STATE half of the gate (testdata/roots/{stock,cruft,malicious})
// ---------------------------------------------------------------------------
//
// Two fixture families, deliberately separate, because they answer different
// questions:
//
//   - testdata/gate/{stock,cruft,malicious} -- the PACKAGE/AUR side. A local DB
//     plus a sync-name oracle plus an aur.Client, fed to Provenance. The tests
//     above.
//   - testdata/roots/{stock,cruft,malicious} -- the FILESYSTEM side, named by
//     roadmap P1-C rows 8 and 9. Whole offline roots carrying the persistence
//     surfaces P1-C reads: unit files, *.wants/ links, hook directories,
//     ld.so.preload, per-user paths, plus the system state that makes those
//     surfaces noisy (pip, npm -g, /usr/local, stale files from removed
//     packages). testdata/roots/stock already existed as internal/alpm's
//     fixture root and was EXTENDED, not rewritten -- its package COUNT is
//     pinned by alpm's TestLoadLocalDBFromStockFixture, so nothing here may add
//     or remove a package under it.
//
// These tests assert the STRUCTURAL FACTS ON DISK, using only what exists
// today: alpm.LoadLocalDB, internal/hook, and a deliberately minimal local
// ownership/symlink oracle below. internal/own, internal/surfaces and
// internal/correlate are being written concurrently in this same phase; when
// they land, the assertions here become the calibration those checks are
// measured against, and the checks' own tests replace the local oracle with
// own.Owners. What CANNOT be asserted until internal/correlate lands is named
// in TestFPGateMaliciousRootStructuralFacts.

// systemRoot returns the on-disk path of one whole-root fixture under
// testdata/roots. Distinct from gateRoot (testdata/gate) on purpose: see the
// block comment above.
func systemRoot(t *testing.T, name string) string {
	t.Helper()
	return filepath.Join("..", "..", "testdata", "roots", name)
}

// fpgOwned is a minimal ownership oracle: root-relative path -> owning package.
//
// It is NOT a stand-in for internal/own and must not grow into one. It exists so
// this file can state what the fixtures ARE without depending on a package
// another lane is writing this hour. It does exactly one non-obvious thing --
// strip the trailing slash real pacman %FILES% entries carry on DIRECTORIES --
// because that detail decides whether a packaged `*.wants/` directory reads as
// owned, and a fixture whose calibration silently depended on it would be
// worthless.
func fpgOwned(t *testing.T, root string) map[string]string {
	t.Helper()
	pkgs, gaps, err := alpm.LoadLocalDB(filepath.Join(root, "var", "lib", "pacman", "local"))
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", root, err)
	}
	if len(gaps) != 0 {
		t.Fatalf("root %s: unreadable local DB entries %v", root, gaps)
	}
	owned := map[string]string{}
	for _, p := range pkgs {
		for _, f := range p.Files {
			owned[strings.TrimSuffix(path.Clean(f), "/")] = p.Name
		}
	}
	if len(owned) == 0 {
		t.Fatalf("root %s: ownership oracle is empty; every 'unowned' assertion below would pass vacuously", root)
	}
	return owned
}

// fpgResolve resolves one root-relative symlink path the way a scan of an
// offline root must: an ABSOLUTE target is relative to the SCANNED ROOT (this is
// the form `systemctl enable` writes, and reading it against the host instead
// would resolve host files while scanning someone else's disk), a relative
// target is relative to the link's own directory, and a target escaping the root
// resolves to nothing.
func fpgResolve(t *testing.T, root, rel string) (target string, ok bool) {
	t.Helper()
	dst, err := os.Readlink(filepath.Join(root, rel))
	if err != nil {
		return "", false
	}
	if strings.HasPrefix(dst, "/") {
		target = path.Clean(strings.TrimPrefix(dst, "/"))
	} else {
		target = path.Clean(path.Join(path.Dir(rel), dst))
	}
	if target == ".." || strings.HasPrefix(target, "../") {
		return "", false
	}
	if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(target))); err != nil {
		// Unresolvable. NOTE: absolute links in a checked-in fixture dangle when
		// read from the repository and resolve when read from a real scan root,
		// which is exactly why they are resolved against `root` above and not
		// with filepath.EvalSymlinks.
		return "", false
	}
	return target, true
}

// fpgWantsSurvey is the *.wants triage rule's three behaviours, applied to a
// fixture root by hand: resolve symlink targets, exclude directories, and treat
// only unresolvable-or-unowned targets as subjects.
type fpgWantsSurvey struct {
	dirs       []string // unowned *.wants directories -- excluded
	ownedLinks []string // links whose TARGET is package-owned -- excluded
	subjects   []string // unresolvable or unowned -- reported
}

func (s fpgWantsSurvey) total() int { return len(s.dirs) + len(s.ownedLinks) + len(s.subjects) }

// fpgSurveyWants enumerates every unowned path under a `*.wants/` directory
// anywhere in the root and classifies it.
func fpgSurveyWants(t *testing.T, root string, owned map[string]string) fpgWantsSurvey {
	t.Helper()
	var s fpgWantsSurvey
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() || !strings.HasSuffix(d.Name(), ".wants") {
			return nil
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		dir := filepath.ToSlash(rel)
		if _, isOwned := owned[dir]; !isOwned {
			s.dirs = append(s.dirs, dir)
		}
		ents, readErr := os.ReadDir(p)
		if readErr != nil {
			// INV-9: an unreadable *.wants directory is a coverage gap, never
			// silence. No fixture can produce one (git cannot store mode 000),
			// so reaching this line means a genuinely broken checkout.
			return readErr
		}
		for _, ent := range ents {
			entRel := path.Join(dir, ent.Name())
			if _, isOwned := owned[entRel]; isOwned {
				continue
			}
			if ent.IsDir() {
				s.dirs = append(s.dirs, entRel)
				continue
			}
			if ent.Type()&fs.ModeSymlink != 0 {
				if tgt, resolved := fpgResolve(t, root, entRel); resolved {
					if _, isOwned := owned[tgt]; isOwned {
						s.ownedLinks = append(s.ownedLinks, entRel)
						continue
					}
				}
			}
			s.subjects = append(s.subjects, entRel)
		}
		return nil
	})
	if err != nil {
		t.Fatalf("survey %s: %v", root, err)
	}
	sort.Strings(s.dirs)
	sort.Strings(s.ownedLinks)
	sort.Strings(s.subjects)
	return s
}

// TestFPGateSystemRootsLoad guards against the whole system-state half of the
// gate going vacuous: a mistyped path, a fixture deleted by a rebase, or an
// ownership oracle that loaded nothing would make every "must not be reported"
// assertion below pass having examined nothing.
func TestFPGateSystemRootsLoad(t *testing.T) {
	cases := []struct {
		root  string
		files []string
	}{
		{"stock", []string{
			"etc/passwd",
			"etc/pacman.conf",
			"usr/lib/systemd/system/foo.service",
			"usr/share/libalpm/hooks/50-foo.hook",
			"etc/systemd/system/multi-user.target.wants/foo.service",
		}},
		{"cruft", []string{
			"etc/passwd",
			"etc/pacman.conf",
			"etc/ld.so.preload",
			"etc/systemd/system/local-backup.service",
			"etc/pacman.d/hooks/99-local-mkinitcpio.hook",
			"usr/local/bin/hand-built-tool",
			"usr/lib/node_modules/prettier/package.json",
			"usr/lib/python3.13/site-packages/requests/__init__.py",
			"home/alice/.local/lib/python3.13/site-packages/rich/__init__.py",
			"home/alice/.config/autostart/nextcloud.desktop",
			"usr/share/oldpkg/data.conf",
		}},
		{"malicious", []string{
			"README.md",
			"etc/systemd/system/systemd-initd-inert.service",
			"etc/systemd/system/multi-user.target.wants/systemd-initd-inert.service",
			"usr/lib/systemd/inert-marker-initd",
			"etc/ld.so.preload",
			"etc/pacman.d/hooks/60-depmod.hook",
			"usr/share/libalpm/hooks/60-depmod.hook",
			"home/alice/.cache/yay/librewolf-fix-bin/PKGBUILD",
			"var/lib/pacman/local/librewolf-fix-bin-1.2.0-1/install",
		}},
	}
	for _, c := range cases {
		t.Run(c.root, func(t *testing.T) {
			root := systemRoot(t, c.root)
			owned := fpgOwned(t, root)
			t.Logf("%s: %d owned paths", c.root, len(owned))
			for _, f := range c.files {
				if _, err := os.Lstat(filepath.Join(root, filepath.FromSlash(f))); err != nil {
					t.Errorf("fixture %s/%s missing: %v", c.root, f, err)
				}
			}
		})
	}
	// The stock root's admin hook dir is absent on a stock install. Its absence
	// is a FACT to record, not an error and not a coverage gap, so it is pinned
	// here: a future fixture edit that creates it would quietly delete the only
	// test of that path.
	if _, err := os.Stat(filepath.Join(systemRoot(t, "stock"), "etc", "pacman.d", "hooks")); !os.IsNotExist(err) {
		t.Errorf("stock root has etc/pacman.d/hooks (err=%v); it must stay ABSENT -- "+
			"absence is the reference system's state and a fact, not an error", err)
	}
}

// TestFPGateWantsRuleProducesExactlyOneSubjectOnCruft is the phase gate's
// headline number. Measured on the reference system: 30 unowned paths under
// *.wants/ decompose into 19 benign enablement symlinks, 8 *.target.wants
// directories and exactly 1 real hand-written unit. A rule that produces more
// than ONE subject there is wrong.
//
// Each of the three counts below fails for a different, diagnosable reason:
//   - dirs != 8 -> the "exclude directories" behaviour is not being exercised
//   - ownedLinks != 19 -> the "resolve symlink targets" behaviour is not
//   - subjects != 1 -> the rule's actual output, the number in the gate
//
// On the arithmetic: 19+8+1 = 28, not the 30 the roadmap states. The published
// decomposition is exhaustive by KIND (any further path is a directory, a link
// to an owned target, or a link to an unowned one), so the remaining 2 cannot be
// derived from it and are not invented here. This root pins the kinds and the
// one-subject outcome -- which is what the gate is stated in terms of. Recorded
// in testdata/roots/cruft/README.md and escalated with the P1-C receipt.
func TestFPGateWantsRuleProducesExactlyOneSubjectOnCruft(t *testing.T) {
	root := systemRoot(t, "cruft")
	owned := fpgOwned(t, root)
	s := fpgSurveyWants(t, root, owned)

	if len(s.dirs) != 8 {
		t.Errorf("cruft: %d unowned *.wants directories, want 8 (they must be EXCLUDED, "+
			"not reported -- systemctl enable creates them and no package ships them): %v", len(s.dirs), s.dirs)
	}
	if len(s.ownedLinks) != 19 {
		t.Errorf("cruft: %d enablement symlinks resolving to a package-owned target, want 19 "+
			"(without target resolution every one of these becomes a false positive): %v",
			len(s.ownedLinks), s.ownedLinks)
	}
	if len(s.subjects) != 1 {
		t.Fatalf("cruft: the *.wants rule yields %d subjects, want exactly 1 "+
			"(roadmap P1-C gate): %v", len(s.subjects), s.subjects)
	}
	want := "etc/systemd/system/multi-user.target.wants/local-backup.service"
	if s.subjects[0] != want {
		t.Errorf("cruft: the one *.wants subject is %q, want %q -- the right COUNT reached "+
			"through the wrong path is not the rule working", s.subjects[0], want)
	}
	if s.total() != 28 {
		t.Errorf("cruft: %d unowned paths under *.wants/ in total, want 28 (19 links + 8 dirs + 1 unit)", s.total())
	}

	// The vendor preset link is OWNED (shipped by foo-daemon, listed in its
	// %FILES% together with its directory), so it is not one of the 28 at all.
	// This is what makes the trailing-slash handling of %FILES% DIRECTORY
	// entries load-bearing rather than cosmetic: drop it and the packaged
	// `*.wants/` directory reads as unowned.
	for _, p := range []string{
		"usr/lib/systemd/system/multi-user.target.wants",
		"usr/lib/systemd/system/multi-user.target.wants/foo-daemon.service",
	} {
		if _, isOwned := owned[p]; !isOwned {
			t.Errorf("cruft: %s must be package-owned (it is a vendor preset shipped in %%FILES%%)", p)
		}
	}

	// The one subject is a LINK; the hand-written unit it points at is a real
	// file outside any *.wants directory. Both halves matter: the link is how
	// the unit is reachable, the file is what an operator has to look at.
	tgt, ok := fpgResolve(t, root, want)
	if !ok {
		t.Fatalf("cruft: the one subject %s does not resolve; it must resolve to an UNOWNED unit, "+
			"which is a different finding from an unresolvable link", want)
	}
	if tgt != "etc/systemd/system/local-backup.service" {
		t.Errorf("cruft: subject resolves to %q, want etc/systemd/system/local-backup.service", tgt)
	}
	if pkg, isOwned := owned[tgt]; isOwned {
		t.Errorf("cruft: the hand-written unit %s is owned by %q; the fixture's one true positive "+
			"has stopped being a true positive", tgt, pkg)
	}
}

// TestFPGateWantsRuleIsSilentOnStock is the same rule against a root where every
// enablement link resolves to a package-owned unit: zero subjects. Cruft proves
// the rule fires once; this proves it does not fire at all when there is nothing
// to fire on, which is the half a rule written to satisfy cruft alone can lose.
func TestFPGateWantsRuleIsSilentOnStock(t *testing.T) {
	root := systemRoot(t, "stock")
	owned := fpgOwned(t, root)
	s := fpgSurveyWants(t, root, owned)

	if len(s.subjects) != 0 {
		t.Errorf("stock: the *.wants rule yields %d subjects, want 0 -- zero criticals on the stock "+
			"root is a release gate (INV-8): %v", len(s.subjects), s.subjects)
	}
	// ...and it must not be silent because it looked at nothing.
	if len(s.dirs) == 0 && len(s.ownedLinks) == 0 {
		t.Fatalf("stock: the survey examined no unowned *.wants paths at all, so 'zero subjects' "+
			"says nothing: %+v", s)
	}
	// The absolute-target form `systemctl enable` writes, resolved against the
	// SCANNED ROOT rather than the host. This single line is the difference
	// between 0 and 19 false positives on the cruft root.
	link := "etc/systemd/system/multi-user.target.wants/foo.service"
	tgt, ok := fpgResolve(t, root, link)
	if !ok {
		t.Fatalf("stock: %s did not resolve; an absolute link target must be resolved against the root", link)
	}
	if pkg := owned[tgt]; pkg != "foo-bin" {
		t.Errorf("stock: %s -> %s owned by %q, want foo-bin (ownership must be recognised THROUGH the link)",
			link, tgt, pkg)
	}
}

// TestFPGateSystemRootHookDirs pins the hook-directory coverage on the whole
// roots family, through the real internal/hook loader: the system dir is active
// by default, the admin dir is absent on stock, and name-shadowing across the
// two is what suppression looks like.
//
// os.DirFS, not fsx: LoadHooks takes an fs.FS view of the root, and a scan
// supplies a confined one. os.DirFS is unconfined, so an ABSOLUTE symlink target
// inside a fixture (cruft's /dev/null mask) resolves against the HOST here. That
// difference is called out where it bites, below, rather than hidden.
func TestFPGateSystemRootHookDirs(t *testing.T) {
	t.Run("stock", func(t *testing.T) {
		root := systemRoot(t, "stock")
		hooks, gaps := hook.LoadHooks(os.DirFS(root), hook.DefaultHookDirs)
		if len(gaps) != 0 {
			t.Errorf("stock: hook gaps %+v, want none -- an ABSENT etc/pacman.d/hooks is normal and "+
				"must not manufacture a coverage gap", gaps)
		}
		if len(hooks) != 1 || hooks[0].Name != "50-foo.hook" {
			t.Fatalf("stock: hooks = %+v, want exactly 50-foo.hook", hooks)
		}
		if hooks[0].Dir != "usr/share/libalpm/hooks" {
			t.Errorf("stock: 50-foo.hook Dir = %q, want the system hook dir", hooks[0].Dir)
		}
		if got := hook.ExecPathLiterals(hooks[0].Exec); len(got) != 1 || got[0] != "/var/cache/foo/index" {
			t.Errorf("stock: 50-foo.hook Exec paths = %v, want [/var/cache/foo/index] "+
				"(and never /usr/bin/foo -- the command itself is never exempt)", got)
		}
	})

	t.Run("cruft", func(t *testing.T) {
		root := systemRoot(t, "cruft")
		owned := fpgOwned(t, root)
		hooks, gaps := hook.LoadHooks(os.DirFS(root), hook.DefaultHookDirs)
		byName := map[string]hook.Hook{}
		for _, h := range hooks {
			byName[h.Name] = h
		}
		if _, ok := byName["70-foo.hook"]; !ok {
			t.Errorf("cruft: 70-foo.hook missing from %+v", hooks)
		}
		if h, ok := byName["99-local-mkinitcpio.hook"]; !ok {
			t.Errorf("cruft: the hand-written admin hook is missing from %+v", hooks)
		} else if h.Dir != "etc/pacman.d/hooks" {
			t.Errorf("cruft: 99-local-mkinitcpio.hook Dir = %q, want etc/pacman.d/hooks", h.Dir)
		} else if _, isOwned := owned["etc/pacman.d/hooks/99-local-mkinitcpio.hook"]; isOwned {
			t.Error("cruft: the admin hook must stay UNOWNED -- an unowned hook in the admin dir is " +
				"what that directory is for, and reporting it as critical fails the gate")
		}

		// The /dev/null mask: the LINK TEXT is the fixture's fact and is
		// asserted directly, because whether it READS as an empty hook or as a
		// coverage gap depends on confinement (see this test's doc comment) and
		// aurvet must behave defensibly either way.
		mask := filepath.Join(root, "etc", "pacman.d", "hooks", "60-depmod.hook")
		dst, err := os.Readlink(mask)
		if err != nil {
			t.Fatalf("cruft: 60-depmod.hook is not a symlink: %v", err)
		}
		if dst != "/dev/null" {
			t.Fatalf("cruft: 60-depmod.hook -> %q, want /dev/null (the documented way to mask a hook)", dst)
		}
		if _, isOwned := owned["usr/share/libalpm/hooks/60-depmod.hook"]; !isOwned {
			t.Error("cruft: the MASKED hook must be package-owned, or there is nothing being suppressed")
		}
		// Whichever way the mask reads, it must never contribute an exemption:
		// a hook that does not run regenerates nothing, so its outputs stay
		// under digest verification.
		if h, ok := byName["60-depmod.hook"]; ok {
			if h.Dir != "etc/pacman.d/hooks" {
				t.Errorf("cruft: 60-depmod.hook resolved to Dir %q; the admin dir must win by file name", h.Dir)
			}
			if got := hook.ExecPathLiterals(h.Exec); len(got) != 0 {
				t.Errorf("cruft: the masked 60-depmod.hook contributed exempt paths %v; a suppressed "+
					"hook regenerates nothing and must exempt nothing", got)
			}
		} else {
			// Read confined (or on a root without /dev/null), the mask is
			// unreadable and INV-9 requires a gap rather than silence.
			if _, ok := gapForSubject(finding.Result{Gaps: gaps}, "hook-coverage",
				"etc/pacman.d/hooks/60-depmod.hook"); !ok {
				t.Errorf("cruft: the masked hook neither parsed nor produced a hook-coverage gap; "+
					"unreadable input must never become silence (INV-9). gaps=%+v", gaps)
			}
		}
	})

	t.Run("malicious", func(t *testing.T) {
		root := systemRoot(t, "malicious")
		owned := fpgOwned(t, root)
		hooks, gaps := hook.LoadHooks(os.DirFS(root), hook.DefaultHookDirs)
		if len(gaps) != 0 {
			t.Errorf("malicious: hook gaps %+v, want none", gaps)
		}
		var shadow hook.Hook
		for _, h := range hooks {
			if h.Name == "60-depmod.hook" {
				shadow = h
			}
		}
		if shadow.Name == "" {
			t.Fatalf("malicious: 60-depmod.hook missing from %+v", hooks)
		}
		// Same file name, two directories: the admin one wins, so the packaged
		// hook's work silently stops happening. Detection must cover hooks
		// SUPPRESSED, not only hooks added.
		if shadow.Dir != "etc/pacman.d/hooks" {
			t.Errorf("malicious: 60-depmod.hook resolved to Dir %q, want etc/pacman.d/hooks "+
				"(the shadowing copy must win, or the suppression is invisible)", shadow.Dir)
		}
		if _, isOwned := owned["etc/pacman.d/hooks/60-depmod.hook"]; isOwned {
			t.Error("malicious: the shadowing hook must be UNOWNED -- that is the whole signal")
		}
		if _, isOwned := owned["usr/share/libalpm/hooks/60-depmod.hook"]; !isOwned {
			t.Error("malicious: the SHADOWED hook must be package-owned, or nothing is being suppressed")
		}
		if strings.Contains(shadow.Exec, "depmod") {
			t.Errorf("malicious: the shadowing hook's Exec %q still does the packaged hook's work; "+
				"the fixture no longer encodes suppression", shadow.Exec)
		}
	})
}

// fpgUnitExecStart pulls the ExecStart value out of a unit file with the
// crudest parse that can work. internal/surfaces/units.go is the real parser
// and is being written concurrently; this exists only so the fixture's claim
// about itself is checked by something.
func fpgUnitExecStart(t *testing.T, root, rel string) string {
	t.Helper()
	data, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(rel)))
	if err != nil {
		t.Fatalf("read unit %s: %v", rel, err)
	}
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if strings.HasPrefix(line, "#") || strings.HasPrefix(line, ";") {
			continue
		}
		if v, ok := strings.CutPrefix(line, "ExecStart="); ok {
			return strings.TrimSpace(v)
		}
	}
	t.Fatalf("unit %s has no ExecStart", rel)
	return ""
}

// TestFPGateMaliciousRootStructuralFacts is the acceptance half of the gate for
// the system-state fixtures: the malicious root must keep producing evidence, or
// "zero criticals on stock and cruft" is satisfiable by a scanner that has gone
// quiet.
//
// It asserts the CHAOS RAT structural shape as it exists on disk. It does NOT
// assert a correlated critical cluster: internal/correlate does not exist yet.
// What awaits that lane, and must be added to this gate when it lands:
//
//  1. the three facts below cluster onto ONE subject, librewolf-fix-bin, by the
//     package key (unowned unit -> scriptlet -> package) and by the
//     path-attribution key (/usr/lib/systemd/inert-marker-initd and the
//     ld.so.preload entry share a directory);
//  2. that cluster reaches SevCritical while no individual fact does;
//  3. the temporal key -- which cannot be exercised from a checked-in tree at
//     all, because git does not preserve mtimes (see the root's README);
//  4. the finding text states, in Limits and not only in documentation
//     (INV-6), that this shape is what SLOPPY malware looks like: a payload
//     built into its own $pkgdir and shipped in the package's file list
//     produces no unowned files, a self-consistent mtree and an ExecStart
//     resolving to a package-owned binary, and every check in this phase goes
//     silent.
func TestFPGateMaliciousRootStructuralFacts(t *testing.T) {
	root := systemRoot(t, "malicious")
	owned := fpgOwned(t, root)
	const (
		unit    = "etc/systemd/system/systemd-initd-inert.service"
		payload = "usr/lib/systemd/inert-marker-initd"
		pkgDir  = "var/lib/pacman/local/librewolf-fix-bin-1.2.0-1"
	)

	// Fact 1: a unit installed by a SCRIPTLET, not by the package's file list.
	// It is on disk and no package's %FILES% mentions it, so `pacman -Qo` has
	// nothing to blame -- which is exactly why ownership, not pacman, has to be
	// the oracle.
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(unit))); err != nil {
		t.Fatalf("malicious: the scriptlet-installed unit is missing: %v", err)
	}
	if pkg, isOwned := owned[unit]; isOwned {
		t.Errorf("malicious: %s is owned by %q; a unit in a %%FILES%% list is the SILENT case, "+
			"not the fixture's case", unit, pkg)
	}
	if _, isOwned := owned["etc/systemd/system"]; !isOwned {
		t.Error("malicious: etc/systemd/system must be package-owned -- an unowned file in an OWNED " +
			"directory is the shape; an unowned directory would be a weaker and different finding")
	}
	script, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pkgDir), "install"))
	if err != nil {
		t.Fatalf("malicious: the package's install scriptlet is missing: %v", err)
	}
	if !strings.Contains(string(script), "post_install") {
		t.Errorf("malicious: the install scriptlet has no post_install function:\n%s", script)
	}

	// Fact 2: ExecStart resolves to an UNOWNED binary, inside a package-owned
	// directory -- the systemd lookalike that made the real incident sneaky.
	exec := fpgUnitExecStart(t, root, unit)
	if exec != "/"+payload {
		t.Fatalf("malicious: unit ExecStart = %q, want /%s", exec, payload)
	}
	if _, err := os.Stat(filepath.Join(root, filepath.FromSlash(payload))); err != nil {
		t.Fatalf("malicious: the ExecStart target does not exist: %v -- an UNRESOLVABLE ExecStart is a "+
			"different finding from an unowned one", err)
	}
	if pkg, isOwned := owned[payload]; isOwned {
		t.Errorf("malicious: the ExecStart target %s is owned by %q; the fixture no longer encodes "+
			"an unowned payload", payload, pkg)
	}
	if _, isOwned := owned["usr/lib/systemd"]; !isOwned {
		t.Error("malicious: usr/lib/systemd must be package-owned, or the masquerade is not being modelled")
	}

	// Fact 3: off-upstream source. url= names the project, source= fetches from
	// an unrelated host. Asserted as text because internal/pkgbuild is P2.
	pkgbuild, err := os.ReadFile(filepath.Join(root, "home", "alice", ".cache", "yay",
		"librewolf-fix-bin", "PKGBUILD"))
	if err != nil {
		t.Fatalf("malicious: the helper-cache PKGBUILD is missing: %v", err)
	}
	src := string(pkgbuild)
	if !strings.Contains(src, `url="https://librewolf-fix.example.invalid/"`) {
		t.Errorf("malicious: PKGBUILD no longer declares an upstream url=:\n%s", src)
	}
	if !strings.Contains(src, "cdn7-dl.librewolf-fix-mirror.example.invalid") {
		t.Errorf("malicious: PKGBUILD source= is no longer off-upstream (it must not share a host "+
			"with url=):\n%s", src)
	}

	// The unit is reachable: enabled through a *.wants link, which is what makes
	// it persistence rather than a file lying on disk. Exactly one subject here
	// too -- the same rule, the same shape, a different verdict from cruft's.
	s := fpgSurveyWants(t, root, owned)
	if len(s.subjects) != 1 || s.subjects[0] != "etc/systemd/system/multi-user.target.wants/systemd-initd-inert.service" {
		t.Errorf("malicious: *.wants subjects = %v, want exactly the enablement link for the "+
			"scriptlet-installed unit", s.subjects)
	}

	// Supporting fact: a NON-EMPTY ld.so.preload naming an unowned object in the
	// SAME directory as the payload. Cruft's is present and empty, so existence
	// alone cannot be the signal.
	preload, err := os.ReadFile(filepath.Join(root, "etc", "ld.so.preload"))
	if err != nil {
		t.Fatalf("malicious: etc/ld.so.preload missing: %v", err)
	}
	entry := strings.TrimSpace(string(preload))
	if entry == "" {
		t.Fatal("malicious: etc/ld.so.preload is empty; the fixture's signal is CONTENTS, not existence")
	}
	if _, isOwned := owned[strings.TrimPrefix(entry, "/")]; isOwned {
		t.Errorf("malicious: the ld.so.preload entry %q is package-owned", entry)
	}
	if path.Dir(entry) != "/"+path.Dir(payload) {
		t.Errorf("malicious: the preload entry %q and the payload /%s no longer share a directory; "+
			"that shared directory is the path-attribution key that merges these into one cluster",
			entry, payload)
	}

	// And the package itself carries only the marks every locally built AUR
	// package carries. Pinned so nobody later mistakes them for the signal.
	desc, err := os.ReadFile(filepath.Join(root, filepath.FromSlash(pkgDir), "desc"))
	if err != nil {
		t.Fatalf("malicious: package desc missing: %v", err)
	}
	if !strings.Contains(string(desc), "%VALIDATION%\nnone") {
		t.Errorf("malicious: librewolf-fix-bin must be %%VALIDATION%% none -- shared with every benign " +
			"AUR package on the system, and therefore worth nothing on its own")
	}
}

// ---------------------------------------------------------------------------
// P1-C: the CORRELATION half of the gate (internal/correlate over
// testdata/roots/{stock,cruft,malicious})
// ---------------------------------------------------------------------------
//
// These two tests close what TestFPGateMaliciousRootStructuralFacts named as
// deferred to the correlation lane: the facts on disk clustering onto ONE
// subject, that cluster reaching SevCritical while no individual finding does,
// the temporal key (which needs mtimes and therefore a copy out of the
// repository), and INV-6 in the Limits text.
//
// The pair is the gate, exactly as the Provenance pair above is: "zero criticals
// on stock and cruft" is trivially satisfied by an engine that clusters nothing,
// so the benign half is only meaningful next to the malicious half, and both are
// top-level Test functions in this file so `go test ./internal/check/` fails if
// either does.

// fpgSyncNames is the repository-name oracle for the whole-root fixtures. It is
// the input that decides which packages are FOREIGN, and therefore whether a
// cluster can be attributed at all. cruft carries exactly one foreign package
// (deskx) on purpose: a benign root with none would satisfy "no critical
// cluster" for the wrong reason.
var fpgSyncNames = map[string]map[string]bool{
	"stock": {"foo-bin": true, "foo-lib": true, "zlib": true},
	"cruft": {
		"systemd": true, "kmod": true, "netbar": true, "printbaz": true,
		"sysutil": true, "foo-daemon": true,
	},
	"malicious": {"systemd": true, "kmod": true},
}

// fpgCorrelateConfig opens one root and builds the correlation input over it.
func fpgCorrelateConfig(t *testing.T, dir, name string) (*os.Root, correlate.Config) {
	t.Helper()
	pkgs, gaps, err := alpm.LoadLocalDB(filepath.Join(dir, "var", "lib", "pacman", "local"))
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", dir, err)
	}
	if len(gaps) != 0 {
		t.Fatalf("%s: unreadable local DB entries %v", name, gaps)
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	owners := own.IndexIn(root, pkgs)
	if owners.Len() == 0 {
		t.Fatalf("%s: empty ownership index; every 'unowned' assertion would pass vacuously", name)
	}
	return root, correlate.Config{Owners: owners, Pkgs: pkgs, SyncNames: fpgSyncNames[name]}
}

// fpgCopyRoot copies a fixture root into t.TempDir(), symlinks verbatim.
//
// It exists for one reason: git does not preserve mtimes, so the temporal
// correlation key cannot be exercised against a checked-in tree at all. The
// copy is written and the fixture is only ever read -- INV-5 forbids writing
// under a scanned root, and testdata/ is not this test's to modify.
func fpgCopyRoot(t *testing.T, name string) string {
	t.Helper()
	src := systemRoot(t, name)
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(src, p)
		if relErr != nil {
			return relErr
		}
		out := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(out, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
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
			return os.WriteFile(out, data, 0o644)
		}
	})
	if err != nil {
		t.Fatalf("copy fixture %s: %v", name, err)
	}
	return dst
}

// TestFPGateMaliciousRootYieldsCorrelatedCriticalCluster is the acceptance half:
// the CHAOS RAT structural shape must produce one correlated critical cluster
// attributed to librewolf-fix-bin, and every fact it is built from must stay
// below critical on its own.
func TestFPGateMaliciousRootYieldsCorrelatedCriticalCluster(t *testing.T) {
	dir := fpgCopyRoot(t, "malicious")
	// librewolf-fix-bin's %INSTALLDATE%, deliberately far from the repository
	// packages' (see testdata/roots/malicious/README.md). The offsets model a
	// scriptlet running inside the transaction pacman recorded that date for.
	const installDate = 1770099000
	for rel, off := range map[string]int64{
		"usr/lib/systemd/inert-marker-initd":             60,
		"usr/lib/systemd/libinert-marker-preload.so":     62,
		"etc/systemd/system/systemd-initd-inert.service": 61,
		"etc/pacman.d/hooks/60-depmod.hook":              63,
	} {
		ts := time.Unix(installDate+off, 0)
		if err := os.Chtimes(filepath.Join(dir, filepath.FromSlash(rel)), ts, ts); err != nil {
			t.Fatalf("chtimes %s: %v", rel, err)
		}
	}
	root, cfg := fpgCorrelateConfig(t, dir, "malicious")

	facts, surfaceRes := correlate.Facts(root, cfg)
	if len(facts) < 3 {
		t.Fatalf("only %d correlation facts on the malicious root; the fixture's three structural facts "+
			"must all be derivable or the cluster below proves nothing: %+v", len(facts), facts)
	}
	for _, f := range surfaceRes.Findings {
		if f.Severity == finding.SevCritical {
			t.Errorf("an individual surface finding reached critical: %s\n  %s", f.RuleID, formatFinding(f))
		}
	}

	res := correlate.Correlate(root, cfg)
	var crit []finding.Finding
	for _, f := range res.Findings {
		if f.Severity == finding.SevCritical {
			crit = append(crit, f)
		}
	}
	if len(crit) != 1 {
		t.Fatalf("%d critical findings on the malicious root, want exactly 1 (the cluster): %+v", len(crit), crit)
	}
	f := crit[0]
	if f.RuleID != correlate.RuleCluster {
		t.Errorf("the critical came from rule %q, not from a correlated cluster:\n  %s", f.RuleID, formatFinding(f))
	}
	if f.Subject != "librewolf-fix-bin" {
		t.Errorf("cluster subject = %q, want librewolf-fix-bin -- the right severity on the wrong subject "+
			"is not attribution:\n  %s", f.Subject, formatFinding(f))
	}
	// INV-6 in the finding text, not only in the documentation. A critical that
	// does not say what it cannot see teaches the reader that silence means
	// safety.
	lim := strings.ToLower(f.Limits)
	for _, want := range []string{"pkgdir", "silent", "sloppy", "mtree"} {
		if !strings.Contains(lim, want) {
			t.Errorf("cluster Limits does not state the phase's ceiling (%q missing): %q", want, f.Limits)
		}
	}
	// The evidence must name the three structural facts, or the cluster is
	// critical for reasons an operator cannot check.
	ev := strings.Join(f.Evidence, "\n")
	for _, want := range []string{
		"etc/systemd/system/systemd-initd-inert.service",
		"usr/lib/systemd/inert-marker-initd",
		"usr/lib/systemd/libinert-marker-preload.so",
		"temporal",
	} {
		if !strings.Contains(ev, want) {
			t.Errorf("cluster evidence does not mention %q:\n%s", want, ev)
		}
	}
}

// TestFPGateNoCriticalClusterOnBenignSystemRoots is the false-positive half, and
// cruft is the hard case: its hand-written unit really is enabled through a
// *.wants link and really does run an unowned binary, so two independent
// surfaces genuinely correlate onto one subject on a root where nothing is
// wrong. It must stay suspicious.
func TestFPGateNoCriticalClusterOnBenignSystemRoots(t *testing.T) {
	for _, name := range []string{"stock", "cruft"} {
		t.Run(name, func(t *testing.T) {
			root, cfg := fpgCorrelateConfig(t, systemRoot(t, name), name)
			res := correlate.Correlate(root, cfg)
			for _, f := range res.Findings {
				if f.Severity == finding.SevCritical {
					t.Errorf("critical finding on benign root %q:\n  %s", name, formatFinding(f))
				}
			}
			if name == "cruft" {
				// Liveness: cruft must still CLUSTER, or "no criticals" is being
				// satisfied by an engine that correlated nothing.
				var clustered bool
				for _, f := range res.Findings {
					if f.RuleID == correlate.RuleCluster {
						clustered = true
					}
				}
				if !clustered {
					t.Errorf("cruft produced no cluster at all; zero criticals then says nothing about "+
						"the engine: findings=%+v", res.Findings)
				}
			}
		})
	}
}

// fpgForbiddenInFixture are the constructs a fixture root in a security tool's
// repository must never contain. This is not style policing: a directory called
// `malicious/` will be read by strangers and crawled by scanners, and a fixture
// that could be mistaken for a working payload is a liability whatever it was
// meant to demonstrate.
var fpgForbiddenInFixture = []string{
	"curl ", "wget ", "base64 -d", "base64 --decode", "openssl enc",
	"nc -", "ncat ", "/dev/tcp/", "socat ", "systemctl enable", "systemctl start",
	"eval ", "exec ", "chmod +x", "setsid ", "crontab ",
}

// fpgURLHost matches the host of an http(s) URL.
var fpgURLHost = regexp.MustCompile(`https?://([A-Za-z0-9._-]+)`)

// fpgIPLiteral matches a dotted-quad.
var fpgIPLiteral = regexp.MustCompile(`\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b`)

// TestFPGateMaliciousFixtureIsInert is a safety gate on the fixture itself, and
// it is as load-bearing as any detection test here. The malicious root asserts
// STRUCTURE, not behaviour: nothing in it may be executable, name a resolvable
// host, carry an encoded blob, or contain a command that could do something if
// someone pasted it into a shell.
//
// INV-2 cuts both ways: the tool never executes a fixture, and the fixture is
// never something worth executing.
func TestFPGateMaliciousFixtureIsInert(t *testing.T) {
	root := systemRoot(t, "malicious")
	files := 0
	err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, relErr := filepath.Rel(root, p)
		if relErr != nil {
			return relErr
		}
		if d.Type()&fs.ModeSymlink != 0 || d.IsDir() {
			return nil
		}
		info, statErr := d.Info()
		if statErr != nil {
			return statErr
		}
		if info.Mode().Perm()&0o111 != 0 {
			t.Errorf("%s is EXECUTABLE (mode %v); no file in the malicious fixture may be", rel, info.Mode())
		}
		files++
		data, readErr := os.ReadFile(p)
		if readErr != nil {
			return readErr
		}
		body := string(data)
		// README.md is the file that has to NAME these constructs in order to
		// explain their absence, so it is exempt from the substring scan and
		// from nothing else.
		if rel != "README.md" {
			for _, bad := range fpgForbiddenInFixture {
				if strings.Contains(body, bad) {
					t.Errorf("%s contains %q -- the fixture must assert structure, never behaviour", rel, bad)
				}
			}
		}
		for _, m := range fpgURLHost.FindAllStringSubmatch(body, -1) {
			host := strings.TrimSuffix(m[1], ".")
			if !strings.HasSuffix(host, ".invalid") {
				t.Errorf("%s names the resolvable host %q; every host in this fixture must be in the "+
					"RFC 2606 .invalid TLD", rel, host)
			}
		}
		for _, ip := range fpgIPLiteral.FindAllString(body, -1) {
			// RFC 5737 documentation ranges only, and nothing else.
			if !strings.HasPrefix(ip, "192.0.2.") && !strings.HasPrefix(ip, "198.51.100.") &&
				!strings.HasPrefix(ip, "203.0.113.") {
				t.Errorf("%s contains the IP literal %q; only RFC 5737 documentation addresses are allowed", rel, ip)
			}
		}
		return nil
	})
	if err != nil {
		t.Fatalf("walk %s: %v", root, err)
	}
	if files == 0 {
		t.Fatal("the malicious fixture root contains no files; this whole test passed having read nothing")
	}
	t.Logf("scanned %d files under testdata/roots/malicious", files)
}

// TestFPGateBenignSystemRootsAreInertToo applies the no-execute-bit half of the
// inertness rule to the benign roots. INV-2 is about all fixtures, not just the
// alarming-looking one, and an executable placeholder in `stock` would be an
// invitation to run it.
func TestFPGateBenignSystemRootsAreInertToo(t *testing.T) {
	for _, name := range []string{"stock", "cruft"} {
		t.Run(name, func(t *testing.T) {
			root := systemRoot(t, name)
			files := 0
			err := filepath.WalkDir(root, func(p string, d fs.DirEntry, err error) error {
				if err != nil {
					return err
				}
				if d.IsDir() || d.Type()&fs.ModeSymlink != 0 {
					return nil
				}
				info, statErr := d.Info()
				if statErr != nil {
					return statErr
				}
				files++
				if info.Mode().Perm()&0o111 != 0 {
					rel, _ := filepath.Rel(root, p)
					t.Errorf("%s/%s is EXECUTABLE (mode %v); fixtures are parsed, never run (INV-2)",
						name, rel, info.Mode())
				}
				return nil
			})
			if err != nil {
				t.Fatalf("walk %s: %v", root, err)
			}
			if files == 0 {
				t.Fatalf("root %q contains no files", name)
			}
		})
	}
}
