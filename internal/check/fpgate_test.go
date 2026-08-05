// internal/check/fpgate_test.go
package check

import (
	"archive/tar"
	"bytes"
	"compress/gzip"
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/finding"
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
