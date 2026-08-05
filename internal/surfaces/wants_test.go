// internal/surfaces/wants_test.go
package surfaces

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/own"
)

// wantsPaths flattens a bucket to its paths for readable failure output.
func wantsPaths(es []WantsEntry) []string {
	out := make([]string, 0, len(es))
	for _, e := range es {
		out = append(out, e.Path)
	}
	return out
}

// TestSurveyWantsExcludesDirectories is behaviour 2, in isolation. A
// *.target.wants directory is created by `systemctl enable`, so no package owns
// it; a rule that reports every unowned path under the search dirs reports all
// of them. On the reference system that alone is 9 false positives.
func TestSurveyWantsExcludesDirectories(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/foo.service": "[Service]\nExecStart=/usr/bin/foo\n",
		// A directory nested inside a .wants directory: also not a subject.
		"etc/systemd/system/multi-user.target.wants/nested.d/keep": "x\n",
	}, map[string]string{
		"etc/systemd/system/multi-user.target.wants/foo.service": "/usr/lib/systemd/system/foo.service",
	})
	owners := own.IndexIn(root, []alpm.Package{{Name: "foo", Files: []string{
		"usr/lib/systemd/system/", "usr/lib/systemd/system/foo.service",
	}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system", "usr/lib/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	if len(s.Subjects) != 0 {
		t.Errorf("subjects = %v, want none: a directory is never a subject and an owned target is not either",
			wantsPaths(s.Subjects))
	}
	wantDirs := []string{
		"etc/systemd/system/multi-user.target.wants",
		"etc/systemd/system/multi-user.target.wants/nested.d",
	}
	if strings.Join(s.Dirs, ",") != strings.Join(wantDirs, ",") {
		t.Errorf("dirs = %v, want %v (recorded as EXAMINED-and-excluded, not dropped)", s.Dirs, wantDirs)
	}
	if s.Examined != 3 {
		t.Errorf("Examined = %d, want 3; a rule that looked at nothing must not read as a silent one", s.Examined)
	}
}

// TestSurveyWantsResolvesSymlinkTargets is behaviour 1 plus behaviour 3. The
// absolute-target form is the one `systemctl enable` writes and is the single
// largest false-positive source in the phase: the LINK is unowned, the TARGET is
// not. The relative form must work identically.
func TestSurveyWantsResolvesSymlinkTargets(t *testing.T) {
	root := unitTree(t, map[string]string{
		"usr/lib/systemd/system/abs.service": "[Service]\nExecStart=/usr/bin/foo\n",
		"usr/lib/systemd/system/rel.service": "[Service]\nExecStart=/usr/bin/foo\n",
	}, map[string]string{
		"etc/systemd/system/multi-user.target.wants/abs.service": "/usr/lib/systemd/system/abs.service",
		"etc/systemd/system/multi-user.target.wants/rel.service": "../../../../usr/lib/systemd/system/rel.service",
	})
	owners := own.IndexIn(root, []alpm.Package{{Name: "foo", Files: []string{
		"usr/lib/systemd/system/abs.service", "usr/lib/systemd/system/rel.service",
	}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	if len(s.Subjects) != 0 {
		t.Errorf("subjects = %v, want none: both targets are package-owned", wantsPaths(s.Subjects))
	}
	if len(s.OwnedTargets) != 2 {
		t.Fatalf("ownedTargets = %v, want 2", wantsPaths(s.OwnedTargets))
	}
	for _, e := range s.OwnedTargets {
		if e.Pkg != "foo" {
			t.Errorf("%s: owning package %q, want foo", e.Path, e.Pkg)
		}
		if e.Link == "" {
			t.Errorf("%s: link text not recorded; the evidence must show what the link said", e.Path)
		}
	}
}

// TestSurveyWantsReportsUnownedTarget is the rule's actual output: an enablement
// link pointing at a unit no package installed.
func TestSurveyWantsReportsUnownedTarget(t *testing.T) {
	root := unitTree(t, map[string]string{
		"etc/systemd/system/local.service": "[Service]\nExecStart=/usr/local/bin/tool\n",
	}, map[string]string{
		"etc/systemd/system/multi-user.target.wants/local.service": "../local.service",
		// A dangling link is unresolvable-or-unowned too, and must be reported
		// rather than skipped for having nothing behind it.
		"etc/systemd/system/multi-user.target.wants/gone.service": "/usr/lib/systemd/system/gone.service",
	})
	owners := own.IndexIn(root, []alpm.Package{{Name: "systemd", Files: []string{"etc/systemd/system/"}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	want := []string{
		"etc/systemd/system/multi-user.target.wants/gone.service",
		"etc/systemd/system/multi-user.target.wants/local.service",
	}
	if strings.Join(wantsPaths(s.Subjects), ",") != strings.Join(want, ",") {
		t.Fatalf("subjects = %v, want %v", wantsPaths(s.Subjects), want)
	}
	for _, e := range s.Subjects {
		if e.State != own.Unowned {
			t.Errorf("%s: state %v, want Unowned", e.Path, e.State)
		}
	}
}

// TestSurveyWantsUnresolvableTargetIsAGap is INV-9: a symlink loop is an
// inability, not a fact. Reporting it as unowned would manufacture a finding out
// of something we could not read.
func TestSurveyWantsUnresolvableTargetIsAGap(t *testing.T) {
	root := unitTree(t, nil, map[string]string{
		"etc/systemd/system/multi-user.target.wants/loop.service": "../loopa",
		"etc/systemd/system/loopa":                                "loopb",
		"etc/systemd/system/loopb":                                "loopa",
	})
	owners := own.IndexIn(root, []alpm.Package{{Name: "systemd", Files: []string{"etc/systemd/system/"}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system"})
	if len(s.Subjects) != 0 {
		t.Errorf("subjects = %v, want none: an unresolvable target is a gap", wantsPaths(s.Subjects))
	}
	if len(gaps) != 1 || !strings.Contains(gaps[0].Subject, "loop.service") {
		t.Fatalf("gaps = %+v, want exactly one naming loop.service", gaps)
	}
	if len(s.Unresolved) != 1 {
		t.Errorf("Unresolved = %v, want 1 -- the path was examined, so it must be counted", wantsPaths(s.Unresolved))
	}
}

// TestSurveyWantsUnreadableDirectoryIsAGap: an unreadable *.wants directory
// hides an unknown number of links. Silence there is the worst answer available.
func TestSurveyWantsUnreadableDirectoryIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits this test depends on")
	}
	root := unitTree(t, map[string]string{
		"etc/systemd/system/multi-user.target.wants/keep": "x\n",
	}, nil)
	dir := filepath.Join(root.Name(), "etc/systemd/system/multi-user.target.wants")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.Chmod(dir, 0o755) })
	owners := own.IndexIn(root, []alpm.Package{{Name: "systemd", Files: []string{"etc/systemd/system/"}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system"})
	if len(s.Subjects) != 0 {
		t.Errorf("subjects = %v, want none", wantsPaths(s.Subjects))
	}
	if len(gaps) != 1 {
		t.Fatalf("gaps = %+v, want exactly 1 for the unreadable directory", gaps)
	}
}

// TestSurveyWantsOnFixtureRoots is the phase gate, applied to the three
// committed roots. The counts of the excluded buckets are asserted too: each one
// fails for a different, diagnosable reason.
//
//	dirs wrong        -> behaviour 2 (exclude directories) is not firing
//	ownedTargets wrong -> behaviour 1 (resolve targets) is not firing
//	subjects wrong    -> the rule's output, which is the gate
//
// On the cruft numbers: testdata/roots/cruft/README.md's own survey reports 8
// directories and 19 owned links, counting only paths that are unowned BY
// LITERAL PATH -- it excludes the vendor-preset link and its directory under
// usr/lib (both are in foo-daemon's %FILES%) before classifying. This survey
// classifies every path it examines, so those two land in the Dirs and
// OwnedTargets buckets and the counts are 9 and 20. Same verdict on every path,
// different denominator; the gate -- one subject -- is unchanged. Stated here
// because a reader comparing the two numbers deserves the reason rather than a
// discrepancy.
func TestSurveyWantsOnFixtureRoots(t *testing.T) {
	cases := []struct {
		root         string
		dirs         int // -1: not asserted, see the malicious note below
		ownedTargets int
		subjects     []string
	}{
		{"stock", 2, 2, nil},
		{"cruft", 9, 20, []string{"etc/systemd/system/multi-user.target.wants/local-backup.service"}},
		// malicious/usr/lib/systemd/system/multi-user.target.wants is EMPTY, and
		// git cannot carry an empty directory: it exists in the fixture lane's
		// working tree and not in a fresh clone. Asserting the directory count
		// here would make this test pass or fail on a checkout artefact, so only
		// the subject set -- which is identical either way -- is pinned.
		{"malicious", -1, 0, []string{"etc/systemd/system/multi-user.target.wants/systemd-initd-inert.service"}},
	}
	for _, c := range cases {
		t.Run(c.root, func(t *testing.T) {
			root, owners := ownersFor(t, c.root)
			s, gaps := SurveyWants(root, owners, DefaultUnitDirs)
			if len(gaps) != 0 {
				t.Errorf("%s: unexpected gaps %+v", c.root, gaps)
			}
			if c.dirs >= 0 && len(s.Dirs) != c.dirs {
				t.Errorf("%s: %d directories examined-and-excluded, want %d (they must be EXCLUDED, "+
					"not reported): %v", c.root, len(s.Dirs), c.dirs, s.Dirs)
			}
			if len(s.OwnedTargets) != c.ownedTargets {
				t.Errorf("%s: %d links resolving to a package-owned target, want %d (without target "+
					"resolution every one of these is a false positive): %v",
					c.root, len(s.OwnedTargets), c.ownedTargets, wantsPaths(s.OwnedTargets))
			}
			if got := wantsPaths(s.Subjects); strings.Join(got, ",") != strings.Join(c.subjects, ",") {
				t.Fatalf("%s: subjects = %v, want %v (roadmap P1-C gate: exactly one on the reference system)",
					c.root, got, c.subjects)
			}
			if s.Examined == 0 {
				t.Errorf("%s: nothing examined; silence must mean 'looked and found nothing', "+
					"not 'looked at nothing'", c.root)
			}
		})
	}
}

// TestSurveyWantsFindingsStayBelowCritical: a hand-written unit and a planted
// one are the same shape. cruft's one subject is a backup script, so critical
// here would fail the INV-8 gate on a legitimate root.
func TestSurveyWantsFindingsStayBelowCritical(t *testing.T) {
	root, owners := ownersFor(t, "cruft")
	s, _ := SurveyWants(root, owners, DefaultUnitDirs)
	findings := s.Findings()
	if len(findings) != 1 {
		t.Fatalf("findings = %+v, want 1", findings)
	}
	f := findings[0]
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: correlation earns critical, an unowned target alone does not",
			f.Severity)
	}
	if f.Limits == "" {
		t.Fatal("finding carries no Limits (INV-6)")
	}
	lim := strings.ToLower(f.Limits)
	for _, want := range []string{"hand-written", "pkgdir", "silent"} {
		if !strings.Contains(lim, want) {
			t.Errorf("Limits does not mention %q: %q", want, f.Limits)
		}
	}
	if len(f.Evidence) == 0 {
		t.Error("finding carries no Evidence; the link text and the resolved target are the whole case")
	}
}

// TestSurveyWantsCoversRequiresToo: *.requires has identical semantics and
// identical abuse potential. There are none on the reference system, so
// covering it costs nothing there and closes a blind spot elsewhere.
func TestSurveyWantsCoversRequiresToo(t *testing.T) {
	root := unitTree(t, map[string]string{
		"etc/systemd/system/local.service": "[Service]\nExecStart=/usr/local/bin/tool\n",
	}, map[string]string{
		"etc/systemd/system/multi-user.target.requires/local.service": "../local.service",
	})
	owners := own.IndexIn(root, []alpm.Package{{Name: "systemd", Files: []string{"etc/systemd/system/"}}})

	s, gaps := SurveyWants(root, owners, []string{"etc/systemd/system"})
	if len(gaps) != 0 {
		t.Fatalf("gaps = %+v, want none", gaps)
	}
	if len(s.Subjects) != 1 {
		t.Fatalf("subjects = %v, want 1 -- a .requires link is an enablement link too",
			wantsPaths(s.Subjects))
	}
}

// TestSurveyWantsIsPureOverTheRoot: INV-4, same argument as for LoadUnits.
func TestSurveyWantsIsPureOverTheRoot(t *testing.T) {
	dir, err := filepath.Abs(filepath.Join("..", "..", "testdata", "roots", "cruft"))
	if err != nil {
		t.Fatal(err)
	}
	survey := func() WantsSurvey {
		pkgs, _, err := alpm.LoadLocalDB(filepath.Join(dir, "var", "lib", "pacman", "local"))
		if err != nil {
			t.Fatal(err)
		}
		root, err := os.OpenRoot(dir)
		if err != nil {
			t.Fatal(err)
		}
		defer root.Close()
		s, gaps := SurveyWants(root, own.IndexIn(root, pkgs), DefaultUnitDirs)
		if len(gaps) != 0 {
			t.Fatalf("gaps: %+v", gaps)
		}
		return s
	}
	before := survey()
	t.Chdir(t.TempDir())
	after := survey()
	if strings.Join(wantsPaths(before.Subjects), ",") != strings.Join(wantsPaths(after.Subjects), ",") {
		t.Fatalf("subjects changed with the process CWD: %v then %v",
			wantsPaths(before.Subjects), wantsPaths(after.Subjects))
	}
}

// TestSurveyWantsLiveSystem asserts the P1-C gate criterion that is stated as a
// number in docs/roadmap.html: "the *.wants rule produces exactly one subject on
// the reference system".
//
// It exists because a release gate expressed only as a sentence in a document is
// a gate nobody runs. The hooks and misc rules each committed an env-gated live
// probe; this rule's live measurement was made ad hoc during development and was
// the only one of the three with no way to reproduce it from the suite.
//
// The subject COUNT is asserted, not the subject's identity: which unit an admin
// hand-wrote is that machine's business. The bucket totals are deliberately only
// logged -- they drift with enablement state and installed set, which is exactly
// why the roadmap's earlier fixed figures went stale and stopped summing.
func TestSurveyWantsLiveSystem(t *testing.T) {
	if os.Getenv("AURVET_LIVE_WANTS") != "1" {
		t.Skip("set AURVET_LIVE_WANTS=1 to measure against the live system")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	pkgs, dbGaps, err := alpm.LoadLocalDB("/var/lib/pacman/local")
	if err != nil {
		t.Fatal(err)
	}
	owners := own.IndexIn(root, pkgs)

	for _, scope := range []struct {
		name string
		dirs []string
	}{
		{"etc/systemd/system", []string{"etc/systemd/system"}},
		{"DefaultUnitDirs", DefaultUnitDirs},
	} {
		s, gaps := SurveyWants(root, owners, scope.dirs)
		t.Logf("%s: packages=%d db-gaps=%d examined=%d dirs=%d ownedTargets=%d subjects=%d unresolved=%d gaps=%d",
			scope.name, len(pkgs), len(dbGaps), s.Examined, len(s.Dirs),
			len(s.OwnedTargets), len(s.Subjects), len(s.Unresolved), len(gaps))
		for _, e := range s.Subjects {
			t.Logf("  subject %s -> %s (link %q)", e.Path, e.Target, e.Link)
		}

		// The gate. One subject, in both scopes: widening the search must not
		// manufacture new ones, because every additional directory scanned is
		// full of ordinary enablement links.
		if got := len(s.Subjects); got != 1 {
			t.Errorf("%s: %d subjects, want exactly 1 (the gate in docs/roadmap.html §P1-C); subjects=%v",
				scope.name, got, wantsPaths(s.Subjects))
		}
		// A survey that examined nothing would satisfy no gate at all, and would
		// report zero subjects for the wrong reason.
		if s.Examined == 0 {
			t.Errorf("%s: examined 0 paths; a silent rule is not a passing rule", scope.name)
		}
		// Behaviour 3's false-positive population must be non-empty on a real
		// machine: ordinary enablement links are the noise this rule exists to
		// suppress, and if none were classified the exclusion is untested here.
		if len(s.OwnedTargets) == 0 {
			t.Errorf("%s: no package-owned enablement links classified; behaviour 3 excluded nothing", scope.name)
		}
		if len(s.Subjects) > 0 && s.Subjects[0].State == own.Owned {
			t.Errorf("%s: a subject is own.Owned, which behaviour 3 must have excluded", scope.name)
		}
	}
}
