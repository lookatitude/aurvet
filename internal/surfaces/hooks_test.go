// internal/surfaces/hooks_test.go
package surfaces

import (
	"os"
	"path"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
)

// hooksRoot opens a confined view of one of the INV-8 fixture roots. Confined,
// not os.DirFS: the fixture masks a hook with an ABSOLUTE /dev/null symlink, and
// an unconfined reader resolves that against the HOST rather than the tree being
// scanned.
func hooksRoot(t *testing.T, name string) *os.Root {
	t.Helper()
	r, err := os.OpenRoot(filepath.Join("..", "..", "testdata", "roots", name))
	if err != nil {
		t.Fatalf("OpenRoot(%s): %v", name, err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

// hooksOwners builds the real ownership oracle over a fixture root's local DB.
// Every "unowned" assertion below is worthless if this is empty, so it says so.
func hooksOwners(t *testing.T, root *os.Root, name string) *own.Owners {
	t.Helper()
	pkgs, gaps, err := alpm.LoadLocalDB(filepath.Join("..", "..", "testdata", "roots", name, "var", "lib", "pacman", "local"))
	if err != nil {
		t.Fatalf("LoadLocalDB(%s): %v", name, err)
	}
	if len(gaps) != 0 {
		t.Fatalf("%s: unreadable local DB entries %v", name, gaps)
	}
	o := own.IndexIn(fsx.Live(root), pkgs)
	if o.Len() == 0 {
		t.Fatalf("%s: ownership oracle is empty; every unowned assertion would pass vacuously", name)
	}
	return o
}

// tempRoot writes files (content "" means "make a symlink to link[path]") and
// returns a confined root over them.
func tempRoot(t *testing.T, files map[string]string, links map[string]string) *os.Root {
	t.Helper()
	dir := t.TempDir()
	for rel, body := range files {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(full, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	for rel, target := range links {
		full := filepath.Join(dir, filepath.FromSlash(rel))
		if err := os.MkdirAll(filepath.Dir(full), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink(target, full); err != nil {
			t.Fatal(err)
		}
	}
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { r.Close() })
	return r
}

func dirPaths(dirs []HookDir) []string {
	out := make([]string, 0, len(dirs))
	for _, d := range dirs {
		out = append(out, d.Path)
	}
	return out
}

func hasGap(res finding.Result, ruleID, subject string) (finding.Gap, bool) {
	for _, g := range res.Gaps {
		if g.RuleID == ruleID && g.Subject == subject {
			return g, true
		}
	}
	return finding.Gap{}, false
}

func findingFor(res finding.Result, ruleID, subject string) (finding.Finding, bool) {
	for _, f := range res.Findings {
		if f.RuleID == ruleID && f.Subject == subject {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// --- task 4: hook directories -----------------------------------------------

// TestResolveHookDirsDefaults: with no pacman.conf the compiled-in pair applies,
// system dir first (it is always active), admin dir second (it wins by name).
func TestResolveHookDirsDefaults(t *testing.T) {
	root := tempRoot(t, map[string]string{"usr/share/libalpm/hooks/10-a.hook": "[Action]\nExec = /usr/bin/true\n"}, nil)
	dirs, gaps := ResolveHookDirs(fsx.Live(root))

	if got, want := dirPaths(dirs), []string{"usr/share/libalpm/hooks", "etc/pacman.d/hooks"}; strings.Join(got, ",") != strings.Join(want, ",") {
		t.Errorf("dirs = %v, want %v (system first, admin second: priority is the contract)", got, want)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none: an ABSENT /etc/pacman.conf means the defaults apply and is not a gap", gaps)
	}
}

// TestResolveHookDirsHonoursOverride reads the cruft root's real pacman.conf,
// which declares two HookDirs. A scan that hardcodes the default pair never
// looks at usr/local/share/pacman-hooks at all.
func TestResolveHookDirsHonoursOverride(t *testing.T) {
	root := hooksRoot(t, "cruft")
	dirs, gaps := ResolveHookDirs(fsx.Live(root))
	if len(gaps) != 0 {
		t.Errorf("gaps = %+v, want none", gaps)
	}
	got := dirPaths(dirs)
	want := []string{"usr/share/libalpm/hooks", "etc/pacman.d/hooks", "usr/local/share/pacman-hooks"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dirs = %v, want %v", got, want)
	}
	if dirs[2].Source != HookDirSourceConfig {
		t.Errorf("the extra dir's Source = %q, want %q", dirs[2].Source, HookDirSourceConfig)
	}
	if dirs[0].Source != HookDirSourceSystem {
		t.Errorf("the system dir's Source = %q, want %q", dirs[0].Source, HookDirSourceSystem)
	}
}

// TestResolveHookDirsConfigReplacesAdminDefault pins pacman's own semantics: a
// HookDir in the config replaces the compiled-in ADMIN default (config.c only
// adds /etc/pacman.d/hooks when the config named none), while the system dir is
// added unconditionally. Guessing the other way would invent a directory pacman
// does not read.
func TestResolveHookDirsConfigReplacesAdminDefault(t *testing.T) {
	root := tempRoot(t, map[string]string{
		"etc/pacman.conf": "[options]\nHookDir = /opt/hooks/\n",
	}, nil)
	got := dirPaths(mustDirs(t, root))
	want := []string{"usr/share/libalpm/hooks", "opt/hooks"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dirs = %v, want %v", got, want)
	}
}

// TestResolveHookDirsFollowsIncludeInOptions: pacman parses Include inline, so a
// HookDir can live in an included file. Ignoring Include leaves that directory
// unscanned and unmentioned.
func TestResolveHookDirsFollowsIncludeInOptions(t *testing.T) {
	root := tempRoot(t, map[string]string{
		"etc/pacman.conf":            "[options]\nInclude = /etc/pacman.d/extra.conf\n",
		"etc/pacman.d/extra.conf":    "HookDir = /srv/hooks\n",
		"srv/hooks/10-included.hook": "[Action]\nExec = /usr/bin/true\n",
	}, nil)
	got := dirPaths(mustDirs(t, root))
	want := []string{"usr/share/libalpm/hooks", "srv/hooks"}
	if strings.Join(got, ",") != strings.Join(want, ",") {
		t.Fatalf("dirs = %v, want %v", got, want)
	}
}

// TestResolveHookDirsGlobIncludeIsAGap: this parser expands nothing (INV-2), so
// an Include it cannot pin to one file makes the hook-dir set unknown. Unknown
// is a gap, never silence (INV-9).
func TestResolveHookDirsGlobIncludeIsAGap(t *testing.T) {
	root := tempRoot(t, map[string]string{
		"etc/pacman.conf": "[options]\nInclude = /etc/pacman.d/conf.d/*.conf\n",
	}, nil)
	dirs, gaps := ResolveHookDirs(fsx.Live(root))
	if len(dirs) == 0 {
		t.Fatal("an unexpandable Include must not empty the hook-dir set: the defaults still apply")
	}
	g, ok := hasGap(finding.Result{Gaps: gaps}, RuleHookDirs, "etc/pacman.d/conf.d/*.conf")
	if !ok {
		t.Fatalf("no %s gap for the glob Include; gaps=%+v", RuleHookDirs, gaps)
	}
	if !strings.Contains(g.Reason, "expand") {
		t.Errorf("gap reason %q does not say why the include was not read", g.Reason)
	}
}

// TestResolveHookDirsUnreadableConfigIsAGap: an unreadable pacman.conf means the
// HookDir set is unknown, so the defaults are scanned AND the shortfall is
// reported. Silence here would hide an attacker-declared hook dir behind a mode
// bit.
func TestResolveHookDirsUnreadableConfigIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is not a refusal for uid 0, so this asserts nothing")
	}
	root := tempRoot(t, map[string]string{"etc/pacman.conf": "[options]\nHookDir = /opt/hooks\n"}, nil)
	if err := os.Chmod(filepath.Join(root.Name(), "etc", "pacman.conf"), 0o000); err != nil {
		t.Fatal(err)
	}
	dirs, gaps := ResolveHookDirs(fsx.Live(root))
	if got, want := len(dirs), 2; got != want {
		t.Errorf("dirs = %v, want the %d defaults to still be scanned", dirPaths(dirs), want)
	}
	if _, ok := hasGap(finding.Result{Gaps: gaps}, RuleHookDirs, "etc/pacman.conf"); !ok {
		t.Fatalf("an unreadable pacman.conf produced no %s gap; gaps=%+v", RuleHookDirs, gaps)
	}
}

func mustDirs(t *testing.T, root *os.Root) []HookDir {
	t.Helper()
	dirs, gaps := ResolveHookDirs(fsx.Live(root))
	if len(gaps) != 0 {
		t.Fatalf("unexpected gaps %+v", gaps)
	}
	return dirs
}

// TestScanHooksStock: the stock root's one hook is package-owned in the system
// dir, /etc/pacman.d/hooks is absent, and nothing is suppressed. Zero findings,
// zero gaps -- and the absence of the admin dir is recorded as a fact rather
// than reported as either an error or a gap.
func TestScanHooksStock(t *testing.T) {
	root := hooksRoot(t, "stock")
	rep, res := ScanHooks(fsx.Live(root), hooksOwners(t, root, "stock"))

	if len(res.Findings) != 0 {
		t.Errorf("findings = %+v, want none on the stock root (INV-8)", res.Findings)
	}
	if len(res.Gaps) != 0 {
		t.Errorf("gaps = %+v, want none", res.Gaps)
	}
	if len(rep.Hooks) != 1 || rep.Hooks[0].Path != "usr/share/libalpm/hooks/50-foo.hook" {
		t.Fatalf("hooks = %+v, want exactly usr/share/libalpm/hooks/50-foo.hook", rep.Hooks)
	}
	if rep.Hooks[0].State != own.Owned || rep.Hooks[0].Pkg != "foo-bin" {
		t.Errorf("50-foo.hook = (%v, %q), want (owned, foo-bin)", rep.Hooks[0].State, rep.Hooks[0].Pkg)
	}
	if !rep.Hooks[0].Active {
		t.Error("the only copy of a hook is the one pacman runs, so it must be Active")
	}
	if len(rep.Suppressed) != 0 {
		t.Errorf("suppressions = %+v, want none", rep.Suppressed)
	}
	byPath := map[string]HookDir{}
	for _, d := range rep.Dirs {
		byPath[d.Path] = d
	}
	if d := byPath["usr/share/libalpm/hooks"]; !d.Present {
		t.Error("the system hook dir must be recorded as present")
	}
	if d, ok := byPath["etc/pacman.d/hooks"]; !ok || d.Present {
		t.Errorf("etc/pacman.d/hooks = %+v; an absent admin dir must be recorded as absent, not omitted", d)
	}
}

// TestScanHooksCruftMask is the benign half of task 5. A /dev/null symlink over
// a packaged hook is the DOCUMENTED way to disable it and a real admin practice,
// so it is reportable at suspicious and never critical -- otherwise this root
// fails the INV-8 gate.
func TestScanHooksCruftMask(t *testing.T) {
	root := hooksRoot(t, "cruft")
	rep, res := ScanHooks(fsx.Live(root), hooksOwners(t, root, "cruft"))

	if got := res.MaxSeverity(); got >= finding.SevCritical {
		t.Errorf("max severity = %v on the cruft root; zero criticals here is a release gate", got)
	}

	sup, ok := rep.Suppression("60-depmod.hook")
	if !ok {
		t.Fatalf("the /dev/null mask of the packaged 60-depmod.hook was not detected; suppressions=%+v", rep.Suppressed)
	}
	if sup.Kind != SuppressMasked {
		t.Errorf("kind = %v, want %v", sup.Kind, SuppressMasked)
	}
	if sup.Shadowed != "usr/share/libalpm/hooks/60-depmod.hook" || sup.ShadowedPkg != "kmod" {
		t.Errorf("suppression names (%q, %q), want the packaged kmod hook", sup.Shadowed, sup.ShadowedPkg)
	}
	f, ok := findingFor(res, RuleHookSuppressed, "etc/pacman.d/hooks/60-depmod.hook")
	if !ok {
		t.Fatalf("no %s finding for the mask; findings=%+v", RuleHookSuppressed, res.Findings)
	}
	if f.Severity != finding.SevSuspicious {
		t.Errorf("mask severity = %v, want suspicious: masking a hook is documented administration "+
			"and the tool cannot tell an admin from an attacker (INV-6)", f.Severity)
	}
	if !strings.Contains(f.Limits, "administrat") {
		t.Errorf("Limits %q does not say that masking is a legitimate administrative action", f.Limits)
	}

	// The mask is UNDERSTOOD, not unreadable: the confined reader refuses to
	// follow the absolute target, but readlinkat tells us it is /dev/null, and a
	// hook whose body is /dev/null demonstrably runs nothing. Leaving a
	// hook-coverage gap here would report "I could not look" about the one file
	// we know most about.
	if g, ok := hasGap(res, RuleHookCoverage, "etc/pacman.d/hooks/60-depmod.hook"); ok {
		t.Errorf("the masked hook is still a coverage gap (%q); a /dev/null mask is a positive finding, "+
			"not an inability to read", g.Reason)
	}

	// The hand-written admin hook and the hook in the extra HookDir are both
	// unowned and both legitimate: suspicious at most.
	for _, p := range []string{
		"etc/pacman.d/hooks/99-local-mkinitcpio.hook",
		"usr/local/share/pacman-hooks/10-local-report.hook",
	} {
		f, ok := findingFor(res, RuleHookUnowned, p)
		if !ok {
			t.Errorf("no %s finding for %s (it is unowned, and an unowned hook is worth stating)", RuleHookUnowned, p)
			continue
		}
		if f.Severity != finding.SevSuspicious {
			t.Errorf("%s severity = %v, want suspicious", p, f.Severity)
		}
		if !strings.Contains(f.Limits, "file list") {
			t.Errorf("%s Limits %q does not say that a hook shipped INSIDE a package's file list is invisible here", p, f.Limits)
		}
	}

	// The masked packaged hook must not be reported as suppressed twice, and the
	// unshadowed packaged hook must not be reported at all.
	if _, ok := findingFor(res, RuleHookUnowned, "usr/share/libalpm/hooks/70-foo.hook"); ok {
		t.Error("the ordinary package-owned 70-foo.hook produced a finding")
	}
}

// TestScanHooksMaliciousShadow is the malicious half: same file name, unowned
// content, higher-priority directory. pacman runs the replacement and the
// packaged hook's work silently stops happening.
func TestScanHooksMaliciousShadow(t *testing.T) {
	root := hooksRoot(t, "malicious")
	rep, res := ScanHooks(fsx.Live(root), hooksOwners(t, root, "malicious"))

	sup, ok := rep.Suppression("60-depmod.hook")
	if !ok {
		t.Fatalf("the shadowed packaged hook was not detected; suppressions=%+v", rep.Suppressed)
	}
	if sup.Kind != SuppressReplaced {
		t.Errorf("kind = %v, want %v", sup.Kind, SuppressReplaced)
	}
	if sup.Winner != "etc/pacman.d/hooks/60-depmod.hook" || sup.WinnerState != own.Unowned {
		t.Errorf("winner = (%q, %v), want the unowned admin-dir copy", sup.Winner, sup.WinnerState)
	}
	if sup.Shadowed != "usr/share/libalpm/hooks/60-depmod.hook" {
		t.Errorf("shadowed = %q, want the packaged system hook", sup.Shadowed)
	}
	f, ok := findingFor(res, RuleHookSuppressed, "etc/pacman.d/hooks/60-depmod.hook")
	if !ok {
		t.Fatalf("no %s finding; findings=%+v", RuleHookSuppressed, res.Findings)
	}
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious: correlation earns critical, this check alone does not", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, "\n"), sup.Shadowed) {
		t.Errorf("evidence %v does not name the packaged hook that stopped running", f.Evidence)
	}
	if !strings.Contains(f.Limits, "sloppy") {
		t.Errorf("Limits %q does not say this catches sloppy malware only", f.Limits)
	}
}

// TestScanHooksEmptyShadowIsSuppression: a same-named EMPTY file disables the
// packaged hook just as thoroughly as one with a hostile Exec, and it is the
// version that looks like nothing at all in a directory listing.
func TestScanHooksEmptyShadowIsSuppression(t *testing.T) {
	root := tempRoot(t, map[string]string{
		"usr/share/libalpm/hooks/60-depmod.hook": "[Action]\nWhen = PostTransaction\nExec = /usr/bin/depmod --all\n",
		"etc/pacman.d/hooks/60-depmod.hook":      "",
	}, nil)
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{
		Name:  "kmod",
		Files: []string{"usr/share/libalpm/hooks/", "usr/share/libalpm/hooks/60-depmod.hook"},
	}})
	rep, res := ScanHooks(fsx.Live(root), owners)

	sup, ok := rep.Suppression("60-depmod.hook")
	if !ok {
		t.Fatalf("an empty same-named file did not register as suppression; suppressions=%+v", rep.Suppressed)
	}
	if sup.Kind != SuppressEmpty {
		t.Errorf("kind = %v, want %v", sup.Kind, SuppressEmpty)
	}
	if _, ok := findingFor(res, RuleHookSuppressed, "etc/pacman.d/hooks/60-depmod.hook"); !ok {
		t.Errorf("no %s finding; findings=%+v", RuleHookSuppressed, res.Findings)
	}
}

// TestScanHooksUnreadableWinnerKeepsItsGap: a symlink to something that is not
// /dev/null is not understood. The suppression is reported AND the coverage gap
// stays, because what pacman now runs is genuinely unknown (INV-9).
func TestScanHooksUnreadableWinnerKeepsItsGap(t *testing.T) {
	root := tempRoot(t, map[string]string{
		"usr/share/libalpm/hooks/60-depmod.hook": "[Action]\nExec = /usr/bin/depmod --all\n",
	}, map[string]string{
		"etc/pacman.d/hooks/60-depmod.hook": "/opt/elsewhere.hook",
	})
	owners := own.IndexIn(fsx.Live(root), []alpm.Package{{
		Name:  "kmod",
		Files: []string{"usr/share/libalpm/hooks/60-depmod.hook"},
	}})
	rep, res := ScanHooks(fsx.Live(root), owners)

	sup, ok := rep.Suppression("60-depmod.hook")
	if !ok {
		t.Fatalf("suppression by an unreadable replacement was not detected; suppressions=%+v", rep.Suppressed)
	}
	if sup.Kind != SuppressUnreadable {
		t.Errorf("kind = %v, want %v", sup.Kind, SuppressUnreadable)
	}
	if _, ok := hasGap(res, RuleHookCoverage, "etc/pacman.d/hooks/60-depmod.hook"); !ok {
		t.Errorf("no %s gap for the unreadable replacement; what pacman runs is unknown and must not "+
			"be reported as if it were known. gaps=%+v", RuleHookCoverage, res.Gaps)
	}
}

// TestScanHooksUnreadableDirIsAGap: INV-9 over a directory. A hook dir that
// cannot be listed makes the hook set unknown, and an unknown hook set must not
// read as an empty one.
func TestScanHooksUnreadableDirIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0000 is not a refusal for uid 0, so this asserts nothing")
	}
	root := tempRoot(t, map[string]string{
		"etc/pacman.d/hooks/50-secret.hook": "[Action]\nExec = /usr/bin/true\n",
	}, nil)
	dir := filepath.Join(root.Name(), "etc", "pacman.d", "hooks")
	if err := os.Chmod(dir, 0o000); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { os.Chmod(dir, 0o755) })

	_, res := ScanHooks(fsx.Live(root), own.IndexIn(fsx.Live(root), nil))
	if _, ok := hasGap(res, RuleHookCoverage, "etc/pacman.d/hooks"); !ok {
		t.Fatalf("an unlistable hook dir produced no %s gap; gaps=%+v", RuleHookCoverage, res.Gaps)
	}
}

// TestScanHooksUnresolvableOwnershipIsAGap: own.Resolve's third state is not a
// verdict. A hook whose ownership cannot be decided is a gap, never an accusation.
func TestScanHooksUnresolvableOwnershipIsAGap(t *testing.T) {
	// A self-referential symlink: the directory still lists, so the hook is
	// found, but resolution cannot arrive anywhere. own.Resolve answers
	// Unresolved, which is a coverage gap and not "unowned".
	root := tempRoot(t, nil, map[string]string{
		"usr/share/libalpm/hooks/50-a.hook": "50-a.hook",
	})

	_, res := ScanHooks(fsx.Live(root), own.IndexIn(fsx.Live(root), nil))
	if _, ok := findingFor(res, RuleHookUnowned, "usr/share/libalpm/hooks/50-a.hook"); ok {
		t.Error("an unresolvable hook was reported as unowned; that is a coverage gap printed as an accusation")
	}
	g, ok := hasGap(res, RuleHookCoverage, "usr/share/libalpm/hooks/50-a.hook")
	if !ok {
		t.Fatalf("no %s gap for the unresolvable hook; gaps=%+v", RuleHookCoverage, res.Gaps)
	}
	// There are two ways this path can be gapped -- the loader could not read it
	// either -- and only the OWNERSHIP gap proves own.Unresolved was handled
	// rather than collapsed into Unowned.
	var ownership bool
	for _, gg := range res.Gaps {
		if gg.Subject == g.Subject && strings.Contains(gg.Reason, "ownership") {
			ownership = true
		}
	}
	if !ownership {
		t.Errorf("no gap explains that the hook's OWNERSHIP could not be resolved; gaps=%+v", res.Gaps)
	}
}

// TestScanHooksEveryFindingStatesItsLimits is INV-6 as a property rather than
// as a habit: no finding this file can produce may ship without saying what it
// cannot prove.
func TestScanHooksEveryFindingStatesItsLimits(t *testing.T) {
	for _, name := range []string{"stock", "cruft", "malicious"} {
		root := hooksRoot(t, name)
		_, res := ScanHooks(fsx.Live(root), hooksOwners(t, root, name))
		for _, f := range res.Findings {
			if strings.TrimSpace(f.Limits) == "" {
				t.Errorf("%s: finding %s/%s has empty Limits (INV-6)", name, f.RuleID, f.Subject)
			}
			if f.SubjectKind == "" || f.Summary == "" {
				t.Errorf("%s: finding %s/%s is under-described: kind=%q summary=%q",
					name, f.RuleID, f.Subject, f.SubjectKind, f.Summary)
			}
		}
		for _, g := range res.Gaps {
			if strings.TrimSpace(g.Reason) == "" {
				t.Errorf("%s: gap %s/%s has no reason (INV-9)", name, g.RuleID, g.Subject)
			}
		}
	}
}

// TestScanHooksNeverExecutes is INV-2 stated where it can be checked: the Exec
// lines of every fixture hook are carried as text and the scan completes without
// any of them running. The marker files the fixtures' Execs name are plain text
// and stay untouched (INV-5).
func TestScanHooksNeverExecutes(t *testing.T) {
	root := hooksRoot(t, "malicious")
	before, err := os.ReadFile(filepath.Join("..", "..", "testdata", "roots", "malicious", "usr", "bin", "depmod"))
	if err != nil {
		t.Fatal(err)
	}
	rep, _ := ScanHooks(fsx.Live(root), hooksOwners(t, root, "malicious"))
	after, err := os.ReadFile(filepath.Join("..", "..", "testdata", "roots", "malicious", "usr", "bin", "depmod"))
	if err != nil {
		t.Fatal(err)
	}
	if string(before) != string(after) {
		t.Fatal("scanning wrote to the fixture root (INV-5)")
	}
	var sawExec bool
	for _, h := range rep.Hooks {
		if h.Hook.Exec != "" {
			sawExec = true
		}
	}
	if !sawExec {
		t.Fatal("no Exec line was carried at all, so this asserts nothing about parsing rather than executing")
	}
}

// TestScanHooksLiveSystem measures the machine it runs on. Skipped by default:
// no unit test may depend on the host's /usr/share/libalpm/hooks. Run with
// AURVET_LIVE_HOOKS=1 to reproduce the numbers in the P1-C receipt (reference
// system: 57 hooks in the system dir, /etc/pacman.d/hooks absent).
func TestScanHooksLiveSystem(t *testing.T) {
	if os.Getenv("AURVET_LIVE_HOOKS") != "1" {
		t.Skip("set AURVET_LIVE_HOOKS=1 to measure against the live system")
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
	rep, res := ScanHooks(fsx.Live(root), own.IndexIn(fsx.Live(root), pkgs))

	perDir := map[string]int{}
	for _, h := range rep.Hooks {
		perDir[path.Dir(h.Path)]++
	}
	t.Logf("packages=%d db-gaps=%d dirs=%+v hooks=%d per-dir=%v suppressed=%d findings=%d gaps=%d",
		len(pkgs), len(dbGaps), rep.Dirs, len(rep.Hooks), perDir, len(rep.Suppressed), len(res.Findings), len(res.Gaps))
	for _, f := range res.Findings {
		t.Logf("finding %s %s %s: %s", f.Severity, f.RuleID, f.Subject, f.Summary)
	}
	for _, g := range res.Gaps {
		t.Logf("gap %s %s: %s", g.RuleID, g.Subject, g.Reason)
	}
	if perDir["usr/share/libalpm/hooks"] == 0 {
		t.Error("no hooks found in the system hook dir; it is active by default and pacman itself ships hooks")
	}
}
