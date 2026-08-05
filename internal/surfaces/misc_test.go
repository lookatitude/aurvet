package surfaces

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/own"
)

// miscFixtureRoot opens one of the committed fixture roots together with the
// ownership oracle built from that root's own local database. Both come from
// the SAME tree, which is the point: the oracle must resolve symlinks against
// the scanned root, not against the machine running the test (INV-4).
func miscFixtureRoot(t *testing.T, name string) (*os.Root, *own.Owners) {
	t.Helper()
	return miscRootAt(t, filepath.Join("..", "..", "testdata", "roots", name))
}

func miscRootAt(t *testing.T, dir string) (*os.Root, *own.Owners) {
	t.Helper()
	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatalf("open root %s: %v", dir, err)
	}
	t.Cleanup(func() { root.Close() })

	var pkgs []alpm.Package
	dbPath := filepath.Join(dir, "var", "lib", "pacman", "local")
	if _, err := os.Stat(dbPath); err == nil {
		var bad []string
		pkgs, bad, err = alpm.LoadLocalDB(dbPath)
		if err != nil {
			t.Fatalf("load local db %s: %v", dbPath, err)
		}
		if len(bad) != 0 {
			t.Fatalf("fixture local db has unreadable entries: %v", bad)
		}
	}
	return root, own.IndexIn(root, pkgs)
}

// miscCopyTree copies a fixture root into a temporary directory so a test may
// chmod it. INV-5: no test writes to a checked-in fixture, and no scan writes
// to an offline root.
func miscCopyTree(t *testing.T, src string) string {
	t.Helper()
	dst := t.TempDir()
	err := filepath.WalkDir(src, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, p)
		if err != nil {
			return err
		}
		target := filepath.Join(dst, rel)
		switch {
		case d.IsDir():
			return os.MkdirAll(target, 0o755)
		case d.Type()&fs.ModeSymlink != 0:
			link, err := os.Readlink(p)
			if err != nil {
				return err
			}
			return os.Symlink(link, target)
		default:
			data, err := os.ReadFile(p)
			if err != nil {
				return err
			}
			return os.WriteFile(target, data, 0o644)
		}
	})
	if err != nil {
		t.Fatalf("copy %s: %v", src, err)
	}
	return dst
}

func miscFindings(res finding.Result, ruleID string) []finding.Finding {
	var out []finding.Finding
	for _, f := range res.Findings {
		if f.RuleID == ruleID {
			out = append(out, f)
		}
	}
	return out
}

func miscSubjects(fs []finding.Finding) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Subject)
	}
	return out
}

func miscDescribe(res finding.Result) string {
	var b strings.Builder
	for _, f := range res.Findings {
		b.WriteString("finding " + f.Severity.String() + " " + f.RuleID + " " + f.Subject + "\n")
	}
	for _, g := range res.Gaps {
		b.WriteString("gap " + g.RuleID + " " + g.Subject + ": " + g.Reason + "\n")
	}
	return b.String()
}

// --- the INV-8 gate halves ------------------------------------------------

// TestMiscStockRootIsSilent pins the benign floor. Every persistence surface in
// the stock root is accounted for by a package, and the root carries no
// ld.so.preload, no profile.d and no autostart entry at all -- so this check
// must produce nothing whatsoever, findings and gaps alike.
func TestMiscStockRootIsSilent(t *testing.T) {
	root, owners := miscFixtureRoot(t, "stock")
	res := Misc(root, owners, MiscConfig{})
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("stock root is not silent:\n%s", miscDescribe(res))
	}
	if !res.Complete() {
		t.Fatalf("stock root reported incomplete coverage:\n%s", miscDescribe(res))
	}
}

// TestMiscNoCriticalsOnBenignRoots is the release gate: zero SevCritical on
// stock and on cruft. Cruft is the hard half -- pip, npm -g, /usr/local, a
// hand-written profile.d snippet, an unowned autostart entry pointing at an
// npm-installed binary, and an EMPTY ld.so.preload. Every one of those is
// legitimate, and every one of them is what a rule keyed on "unowned path on a
// persistence surface" would call critical.
func TestMiscNoCriticalsOnBenignRoots(t *testing.T) {
	for _, name := range []string{"stock", "cruft"} {
		t.Run(name, func(t *testing.T) {
			root, owners := miscFixtureRoot(t, name)
			res := Misc(root, owners, MiscConfig{})
			if got := res.MaxSeverity(); got >= finding.SevCritical {
				t.Fatalf("%s root reached %v:\n%s", name, got, miscDescribe(res))
			}
		})
	}
}

// TestMiscCruftRootIsNotSilent is the liveness half of the gate. Zero criticals
// with zero findings would satisfy the gate trivially, which is the silent
// scanner wearing a benign root as a disguise. Cruft has real unowned traffic on
// two surfaces and the check must see it -- at suspicious.
func TestMiscCruftRootReportsBenignTrafficAsSuspicious(t *testing.T) {
	root, owners := miscFixtureRoot(t, "cruft")
	res := Misc(root, owners, MiscConfig{})

	profiled := miscFindings(res, RuleProfileD)
	if len(profiled) != 1 || profiled[0].Subject != "etc/profile.d/local-path.sh" {
		t.Fatalf("want exactly the hand-written profile.d snippet, got %v:\n%s",
			miscSubjects(profiled), miscDescribe(res))
	}
	if profiled[0].Severity != finding.SevSuspicious {
		t.Fatalf("profile.d finding severity = %v, want suspicious", profiled[0].Severity)
	}

	autostart := miscFindings(res, RuleAutostart)
	if len(autostart) != 1 || autostart[0].Subject != "home/alice/.config/autostart/nextcloud.desktop" {
		t.Fatalf("want exactly alice's autostart entry, got %v:\n%s",
			miscSubjects(autostart), miscDescribe(res))
	}
	if autostart[0].Severity != finding.SevSuspicious {
		t.Fatalf("autostart finding severity = %v, want suspicious", autostart[0].Severity)
	}
	// The Exec target is /usr/bin/prettier: an unowned symlink to an unowned
	// npm target. Both hops are unowned, so this is the finding; the evidence
	// must name the program, not just the entry.
	if !strings.Contains(strings.Join(autostart[0].Evidence, "\n"), "usr/bin/prettier") {
		t.Fatalf("autostart evidence does not name the program: %v", autostart[0].Evidence)
	}
}

// TestMiscEmptyPreloadIsNotAFinding is the single assertion that the highest
// value rule in this file is keyed on CONTENTS and not on existence. An empty
// /etc/ld.so.preload is ordinary; cruft has one.
func TestMiscEmptyPreloadIsNotAFinding(t *testing.T) {
	root, owners := miscFixtureRoot(t, "cruft")
	res := Misc(root, owners, MiscConfig{})
	if got := miscFindings(res, RulePreload); len(got) != 0 {
		t.Fatalf("empty ld.so.preload produced %v:\n%s", miscSubjects(got), miscDescribe(res))
	}
	for _, g := range res.Gaps {
		if g.RuleID == RulePreload {
			t.Fatalf("empty ld.so.preload produced a coverage gap: %s", g.Reason)
		}
	}
}

// TestMiscAbsentPreloadIsNeitherFindingNorGap: the reference system has no
// /etc/ld.so.preload at all. Absence of a surface hides nothing.
func TestMiscAbsentPreloadIsNeitherFindingNorGap(t *testing.T) {
	root, owners := miscFixtureRoot(t, "stock")
	if _, err := os.Stat(filepath.Join("..", "..", "testdata", "roots", "stock", "etc", "ld.so.preload")); !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("fixture changed: stock root now has an ld.so.preload (%v)", err)
	}
	res := miscPreload(root, owners, DefaultMiscConfig())
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("absent ld.so.preload produced output:\n%s", miscDescribe(res))
	}
}

// TestMiscMaliciousPreloadNamesTheUnownedObject is the acceptance half for this
// surface: a non-empty preload list naming an object no package owns.
func TestMiscMaliciousPreloadNamesTheUnownedObject(t *testing.T) {
	root, owners := miscFixtureRoot(t, "malicious")
	res := Misc(root, owners, MiscConfig{})

	got := miscFindings(res, RulePreload)
	if len(got) != 1 {
		t.Fatalf("want 1 preload finding, got %v:\n%s", miscSubjects(got), miscDescribe(res))
	}
	// The subject is the OBJECT, not the list, and it is in the canonical
	// root-relative form internal/own keys on -- so internal/correlate can
	// cluster it by directory against the unit's ExecStart.
	if got[0].Subject != "usr/lib/systemd/libinert-marker-preload.so" {
		t.Fatalf("preload subject = %q, want the named object", got[0].Subject)
	}
	if got[0].Severity != finding.SevSuspicious {
		t.Fatalf("preload severity = %v; on its own this rule must not exceed suspicious -- "+
			"critical is earned by correlation", got[0].Severity)
	}
	if !strings.Contains(strings.Join(got[0].Evidence, "\n"), "etc/ld.so.preload") {
		t.Fatalf("preload evidence does not name the list it came from: %v", got[0].Evidence)
	}
}

// TestMiscFindingsStateTheirLimits is INV-6 made mechanical, and it is
// deliberately not satisfied by any non-empty string: the limit a user of this
// phase must be told is that a competent attacker produces no unowned path at
// all and every check here goes silent. A finding that does not say so
// overstates what it proves.
func TestMiscFindingsStateTheirLimits(t *testing.T) {
	for _, name := range []string{"cruft", "malicious"} {
		root, owners := miscFixtureRoot(t, name)
		res := Misc(root, owners, MiscConfig{})
		if len(res.Findings) == 0 {
			t.Fatalf("%s: no findings to check limits on", name)
		}
		for _, f := range res.Findings {
			low := strings.ToLower(f.Limits)
			for _, want := range []string{"sloppy", "$pkgdir", "not evidence of a clean system"} {
				if !strings.Contains(low, strings.ToLower(want)) {
					t.Errorf("%s: finding %s on %s omits %q from its Limits: %q",
						name, f.RuleID, f.Subject, want, f.Limits)
				}
			}
		}
	}
}

// --- INV-9: the gap/finding distinction ----------------------------------

// TestMiscAbsentHomeIsNotAGap. cruft's passwd lists bob, whose home does not
// exist on disk, and buildbot, whose /var/lib/buildbot does not either. An
// account with no home is ordinary: there is nothing to read and nothing was
// hidden, so it is neither a finding nor a gap.
func TestMiscAbsentHomeIsNotAGap(t *testing.T) {
	root, owners := miscFixtureRoot(t, "cruft")
	res := Misc(root, owners, MiscConfig{})
	for _, g := range res.Gaps {
		if strings.Contains(g.Subject, "home/bob") || strings.Contains(g.Subject, "buildbot") {
			t.Fatalf("absent home produced a gap: %s: %s", g.Subject, g.Reason)
		}
	}
	for _, f := range res.Findings {
		if strings.Contains(f.Subject, "home/bob") || strings.Contains(f.Subject, "buildbot") {
			t.Fatalf("absent home produced a finding: %s", f.Subject)
		}
	}
	// And the account list itself must have been read: bob's absence must not
	// be indistinguishable from bob never having been enumerated.
	users, gaps := PasswdUsers(root.FS(), "etc/passwd")
	if len(gaps) != 0 {
		t.Fatalf("cruft passwd produced gaps: %v", gaps)
	}
	want := []string{"root", "alice", "bob", "buildbot"}
	if len(users) != len(want) {
		t.Fatalf("PasswdUsers = %v, want the %d accounts with real homes", users, len(want))
	}
	for i, u := range users {
		if u.Name != want[i] {
			t.Fatalf("PasswdUsers[%d] = %q, want %q", i, u.Name, want[i])
		}
		if strings.HasPrefix(u.Home, "/") {
			t.Fatalf("home %q is not in root-relative form", u.Home)
		}
	}
}

// TestMiscUnreadableHomeIsAGapNotSilence is the INV-9 case the fixture cannot
// encode: git cannot store a mode-000 directory, so the unreadable home is made
// at runtime on a copy (INV-5 -- never on the checked-in tree).
//
// Reporting "no autostart entries found" for a home this scan cannot open would
// be a lie told with confidence, and it is the lie an unprivileged scan is most
// likely to tell.
func TestMiscUnreadableHomeIsAGapNotSilence(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits, so no gap can be produced")
	}
	dir := miscCopyTree(t, filepath.Join("..", "..", "testdata", "roots", "cruft"))
	home := filepath.Join(dir, "home", "alice")
	if err := os.Chmod(home, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(home, 0o755) })

	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})

	var found bool
	for _, g := range res.Gaps {
		if g.Subject == "home/alice" {
			found = true
			if !strings.Contains(g.Reason, "alice") {
				t.Errorf("gap does not name the account: %s", g.Reason)
			}
			if !strings.Contains(g.Reason, "not examined") {
				t.Errorf("gap does not say the surfaces went unexamined: %s", g.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("unreadable home produced no coverage gap; got:\n%s", miscDescribe(res))
	}
	if res.Complete() {
		t.Fatalf("Result.Complete() is true with an unreadable home; incomplete coverage is exit 3")
	}
	// And it must not have become a finding: a permission bit is not evidence.
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Subject, "home/alice") {
			t.Fatalf("unreadable home produced a finding: %s %s", f.RuleID, f.Subject)
		}
	}
}

// TestMiscAbsentPasswdIsAGapCoveringEveryUser. The malicious root ships no
// /etc/passwd. With no account list, no home is examined -- and the scan must
// say that rather than report per-user surfaces as clean.
func TestMiscAbsentPasswdIsAGapCoveringEveryUser(t *testing.T) {
	root, owners := miscFixtureRoot(t, "malicious")
	res := Misc(root, owners, MiscConfig{})

	var found bool
	for _, g := range res.Gaps {
		if g.Subject == "etc/passwd" {
			found = true
			if !strings.Contains(g.Reason, "per-user") {
				t.Errorf("passwd gap does not say which surfaces were skipped: %s", g.Reason)
			}
		}
	}
	if !found {
		t.Fatalf("absent passwd produced no gap; got:\n%s", miscDescribe(res))
	}
	// The malicious root DOES have home/alice/.cache with the helper's build
	// dir in it. Without an account list it must not have been walked -- the
	// point of the gap is that the surface is unexamined, not that it was
	// examined by another route.
	for _, f := range res.Findings {
		if strings.HasPrefix(f.Subject, "home/") {
			t.Fatalf("per-user finding without an account list: %s", f.Subject)
		}
	}
}

// TestMiscUnresolvablePathIsAGapNotAFinding. A directory component that cannot
// be searched makes ownership unknowable. "Unowned" would be a false
// accusation manufactured out of a permission bit.
func TestMiscUnresolvablePathIsAGapNotAFinding(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits, so resolution cannot fail")
	}
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "etc"))
	mustMkdirAll(t, filepath.Join(dir, "usr", "lib", "hidden"))
	mustWrite(t, filepath.Join(dir, "usr", "lib", "hidden", "obj.so"), "inert placeholder\n")
	mustWrite(t, filepath.Join(dir, "etc", "ld.so.preload"), "/usr/lib/hidden/obj.so\n")
	if err := os.Chmod(filepath.Join(dir, "usr", "lib"), 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(filepath.Join(dir, "usr", "lib"), 0o755) })

	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})

	if got := miscFindings(res, RulePreload); len(got) != 0 {
		t.Fatalf("unresolvable preload entry became a finding: %v", miscSubjects(got))
	}
	var found bool
	for _, g := range res.Gaps {
		if g.RuleID == RulePreload && g.Subject == "usr/lib/hidden/obj.so" {
			found = true
		}
	}
	if !found {
		t.Fatalf("unresolvable preload entry produced no gap; got:\n%s", miscDescribe(res))
	}
}

// TestMiscUnreadablePreloadIsAGap: the list is there and cannot be read, so
// every process on the machine is loading something this scan cannot name.
func TestMiscUnreadablePreloadIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits")
	}
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "etc"))
	p := filepath.Join(dir, "etc", "ld.so.preload")
	mustWrite(t, p, "/usr/lib/whatever.so\n")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}

	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})
	if len(res.Findings) != 0 {
		t.Fatalf("unreadable preload produced findings: %s", miscDescribe(res))
	}
	if !miscHasGap(res, RulePreload, "etc/ld.so.preload") {
		t.Fatalf("unreadable preload produced no gap; got:\n%s", miscDescribe(res))
	}
}

// TestMiscPreloadSymlinkIsRefusedNotFollowed. The confined opener refuses a
// symlink leaf unresolved, and that refusal is a gap: the target was never
// looked at, so nothing may be claimed about it.
func TestMiscPreloadSymlinkIsRefusedNotFollowed(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "etc"))
	mustWrite(t, filepath.Join(dir, "etc", "real-preload"), "/usr/lib/whatever.so\n")
	if err := os.Symlink("real-preload", filepath.Join(dir, "etc", "ld.so.preload")); err != nil {
		t.Fatalf("symlink: %v", err)
	}
	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})
	if len(res.Findings) != 0 {
		t.Fatalf("symlinked preload produced findings: %s", miscDescribe(res))
	}
	if !miscHasGap(res, RulePreload, "etc/ld.so.preload") {
		t.Fatalf("symlinked preload was not reported as a gap; got:\n%s", miscDescribe(res))
	}
}

// --- generator directories ------------------------------------------------

// TestMiscGeneratorDirsAlertOnlyOnUnownedFiles carries the three behaviours the
// *.wants rule needs, on this surface: resolve symlink targets, exclude
// directories, alert only on what no package owns.
func TestMiscGeneratorDirsAlertOnlyOnUnownedFiles(t *testing.T) {
	dir := t.TempDir()
	gen := filepath.Join(dir, "usr", "lib", "systemd", "system-generators")
	mustMkdirAll(t, gen)
	mustMkdirAll(t, filepath.Join(gen, "a-subdirectory"))
	mustWrite(t, filepath.Join(gen, "systemd-fstab-generator"), "inert placeholder\n")
	mustWrite(t, filepath.Join(gen, "planted-generator"), "inert placeholder\n")
	// An enablement-shaped symlink whose TARGET is packaged: unowned link,
	// owned target, and therefore not a subject.
	mustMkdirAll(t, filepath.Join(dir, "usr", "lib", "systemd"))
	mustWrite(t, filepath.Join(dir, "usr", "lib", "systemd", "vendor-generator"), "inert placeholder\n")
	if err := os.Symlink("/usr/lib/systemd/vendor-generator", filepath.Join(gen, "linked-generator")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	owners := own.IndexIn(root, []alpm.Package{{Name: "systemd", Files: []string{
		"usr/lib/systemd/system-generators/",
		"usr/lib/systemd/system-generators/systemd-fstab-generator",
		"usr/lib/systemd/vendor-generator",
	}}})

	res := Misc(root, owners, MiscConfig{})
	got := miscSubjects(miscFindings(res, RuleGenerator))
	if len(got) != 1 || got[0] != "usr/lib/systemd/system-generators/planted-generator" {
		t.Fatalf("generator rule reported %v, want exactly the planted generator:\n%s",
			got, miscDescribe(res))
	}
	for _, g := range res.Gaps {
		if g.RuleID == RuleGenerator {
			t.Fatalf("unexpected generator gap: %s: %s", g.Subject, g.Reason)
		}
	}
}

// TestMiscUnreadableGeneratorDirIsAGap: a directory systemd runs as root at
// every daemon-reload, which this scan could not list.
func TestMiscUnreadableGeneratorDirIsAGap(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("root ignores the permission bits")
	}
	dir := t.TempDir()
	gen := filepath.Join(dir, "etc", "systemd", "system-generators")
	mustMkdirAll(t, gen)
	if err := os.Chmod(gen, 0o000); err != nil {
		t.Fatalf("chmod: %v", err)
	}
	t.Cleanup(func() { _ = os.Chmod(gen, 0o755) })

	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})
	if !miscHasGap(res, RuleGenerator, "etc/systemd/system-generators") {
		t.Fatalf("unreadable generator dir produced no gap; got:\n%s", miscDescribe(res))
	}
}

// --- autostart parsing ----------------------------------------------------

func TestMiscDesktopExec(t *testing.T) {
	cases := []struct {
		name, in, want string
		hidden, ok     bool
	}{
		{name: "absolute with field code", in: "[Desktop Entry]\nExec=/usr/bin/foo %U\n", want: "/usr/bin/foo", ok: true},
		{name: "bare command", in: "[Desktop Entry]\nExec=nm-applet\n", want: "nm-applet", ok: true},
		{name: "escaped space", in: "[Desktop Entry]\nExec=/opt/my\\ app/run --now\n", want: "/opt/my app/run", ok: true},
		{name: "hidden entry is not a surface", in: "[Desktop Entry]\nExec=/usr/bin/foo\nHidden=true\n", hidden: true},
		{name: "variable is unresolvable", in: "[Desktop Entry]\nExec=$SHELL -c foo\n"},
		{name: "no exec key", in: "[Desktop Entry]\nType=Application\n"},
		{name: "exec outside the group is ignored", in: "[Desktop Action Open]\nExec=/usr/bin/foo\n"},
		{name: "first exec wins", in: "[Desktop Entry]\nExec=/usr/bin/a\nExec=/usr/bin/b\n", want: "/usr/bin/a", ok: true},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got, hidden, ok := miscDesktopExec(c.in)
			if got != c.want || hidden != c.hidden || ok != c.ok {
				t.Fatalf("miscDesktopExec = (%q, %v, %v), want (%q, %v, %v)",
					got, hidden, ok, c.want, c.hidden, c.ok)
			}
		})
	}
}

// TestMiscAutostartOwnedTargetsAreSilent covers the two shapes that make up
// almost all real autostart entries: a bare command name that is a packaged
// binary (5 of the reference system's 15 system entries), and an unowned entry
// file symlinked to a packaged .desktop (the reference system's only per-user
// entry). Neither is a finding.
func TestMiscAutostartOwnedTargetsAreSilent(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "etc"))
	mustMkdirAll(t, filepath.Join(dir, "etc", "xdg", "autostart"))
	mustMkdirAll(t, filepath.Join(dir, "usr", "bin"))
	mustMkdirAll(t, filepath.Join(dir, "usr", "share", "applications"))
	mustMkdirAll(t, filepath.Join(dir, "home", "alice", ".config", "autostart"))
	mustWrite(t, filepath.Join(dir, "etc", "passwd"), "alice:x:1000:1000::/home/alice:/usr/bin/bash\n")
	mustWrite(t, filepath.Join(dir, "usr", "bin", "nm-applet"), "inert placeholder\n")
	mustWrite(t, filepath.Join(dir, "etc", "xdg", "autostart", "nm-applet.desktop"),
		"[Desktop Entry]\nExec=nm-applet\n")
	mustWrite(t, filepath.Join(dir, "usr", "share", "applications", "slack.desktop"),
		"[Desktop Entry]\nExec=/usr/bin/nm-applet\n")
	if err := os.Symlink("/usr/share/applications/slack.desktop",
		filepath.Join(dir, "home", "alice", ".config", "autostart", "slack.desktop")); err != nil {
		t.Fatalf("symlink: %v", err)
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	owners := own.IndexIn(root, []alpm.Package{{Name: "nm", Files: []string{
		"usr/bin/nm-applet",
		"usr/share/applications/slack.desktop",
	}}})

	res := Misc(root, owners, MiscConfig{})
	if len(res.Findings) != 0 || len(res.Gaps) != 0 {
		t.Fatalf("owned autostart targets produced output:\n%s", miscDescribe(res))
	}
}

// TestMiscAutostartBareCommandNotFoundIsAGap. This scan does not model PATH, so
// a bare command it cannot locate is unknown ownership -- not unowned.
func TestMiscAutostartBareCommandNotFoundIsAGap(t *testing.T) {
	dir := t.TempDir()
	mustMkdirAll(t, filepath.Join(dir, "etc", "xdg", "autostart"))
	mustWrite(t, filepath.Join(dir, "etc", "xdg", "autostart", "x.desktop"),
		"[Desktop Entry]\nExec=somewhere-on-path\n")
	root, owners := miscRootAt(t, dir)
	res := Misc(root, owners, MiscConfig{})
	if len(miscFindings(res, RuleAutostart)) != 0 {
		t.Fatalf("bare command became a finding:\n%s", miscDescribe(res))
	}
	if !miscHasGap(res, RuleAutostart, "etc/xdg/autostart/x.desktop") {
		t.Fatalf("bare command produced no gap; got:\n%s", miscDescribe(res))
	}
}

// --- purity ---------------------------------------------------------------

// TestMiscIsPureInTheRoot: the same root scanned twice yields identical
// evidence, and nothing in the process environment changes it. $HOME and
// XDG_CONFIG_HOME are set to a decoy that, if consulted, would produce
// different output (INV-4).
func TestMiscIsPureInTheRoot(t *testing.T) {
	decoy := t.TempDir()
	mustMkdirAll(t, filepath.Join(decoy, ".config", "autostart"))
	mustWrite(t, filepath.Join(decoy, ".config", "autostart", "decoy.desktop"),
		"[Desktop Entry]\nExec=/usr/bin/decoy\n")
	t.Setenv("HOME", decoy)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(decoy, ".config"))

	root, owners := miscFixtureRoot(t, "cruft")
	first := miscDescribe(Misc(root, owners, MiscConfig{}))
	second := miscDescribe(Misc(root, owners, MiscConfig{}))
	if first != second {
		t.Fatalf("Misc is not deterministic:\nfirst:\n%s\nsecond:\n%s", first, second)
	}
	if strings.Contains(first, "decoy") {
		t.Fatalf("Misc consulted the process environment:\n%s", first)
	}
}

// TestMiscNilOwnersIsAGapNotSilence: without the oracle every rule here
// degenerates to "this path exists", and saying nothing would report the
// surfaces as clean.
func TestMiscNilOwnersIsAGapNotSilence(t *testing.T) {
	root, _ := miscFixtureRoot(t, "cruft")
	res := Misc(root, nil, MiscConfig{})
	if len(res.Findings) != 0 || res.Complete() {
		t.Fatalf("Misc with no ownership oracle: %s", miscDescribe(res))
	}
}

// --- live measurement -----------------------------------------------------

// TestLiveMiscSurfaces measures this check against the machine it runs on.
// Skipped by default: it reads / and /var/lib/pacman/local, which no unit test
// may depend on. Run with AURVET_LIVE_SURFACES=1 to reproduce the numbers in
// the P1-C receipt.
func TestLiveMiscSurfaces(t *testing.T) {
	if os.Getenv("AURVET_LIVE_SURFACES") != "1" {
		t.Skip("set AURVET_LIVE_SURFACES=1 to measure against the live system")
	}
	pkgs, bad, err := alpm.LoadLocalDB("/var/lib/pacman/local")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	owners := own.IndexIn(root, pkgs)

	res := Misc(root, owners, MiscConfig{})
	byRule := map[string]int{}
	for _, f := range res.Findings {
		byRule[f.RuleID]++
		t.Logf("finding %-34s %-9s %s", f.RuleID, f.Severity, f.Subject)
	}
	for _, g := range res.Gaps {
		t.Logf("gap     %-34s %s: %s", g.RuleID, g.Subject, g.Reason)
	}
	users, _ := PasswdUsers(root.FS(), "etc/passwd")
	t.Logf("packages=%d db-gaps=%d accounts-with-homes=%d findings=%d gaps=%d by-rule=%v max=%v",
		len(pkgs), len(bad), len(users), len(res.Findings), len(res.Gaps), byRule, res.MaxSeverity())
	if res.MaxSeverity() >= finding.SevCritical {
		t.Errorf("live system reached %v; no rule in this file may exceed suspicious", res.MaxSeverity())
	}
}

// --- helpers --------------------------------------------------------------

func miscHasGap(res finding.Result, ruleID, subject string) bool {
	for _, g := range res.Gaps {
		if g.RuleID == ruleID && g.Subject == subject {
			return true
		}
	}
	return false
}

func mustMkdirAll(t *testing.T, dir string) {
	t.Helper()
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatalf("mkdir %s: %v", dir, err)
	}
}

func mustWrite(t *testing.T, p, content string) {
	t.Helper()
	if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
		t.Fatalf("write %s: %v", p, err)
	}
}
