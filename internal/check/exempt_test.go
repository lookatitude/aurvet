// internal/check/exempt_test.go
package check

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/mtree"
)

// The hook bodies below are verbatim copies of installed Arch hooks (the
// reference system's /usr/share/libalpm/hooks, 57 hooks), trimmed of nothing.
// They are the input the derivation is measured against: a hand-written
// exemption list rots silently and every stale entry is a permanent blind
// spot, so the exemptions have to fall out of what pacman itself is
// configured to regenerate.

const hookLdconfigRemove = `[Trigger]
Operation = Remove
Target = glibc
Type = Package

[Action]
Depends = coreutils
Description = Removing cache for dynamic linker run-time bindings...
Exec = /usr/bin/rm --force /etc/ld.so.cache
When = PreTransaction
`

// The regenerating half of the same pair: the Exec names no output path at
// all, so it must contribute no exemption. Its /usr/bin/ldconfig is in
// command position and exempting it would leave the dynamic linker's own
// configuration tool unexamined.
const hookLdconfig = `[Trigger]
Operation = Install
Operation = Upgrade
Target = glibc
Type = Package

[Trigger]
Operation = Install
Operation = Upgrade
Operation = Remove
Target = usr/lib/ld.so.conf.d/*
Type = Path

[Action]
Depends = glibc
Description = Configuring dynamic linker run-time bindings...
Exec = /usr/bin/ldconfig -r .
When = PostTransaction
`

const hookGioRemove = `[Trigger]
Type = Package
Operation = Remove
Target = glib2

[Action]
Description = Removing GIO module cache...
When = PreTransaction
Exec = /usr/bin/rm --force /usr/lib/gio/modules/giomodule.cache
`

// A nested sh -c: the exemptable path sits inside the quoted script, and both
// /usr/bin/sh and the inner /usr/bin/rm are in command position.
const hookLocaleRemove = `[Trigger]
Operation = Remove
Target = glibc
Type = Package

[Action]
Description = Removing the locale archive...
Exec = /usr/bin/sh -c '/usr/bin/rm --force /usr/lib/locale/locale-archive'
When = PreTransaction
`

// shared-mime-info's remove hook, verbatim. Its rm argument is a brace
// expansion, which this parser refuses to expand -- an unexpanded token
// yields no exemption, which is the safe direction.
const hookMimeRemove = `[Trigger]
Type = Package
Operation = Remove
Target = shared-mime-info

[Action]
Depends = bash
Description = Removing generated entries of the MIME type database...
Exec = /usr/bin/sh -c '/usr/bin/rm --force --recursive /usr/share/mime/{globs,magic,types}; rmdir --ignore-fail-on-non-empty /usr/share/mime'
When = PostTransaction
`

// texinfo's install hook: the regenerated file is the third argument of an
// install-info call buried in a while/do/done loop.
const hookTexinfo = `[Trigger]
Type = Path
Operation = Install
Operation = Upgrade
Target = usr/share/info/*

[Action]
Description = Updating the info directory file...
When = PostTransaction
Exec = /bin/sh -c 'while read -r f; do if test -f "$f"; then install-info "$f" /usr/share/info/dir 2> /dev/null; fi; done'
NeedsTargets
`

// writeHookDir materialises hook files in a fresh root and returns the root.
func writeHookDir(t *testing.T, dir string, hooks map[string]string) string {
	t.Helper()
	root := t.TempDir()
	full := filepath.Join(root, dir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	for name, body := range hooks {
		if err := os.WriteFile(filepath.Join(full, name), []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	return root
}

func TestParseHookReadsTriggersAndAction(t *testing.T) {
	h, err := ParseHook("11-glibc-ldconfig.hook", []byte(hookLdconfig))
	if err != nil {
		t.Fatalf("ParseHook: %v", err)
	}
	if h.Exec != "/usr/bin/ldconfig -r ." {
		t.Errorf("Exec = %q", h.Exec)
	}
	if h.When != "PostTransaction" {
		t.Errorf("When = %q", h.When)
	}
	if len(h.Triggers) != 2 {
		t.Fatalf("got %d triggers, want 2: %+v", len(h.Triggers), h.Triggers)
	}
	if got := h.Triggers[0].Operations; len(got) != 2 || got[0] != "Install" || got[1] != "Upgrade" {
		t.Errorf("trigger 0 operations = %v", got)
	}
	if got := h.Triggers[1].Targets; len(got) != 1 || got[0] != "usr/lib/ld.so.conf.d/*" {
		t.Errorf("trigger 1 targets = %v", got)
	}
}

// TestExecPathLiteralsNeverExemptTheCommand is the check with teeth: every
// path in command position is an executable pacman runs, and exempting one
// would take a binary out of digest coverage entirely.
func TestExecPathLiteralsNeverExemptTheCommand(t *testing.T) {
	cases := []struct {
		name string
		exec string
		want []string
	}{
		{"rm with one output", "/usr/bin/rm --force /etc/ld.so.cache", []string{"/etc/ld.so.cache"}},
		{"no output path at all", "/usr/bin/ldconfig -r .", nil},
		{"nested sh -c", "/usr/bin/sh -c '/usr/bin/rm --force /usr/lib/locale/locale-archive'",
			[]string{"/usr/lib/locale/locale-archive"}},
		{"separator restarts command position", "/usr/bin/rm -f /etc/a.cache; /usr/bin/rm -f /etc/b.cache",
			[]string{"/etc/a.cache", "/etc/b.cache"}},
		{"brace expansion refused", "/usr/bin/rm -r /usr/share/mime/{globs,magic}", nil},
		{"glob refused", "/usr/bin/rm -f /usr/share/icons/*/icon-theme.cache", nil},
		{"variable refused", "/usr/bin/rm -f $DESTDIR/etc/x.cache", nil},
		{"relative path is not a system file", "/usr/bin/rm -f etc/ld.so.cache", nil},
		{"script argument", "/bin/sh -c 'install-info \"$f\" /usr/share/info/dir'",
			[]string{"/usr/share/info/dir"}},
		// texinfo-install.hook's verbatim redirection: /dev/null is a stream
		// destination, not a file pacman regenerates. Measured -- without the
		// redirect rule it lands in the derived set.
		{"redirection target", "/bin/sh -c 'install-info \"$f\" /usr/share/info/dir 2> /dev/null'",
			[]string{"/usr/share/info/dir"}},
		{"redirection with no descriptor", "/usr/bin/foo /etc/x.cache > /dev/null", []string{"/etc/x.cache"}},
		// 30-update-mime-database.hook, verbatim. The real command follows an
		// env(1) prefix and one assignment; exempting it would take a binary out
		// of digest coverage. Measured: this exact line put
		// /usr/bin/update-mime-database in the derived set before the
		// command-position propagation rule existed.
		{"env prefix", "/usr/bin/env PKGSYSTEM_ENABLE_FSYNC=0 /usr/bin/update-mime-database /usr/share/mime",
			[]string{"/usr/share/mime"}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			got := ExecPathLiterals(c.exec)
			sort.Strings(got)
			want := append([]string(nil), c.want...)
			sort.Strings(want)
			if strings.Join(got, ",") != strings.Join(want, ",") {
				t.Errorf("ExecPathLiterals(%q) = %v, want %v", c.exec, got, c.want)
			}
			for _, p := range got {
				if p == "/usr/bin/rm" || p == "/usr/bin/sh" || p == "/bin/sh" || p == "/usr/bin/ldconfig" {
					t.Errorf("ExecPathLiterals(%q) exempted the command itself (%s)", c.exec, p)
				}
			}
		})
	}
}

func TestLoadHooksAndDeriveExemptions(t *testing.T) {
	root := writeHookDir(t, "usr/share/libalpm/hooks", map[string]string{
		"11-glibc-remove-ldconfig-cache.hook": hookLdconfigRemove,
		"11-glibc-ldconfig.hook":              hookLdconfig,
		"gio-remove-module-cache.hook":        hookGioRemove,
		"10-glibc-remove-locale-archive.hook": hookLocaleRemove,
		"shared-mime-info-remove-cache.hook":  hookMimeRemove,
		"texinfo-install.hook":                hookTexinfo,
		"not-a-hook.conf":                     "Exec = /usr/bin/rm -f /etc/ignored.cache\n",
	})
	hooks, gaps := LoadHooks(os.DirFS(root), DefaultHookDirs)
	if len(gaps) != 0 {
		t.Errorf("unexpected gaps: %+v", gaps)
	}
	if len(hooks) != 6 {
		t.Fatalf("loaded %d hooks, want 6 (.hook only): %+v", len(hooks), hooks)
	}

	ex := DeriveExemptions(hooks, nil)
	for _, want := range []string{
		"etc/ld.so.cache",
		"usr/lib/gio/modules/giomodule.cache",
		"usr/lib/locale/locale-archive",
		"usr/share/info/dir",
	} {
		e, ok := ex.Lookup(want)
		if !ok {
			t.Errorf("%s is not exempt; derived set = %v", want, ex.All())
			continue
		}
		if !strings.Contains(e.Reason, "hook") || e.Source == "" {
			t.Errorf("%s exemption is not attributable: %+v", want, e)
		}
	}
	// usr/share/mime IS derived, from that hook's trailing `rmdir
	// --ignore-fail-on-non-empty /usr/share/mime`, and is deliberately not
	// asserted against: it names a directory, and Integrity never consults the
	// exemption set for a type=dir entry. What must not be derived from that
	// same Exec is the brace expansion's contents -- asserted below.
	for _, notWant := range []string{
		"usr/bin/ldconfig", "usr/bin/rm", "usr/bin/sh", "bin/sh",
		"etc/ignored.cache",
		"usr/share/mime/globs",
	} {
		if e, ok := ex.Lookup(notWant); ok {
			t.Errorf("%s must not be exempt: %+v", notWant, e)
		}
	}
}

func TestBackupFilesAreExempt(t *testing.T) {
	pkgs := []alpm.Package{{
		Name:   "pacman",
		Backup: map[string]string{"etc/pacman.conf": "d41d8cd98f00b204e9800998ecf8427e"},
	}}
	ex := DeriveExemptions(nil, pkgs)
	e, ok := ex.Lookup("etc/pacman.conf")
	if !ok {
		t.Fatalf("etc/pacman.conf is not exempt: %v", ex.All())
	}
	if !strings.Contains(e.Reason, "%BACKUP%") || !strings.Contains(e.Reason, "pacman") {
		t.Errorf("backup exemption does not name its origin: %+v", e)
	}
}

// TestPycacheIsNotBlanketExempt pins the measured decision: 103 packages ship
// digest-covered .pyc files, so a blanket __pycache__ exemption would discard
// real integrity coverage across a hundred packages to silence noise from a
// few.
func TestPycacheIsNotBlanketExempt(t *testing.T) {
	root := writeHookDir(t, "usr/share/libalpm/hooks", map[string]string{
		"11-glibc-remove-ldconfig-cache.hook": hookLdconfigRemove,
	})
	hooks, _ := LoadHooks(os.DirFS(root), DefaultHookDirs)
	ex := DeriveExemptions(hooks, []alpm.Package{{Name: "python-foo"}})
	for _, p := range []string{
		"usr/lib/python3.13/site-packages/foo/__pycache__/bar.cpython-313.pyc",
		"usr/lib/python3.13/__pycache__/os.cpython-313.pyc",
	} {
		if e, ok := ex.Lookup(p); ok {
			t.Errorf("%s is exempt (%+v); 103 packages ship digest-covered .pyc", p, e)
		}
	}
}

// TestExemptionNeverCoversAnExecutable is the second line of defence behind
// the command-position rule: even if a hook Exec named a binary as an
// argument, an entry the package records as executable is still verified.
func TestExemptionNeverCoversAnExecutable(t *testing.T) {
	ex := DeriveExemptions([]Hook{{
		Name: "hostile.hook", When: "PostTransaction",
		Exec: "/usr/bin/touch /usr/bin/sudo /var/lib/x.cache",
	}}, nil)
	if _, ok := ex.Lookup("usr/bin/sudo"); !ok {
		t.Fatal("precondition: the path-literal rule was expected to pick usr/bin/sudo up")
	}
	if e, ok := ex.Applies(mtree.Entry{Path: "./usr/bin/sudo", Type: "file", Mode: 0o4755}); ok {
		t.Errorf("an executable entry was exempted: %+v", e)
	}
	if _, ok := ex.Applies(mtree.Entry{Path: "./var/lib/x.cache", Type: "file", Mode: 0o644}); !ok {
		t.Error("a non-executable derived exemption did not apply")
	}
}

// TestLoadHooksReportsUnreadableHooksAsGaps: INV-9. A hook we cannot read is
// a hook whose exemptions we do not know, which is a coverage gap, never
// silence.
func TestLoadHooksReportsUnreadableHooksAsGaps(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("running as root: mode 0 is still readable")
	}
	root := writeHookDir(t, "usr/share/libalpm/hooks", map[string]string{
		"unreadable.hook": hookGioRemove,
	})
	p := filepath.Join(root, "usr/share/libalpm/hooks/unreadable.hook")
	if err := os.Chmod(p, 0o000); err != nil {
		t.Fatal(err)
	}
	_, gaps := LoadHooks(os.DirFS(root), DefaultHookDirs)
	if len(gaps) != 1 {
		t.Fatalf("got %d gaps, want 1: %+v", len(gaps), gaps)
	}
	if !strings.Contains(gaps[0].Subject, "unreadable.hook") {
		t.Errorf("gap does not name the hook: %+v", gaps[0])
	}
}

// An absent hook directory is normal: /etc/pacman.d/hooks does not exist on
// the reference system. Absent is not the same as unreadable.
func TestAbsentHookDirIsNotAGap(t *testing.T) {
	root := writeHookDir(t, "usr/share/libalpm/hooks", map[string]string{
		"gio-remove-module-cache.hook": hookGioRemove,
	})
	hooks, gaps := LoadHooks(os.DirFS(root), DefaultHookDirs)
	if len(gaps) != 0 {
		t.Errorf("absent /etc/pacman.d/hooks produced gaps: %+v", gaps)
	}
	if len(hooks) != 1 {
		t.Errorf("got %d hooks, want 1", len(hooks))
	}
}

// A hook disabled by an empty file (the /dev/null symlink shape pacman
// documents) contributes no exemptions: a hook that does not run regenerates
// nothing.
func TestDisabledHookContributesNoExemption(t *testing.T) {
	root := writeHookDir(t, "usr/share/libalpm/hooks", map[string]string{
		"gio-remove-module-cache.hook": hookGioRemove,
	})
	// Same name in the higher-priority admin dir, empty: pacman runs this one.
	admin := filepath.Join(root, "etc/pacman.d/hooks")
	if err := os.MkdirAll(admin, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(admin, "gio-remove-module-cache.hook"), nil, 0o644); err != nil {
		t.Fatal(err)
	}
	hooks, _ := LoadHooks(os.DirFS(root), DefaultHookDirs)
	ex := DeriveExemptions(hooks, nil)
	if e, ok := ex.Lookup("usr/lib/gio/modules/giomodule.cache"); ok {
		t.Errorf("a shadowed hook still contributed an exemption: %+v", e)
	}
}
