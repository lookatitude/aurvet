// internal/hook/hook_test.go
package hook

import (
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"
)

// The hook bodies below are verbatim copies of installed Arch hooks (the
// reference system's /usr/share/libalpm/hooks, 57 hooks), trimmed of nothing.
// They are the input the parser is measured against: hook files are the format
// any package may ship, so what this package accepts has to be what pacman
// itself accepts.

// The Exec names no output path at all, so it must contribute no path literal.
// Its /usr/bin/ldconfig is in command position and yielding it would leave the
// dynamic linker's own configuration tool unexamined.
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
