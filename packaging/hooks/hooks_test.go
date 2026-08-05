// Package hooks holds no Go code: it exists so the shipped pacman hooks are
// tested by the same `go test ./...` that tests everything else.
//
// The two properties under test are the ones whose failure is unrecoverable:
//
//   - Orphan safety. A pacman hook whose Exec cannot run fails EVERY subsequent
//     transaction, including the transaction that would reinstall the missing
//     binary. The operator's recovery is editing files as root with no working
//     pacman. This is the highest-blast-radius thing in the project, so it is
//     tested by actually running the shipped Exec command with the wrapper and
//     the binary absent.
//   - The hooks parse as pacman will read them, asserted with internal/hook --
//     the parser the tool itself uses on other packages' hooks.
//
// No test here installs anything into the live pacman configuration. The shipped
// Exec names /usr/share/aurvet/aurvet-hook; the tests substitute a temporary
// copy for that literal and say so.
package hooks

import (
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/hook"
)

// installedWrapper is the path the shipped hooks name. Tests replace this
// literal in the Exec string with a temporary copy of the wrapper.
const installedWrapper = "/usr/share/aurvet/aurvet-hook"

const (
	preHook   = "aurvet-precheck.hook"
	postHook  = "aurvet-provenance.hook"
	wrapperSh = "aurvet-hook"
)

func read(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(name)
	if err != nil {
		t.Fatal(err)
	}
	return b
}

func parse(t *testing.T, name string) hook.Hook {
	t.Helper()
	h, err := hook.ParseHook(name, read(t, name))
	if err != nil {
		t.Fatalf("ParseHook(%s): %v", name, err)
	}
	return h
}

// TestShippedHooksParseAsPacmanWillReadThem uses the project's own hook parser,
// which is a cheap and genuine check that what ships is what pacman reads.
func TestShippedHooksParseAsPacmanWillReadThem(t *testing.T) {
	for _, tc := range []struct {
		file string
		when string
	}{
		{preHook, "PreTransaction"},
		{postHook, "PostTransaction"},
	} {
		h := parse(t, tc.file)
		if h.When != tc.when {
			t.Errorf("%s: When = %q, want %q", tc.file, h.When, tc.when)
		}
		if h.Desc == "" {
			t.Errorf("%s: no Description; pacman prints it and an unlabelled hook is unattributable", tc.file)
		}
		if len(h.Triggers) != 1 {
			t.Fatalf("%s: %d [Trigger] sections, want 1", tc.file, len(h.Triggers))
		}
		tr := h.Triggers[0]
		if tr.Type != "Package" {
			t.Errorf("%s: Type = %q, want Package (targets are then package names, which the wrapper maps to pkgbases)",
				tc.file, tr.Type)
		}
		if len(tr.Targets) == 0 || len(tr.Operations) == 0 {
			t.Errorf("%s: trigger has no Target/Operation: %+v", tc.file, tr)
		}
		if !strings.Contains(string(read(t, tc.file)), "NeedsTargets") {
			t.Errorf("%s: no NeedsTargets, so the command would receive no targets on stdin", tc.file)
		}
		if h.Exec == "" {
			t.Fatalf("%s: no Exec", tc.file)
		}
		// The INTERPRETER must be a path that exists on a system where aurvet has
		// been removed. Note ExecPathLiterals deliberately excludes the command
		// itself (it derives the files a hook operates ON), so the interpreter is
		// asserted from the Exec string and the operands from the derivation.
		if !strings.HasPrefix(h.Exec, "/bin/sh ") {
			t.Errorf("%s: Exec = %q; it must run /bin/sh, never /usr/bin/aurvet -- an Exec naming a removed binary "+
				"fails every later transaction, including the one that would reinstall it", tc.file, h.Exec)
		}
		if _, err := os.Stat("/bin/sh"); err != nil {
			t.Errorf("/bin/sh does not exist on this system: %v", err)
		}
		// The only aurvet-owned path Exec may name is the wrapper, and only
		// behind a test that it exists.
		for _, p := range hook.ExecPathLiterals(h.Exec) {
			if p != installedWrapper {
				t.Errorf("%s: Exec names %q; the only aurvet-owned path it may name is the guarded wrapper %q",
					tc.file, p, installedWrapper)
			}
		}
		if !strings.Contains(h.Exec, "[ -x "+installedWrapper+" ] || exit 0") {
			t.Errorf("%s: Exec does not guard the wrapper with an exit-0 test: %q", tc.file, h.Exec)
		}
	}
}

// TestPreTransactionHookShipsWithoutAbortOnFail: inert by default. AbortOnFail
// is what makes a non-zero exit abort a transaction, and it must be the
// operator's decision.
func TestPreTransactionHookShipsWithoutAbortOnFail(t *testing.T) {
	body := string(read(t, preHook))
	for _, line := range strings.Split(body, "\n") {
		trimmed := strings.TrimSpace(line)
		if strings.HasPrefix(trimmed, "#") {
			continue
		}
		if strings.HasPrefix(trimmed, "AbortOnFail") {
			t.Fatalf("%s ships with AbortOnFail active: %q", preHook, line)
		}
	}
	// ... and the one line to add is documented, in the file, where the operator
	// enabling it will be looking.
	if !strings.Contains(body, "AbortOnFail") {
		t.Errorf("%s does not show the one line that opts in to gating", preHook)
	}
	if strings.Contains(string(read(t, postHook)), "\nAbortOnFail") {
		t.Errorf("%s carries AbortOnFail; a PostTransaction failure must never fail a transaction", postHook)
	}
}

// execCommand returns the shipped Exec with the wrapper path rewritten to point
// at wrapper (which may be a path that does not exist -- that is the orphan
// case).
//
// pacman splits Exec itself and execs argv directly; running the same string
// through `sh -c` is the faithful equivalent for a command that is already
// `/bin/sh -c '...'`.
func execCommand(t *testing.T, file, wrapper string) string {
	t.Helper()
	h := parse(t, file)
	if !strings.Contains(h.Exec, installedWrapper) {
		t.Fatalf("%s: Exec does not name %s: %q", file, installedWrapper, h.Exec)
	}
	return strings.ReplaceAll(h.Exec, installedWrapper, wrapper)
}

// runExec runs a hook Exec string with a controlled PATH and returns its exit
// code and combined output.
func runExec(t *testing.T, command string, path string, stdin string) (int, string) {
	t.Helper()
	cmd := exec.Command("/bin/sh", "-c", command)
	cmd.Env = []string{"PATH=" + path, "AURVET_HOOK_DBPATH=" + t.TempDir()}
	cmd.Stdin = strings.NewReader(stdin)
	out, err := cmd.CombinedOutput()
	code := 0
	if ee, ok := err.(*exec.ExitError); ok {
		code = ee.ExitCode()
	} else if err != nil {
		t.Fatalf("running %q: %v", command, err)
	}
	return code, string(out)
}

// TestHookExecExitsZeroWhenAurvetIsRemoved is the orphan-safety proof, both
// layers of it: the wrapper missing (the package was removed) and the wrapper
// present with the binary missing (a partial removal, or a broken install).
func TestHookExecExitsZeroWhenAurvetIsRemoved(t *testing.T) {
	emptyPATH := t.TempDir()
	missing := filepath.Join(t.TempDir(), "definitely-not-installed", "aurvet-hook")

	for _, file := range []string{preHook, postHook} {
		// Layer 1: aurvet removed, so the wrapper is gone with it.
		if code, out := runExec(t, execCommand(t, file, missing), emptyPATH, "foo\n"); code != 0 {
			t.Errorf("%s with the wrapper absent exited %d, want 0 -- an orphaned hook that fails would brick "+
				"pacman\noutput: %s", file, code, out)
		}
		// Layer 2: the wrapper survived, the binary did not.
		wrapper := stagedWrapper(t)
		if code, out := runExec(t, execCommand(t, file, wrapper), emptyPATH, "foo\n"); code != 0 {
			t.Errorf("%s with the wrapper present and aurvet absent exited %d, want 0\noutput: %s", file, code, out)
		}
	}
}

// stagedWrapper copies the shipped wrapper into a temporary directory, executable.
func stagedWrapper(t *testing.T) string {
	t.Helper()
	dst := filepath.Join(t.TempDir(), wrapperSh)
	if err := os.WriteFile(dst, read(t, wrapperSh), 0o755); err != nil {
		t.Fatal(err)
	}
	return dst
}

// fakeAurvet writes an `aurvet` on PATH that records its arguments and exits
// with code.
func fakeAurvet(t *testing.T, code int) (dir, log string) {
	t.Helper()
	dir = t.TempDir()
	log = filepath.Join(dir, "calls.log")
	script := "#!/bin/sh\nprintf '%s\\n' \"$*\" >> " + log + "\nexit " + itoa(code) + "\n"
	if err := os.WriteFile(filepath.Join(dir, "aurvet"), []byte(script), 0o755); err != nil {
		t.Fatal(err)
	}
	return dir, log
}

func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	var b []byte
	for n > 0 {
		b = append([]byte{byte('0' + n%10)}, b...)
		n /= 10
	}
	return string(b)
}

// TestPreHookPropagatesTheWorstExitSoAbortOnFailCanGate: the inertness must come
// from the missing AbortOnFail, not from a wrapper that always exits 0 -- a
// wrapper that swallowed the code would make the documented one-line opt-in a
// lie.
func TestPreHookPropagatesTheWorstExitSoAbortOnFailCanGate(t *testing.T) {
	wrapper := stagedWrapper(t)
	for _, code := range []int{0, 1, 3} {
		bin, _ := fakeAurvet(t, code)
		got, out := runExec(t, execCommand(t, preHook, wrapper), bin, "foo\n")
		if got != code {
			t.Errorf("pre hook with aurvet exiting %d exited %d\noutput: %s", code, got, out)
		}
	}
}

// TestPostHookAlwaysExitsZero: a failed capture must never fail a transaction.
func TestPostHookAlwaysExitsZero(t *testing.T) {
	wrapper := stagedWrapper(t)
	for _, code := range []int{1, 2, 3} {
		bin, _ := fakeAurvet(t, code)
		if got, out := runExec(t, execCommand(t, postHook, wrapper), bin, "foo\n"); got != 0 {
			t.Errorf("post hook with aurvet exiting %d exited %d, want 0\noutput: %s", code, got, out)
		}
	}
}

// TestWrapperKeysOnPkgBaseNotPackageName: pacman hands the hook PACKAGE names.
// 433 of 1409 packages on the reference system are split, so a wrapper that
// passed the name through would file a snapshot under the wrong unit -- and file
// the same build several times over.
func TestWrapperKeysOnPkgBaseNotPackageName(t *testing.T) {
	wrapper := stagedWrapper(t)
	bin, log := fakeAurvet(t, 0)
	db := t.TempDir()
	// One base, two packages: exactly the shape that breaks name-keyed capture.
	writeDesc(t, db, "foo-a-1.0-1", "foo-a", "foo")
	writeDesc(t, db, "foo-b-1.0-1", "foo-b", "foo")

	cmd := exec.Command("/bin/sh", "-c", execCommand(t, postHook, wrapper))
	cmd.Env = []string{"PATH=" + bin, "AURVET_HOOK_DBPATH=" + db}
	cmd.Stdin = strings.NewReader("foo-a\nfoo-b\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post hook: %v\n%s", err, out)
	}

	calls := strings.TrimSpace(readFile(t, log))
	if calls != "snapshot foo" {
		t.Errorf("calls = %q, want exactly one capture keyed on the pkgbase (%q)", calls, "snapshot foo")
	}
}

// TestWrapperFallsBackToTheNameWhenTheDatabaseDoesNotSay: a package with no
// %BASE% recorded (or not installed yet) is still captured under the only key
// available, rather than being silently skipped.
func TestWrapperFallsBackToTheNameWhenTheDatabaseDoesNotSay(t *testing.T) {
	wrapper := stagedWrapper(t)
	bin, log := fakeAurvet(t, 0)
	cmd := exec.Command("/bin/sh", "-c", execCommand(t, postHook, wrapper))
	cmd.Env = []string{"PATH=" + bin, "AURVET_HOOK_DBPATH=" + t.TempDir()}
	cmd.Stdin = strings.NewReader("solo\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post hook: %v\n%s", err, out)
	}
	if calls := strings.TrimSpace(readFile(t, log)); calls != "snapshot solo" {
		t.Errorf("calls = %q, want %q", calls, "snapshot solo")
	}
}

// TestWrapperDoesNotConfuseAPrefixSiblingForItsTarget: the glob "foo-*" also
// matches "foo-bar-1.0-1", so %NAME% must be compared exactly or a different
// package's record answers.
func TestWrapperDoesNotConfuseAPrefixSiblingForItsTarget(t *testing.T) {
	wrapper := stagedWrapper(t)
	bin, log := fakeAurvet(t, 0)
	db := t.TempDir()
	writeDesc(t, db, "foo-bar-1.0-1", "foo-bar", "wrong-base")
	writeDesc(t, db, "foo-2.0-1", "foo", "right-base")

	cmd := exec.Command("/bin/sh", "-c", execCommand(t, postHook, wrapper))
	cmd.Env = []string{"PATH=" + bin, "AURVET_HOOK_DBPATH=" + db}
	cmd.Stdin = strings.NewReader("foo\n")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("post hook: %v\n%s", err, out)
	}
	if calls := strings.TrimSpace(readFile(t, log)); calls != "snapshot right-base" {
		t.Errorf("calls = %q, want %q", calls, "snapshot right-base")
	}
}

func writeDesc(t *testing.T, db, dir, name, base string) {
	t.Helper()
	d := filepath.Join(db, dir)
	if err := os.MkdirAll(d, 0o755); err != nil {
		t.Fatal(err)
	}
	body := "%NAME%\n" + name + "\n\n%BASE%\n" + base + "\n\n%VERSION%\n1.0-1\n"
	if err := os.WriteFile(filepath.Join(d, "desc"), []byte(body), 0o644); err != nil {
		t.Fatal(err)
	}
}

func readFile(t *testing.T, p string) string {
	t.Helper()
	b, err := os.ReadFile(p)
	if err != nil {
		return ""
	}
	return string(b)
}
