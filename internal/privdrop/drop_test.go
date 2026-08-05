// internal/privdrop/drop_test.go
package privdrop

import (
	"context"
	"crypto/sha256"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/safe"
)

// These are process-model assertions (P1-B task 12), so most of them cannot be
// made in the test process: ReduceToRead re-execs, DropAll is irreversible, and
// a deliberately unrecovered goroutine panic kills whatever process runs it. So
// each such assertion runs in a re-invocation of this same test binary, steered
// by helperEnv, and the parent asserts on the child's stdout and REAL exit code.
const (
	helperEnv  = "AURVET_PRIVDROP_TEST_HELPER"
	witnessEnv = "AURVET_PRIVDROP_TEST_WITNESS"

	// skipExitCode is how a helper says "this assertion could not run here".
	// INV-3 applied to the suite: an unrunnable privilege assertion must stay
	// visible rather than read as a pass. The one cause in practice is -race,
	// which links cgo and thereby disables syscall.AllThreadsSyscall, so the
	// drop correctly refuses.
	skipExitCode = 79
	// nsRefusedCode reports that the kernel refused a new user namespace.
	nsRefusedCode = -2
)

func TestMain(m *testing.M) {
	if mode := os.Getenv(helperEnv); mode != "" {
		os.Exit(helper(mode))
	}
	os.Exit(m.Run())
}

// ---------------------------------------------------------------- task 6 ----

func TestSanitiseEnvRemovesLoaderVariables(t *testing.T) {
	// Every name in this table is a real loader knob: with any of them set, the
	// image this process is already running is not the image on disk, so the
	// drop has to happen in a fresh one.
	in := []string{
		"PATH=/usr/bin",
		"LD_PRELOAD=/tmp/evil.so",
		"LD_LIBRARY_PATH=/tmp",
		"LD_AUDIT=/tmp/audit.so",
		"LD_=weird",
		"GLIBC_TUNABLES=glibc.malloc.check=3",
		// Kept: ld.so matches LD_ as a prefix and GLIBC_TUNABLES exactly, and
		// the environment is case-sensitive, so none of these are loader knobs.
		"LDFLAGS=-s",
		"OLD_LD_PRELOAD=/tmp/x.so",
		"ld_preload=/tmp/x.so",
		"GLIBC_TUNABLES_BACKUP=x",
		"HOME=/root",
	}
	wantKept := []string{"PATH=/usr/bin", "LDFLAGS=-s", "OLD_LD_PRELOAD=/tmp/x.so", "ld_preload=/tmp/x.so", "GLIBC_TUNABLES_BACKUP=x", "HOME=/root"}
	wantRemoved := []string{"LD_PRELOAD", "LD_LIBRARY_PATH", "LD_AUDIT", "LD_", "GLIBC_TUNABLES"}

	clean, removed := sanitiseEnv(in)
	if got := strings.Join(clean, " "); got != strings.Join(wantKept, " ") {
		t.Errorf("sanitiseEnv kept %q, want %q", clean, wantKept)
	}
	if got := strings.Join(removed, " "); got != strings.Join(wantRemoved, " ") {
		t.Errorf("sanitiseEnv removed %q, want %q", removed, wantRemoved)
	}
}

func TestSanitiseEnvIsIdempotentOnACleanEnvironment(t *testing.T) {
	in := []string{"PATH=/usr/bin", "TERM=dumb"}
	clean, removed := sanitiseEnv(in)
	if len(removed) != 0 {
		t.Errorf("sanitiseEnv removed %q from a clean environment", removed)
	}
	if strings.Join(clean, " ") != strings.Join(in, " ") {
		t.Errorf("sanitiseEnv rewrote a clean environment to %q", clean)
	}
}

// TestReduceToReadReExecsWhenTheLoaderEnvironmentIsHostile proves the re-exec
// actually happens rather than merely that the variables are gone from
// os.Environ (which os.Unsetenv alone would achieve while leaving the
// already-preloaded image in place). The witness file is appended to BEFORE
// ReduceToRead is called, so a re-exec leaves two "enter" records.
func TestReduceToReadReExecsWhenTheLoaderEnvironmentIsHostile(t *testing.T) {
	witness := filepath.Join(t.TempDir(), "witness")
	out, errOut, code, timedOut := runHelper(t, "reduce-reexec", []string{
		witnessEnv + "=" + witness,
		"LD_PRELOAD=/tmp/definitely-not-here.so",
		"GLIBC_TUNABLES=glibc.malloc.check=3",
	}, 30*time.Second)
	requireHelperRan(t, out, errOut, code, timedOut)

	if got := witnessRecords(t, witness); got != "enter enter past-reduce" {
		t.Errorf("witness = %q, want %q (two enters == one re-exec)", got, "enter enter past-reduce")
	}
	for _, want := range []string{"ld_vars=0", "glibc_tunables=absent", "marker=1"} {
		if !strings.Contains(out, want) {
			t.Errorf("helper stdout %q missing %q", out, want)
		}
	}
}

// The mirror image of the test above: with nothing hostile in the environment
// the running image was never subverted, so re-exec would be ceremony. Asserting
// the negative keeps sanitiseEnv's result load-bearing for the re-exec decision
// instead of the re-exec being unconditional.
func TestReduceToReadDoesNotReExecWhenTheEnvironmentIsAlreadyClean(t *testing.T) {
	witness := filepath.Join(t.TempDir(), "witness")
	out, errOut, code, timedOut := runHelper(t, "reduce-reexec", []string{witnessEnv + "=" + witness}, 30*time.Second)
	requireHelperRan(t, out, errOut, code, timedOut)
	if got := witnessRecords(t, witness); got != "enter past-reduce" {
		t.Errorf("witness = %q, want %q (one enter == no re-exec)", got, "enter past-reduce")
	}
	if !strings.Contains(out, "marker=0") {
		t.Errorf("helper stdout %q: expected no re-exec marker", out)
	}
}

func TestReduceToReadSetsNoNewPrivs(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "reduce-nnp", nil, 30*time.Second)
	requireHelperRan(t, out, errOut, code, timedOut)
	if !strings.Contains(out, "nnp_before=0") {
		t.Skipf("test runner already had PR_SET_NO_NEW_PRIVS set; assertion not meaningful: %q", out)
	}
	if !strings.Contains(out, "nnp_after=1") {
		t.Errorf("helper stdout %q: PR_SET_NO_NEW_PRIVS not set after ReduceToRead", out)
	}
	// Every thread, not just the calling one: capabilities and no_new_privs are
	// per-thread on Linux, and any goroutine can be scheduled onto any thread.
	if !strings.Contains(out, "nnp_all_threads=1") {
		t.Errorf("helper stdout %q: PR_SET_NO_NEW_PRIVS not set on every thread", out)
	}
}

// TestDropAllOnAnAlreadyUnprivilegedProcess pins the shape of the drop when
// there was nothing to drop: it must succeed, leave all three sets empty, and
// refuse both regain routes.
//
// Read the LIMIT with it, because it is the whole reason the user-namespace test
// below exists: this process starts with an empty permitted set, so "permitted
// is empty afterwards" would also hold if DropAll did nothing at all. What this
// test proves is that DropAll is safe and total on the degraded path, not that
// it destroys anything.
func TestDropAllOnAnAlreadyUnprivilegedProcess(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "dropall", nil, 30*time.Second)
	requireHelperRan(t, out, errOut, code, timedOut)
	for _, want := range []string{
		"drop_err=<nil>",
		// The permitted set, not merely the effective set. Anything left in
		// permitted is recoverable, which makes the drop decorative.
		"effective=0",
		"permitted=0",
		"inheritable=0",
		// Regaining must be impossible, not merely unattempted.
		"regain_effective=refused",
		"regain_ambient=refused",
		"read_unreadable_file=refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("helper stdout %q missing %q", out, want)
		}
	}
}

// TestPrivilegeLifecycleWithRealCapabilities is the assertion that is NOT
// vacuous. It runs the whole staging sequence in a new user namespace, where an
// ordinary user genuinely holds a full capability set -- so the pre-drop reads
// SUCCEED, and their post-drop failure is caused by the drop rather than by the
// process never having had the capability.
//
// It needs no root, which is the point: a privilege assertion that only runs
// under sudo never runs in CI. It skips visibly if the kernel refuses
// unprivileged user namespaces.
func TestPrivilegeLifecycleWithRealCapabilities(t *testing.T) {
	out, errOut, code, timedOut := runHelperInUserNS(t, "staged", 30*time.Second)
	if timedOut {
		t.Fatalf("helper hung: out=%q", out)
	}
	if code == nsRefusedCode {
		t.Skipf("this kernel refused an unprivileged user namespace, so the capability lifecycle ran nowhere and is UNVERIFIED: %s", strings.TrimSpace(errOut))
	}
	requireHelperRan(t, out, errOut, code, timedOut)

	for _, want := range []string{
		// Non-vacuity: the process really held CAP_DAC_READ_SEARCH and really
		// could read a file its own DAC bits forbid.
		"start_has_dac_read_search=1",
		"start_has_setpcap=1",
		"read_at_start=allowed",

		// After ReduceToRead: exactly one capability, nothing inheritable, an
		// empty bounding set, SECBIT_NOROOT locked -- and phase 1 still works,
		// which is the requirement that makes the reduction usable at all.
		"reduce_err=<nil>",
		"reduced_effective=CAP_DAC_READ_SEARCH",
		"reduced_permitted=CAP_DAC_READ_SEARCH",
		"reduced_inheritable=0",
		"reduced_bounding=empty",
		"reduced_secbit_noroot=locked",
		"read_after_reduce=allowed",

		// After DropAll: gone from the permitted set, not just the effective
		// one, and unrecoverable by either route.
		"drop_err=<nil>",
		"dropped_effective=0",
		"dropped_permitted=0",
		"dropped_inheritable=0",
		"regain_effective=refused",
		"regain_ambient=refused",
		"read_after_drop=refused",

		// The route no capset can close: execve. Measured -- with both guards
		// removed, this same helper reported postexec_permitted=2199023255551
		// (all 41 capabilities) and postexec_read=ALLOWED, so a "complete" drop
		// was undone by an exec.
		"postexec_effective=0",
		"postexec_permitted=0",
		"postexec_read=refused",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("helper stdout %q missing %q", out, want)
		}
	}

	// INV-3 in the test suite: the drop is proven against namespaced
	// capabilities. Real uid-0 on the host is a different credential and this
	// suite does not exercise it.
	if os.Geteuid() != 0 {
		t.Logf("euid=%d: proven with user-namespace capabilities; the host-root path (reading a root-owned 0600 file before the drop) did not run and is unverified", os.Geteuid())
	}
}

// TestDropAllRefusesWhenThreadsCannotBeSynchronised guards the sharpest edge in
// this package: capset and prctl act on the CALLING THREAD, and the Go runtime
// has many. syscall.AllThreadsSyscall is the only process-wide mechanism, and it
// returns ENOTSUP in a cgo-linked binary. A silent fall back to a single-thread
// capset would leave privileged threads behind for any goroutine to be scheduled
// onto, so the only correct answer is to refuse.
func TestDropAllRefusesWhenThreadsCannotBeSynchronised(t *testing.T) {
	restore := allThreadsSyscall
	allThreadsSyscall = func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, unix.Errno) {
		return 0, 0, unix.ENOTSUP
	}
	t.Cleanup(func() { allThreadsSyscall = restore })

	err := DropAll()
	if err == nil {
		t.Fatal("DropAll returned nil when the drop could not be applied to every thread")
	}
	if !errors.Is(err, unix.ENOTSUP) {
		t.Errorf("DropAll error = %v, want one wrapping ENOTSUP", err)
	}
	if !strings.Contains(err.Error(), "cgo") {
		t.Errorf("DropAll error = %q: should name cgo, which is the only cause", err)
	}

	// ReduceToRead re-execs if the loader environment is hostile, and re-execing
	// the TEST binary would rerun the whole suite. Clear the variables first so
	// this stays an assertion about the capability reduction.
	clearLoaderEnv(t)
	if err := ReduceToRead(); err == nil {
		t.Error("ReduceToRead returned nil when the reduction could not be applied to every thread")
	}
}

// requireHelperRan turns a helper's real exit status into pass, visible skip, or
// failure -- never into a silent pass.
func requireHelperRan(t *testing.T, out, errOut string, code int, timedOut bool) {
	t.Helper()
	if timedOut {
		t.Fatalf("helper hung: out=%q stderr=%q", out, errOut)
	}
	switch code {
	case 0:
	case skipExitCode:
		t.Skipf("the privilege drop is unavailable in this build, so this assertion did not run and is UNVERIFIED: %s", strings.TrimSpace(errOut))
	default:
		t.Fatalf("helper failed: code=%d out=%q stderr=%q", code, out, errOut)
	}
}

func clearLoaderEnv(t *testing.T) {
	t.Helper()
	for _, kv := range os.Environ() {
		name, value, _ := strings.Cut(kv, "=")
		if !strings.HasPrefix(name, "LD_") && name != "GLIBC_TUNABLES" {
			continue
		}
		if err := os.Unsetenv(name); err != nil {
			t.Fatalf("unsetting %s: %v", name, err)
		}
		t.Cleanup(func() { os.Setenv(name, value) })
	}
}

// --------------------------------------------------------------- task 12 ----

// TestPostDropHostileNodesAreRefusedNotFollowed asserts the process-model half
// of TOCTOU safety: in the unprivileged post-drop process, a fifo and a symlink
// escaping the root are refused. internal/fsx owns the shipped OpenConfined;
// what is asserted here is that the guarantee survives the privilege drop and
// that neither node can stall the scan.
func TestPostDropHostileNodesAreRefusedNotFollowed(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "hostile-nodes", nil, 30*time.Second)
	if timedOut {
		t.Fatalf("helper hung: a hostile node stalled the scan. out=%q", out)
	}
	requireHelperRan(t, out, errOut, code, timedOut)
	for _, want := range []string{
		"regular=opened",
		"fifo=refused-not-regular",
		"escaping_symlink=refused",
		"internal_symlink=opened",
		"directory=refused-not-regular",
	} {
		if !strings.Contains(out, want) {
			t.Errorf("helper stdout %q missing %q", out, want)
		}
	}
}

// The negative control for the assertion above, kept permanently rather than
// run once by hand: without O_NONBLOCK the same fifo open blocks forever. If
// this test stops timing out, O_NONBLOCK has stopped mattering and the guard
// above is no longer testing anything.
func TestFifoWithoutNonblockHangsSoTheGuardIsLoadBearing(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "hostile-fifo-unguarded", nil, 3*time.Second)
	if code == skipExitCode {
		t.Skipf("the helper could not reach the fifo because the drop is unavailable in this build; the O_NONBLOCK negative control is UNVERIFIED: %s", strings.TrimSpace(errOut))
	}
	if !timedOut {
		t.Logf("helper stdout %q", out)
		t.Error("opening a fifo without O_NONBLOCK completed; the hang this package defends against no longer reproduces, so the O_NONBLOCK assertion is vacuous")
	}
}

func TestMidScanMutationIsDetected(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "mutate", nil, 30*time.Second)
	requireHelperRan(t, out, errOut, code, timedOut)
	// A file rewritten between the open and the post-hash re-fstat is a finding
	// about the SCAN. Reporting it as a digest mismatch would misattribute it.
	if !strings.Contains(out, "mutated=mutated during scan") {
		t.Errorf("helper stdout %q: mid-scan mutation not detected", out)
	}
	if !strings.Contains(out, "stable=verified") {
		t.Errorf("helper stdout %q: an untouched file must not be reported as mutated", out)
	}
}

// TestPanickingSubjectYieldsAGapAndExitThree is the assertion the lane brief
// singles out. Three subjects, the middle one panics: the scan must COMPLETE,
// the panic must become a coverage gap attributed to its subject (INV-9), and
// the process must exit 3 -- including when the panic originates inside a worker
// goroutine, where the parent's recover cannot reach it.
func TestPanickingSubjectYieldsAGapAndExitThree(t *testing.T) {
	for _, mode := range []string{"scan-inline", "scan-goroutine"} {
		t.Run(mode, func(t *testing.T) {
			out, _, code, timedOut := runHelper(t, mode, nil, 30*time.Second)
			if timedOut {
				t.Fatalf("helper hung: out=%q", out)
			}
			if code != 3 {
				t.Errorf("exit code = %d, want 3 (incomplete coverage outranks findings)", code)
			}
			for _, want := range []string{
				"subject=pkg-a result=analysed",
				"subject=pkg-b result=gap",
				"subject=pkg-c result=analysed",
				"gap=pkg-b",
				"findings=1",
			} {
				if !strings.Contains(out, want) {
					t.Errorf("helper stdout %q missing %q", out, want)
				}
			}
		})
	}
}

// The negative control, and the reason the goroutine case had to be written
// separately: a worker goroutine whose top-level function has no recover takes
// the whole process down. The scan does not complete, no report is written, and
// the exit code is Go's panic status -- not 3. If this ever stops reproducing,
// per-goroutine recovers have become unnecessary and the assertion above is
// no longer proving anything.
func TestUnrecoveredWorkerGoroutinePanicKillsTheScan(t *testing.T) {
	out, errOut, code, timedOut := runHelper(t, "scan-goroutine-unrecovered", nil, 30*time.Second)
	if timedOut {
		t.Fatalf("helper hung: out=%q", out)
	}
	if code == 3 {
		t.Fatal("an unrecovered goroutine panic produced exit 3; the process cannot have survived it, so the harness is not testing what it claims")
	}
	if !strings.Contains(errOut, "panic:") {
		t.Errorf("stderr %q: expected a Go panic trace", errOut)
	}
	if strings.Contains(out, "gap=pkg-b") {
		t.Errorf("stdout %q: a report was produced despite the process dying", out)
	}
}

// ------------------------------------------------------------- plumbing ----

// runHelperInUserNS runs a helper as uid 0 of a fresh user namespace, where an
// unprivileged caller holds a full capability set over its own files. code is
// -2 when the kernel refused the namespace, so the caller can skip visibly
// instead of reporting a pass.
func runHelperInUserNS(t *testing.T, mode string, timeout time.Duration) (stdout, stderr string, code int, timedOut bool) {
	t.Helper()
	return runHelperWith(t, mode, nil, timeout, &syscall.SysProcAttr{
		Cloneflags: syscall.CLONE_NEWUSER,
		UidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getuid(), Size: 1},
		},
		GidMappings: []syscall.SysProcIDMap{
			{ContainerID: 0, HostID: os.Getgid(), Size: 1},
		},
		GidMappingsEnableSetgroups: false,
	})
}

func runHelper(t *testing.T, mode string, extraEnv []string, timeout time.Duration) (stdout, stderr string, code int, timedOut bool) {
	t.Helper()
	return runHelperWith(t, mode, extraEnv, timeout, nil)
}

func runHelperWith(t *testing.T, mode string, extraEnv []string, timeout time.Duration, attr *syscall.SysProcAttr) (stdout, stderr string, code int, timedOut bool) {
	t.Helper()
	self, err := os.Executable()
	if err != nil {
		t.Fatalf("os.Executable: %v", err)
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	cmd := exec.CommandContext(ctx, self)
	cmd.SysProcAttr = attr
	// A deliberately minimal environment: the helper must see exactly the
	// loader variables the test injects and nothing the developer's shell
	// happens to export.
	cmd.Env = append([]string{
		helperEnv + "=" + mode,
		"PATH=/usr/bin",
		"HOME=" + t.TempDir(),
	}, extraEnv...)
	var out, errBuf strings.Builder
	cmd.Stdout = &out
	cmd.Stderr = &errBuf
	err = cmd.Run()
	if ctx.Err() != nil {
		return out.String(), errBuf.String(), -1, true
	}
	var exitErr *exec.ExitError
	switch {
	case err == nil:
		code = 0
	case errors.As(err, &exitErr):
		code = exitErr.ExitCode()
	case attr != nil:
		// The namespace itself was refused (clone failed), which is a skip
		// signal rather than a test failure.
		return out.String(), err.Error(), nsRefusedCode, false
	default:
		t.Fatalf("running helper %s: %v", mode, err)
	}
	return out.String(), errBuf.String(), code, false
}

func witnessRecords(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("reading witness: %v", err)
	}
	return strings.Join(strings.Fields(string(b)), " ")
}

func witness(record string) {
	path := os.Getenv(witnessEnv)
	if path == "" {
		return
	}
	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		return
	}
	defer f.Close()
	fmt.Fprintln(f, record)
}

// ---------------------------------------------------------- helper modes ----

func helper(mode string) int {
	switch mode {
	case "reduce-reexec":
		return helperReduceReexec()
	case "reduce-nnp":
		return helperReduceNoNewPrivs()
	case "dropall":
		return helperDropAll()
	case "staged":
		return helperStaged()
	case "caps-report":
		return helperCapsReport()
	case "hostile-nodes":
		return helperHostileNodes(true)
	case "hostile-fifo-unguarded":
		return helperHostileNodes(false)
	case "mutate":
		return helperMutate()
	case "scan-inline":
		return helperScan(false, true)
	case "scan-goroutine":
		return helperScan(true, true)
	case "scan-goroutine-unrecovered":
		return helperScan(true, false)
	default:
		fmt.Fprintf(os.Stderr, "unknown helper mode %q\n", mode)
		return 64
	}
}

func helperReduceReexec() int {
	witness("enter")
	if err := ReduceToRead(); err != nil {
		fmt.Fprintf(os.Stderr, "ReduceToRead: %v\n", err)
		if errors.Is(err, unix.ENOTSUP) {
			return skipExitCode
		}
		return 1
	}
	witness("past-reduce")

	ld := 0
	for _, kv := range os.Environ() {
		if strings.HasPrefix(kv, "LD_") {
			ld++
		}
	}
	tunables := "absent"
	if _, ok := os.LookupEnv("GLIBC_TUNABLES"); ok {
		tunables = "present"
	}
	marker := "0"
	if os.Getenv(reexecMarkerEnv) != "" {
		marker = "1"
	}
	fmt.Printf("ld_vars=%d\nglibc_tunables=%s\nmarker=%s\n", ld, tunables, marker)
	return 0
}

func helperReduceNoNewPrivs() int {
	before, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PR_GET_NO_NEW_PRIVS: %v\n", err)
		return 1
	}
	if err := ReduceToRead(); err != nil {
		fmt.Fprintf(os.Stderr, "ReduceToRead: %v\n", err)
		if errors.Is(err, unix.ENOTSUP) {
			return skipExitCode
		}
		return 1
	}
	after, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PR_GET_NO_NEW_PRIVS: %v\n", err)
		return 1
	}

	// Sample other threads: pin a goroutine to a fresh OS thread and read the
	// flag there. A per-thread flag set on only the calling thread would show
	// up here as 0.
	allThreads := int64(1)
	var wg sync.WaitGroup
	for range 8 {
		wg.Add(1)
		go func() {
			defer wg.Done()
			runtime.LockOSThread()
			defer runtime.UnlockOSThread()
			v, err := unix.PrctlRetInt(unix.PR_GET_NO_NEW_PRIVS, 0, 0, 0, 0)
			if err != nil || v != 1 {
				atomic.StoreInt64(&allThreads, 0)
			}
		}()
	}
	wg.Wait()

	fmt.Printf("nnp_before=%d\nnnp_after=%d\nnnp_all_threads=%d\n", before, after, atomic.LoadInt64(&allThreads))
	return 0
}

func helperDropAll() int {
	// Captured before the drop: post-drop this file must be unreadable, and it
	// is owned by the caller so the only thing that could have read it is the
	// capability the drop destroys.
	unreadable := filepath.Join(os.Getenv("HOME"), "unreadable")
	if err := os.WriteFile(unreadable, []byte("secret"), 0o000); err != nil {
		fmt.Fprintf(os.Stderr, "creating unreadable fixture: %v\n", err)
		return 1
	}

	if err := DropAll(); err != nil {
		fmt.Fprintf(os.Stderr, "DropAll: %v\n", err)
		if errors.Is(err, unix.ENOTSUP) {
			return skipExitCode
		}
		return 1
	}
	fmt.Printf("drop_err=%v\n", error(nil))

	var hdr = unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		fmt.Fprintf(os.Stderr, "capget: %v\n", err)
		return 1
	}
	eff := uint64(data[1].Effective)<<32 | uint64(data[0].Effective)
	perm := uint64(data[1].Permitted)<<32 | uint64(data[0].Permitted)
	inh := uint64(data[1].Inheritable)<<32 | uint64(data[0].Inheritable)
	fmt.Printf("effective=%d\npermitted=%d\ninheritable=%d\n", eff, perm, inh)

	// Regain attempt 1: raise CAP_DAC_READ_SEARCH back into effective and
	// permitted. With permitted empty the kernel must answer EPERM.
	var regain [2]unix.CapUserData
	regain[0].Effective = 1 << uint(unix.CAP_DAC_READ_SEARCH)
	regain[0].Permitted = 1 << uint(unix.CAP_DAC_READ_SEARCH)
	fmt.Printf("regain_effective=%s\n", refusedOrNot(unix.Capset(&hdr, &regain[0])))

	// Regain attempt 2: the ambient set, which survives execve.
	fmt.Printf("regain_ambient=%s\n", refusedOrNot(unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(unix.CAP_DAC_READ_SEARCH), 0, 0)))

	fmt.Printf("read_unreadable_file=%s\n", refusedOrNot(readable(unreadable)))
	if os.Geteuid() == 0 {
		fmt.Printf("read_root_only_file=%s\n", refusedOrNot(readable("/etc/shadow")))
	}
	return 0
}

// helperStaged walks the real startup -> collect -> transition -> analyse
// sequence and reports what the kernel says at each step. It runs as uid 0 of a
// user namespace, so the capabilities involved are real.
func helperStaged() int {
	unreadable := filepath.Join(os.Getenv("HOME"), "unreadable")
	if err := os.WriteFile(unreadable, []byte("secret"), 0o000); err != nil {
		fmt.Fprintf(os.Stderr, "creating unreadable fixture: %v\n", err)
		return 1
	}

	start, err := capsOfCallingThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capget: %v\n", err)
		return 1
	}
	fmt.Printf("start_has_dac_read_search=%d\nstart_has_setpcap=%d\n",
		bit(start.effective, unix.CAP_DAC_READ_SEARCH), bit(start.effective, unix.CAP_SETPCAP))
	fmt.Printf("read_at_start=%s\n", allowedOrRefused(readable(unreadable)))

	if err := ReduceToRead(); err != nil {
		fmt.Fprintf(os.Stderr, "ReduceToRead: %v\n", err)
		if errors.Is(err, unix.ENOTSUP) {
			return skipExitCode
		}
		return 1
	}
	fmt.Printf("reduce_err=%v\n", error(nil))
	reduced, err := capsOfCallingThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capget: %v\n", err)
		return 1
	}
	fmt.Printf("reduced_effective=%s\nreduced_permitted=%s\nreduced_inheritable=%d\n",
		describeCaps(reduced.effective), describeCaps(reduced.permitted), reduced.inheritable)
	fmt.Printf("reduced_bounding=%s\n", describeBounding())
	bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		fmt.Fprintf(os.Stderr, "PR_GET_SECUREBITS: %v\n", err)
		return 1
	}
	noroot := "unset"
	if bits&secbitNoRoot != 0 && bits&secbitNoRootLocked != 0 {
		noroot = "locked"
	}
	fmt.Printf("reduced_secbit_noroot=%s\n", noroot)
	// The reduction must not break phase 1: the collector still has to read
	// files whose DAC bits forbid it.
	fmt.Printf("read_after_reduce=%s\n", allowedOrRefused(readable(unreadable)))

	if code, ok := dropOrSkip(); !ok {
		return code
	}
	fmt.Printf("drop_err=%v\n", error(nil))
	dropped, err := capsOfCallingThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capget: %v\n", err)
		return 1
	}
	fmt.Printf("dropped_effective=%d\ndropped_permitted=%d\ndropped_inheritable=%d\n",
		dropped.effective, dropped.permitted, dropped.inheritable)

	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var regain [2]unix.CapUserData
	regain[0].Effective = 1 << uint(unix.CAP_DAC_READ_SEARCH)
	regain[0].Permitted = 1 << uint(unix.CAP_DAC_READ_SEARCH)
	fmt.Printf("regain_effective=%s\n", refusedOrNot(unix.Capset(&hdr, &regain[0])))
	fmt.Printf("regain_ambient=%s\n", refusedOrNot(unix.Prctl(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_RAISE, uintptr(unix.CAP_DAC_READ_SEARCH), 0, 0)))
	fmt.Printf("read_after_drop=%s\n", refusedOrNot(readable(unreadable)))

	// Last route: execve. Still euid 0 in this namespace, so without
	// SECBIT_NOROOT and an emptied bounding set the fresh image would be handed
	// permitted = bounding|inheritable. Hand over to caps-report, which reports
	// on the other side.
	if err := unix.Exec("/proc/self/exe", os.Args, []string{
		helperEnv + "=caps-report",
		"HOME=" + os.Getenv("HOME"),
	}); err != nil {
		fmt.Fprintf(os.Stderr, "re-exec for the post-exec report: %v\n", err)
		return 1
	}
	return 1 // unreachable
}

func helperCapsReport() int {
	caps, err := capsOfCallingThread()
	if err != nil {
		fmt.Fprintf(os.Stderr, "capget: %v\n", err)
		return 1
	}
	fmt.Printf("postexec_effective=%d\npostexec_permitted=%d\n", caps.effective, caps.permitted)
	fmt.Printf("postexec_read=%s\n", refusedOrNot(readable(filepath.Join(os.Getenv("HOME"), "unreadable"))))
	return 0
}

func bit(set uint64, cap int) int {
	if set&(uint64(1)<<uint(cap)) != 0 {
		return 1
	}
	return 0
}

// describeCaps names the set when it is exactly CAP_DAC_READ_SEARCH, so the
// assertion reads as the requirement rather than as a bitmask.
func describeCaps(set uint64) string {
	if set == uint64(1)<<uint(unix.CAP_DAC_READ_SEARCH) {
		return "CAP_DAC_READ_SEARCH"
	}
	return fmt.Sprintf("%d", set)
}

func describeBounding() string {
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		v, err := unix.PrctlRetInt(unix.PR_CAPBSET_READ, uintptr(c), 0, 0, 0)
		if err != nil {
			continue
		}
		if v == 1 {
			return fmt.Sprintf("holds %d", c)
		}
	}
	return "empty"
}

func allowedOrRefused(err error) string {
	if err != nil {
		return "refused"
	}
	return "allowed"
}

// dropOrSkip performs the real drop and, when the kernel-wide apply is
// unavailable, hands the parent a skip signal instead of a failure. The
// distinction matters: "the drop refused" and "the drop did not hold" must not
// arrive as the same result.
func dropOrSkip() (int, bool) {
	err := DropAll()
	if err == nil {
		return 0, true
	}
	fmt.Fprintf(os.Stderr, "DropAll: %v\n", err)
	if errors.Is(err, unix.ENOTSUP) {
		return skipExitCode, false
	}
	return 1, false
}

func refusedOrNot(err error) string {
	if err != nil {
		return "refused"
	}
	return "ALLOWED"
}

func readable(path string) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	f.Close()
	return nil
}

// helperHostileNodes builds a root containing the nodes a hostile filesystem
// would substitute for a packaged file, then opens each one in the post-drop
// process. guarded=false omits O_NONBLOCK and is expected to hang on the fifo.
func helperHostileNodes(guarded bool) int {
	dir := filepath.Join(os.Getenv("HOME"), "root")
	if err := os.MkdirAll(filepath.Join(dir, "sub"), 0o755); err != nil {
		fmt.Fprintf(os.Stderr, "mkdir: %v\n", err)
		return 1
	}
	if err := os.WriteFile(filepath.Join(dir, "regular"), []byte("payload"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "write: %v\n", err)
		return 1
	}
	if err := unix.Mkfifo(filepath.Join(dir, "fifo"), 0o644); err != nil {
		fmt.Fprintf(os.Stderr, "mkfifo: %v\n", err)
		return 1
	}
	// Created at run time, not committed: git cannot carry a fifo, and a
	// checked-out escaping symlink is a hazard for anything that walks the
	// working tree.
	if err := os.Symlink("../../../../etc/passwd", filepath.Join(dir, "escaping")); err != nil {
		fmt.Fprintf(os.Stderr, "symlink: %v\n", err)
		return 1
	}
	if err := os.Symlink("regular", filepath.Join(dir, "internal")); err != nil {
		fmt.Fprintf(os.Stderr, "symlink: %v\n", err)
		return 1
	}
	if code, ok := dropOrSkip(); !ok {
		return code
	}

	root, err := os.OpenRoot(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenRoot: %v\n", err)
		return 1
	}
	defer root.Close()

	if !guarded {
		// No O_NONBLOCK: this open never returns, which is the whole point.
		f, err := root.OpenFile("fifo", os.O_RDONLY, 0)
		if err == nil {
			f.Close()
		}
		fmt.Println("fifo=opened-without-nonblock")
		return 0
	}
	for label, name := range map[string]string{
		"regular":          "regular",
		"fifo":             "fifo",
		"escaping_symlink": "escaping",
		"internal_symlink": "internal",
		"directory":        "sub",
	} {
		fmt.Printf("%s=%s\n", label, openConfinedOutcome(root, name))
	}
	return 0
}

// openConfinedOutcome is the local, test-only mirror of the open-once contract
// internal/fsx owns (P1-B task 4): one resolution, O_NOFOLLOW|O_NONBLOCK, and
// the type check taken from the fd rather than from a second path lookup.
func openConfinedOutcome(root *os.Root, name string) string {
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "refused"
	}
	defer f.Close()
	var st unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &st); err != nil {
		return "refused"
	}
	if st.Mode&unix.S_IFMT != unix.S_IFREG {
		return "refused-not-regular"
	}
	return "opened"
}

func helperMutate() int {
	dir := os.Getenv("HOME")
	if code, ok := dropOrSkip(); !ok {
		return code
	}
	root, err := os.OpenRoot(dir)
	if err != nil {
		fmt.Fprintf(os.Stderr, "OpenRoot: %v\n", err)
		return 1
	}
	defer root.Close()

	for _, tc := range []struct {
		label  string
		mutate bool
	}{{"mutated", true}, {"stable", false}} {
		name := tc.label + ".bin"
		if err := os.WriteFile(filepath.Join(dir, name), []byte("original"), 0o644); err != nil {
			fmt.Fprintf(os.Stderr, "write: %v\n", err)
			return 1
		}
		outcome, err := hashAndReverify(root, name, tc.mutate, filepath.Join(dir, name))
		if err != nil {
			fmt.Fprintf(os.Stderr, "%s: %v\n", tc.label, err)
			return 1
		}
		fmt.Printf("%s=%s\n", tc.label, outcome)
	}
	return 0
}

// hashAndReverify mirrors task 5's contract locally: fstat the fd at open,
// stream the digest from that same fd, then re-fstat THE SAME FD and compare.
func hashAndReverify(root *os.Root, name string, mutate bool, absPath string) (string, error) {
	f, err := root.OpenFile(name, os.O_RDONLY|unix.O_NOFOLLOW|unix.O_NONBLOCK, 0)
	if err != nil {
		return "", err
	}
	defer f.Close()
	var before unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &before); err != nil {
		return "", err
	}
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	if mutate {
		// A different, longer content and a moved mtime: the swap an attacker
		// performs once the tool has decided the file is worth hashing.
		if err := os.WriteFile(absPath, []byte("swapped after hashing"), 0o644); err != nil {
			return "", err
		}
		if err := os.Chtimes(absPath, time.Now().Add(time.Hour), time.Now().Add(time.Hour)); err != nil {
			return "", err
		}
	}
	var after unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &after); err != nil {
		return "", err
	}
	if before.Ino != after.Ino || before.Dev != after.Dev || before.Size != after.Size ||
		before.Mtim.Sec != after.Mtim.Sec || before.Mtim.Nsec != after.Mtim.Nsec {
		return "mutated during scan", nil
	}
	return "verified", nil
}

// helperScan is the process-model harness for INV-9: three subjects, the middle
// one panics, and the exit code comes from the shipped report.ExitCode.
//
// The per-subject recover is safe.Run's -- the shipped one (P1-B task 8), no
// longer a test-local copy. What is being asserted is the process model: the
// scan completes, the panic is a gap, and the status is 3.
func helperScan(inGoroutine, recoverInWorker bool) int {
	subjects := []struct {
		name string
		fn   func() error
	}{
		{"pkg-a", func() error { return nil }},
		{"pkg-b", func() error { panic("crafted metadata") }},
		{"pkg-c", func() error { return nil }},
	}

	var (
		mu     sync.Mutex
		result finding.Result
		lines  []string
	)
	record := func(name string, gap *finding.Gap) {
		mu.Lock()
		defer mu.Unlock()
		if gap != nil {
			result.Gaps = append(result.Gaps, *gap)
			lines = append(lines, fmt.Sprintf("subject=%s result=gap", name))
			return
		}
		lines = append(lines, fmt.Sprintf("subject=%s result=analysed", name))
	}

	var wg sync.WaitGroup
	for _, s := range subjects {
		if !inGoroutine {
			record(s.name, runSubject(s.name, s.fn))
			continue
		}
		wg.Add(1)
		go func(name string, fn func() error) {
			// Not a convenience: a goroutine's panic cannot be recovered by
			// its parent, so the recover has to live at the top of the worker.
			// recoverInWorker=false is the negative control and takes the
			// process down.
			if !recoverInWorker {
				// wg.Done is NOT deferred here, deliberately. A deferred Done
				// runs during panic unwinding, releasing the parent from
				// wg.Wait so that main races the runtime's panic output and
				// exit -- which made this negative control flaky. Without it
				// the process dies while main is still waiting, every time.
				if err := fn(); err != nil {
					wg.Done()
					return
				}
				record(name, nil)
				wg.Done()
				return
			}
			defer wg.Done()
			record(name, runSubject(name, fn))
		}(s.name, s.fn)
	}
	wg.Wait()

	// One finding so the assertion also pins 3 outranking 1.
	result.Findings = append(result.Findings, finding.Finding{
		RuleID:      "TEST-001",
		SubjectKind: "package",
		Subject:     "pkg-c",
		Severity:    finding.SevCritical,
		Summary:     "fixture finding",
		Limits:      "fixture only",
	})

	for _, l := range lines {
		fmt.Println(l)
	}
	for _, g := range result.Gaps {
		fmt.Printf("gap=%s reason=%s\n", g.Subject, g.Reason)
	}
	fmt.Printf("findings=%d\n", len(result.Findings))
	return report.ExitCode(result, finding.SevSuspicious)
}

// runSubject adapts the shipped containment boundary (internal/safe, P1-B task
// 8) to a finding.Gap. It used to carry its own recover, recorded at the time as
// debt to be re-pointed once safe.Run existed: two implementations of a
// containment boundary drift, and the drifted one is the one that fails to
// contain something. The assertions above are unchanged -- what they test is the
// process model, and they now test it against the code that ships.
func runSubject(subject string, fn func() error) *finding.Gap {
	err, _ := safe.Run(subject, fn)
	if err == nil {
		return nil
	}
	return &finding.Gap{RuleID: "INV-9", Subject: subject, Reason: err.Error()}
}
