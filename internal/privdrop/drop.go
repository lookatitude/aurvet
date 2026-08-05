// internal/privdrop/drop.go
//
// Package privdrop stages the process's privilege so that the phase which needs
// root (walking the filesystem, opening files, streaming digests) and the phase
// which parses attacker-controlled bytes are separated in time rather than
// accepted together. spec.html §11.1 is the authority.
//
// The two calls are used in this order and nowhere else:
//
//	privdrop.ReduceToRead()   // startup, before anything is read
//	... phase 1: collect. Syscalls and sha256. NO PARSERS. ...
//	privdrop.DropAll()        // transition, irreversible
//	... phase 2: analyse. Decompress, parse, correlate, report. ...
//
// Nothing in this package parses (INV-2). It moves bits in the kernel's
// credential structures and re-execs; that is the whole surface.
package privdrop

import (
	"errors"
	"fmt"
	"os"
	"runtime"
	"strings"
	"syscall"
	"unsafe"

	"golang.org/x/sys/unix"
)

// reexecMarkerEnv records that this image is the re-execed one. It exists to
// bound the re-exec at exactly one: if the loader environment is hostile AGAIN
// in a process that has already been re-execed, something is actively
// re-injecting it and the correct answer is to refuse, not to loop.
const reexecMarkerEnv = "AURVET_PRIVDROP_SANITISED"

// keepMask is the entire capability set phase 1 needs: read any file, traverse
// any directory. Not CAP_DAC_OVERRIDE (which also grants write), and nothing
// else. spec.html §11.1.
const keepMask = uint64(1) << uint(unix.CAP_DAC_READ_SEARCH)

// Securebits from linux/securebits.h, which x/sys/unix does not export:
// issecure_mask(bit) is 1<<bit, SECURE_NOROOT is 0 and SECURE_NOROOT_LOCKED is 1.
//
// These exist because execve is a route back to privilege that no capset can
// close. For a process whose euid is still 0, the kernel's compatibility path
// (handle_privileged_root in security/commoncap.c) hands a fresh image
// permitted = bounding | inheritable, and that path is gated on SECBIT_NOROOT
// rather than on no_new_privs.
//
// Measured rather than assumed, in a user namespace holding a full capability
// set (TestPrivilegeLifecycleWithRealCapabilities): with neither this securebit
// nor PR_SET_NO_NEW_PRIVS, an execve after a COMPLETE DropAll restored all 41
// capabilities and the previously-refused read succeeded. Each guard closes it
// alone -- no_new_privs via the LSM_UNSAFE_NO_NEW_PRIVS downgrade in
// cap_bprm_creds_from_file, this securebit plus an emptied bounding set via
// handle_privileged_root. Both are applied anyway, because securebits and the
// bounding set need CAP_SETPCAP and so are unavailable on the degraded
// unprivileged path, where no_new_privs is all there is.
const (
	secbitNoRoot       = 1 << 0
	secbitNoRootLocked = 1 << 1
)

// allThreadsSyscall is syscall.AllThreadsSyscall6, indirected for one reason:
// the ENOTSUP path below cannot otherwise be tested, since it depends on how the
// binary under test was LINKED.
//
// Why not unix.Capset and unix.Prctl, which would be the obvious choices --
// capabilities and no_new_privs are per-THREAD on Linux, and the Go runtime has
// many threads that any goroutine may be scheduled onto. A capset that lands on
// the calling thread only leaves privileged threads behind, so the drop would be
// decorative in precisely the way spec.html §11.1 forbids. AllThreadsSyscall6 is
// the runtime's supported mechanism for a process-wide per-thread state change.
// D-3's dependency on x/sys/unix still earns its keep: every struct and constant
// crossing the kernel boundary here comes from it, and only the invocation does
// not.
var allThreadsSyscall = func(trap, a1, a2, a3, a4, a5, a6 uintptr) (uintptr, uintptr, unix.Errno) {
	r1, r2, errno := syscall.AllThreadsSyscall6(trap, a1, a2, a3, a4, a5, a6)
	return r1, r2, unix.Errno(errno)
}

// ReduceToRead sanitises the loader environment (re-execing if it was hostile),
// reduces the capability set to CAP_DAC_READ_SEARCH alone, and sets
// PR_SET_NO_NEW_PRIVS. On return the process can read everything and can gain
// nothing.
//
// It is safe and meaningful unprivileged: with an empty permitted set every
// reduction is a no-op that cannot fail, and no_new_privs still applies.
func ReduceToRead() error {
	if err := sanitiseAndReexec(); err != nil {
		return err
	}
	if err := lockdown(); err != nil {
		return err
	}

	cur, err := capsOfCallingThread()
	if err != nil {
		return err
	}
	keep := cur.permitted & keepMask
	if err := setCaps(keep, keep, 0); err != nil {
		return fmt.Errorf("privdrop: reducing to CAP_DAC_READ_SEARCH: %w", err)
	}
	if err := verifyCaps(keep, keep, 0); err != nil {
		return err
	}
	return setNoNewPrivs()
}

// DropAll destroys every capability irrevocably: the permitted set is cleared,
// not merely the effective set, because anything left in permitted can be raised
// back into effective at will. After this call, regaining privilege is not
// merely unattempted -- there is nothing left to raise, nothing inheritable to
// carry across an execve, no ambient set, and no_new_privs is set so a later
// execve cannot acquire any.
//
// It refuses rather than half-succeeds. A partial drop is worse than none,
// because the caller would proceed into the parsers believing it had happened.
func DropAll() error {
	// Ambient first: it is the one set that survives execve, and clearing it
	// requires no capability, so it is also the step most likely to succeed.
	if err := clearAmbient(); err != nil {
		return err
	}
	// Before capset takes CAP_SETPCAP away. Idempotent after ReduceToRead;
	// meaningful when DropAll is called without it.
	if err := lockdown(); err != nil {
		return err
	}
	if err := setNoNewPrivs(); err != nil {
		return err
	}
	if err := setCaps(0, 0, 0); err != nil {
		return fmt.Errorf("privdrop: clearing all capability sets: %w", err)
	}
	return verifyCaps(0, 0, 0)
}

// sanitiseAndReexec removes LD_* and GLIBC_TUNABLES and, if any were present,
// replaces this process image with a fresh one via execve.
//
// Removing them without the re-exec would be theatre. By the time main runs, a
// hostile LD_PRELOAD or LD_AUDIT has ALREADY been honoured by the loader and the
// attacker's code is inside this image -- at the moment the tool holds the most
// privilege it will ever hold. Unsetting the variable only protects children.
// Only a fresh image, loaded from a clean environment, is trustworthy. aurvet
// ships statically linked (spec.html §16) precisely so this window is normally
// closed, but a dynamically linked build must not be silently unsafe.
func sanitiseAndReexec() error {
	clean, removed := sanitiseEnv(os.Environ())
	if len(removed) == 0 {
		// Nothing was set, so the running image was loaded from a clean
		// environment. Re-execing would prove nothing and cost a syscall.
		return nil
	}
	if os.Getenv(reexecMarkerEnv) != "" {
		return fmt.Errorf("privdrop: loader environment hostile again after re-exec (%s): refusing to continue in an untrusted image",
			strings.Join(removed, ", "))
	}
	// /proc/self/exe, not os.Args[0]: argv is caller-controlled and need not
	// name this binary at all.
	if err := unix.Exec("/proc/self/exe", os.Args, append(clean, reexecMarkerEnv+"=1")); err != nil {
		return fmt.Errorf("privdrop: re-exec after sanitising %s: %w", strings.Join(removed, ", "), err)
	}
	// Unreachable: a successful execve does not return.
	return errors.New("privdrop: execve returned without an error")
}

// sanitiseEnv splits env into the entries that survive and the NAMES of the
// loader variables removed. The removed names are reported so a refusal or a
// re-exec can say what it reacted to.
//
// The match is ld.so's own: the LD_ prefix, plus GLIBC_TUNABLES exactly. It is
// deliberately case-sensitive, because the loader is.
func sanitiseEnv(env []string) (clean, removed []string) {
	clean = make([]string, 0, len(env))
	for _, kv := range env {
		name, _, _ := strings.Cut(kv, "=")
		if strings.HasPrefix(name, "LD_") || name == "GLIBC_TUNABLES" {
			removed = append(removed, name)
			continue
		}
		clean = append(clean, kv)
	}
	return clean, removed
}

// lockdown closes the two exec-time routes back to privilege, both of which need
// CAP_SETPCAP and are therefore done while it is still held. Unprivileged there
// is nothing to lock down and nothing is attempted, which is why the whole
// package works without root.
func lockdown() error {
	cur, err := capsOfCallingThread()
	if err != nil {
		return err
	}
	if cur.effective&(uint64(1)<<uint(unix.CAP_SETPCAP)) == 0 {
		return nil
	}

	bits, err := unix.PrctlRetInt(unix.PR_GET_SECUREBITS, 0, 0, 0, 0)
	if err != nil {
		return fmt.Errorf("privdrop: reading securebits: %w", err)
	}
	if err := prctlAllThreads(unix.PR_SET_SECUREBITS, uintptr(bits)|secbitNoRoot|secbitNoRootLocked, 0); err != nil {
		return fmt.Errorf("privdrop: setting SECBIT_NOROOT: %w", err)
	}

	// The bounding set gates execve and any future addition to the inheritable
	// or ambient sets. Phase 1 does neither, so emptying it entirely -- including
	// the capability being kept in the permitted set -- costs nothing and removes
	// the last thing an execve could be handed.
	for c := 0; c <= unix.CAP_LAST_CAP; c++ {
		err := prctlAllThreads(unix.PR_CAPBSET_DROP, uintptr(c), 0)
		// EINVAL means this kernel does not know that capability number.
		if err != nil && !errors.Is(err, unix.EINVAL) {
			return fmt.Errorf("privdrop: dropping capability %d from the bounding set: %w", c, err)
		}
	}
	return nil
}

func setNoNewPrivs() error {
	if err := prctlAllThreads(unix.PR_SET_NO_NEW_PRIVS, 1, 0); err != nil {
		return fmt.Errorf("privdrop: setting PR_SET_NO_NEW_PRIVS: %w", err)
	}
	return nil
}

func clearAmbient() error {
	if err := prctlAllThreads(unix.PR_CAP_AMBIENT, unix.PR_CAP_AMBIENT_CLEAR_ALL, 0); err != nil {
		return fmt.Errorf("privdrop: clearing the ambient capability set: %w", err)
	}
	return nil
}

// capSets is a 64-bit view of the three per-thread capability sets, assembled
// from the two 32-bit halves the kernel's version-3 layout uses.
type capSets struct {
	effective   uint64
	permitted   uint64
	inheritable uint64
}

func capsOfCallingThread() (capSets, error) {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	var data [2]unix.CapUserData
	if err := unix.Capget(&hdr, &data[0]); err != nil {
		return capSets{}, fmt.Errorf("privdrop: capget: %w", err)
	}
	return capSets{
		effective:   uint64(data[1].Effective)<<32 | uint64(data[0].Effective),
		permitted:   uint64(data[1].Permitted)<<32 | uint64(data[0].Permitted),
		inheritable: uint64(data[1].Inheritable)<<32 | uint64(data[0].Inheritable),
	}, nil
}

// setCaps writes the three sets on EVERY thread of the process. See
// allThreadsSyscall for why a per-thread capset would not do.
func setCaps(effective, permitted, inheritable uint64) error {
	hdr := unix.CapUserHeader{Version: unix.LINUX_CAPABILITY_VERSION_3, Pid: 0}
	data := [2]unix.CapUserData{
		{
			Effective:   uint32(effective),
			Permitted:   uint32(permitted),
			Inheritable: uint32(inheritable),
		},
		{
			Effective:   uint32(effective >> 32),
			Permitted:   uint32(permitted >> 32),
			Inheritable: uint32(inheritable >> 32),
		},
	}
	// The kernel writes through these two pointers while they are travelling as
	// uintptr, and Go's stacks move. runtime.Pinner both forces the objects onto
	// the heap (its argument escapes) and pins them there for the duration, so
	// the addresses the syscall receives stay valid. syscall.AllThreadsSyscall6
	// carries //go:uintptrescapes, but that only pins conversions written in ITS
	// own argument list -- and this call reaches it through a seam.
	var pin runtime.Pinner
	pin.Pin(&hdr)
	pin.Pin(&data[0])
	defer pin.Unpin()

	_, _, errno := allThreadsSyscall(unix.SYS_CAPSET,
		uintptr(unsafe.Pointer(&hdr)), uintptr(unsafe.Pointer(&data[0])), 0, 0, 0, 0)
	if errno != 0 {
		return threadWideError(errno)
	}
	return nil
}

// verifyCaps re-reads the credentials and refuses if they are not what was just
// written. A drop that silently did not take effect is the failure mode that
// makes every downstream assumption false.
//
// What it does NOT check, stated because the limit matters: capget reports the
// CALLING thread, so this confirms one thread of many. The guarantee for the
// others comes from syscall.AllThreadsSyscall, which terminates the program if
// any thread's return value differs from the first thread's -- so a divergent
// thread cannot get past the write and arrive here as a silent pass.
func verifyCaps(effective, permitted, inheritable uint64) error {
	got, err := capsOfCallingThread()
	if err != nil {
		return err
	}
	want := capSets{effective: effective, permitted: permitted, inheritable: inheritable}
	if got != want {
		return fmt.Errorf("privdrop: capability sets after the write are %+v, want %+v", got, want)
	}
	return nil
}

// prctlAllThreads issues prctl on every thread. arg4 and arg5 are always zero,
// which is not cosmetic: the kernel rejects PR_SET_NO_NEW_PRIVS and
// PR_CAP_AMBIENT outright with EINVAL if the unused arguments are non-zero, so
// the six-argument form is required to pass them explicitly rather than leave
// whatever the registers held.
func prctlAllThreads(option int, arg2, arg3 uintptr) error {
	_, _, errno := allThreadsSyscall(unix.SYS_PRCTL, uintptr(option), arg2, arg3, 0, 0, 0)
	if errno != 0 {
		return threadWideError(errno)
	}
	return nil
}

// threadWideError names the single cause of ENOTSUP, because the message is the
// only thing that will make the failure actionable: syscall.AllThreadsSyscall is
// unavailable in a cgo-linked binary, since the runtime cannot see threads cgo
// created. aurvet is built CGO_ENABLED=0 (spec.html §16, and the static-link
// assertion in P3), so this is a build regression rather than a runtime
// condition -- and the only safe response is to refuse the drop.
func threadWideError(errno unix.Errno) error {
	if errno == unix.ENOTSUP {
		return fmt.Errorf("cannot apply to every thread: %w -- capabilities are per-thread and syscall.AllThreadsSyscall is unavailable in a cgo-linked binary; rebuild with CGO_ENABLED=0", errno)
	}
	return errno
}
