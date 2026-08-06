package fsx

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// The attack, first: a second holder must not be allowed in, and must not hang
// waiting either. Both halves matter -- an unbounded wait is how a lock turns
// into a denial of service against the tool that took it.
func TestASecondHolderIsRefusedAndBounded(t *testing.T) {
	path := filepath.Join(t.TempDir(), "sub", ".lock")

	release, err := Lock(path, time.Second)
	if err != nil {
		t.Fatalf("first Lock: %v", err)
	}
	defer release()

	start := time.Now()
	second, err := Lock(path, 100*time.Millisecond)
	if err == nil {
		second()
		t.Fatal("a second holder acquired a lock that was already held")
	}
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatalf("the wait was not bounded: %v", time.Since(start))
	}
	if got := err.Error(); !strings.Contains(got, path) {
		t.Errorf("the refusal does not name the lock file: %q", got)
	}
}

// Released means released. A lock that stayed held after its release closure
// would deadlock the next run of the same command, and the operator's only
// remedy would be a reboot.
func TestReleaseLetsTheNextHolderIn(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".lock")
	release, err := Lock(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	if err := release(); err != nil {
		t.Fatalf("release: %v", err)
	}
	again, err := Lock(path, 200*time.Millisecond)
	if err != nil {
		t.Fatalf("second Lock after release: %v", err)
	}
	if err := again(); err != nil {
		t.Fatal(err)
	}
}

// A real error is not contention. Retrying an undirectory for the whole timeout
// and then reporting ErrBusy would tell the operator that another process is
// writing when in fact the path is unusable.
func TestARealFailureIsNotReportedAsContention(t *testing.T) {
	dir := t.TempDir()
	file := filepath.Join(dir, "not-a-dir")
	if err := os.WriteFile(file, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	_, err := Lock(filepath.Join(file, ".lock"), time.Second)
	if err == nil {
		t.Fatal("locking under a regular file succeeded")
	}
	if errors.Is(err, ErrBusy) {
		t.Fatalf("a path failure was reported as contention: %v", err)
	}
	if !errors.Is(err, unix.ENOTDIR) && !errors.Is(err, os.ErrInvalid) &&
		!errors.Is(err, os.ErrPermission) && !errors.Is(err, os.ErrExist) {
		t.Logf("error was %v (accepted: it is not ErrBusy, which is the property)", err)
	}
}

// Permissions: the lock file must not be one any local user can hold. 0600 on
// the file, 0700 on a directory this call created.
func TestLockFilePermissionsDoNotHandOutADenialOfService(t *testing.T) {
	base := t.TempDir()
	path := filepath.Join(base, "state", ".lock")
	release, err := Lock(path, time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	fi, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm()&0o077 != 0 {
		t.Errorf("lock file mode %04o: any local user can open and hold it", fi.Mode().Perm())
	}
	di, err := os.Stat(filepath.Dir(path))
	if err != nil {
		t.Fatal(err)
	}
	if di.Mode().Perm()&0o077 != 0 {
		t.Errorf("created lock directory mode %04o, want 0700", di.Mode().Perm())
	}
}
