// internal/fsx/open_test.go
package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"syscall"
	"testing"
	"time"

	"golang.org/x/sys/unix"
)

// payloadSHA256 is the digest of testdata/fsx/payload.txt as reported by
// sha256sum(1) -- computed outside Go on purpose, so a bug in this package
// cannot define its own expected answer.
const payloadSHA256 = "d643ba1aa2a043fda719d78864aeab57d993e53ddd71e679c86995546b5c36f8"

const payloadPath = "../../testdata/fsx/payload.txt"

// hostileRoot materializes the fixture tree described in testdata/fsx/README.md
// and returns a root confined to its `root` subdirectory. The tree deliberately
// contains objects git cannot carry, which is why it is built here rather than
// checked in.
//
// Layout:
//
//	<tmp>/outside/secret.txt   a file the scan must never reach
//	<tmp>/root/payload.txt     a copy of the checked-in fixture
//	<tmp>/root/usr/bin/hello   the same content one level down
//	<tmp>/root/inlink       -> payload.txt          (in-root symlink)
//	<tmp>/root/outlink      -> ../outside/secret.txt
//	<tmp>/root/escdir       -> ../outside           (escaping dir component)
//	<tmp>/root/fifo                                 (would hang a blocking open)
//	<tmp>/root/adir/                                (directory)
func hostileRoot(t *testing.T) (*os.Root, string) {
	t.Helper()
	tmp := t.TempDir()
	mkdir := func(p string) {
		if err := os.MkdirAll(filepath.Join(tmp, p), 0o755); err != nil {
			t.Fatalf("mkdir %s: %v", p, err)
		}
	}
	mkdir("outside")
	mkdir("root/usr/bin")
	mkdir("root/adir")

	payload, err := os.ReadFile(payloadPath)
	if err != nil {
		t.Fatalf("read fixture payload: %v", err)
	}
	write := func(p string, b []byte) {
		if err := os.WriteFile(filepath.Join(tmp, p), b, 0o644); err != nil {
			t.Fatalf("write %s: %v", p, err)
		}
	}
	write("outside/secret.txt", []byte("SECRET-OUTSIDE-THE-ROOT\n"))
	write("root/payload.txt", payload)
	write("root/usr/bin/hello", payload)

	link := func(target, p string) {
		if err := os.Symlink(target, filepath.Join(tmp, p)); err != nil {
			t.Fatalf("symlink %s: %v", p, err)
		}
	}
	link("payload.txt", "root/inlink")
	link("../outside/secret.txt", "root/outlink")
	link("../outside", "root/escdir")

	if err := syscall.Mkfifo(filepath.Join(tmp, "root/fifo"), 0o644); err != nil {
		t.Fatalf("mkfifo: %v", err)
	}

	root, err := os.OpenRoot(filepath.Join(tmp, "root"))
	if err != nil {
		t.Fatalf("OpenRoot: %v", err)
	}
	t.Cleanup(func() { root.Close() })
	return root, tmp
}

func TestOpenConfinedReadsRegularFileFromTheReturnedFd(t *testing.T) {
	root, _ := hostileRoot(t)
	f, st, err := OpenConfined(root, "usr/bin/hello")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	if got := st.Mode & unix.S_IFMT; got != unix.S_IFREG {
		t.Errorf("st.Mode type bits = %#o, want S_IFREG", got)
	}
	if st.Size != 98 {
		t.Errorf("st.Size = %d, want 98", st.Size)
	}
	// The stat must describe the very fd we hand back, not a second
	// resolution of the path.
	var again unix.Stat_t
	if err := unix.Fstat(int(f.Fd()), &again); err != nil {
		t.Fatalf("fstat returned fd: %v", err)
	}
	if again.Ino != st.Ino || again.Dev != st.Dev {
		t.Errorf("returned stat (dev=%d ino=%d) does not describe the returned fd (dev=%d ino=%d)",
			st.Dev, st.Ino, again.Dev, again.Ino)
	}
}

func TestOpenConfinedAcceptsMtreeDotSlashPrefix(t *testing.T) {
	root, _ := hostileRoot(t)
	// mtree records every path as ./usr/bin/hello; the collector should not
	// have to strip that before it can open anything.
	f, st, err := OpenConfined(root, "./usr/bin/hello")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()
	if st.Size != 98 {
		t.Errorf("st.Size = %d, want 98", st.Size)
	}
}

func TestOpenConfinedRefusesSymlinkEscapingRoot(t *testing.T) {
	root, _ := hostileRoot(t)
	f, _, err := OpenConfined(root, "outlink")
	if err == nil {
		f.Close()
		t.Fatal("OpenConfined followed a symlink pointing outside the root")
	}
	if f != nil {
		t.Fatal("OpenConfined returned a non-nil file alongside an error")
	}
	// The refusal must come from O_NOFOLLOW on the leaf, i.e. before the
	// target is resolved at all -- "not followed", not "followed and then
	// found to escape".
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", err)
	}
}

func TestOpenConfinedRefusesSymlinkInsideRoot(t *testing.T) {
	root, _ := hostileRoot(t)
	// os.Root on its own WOULD follow this one: it is in-root, it resolves to
	// a regular file, and Root.OpenFile retries through symlinks even when the
	// caller passed O_NOFOLLOW. mtree recorded this path as type=file, so a
	// symlink standing in its place is a swap and must be refused, not hashed
	// via its target.
	f, _, err := OpenConfined(root, "inlink")
	if err == nil {
		f.Close()
		t.Fatal("OpenConfined followed an in-root symlink")
	}
	if !errors.Is(err, ErrSymlink) {
		t.Errorf("err = %v, want ErrSymlink", err)
	}
}

func TestOpenConfinedRefusesEscapingDirectoryComponent(t *testing.T) {
	root, _ := hostileRoot(t)
	f, _, err := OpenConfined(root, "escdir/secret.txt")
	if err == nil {
		f.Close()
		t.Fatal("OpenConfined traversed a directory component symlinked out of the root")
	}
	if f != nil {
		t.Fatal("OpenConfined returned a non-nil file alongside an error")
	}
	if errors.Is(err, ErrNotRegular) {
		t.Errorf("err = %v: the escape must be refused during resolution, not by the S_ISREG check", err)
	}
}

func TestOpenConfinedRefusesFifoWithoutHanging(t *testing.T) {
	root, _ := hostileRoot(t)
	type result struct {
		f   *os.File
		err error
	}
	done := make(chan result, 1)
	go func() {
		f, _, err := OpenConfined(root, "fifo")
		done <- result{f, err}
	}()
	select {
	case r := <-done:
		if r.err == nil {
			r.f.Close()
			t.Fatal("OpenConfined accepted a fifo where a regular file was recorded")
		}
		if !errors.Is(r.err, ErrNotRegular) {
			t.Errorf("err = %v, want ErrNotRegular", r.err)
		}
	case <-time.After(5 * time.Second):
		// Without O_NONBLOCK an RDONLY open of a fifo with no writer blocks
		// forever: a hostile filesystem becomes a denial of tool.
		t.Fatal("OpenConfined hung on a fifo")
	}
}

func TestOpenConfinedRefusesDirectory(t *testing.T) {
	root, _ := hostileRoot(t)
	f, _, err := OpenConfined(root, "adir")
	if err == nil {
		f.Close()
		t.Fatal("OpenConfined accepted a directory")
	}
	if !errors.Is(err, ErrNotRegular) {
		t.Errorf("err = %v, want ErrNotRegular", err)
	}
}

func TestOpenConfinedRefusesUnsafeRelativePaths(t *testing.T) {
	root, _ := hostileRoot(t)
	// Measured on the reference system: zero packaged paths are absolute,
	// contain a .. component, or fail to be ./-rooted. Any such path is
	// therefore hostile by construction and is refused before a syscall is
	// issued -- os.Root would also refuse most of these, but "some other
	// layer probably catches it" is not a guarantee.
	for _, rel := range []string{
		"",
		"/etc/passwd",
		"../outside/secret.txt",
		"./../outside/secret.txt",
		"usr/../../outside/secret.txt",
		"usr/bin/..",
		"usr\x00bin/hello",
	} {
		f, _, err := OpenConfined(root, rel)
		if err == nil {
			f.Close()
			t.Errorf("OpenConfined(%q) = nil error, want refusal", rel)
			continue
		}
		if !errors.Is(err, ErrUnsafePath) {
			t.Errorf("OpenConfined(%q) err = %v, want ErrUnsafePath", rel, err)
		}
	}
}

func TestOpenConfinedMissingFileIsNotExist(t *testing.T) {
	root, _ := hostileRoot(t)
	// A packaged path that is simply gone is an ordinary finding for a caller
	// to classify, so it must stay distinguishable from a refusal.
	_, _, err := OpenConfined(root, "usr/bin/absent")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Fatalf("err = %v, want fs.ErrNotExist", err)
	}
	if errors.Is(err, ErrSymlink) || errors.Is(err, ErrNotRegular) || errors.Is(err, ErrUnsafePath) {
		t.Errorf("err = %v: a missing file must not be reported as a refusal", err)
	}
}

func TestOpenConfinedErrorNamesThePath(t *testing.T) {
	root, _ := hostileRoot(t)
	_, _, err := OpenConfined(root, "adir")
	var pe *fs.PathError
	if !errors.As(err, &pe) {
		t.Fatalf("err = %v (%T), want *fs.PathError", err, err)
	}
	if pe.Path != "adir" {
		t.Errorf("PathError.Path = %q, want %q", pe.Path, "adir")
	}
}
