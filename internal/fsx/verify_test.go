// internal/fsx/verify_test.go
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

// rewrite replaces the fixture copy's contents through a second descriptor,
// which is what an attacker racing the scan does: our fd keeps pointing at the
// same inode, so nothing about the mutation is visible except in the stat.
func rewrite(t *testing.T, tmp, rel string, content string) {
	t.Helper()
	if err := os.WriteFile(filepath.Join(tmp, "root", rel), []byte(content), 0o644); err != nil {
		t.Fatalf("rewrite %s: %v", rel, err)
	}
}

func TestDigestMatchesSHA256Sum(t *testing.T) {
	root, _ := hostileRoot(t)
	f, st, err := OpenConfined(root, "usr/bin/hello")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	sum, n, err := Digest(f, st)
	if err != nil {
		t.Fatalf("Digest: %v", err)
	}
	if sum != payloadSHA256 {
		t.Errorf("sum = %q, want %q (sha256sum(1) of testdata/fsx/payload.txt)", sum, payloadSHA256)
	}
	if n != 98 {
		t.Errorf("n = %d, want 98", n)
	}
}

func TestDigestOnUnmutatedFileReportsNothing(t *testing.T) {
	root, _ := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()
	if _, _, err := Digest(f, st); err != nil {
		t.Fatalf("Digest on an untouched file: %v", err)
	}
}

func TestDigestIgnoresItsOwnAccessTimeUpdate(t *testing.T) {
	root, tmp := hostileRoot(t)
	// Reading a file updates st_atime, so a mutation check that compared
	// atime would flag every single file it hashed. The recorded fields are
	// ino/dev/size/mtime precisely so that the scan's own read is invisible.
	// Backdate atime before the open so that the hash below moves it forward
	// even under relatime.
	past := time.Now().Add(-2 * time.Hour)
	if err := os.Chtimes(filepath.Join(tmp, "root", "payload.txt"), past, past); err != nil {
		t.Fatalf("chtimes: %v", err)
	}
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()
	if _, _, err := Digest(f, st); err != nil {
		t.Fatalf("Digest reported %v after nothing but its own read", err)
	}
}

func TestDigestDetectsMutationBetweenHashAndRefstat(t *testing.T) {
	root, tmp := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	// The window the spec names: the bytes are already hashed, the answer
	// looks trustworthy, and the file changes before we say so.
	afterHashForTest = func() { rewrite(t, tmp, "payload.txt", "swapped after the hash\n") }
	t.Cleanup(func() { afterHashForTest = nil })

	sum, _, err := Digest(f, st)
	if !errors.Is(err, ErrMutatedDuringScan) {
		t.Fatalf("err = %v, want ErrMutatedDuringScan", err)
	}
	if !strings.Contains(err.Error(), "mutated during scan") {
		t.Errorf("err = %q, want it to say %q", err, "mutated during scan")
	}
	// The digest we computed is of bytes that no longer describe the file, so
	// it must not be handed back as if it did.
	if sum != "" {
		t.Errorf("sum = %q, want empty: a digest of superseded bytes is not evidence", sum)
	}
}

func TestDigestDetectsTruncationDuringScan(t *testing.T) {
	root, tmp := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	// Mutated after the open, before the read: same inode, shorter.
	rewrite(t, tmp, "payload.txt", "short\n")

	if _, _, err := Digest(f, st); !errors.Is(err, ErrMutatedDuringScan) {
		t.Fatalf("err = %v, want ErrMutatedDuringScan", err)
	}
}

func TestDigestDetectsSameSizeRewrite(t *testing.T) {
	root, tmp := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	// Same length, different bytes -- size alone cannot see this, so mtime
	// has to. The write is a fresh WriteFile, so mtime moves.
	same := strings.Repeat("A", 97) + "\n"
	if len(same) != 98 {
		t.Fatalf("fixture arithmetic wrong: %d", len(same))
	}
	rewrite(t, tmp, "payload.txt", same)

	if _, _, err := Digest(f, st); !errors.Is(err, ErrMutatedDuringScan) {
		t.Fatalf("err = %v, want ErrMutatedDuringScan", err)
	}
}

func TestDigestMutationIsDistinctFromEveryOtherOutcome(t *testing.T) {
	root, tmp := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()
	rewrite(t, tmp, "payload.txt", "swapped\n")

	_, _, err = Digest(f, st)
	// A file rewritten mid-scan is a finding about the scan. Reporting it as a
	// digest mismatch would blame the package for the racer's edit, and
	// reporting nothing would report clean for what was not examined (INV-3).
	if errors.Is(err, ErrNotRegular) || errors.Is(err, ErrSymlink) || errors.Is(err, ErrUnsafePath) {
		t.Errorf("err = %v: a mid-scan mutation must not surface as an open refusal", err)
	}
	if !errors.Is(err, ErrMutatedDuringScan) {
		t.Fatalf("err = %v, want ErrMutatedDuringScan", err)
	}
}

func TestCheckUnchangedComparesEveryRecordedField(t *testing.T) {
	base := unix.Stat_t{Ino: 42, Dev: 7, Size: 1024}
	base.Mtim = unix.Timespec{Sec: 1700000000, Nsec: 123456789}

	// Each perturbation must be detected on its own, so that deleting any one
	// comparison fails a test rather than passing quietly on the others.
	for name, mutate := range map[string]func(*unix.Stat_t){
		"ino":        func(s *unix.Stat_t) { s.Ino++ },
		"dev":        func(s *unix.Stat_t) { s.Dev++ },
		"size":       func(s *unix.Stat_t) { s.Size-- },
		"mtime-sec":  func(s *unix.Stat_t) { s.Mtim.Sec++ },
		"mtime-nsec": func(s *unix.Stat_t) { s.Mtim.Nsec++ },
	} {
		after := base
		mutate(&after)
		if Unchanged(base, after) {
			t.Errorf("%s change reported as unchanged", name)
		}
	}

	if !Unchanged(base, base) {
		t.Error("identical stats reported as changed")
	}

	// Fields outside the recorded set must not trip it: atime moves on every
	// read, and ctime moves on a metadata-only touch that says nothing about
	// the bytes we hashed.
	noise := base
	noise.Atim = unix.Timespec{Sec: 1800000000}
	noise.Ctim = unix.Timespec{Sec: 1800000000}
	noise.Nlink = base.Nlink + 1
	if !Unchanged(base, noise) {
		t.Error("a change outside ino/dev/size/mtime was reported as a mutation")
	}
}

func TestCheckUnchangedReadsTheSameFd(t *testing.T) {
	root, tmp := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	defer f.Close()

	if err := CheckUnchanged(f, st); err != nil {
		t.Fatalf("CheckUnchanged on an untouched file: %v", err)
	}
	rewrite(t, tmp, "payload.txt", "different length entirely\n")
	if err := CheckUnchanged(f, st); !errors.Is(err, ErrMutatedDuringScan) {
		t.Fatalf("err = %v, want ErrMutatedDuringScan", err)
	}
}

func TestCheckUnchangedOnClosedFdIsAnErrorNotAPass(t *testing.T) {
	root, _ := hostileRoot(t)
	f, st, err := OpenConfined(root, "payload.txt")
	if err != nil {
		t.Fatalf("OpenConfined: %v", err)
	}
	if err := f.Close(); err != nil {
		t.Fatalf("close: %v", err)
	}
	// If the re-fstat cannot be performed, we do not know whether the file
	// moved; INV-3 forbids calling that clean.
	if err := CheckUnchanged(f, st); err == nil {
		t.Fatal("CheckUnchanged returned nil when it could not fstat the fd")
	}
}
