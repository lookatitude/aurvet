package fsx

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/unix"
)

// tree builds a fixture with the shapes a persistence surface actually meets: a
// regular file, a symlink, a subdirectory, and a file too large for the bound.
func tree(t *testing.T) string {
	t.Helper()
	d := t.TempDir()
	mk := func(rel, body string) {
		p := filepath.Join(d, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(body), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	mk("etc/conf.d/a.conf", "Key=value\n")
	mk("etc/conf.d/b.conf", "Other=thing\n")
	mk("usr/bin/prog", "#!/bin/sh\n")
	if err := os.MkdirAll(filepath.Join(d, "etc/conf.d/sub"), 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../../usr/bin/prog", filepath.Join(d, "etc/conf.d/link")); err != nil {
		t.Fatal(err)
	}
	return d
}

func liveOf(t *testing.T, dir string) Source {
	t.Helper()
	r, err := os.OpenRoot(dir)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = r.Close() })
	return Live(r)
}

// The property the whole type exists for: what phase 2 sees through a buffered
// Source must equal what phase 1 saw through a live one. If the two can disagree,
// moving the capability drop changes findings, and a privilege fix that changes
// findings is not a privilege fix.
func TestABufferedSourceAnswersIdenticallyToALiveOne(t *testing.T) {
	dir := tree(t)
	live := liveOf(t, dir)

	buf := NewBuffer()
	buf.CopyTree(live, "etc/conf.d")
	got := buf.Source()

	// Directory listings agree, including order.
	wantEnts, err := live.ReadDir("etc/conf.d")
	if err != nil {
		t.Fatal(err)
	}
	gotEnts, err := got.ReadDir("etc/conf.d")
	if err != nil {
		t.Fatal(err)
	}
	if len(wantEnts) != len(gotEnts) {
		t.Fatalf("listing length %d vs %d", len(wantEnts), len(gotEnts))
	}
	for i := range wantEnts {
		if wantEnts[i] != gotEnts[i] {
			t.Errorf("entry %d: live %+v, buffered %+v", i, wantEnts[i], gotEnts[i])
		}
	}

	// File contents and the stat taken with them agree.
	for _, rel := range []string{"etc/conf.d/a.conf", "etc/conf.d/b.conf"} {
		wb, wst, werr := live.ReadFile(rel)
		gb, gst, gerr := got.ReadFile(rel)
		if werr != nil || gerr != nil {
			t.Fatalf("%s: live err %v, buffered err %v", rel, werr, gerr)
		}
		if string(wb) != string(gb) {
			t.Errorf("%s: contents differ", rel)
		}
		if wst.Ino != gst.Ino || wst.Size != gst.Size || wst.Mode != gst.Mode {
			t.Errorf("%s: stat differs: live %+v vs buffered ino=%d size=%d mode=%d",
				rel, wst.Ino, gst.Ino, gst.Size, gst.Mode)
		}
	}

	// Symlink targets agree, and are the recorded text rather than a resolution.
	wl, werr := live.ReadLink("etc/conf.d/link")
	gl, gerr := got.ReadLink("etc/conf.d/link")
	if werr != nil || gerr != nil {
		t.Fatalf("readlink: live %v, buffered %v", werr, gerr)
	}
	if wl != gl || wl != "../../usr/bin/prog" {
		t.Errorf("link target: live %q, buffered %q", wl, gl)
	}
}

// A read that FAILED in phase 1 must fail the same way in phase 2. Dropping the
// error would convert "I could not look" into "not present", which is INV-9
// inverted -- and it would happen at exactly the moment the capability is given
// up, so the silence would look like a privilege improvement.
func TestARecordedFailureSurvivesIntoPhaseTwo(t *testing.T) {
	buf := NewBuffer()
	sentinel := errors.New("permission denied by fixture")
	buf.AddFile("etc/secret", nil, statZero(), sentinel)
	buf.AddDir("etc/locked", nil, sentinel)
	buf.AddLink("etc/badlink", "", sentinel)
	s := buf.Source()

	if _, _, err := s.ReadFile("etc/secret"); !errors.Is(err, sentinel) {
		t.Errorf("a recorded file error was not replayed: %v", err)
	}
	if _, err := s.ReadDir("etc/locked"); !errors.Is(err, sentinel) {
		t.Errorf("a recorded listing error was not replayed: %v", err)
	}
	if _, err := s.ReadLink("etc/badlink"); !errors.Is(err, sentinel) {
		t.Errorf("a recorded link error was not replayed: %v", err)
	}
}

// An unbuffered path is ErrNotExist, distinct from a recorded failure. A caller
// deciding between "absent, which is ordinary" and "unreadable, which is a gap"
// needs those to be different values.
func TestAnUnbufferedPathIsAbsentNotAFailure(t *testing.T) {
	s := NewBuffer().Source()
	_, _, err := s.ReadFile("etc/never-buffered")
	if !errors.Is(err, fs.ErrNotExist) {
		t.Errorf("an unbuffered path reported %v, want fs.ErrNotExist", err)
	}
}

// The zero Source refuses rather than reporting an empty tree. A nil-map read
// returning "not found" would make a programming error look like a clean system.
func TestTheZeroSourceRefuses(t *testing.T) {
	var s Source
	if !s.Zero() {
		t.Fatal("the zero Source does not report itself as zero")
	}
	if _, _, err := s.ReadFile("x"); !errors.Is(err, ErrNoSource) {
		t.Errorf("ReadFile on a zero Source = %v, want ErrNoSource", err)
	}
	if _, err := s.ReadDir("x"); !errors.Is(err, ErrNoSource) {
		t.Errorf("ReadDir on a zero Source = %v, want ErrNoSource", err)
	}
	if _, err := s.ReadLink("x"); !errors.Is(err, ErrNoSource) {
		t.Errorf("ReadLink on a zero Source = %v, want ErrNoSource", err)
	}
}

// A live Source must keep every refusal OpenConfined makes. These are the
// controls the surface readers were relying on before they took a Source, and
// routing through a new type must not quietly relax any of them.
func TestALiveSourceKeepsTheConfinedRefusals(t *testing.T) {
	dir := tree(t)
	live := liveOf(t, dir)

	// A symlink leaf is refused, not followed: reading through it would report
	// the target's contents under the link's path.
	if _, _, err := live.ReadFile("etc/conf.d/link"); err == nil {
		t.Error("ReadFile followed a symlink leaf")
	}
	// A directory is not a file.
	if _, _, err := live.ReadFile("etc/conf.d"); err == nil {
		t.Error("ReadFile accepted a directory")
	}
	// An escaping path is refused by os.Root before anything is opened.
	if _, _, err := live.ReadFile("../outside"); err == nil {
		t.Error("ReadFile accepted a path escaping the root")
	}
}

// The bound is a refusal, never a truncated read: a truncated parse can lose the
// last directive in a file, and a unit that lost its last ExecStart is
// indistinguishable from one that never had one.
func TestAnOversizeFileIsRefusedNotTruncated(t *testing.T) {
	dir := tree(t)
	big := filepath.Join(dir, "etc/huge.conf")
	if err := os.WriteFile(big, []byte(strings.Repeat("x", maxSourceFile+10)), 0o644); err != nil {
		t.Fatal(err)
	}
	live := liveOf(t, dir)
	b, _, err := live.ReadFile("etc/huge.conf")
	if err == nil {
		t.Fatalf("an oversize file was accepted, %d bytes returned", len(b))
	}
	if len(b) != 0 {
		t.Errorf("a refused read still returned %d bytes", len(b))
	}
}

// CopyTree records the listing error for a missing directory rather than
// skipping it, because absent and unreadable are different facts and only the
// caller knows which is ordinary for a given path.
func TestCopyTreeRecordsAMissingDirectoryAsAnError(t *testing.T) {
	dir := tree(t)
	live := liveOf(t, dir)
	buf := NewBuffer()
	buf.CopyTree(live, "etc/does-not-exist")
	if _, err := buf.Source().ReadDir("etc/does-not-exist"); err == nil {
		t.Error("a missing directory was buffered as an empty listing rather than an error")
	}
}

// CopyTree does not recurse. Every surface it serves is a flat directory, and a
// recursive buffer over an attacker-influenced tree is an unbounded read.
func TestCopyTreeDoesNotRecurse(t *testing.T) {
	dir := tree(t)
	if err := os.WriteFile(filepath.Join(dir, "etc/conf.d/sub/deep.conf"), []byte("x"), 0o644); err != nil {
		t.Fatal(err)
	}
	buf := NewBuffer()
	buf.CopyTree(liveOf(t, dir), "etc/conf.d")
	if _, _, err := buf.Source().ReadFile("etc/conf.d/sub/deep.conf"); err == nil {
		t.Error("CopyTree recursed into a subdirectory")
	}
}

// Has lets a caller enumerate overlapping directories without reading a path
// twice -- two reads of one attacker-writable file can disagree, and the loser
// of that disagreement is whatever the parser sees.
func TestHasPreventsASecondReadOfTheSamePath(t *testing.T) {
	dir := tree(t)
	buf := NewBuffer()
	buf.CopyTree(liveOf(t, dir), "etc/conf.d")
	if !buf.Has("etc/conf.d/a.conf") {
		t.Fatal("a buffered file does not report Has")
	}
	if buf.Has("etc/conf.d/never") {
		t.Error("an unbuffered file reports Has")
	}
}

// Listings are sorted by name in both backings. Directory order is a filesystem
// artefact, and findings that come out in a different order on two machines
// cannot be diffed.
func TestListingsAreSortedInBothBackings(t *testing.T) {
	dir := tree(t)
	live := liveOf(t, dir)
	buf := NewBuffer()
	buf.CopyTree(live, "etc/conf.d")

	for name, s := range map[string]Source{"live": live, "buffered": buf.Source()} {
		ents, err := s.ReadDir("etc/conf.d")
		if err != nil {
			t.Fatalf("%s: %v", name, err)
		}
		for i := 1; i < len(ents); i++ {
			if ents[i-1].Name > ents[i].Name {
				t.Errorf("%s listing is not sorted: %q before %q",
					name, ents[i-1].Name, ents[i].Name)
			}
		}
	}
}

// statZero is the zero stat, for recording a read that produced no descriptor.
func statZero() (z unix.Stat_t) { return z }
