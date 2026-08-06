package main

import (
	"bytes"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/bundle"
)

// ---------------------------------------------------------------------------
// `update --check`: report what an update WOULD do, write nothing.
//
// internal/bundle already separates deciding from persisting -- Verify performs
// no I/O and reads no clock -- so this is a decision about which of its two
// halves the CLI calls, and the test is a before/after digest of everything the
// writing half would have touched.
// ---------------------------------------------------------------------------

// treeDigest is a stable fingerprint of a directory tree: every path, its mode,
// its size and its content digest. It is what makes "wrote nothing" assertable
// rather than asserted -- an mtime-only comparison would miss a rewrite with
// identical bytes, and a mere existence check would miss a modification.
func treeDigest(t *testing.T, dir string) string {
	t.Helper()
	var lines []string
	err := filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			if os.IsNotExist(err) && p == dir {
				return nil // an absent directory is a state, and a stable one
			}
			return err
		}
		rel, rerr := filepath.Rel(dir, p)
		if rerr != nil {
			return rerr
		}
		info, ierr := d.Info()
		if ierr != nil {
			return ierr
		}
		if d.IsDir() {
			lines = append(lines, "d "+rel+" "+info.Mode().String())
			return nil
		}
		b, rerr := os.ReadFile(p)
		if rerr != nil {
			return rerr
		}
		sum := sha256.Sum256(b)
		lines = append(lines, "f "+rel+" "+info.Mode().String()+" "+hex.EncodeToString(sum[:]))
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	sort.Strings(lines)
	sum := sha256.Sum256([]byte(strings.Join(lines, "\n")))
	return hex.EncodeToString(sum[:])
}

// The deliverable, on the one path where there is something to refrain from
// doing: the accept path. A --check that never reached a verdict would pass this
// test vacuously, so the verdict is asserted too.
func TestUpdateCheckWritesNeitherCacheNorFloor(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)

	beforeState, beforeCache := treeDigest(t, state), treeDigest(t, cache)

	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.check = true
	var out, errb bytes.Buffer
	code := runUpdate(opts, &out, &errb)
	got := out.String()

	// The verdict is reached in full: this is a dry run, not a shorter run.
	for _, want := range []string{"indicator bundle: active", "version:     5", "indicators:  6 active"} {
		if !strings.Contains(got, want) {
			t.Errorf("--check did not reach the verdict (%q missing):\n%s", want, got)
		}
	}
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d (the software-root-key gap, same as a writing run)\n%s%s",
			code, exitIncomplete, got, errb.String())
	}
	// It says what it WOULD have done, in both places a writing run reports.
	if !strings.Contains(got, "would") {
		t.Errorf("--check does not state what an update would do:\n%s", got)
	}
	if !strings.Contains(got, "--check") {
		t.Errorf("--check does not stamp its own output, so it reads like a real update:\n%s", got)
	}

	if after := treeDigest(t, state); after != beforeState {
		t.Errorf("--check changed the state directory (the anti-rollback floor lives there):\n"+
			"before %s\nafter  %s", beforeState, after)
	}
	if after := treeDigest(t, cache); after != beforeCache {
		t.Errorf("--check wrote to the bundle cache:\nbefore %s\nafter  %s", beforeCache, after)
	}

	// Stated positively as well, because a digest match is also what a broken
	// fixture produces: the floor must be ABSENT afterwards.
	fstore, err := bundle.OpenFloor(state, bundle.FloorOptions{CacheDir: cache, EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if _, present, lerr := fstore.Load(); present || lerr != nil {
		t.Errorf("the floor exists after --check (present=%v err=%v); the next real update would "+
			"treat this run's bundle as the high-water mark it never recorded", present, lerr)
	}
	// Cache.Load reports an ABSENT file as an empty field rather than an error, so
	// the assertion is on the bytes: err == nil here means "nothing is cached".
	cached, cerr := bundle.OpenCache(cache).Load()
	if cerr != nil {
		t.Fatalf("the cache is unreadable: %v", cerr)
	}
	if len(cached.BundleRaw) != 0 || len(cached.DelegationRaw) != 0 || len(cached.DelegationSigs) != 0 {
		t.Errorf("the cache holds a bundle after --check: %d bundle byte(s), %d delegation byte(s), "+
			"%d signature(s)", len(cached.BundleRaw), len(cached.DelegationRaw), len(cached.DelegationSigs))
	}
}

// A writing run after a --check must still advance both, which is what proves the
// --check was a suppression rather than a failure.
func TestAWritingUpdateAfterACheckStillPersists(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)

	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.check = true
	runUpdate(opts, &bytes.Buffer{}, &bytes.Buffer{})

	var out, errb bytes.Buffer
	if code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb); code != exitIncomplete {
		t.Fatalf("exit = %d, want %d\n%s%s", code, exitIncomplete, out.String(), errb.String())
	}
	fstore, err := bundle.OpenFloor(state, bundle.FloorOptions{CacheDir: cache, EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	f, present, err := fstore.Load()
	if err != nil || !present {
		t.Fatalf("the floor did not advance on the writing run: present=%v err=%v", present, err)
	}
	if f.MinBundleVersion != 5 {
		t.Errorf("floor = %+v, want MinBundleVersion 5", f)
	}
}

// The JSON document says so too: a caller that automates `update --check` must be
// able to read that nothing was written.
func TestUpdateCheckJSONSaysNothingWasWritten(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)
	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.check = true
	opts.jsonOut = true

	var out bytes.Buffer
	runUpdate(opts, &out, &bytes.Buffer{})
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not JSON (%v):\n%s", err, out.String())
	}
	if doc["check_only"] != true {
		t.Errorf("check_only = %v, want true: %v", doc["check_only"], doc)
	}
	if doc["cached"] != false || doc["floor_advanced"] != false {
		t.Errorf("--check reported writes it did not make: cached=%v floor_advanced=%v",
			doc["cached"], doc["floor_advanced"])
	}
	if doc["would_cache"] != true || doc["would_advance_floor"] != true {
		t.Errorf("--check did not report what a real update would do: %v", doc)
	}
}

// The flag is wired to the command line, and `update --check` is the spelling
// spec §14 uses.
func TestUpdateCheckIsWiredToTheCommandLine(t *testing.T) {
	// The production path with no root keys: it refuses before the network, which
	// is enough to prove the flag parses and reaches runUpdate.
	code, stdout, stderr := scanOut(t, "update", "--check")
	if code != exitIncomplete {
		t.Fatalf("exit = %d, want %d\nstdout:\n%s\nstderr:\n%s", code, exitIncomplete, stdout, stderr)
	}
	if strings.Contains(stderr, "flag provided but not defined") {
		t.Fatalf("--check is not registered:\n%s", stderr)
	}
}
