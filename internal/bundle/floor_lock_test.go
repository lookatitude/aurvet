package bundle

import (
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/fsx"
)

// E-BUNDLE-3. `update` is reachable from a systemd timer and from a human at the
// same time, so Save's read-modify-write is contended in production.
//
// The claim under test is narrow, and deliberately so: the lock stops two
// writers interleaving. It is NOT what stops the floor being lowered (Save's
// monotonicity check does that, and it is re-read under the lock) and it is NOT
// what stops a torn file (writeAtomic does that). See Save's comment.

// The attack: hold the floor lock, then ask Save to write. It must refuse and
// leave the floor exactly as it was, rather than blocking forever or writing
// anyway.
func TestFloorSaveRefusesWhileAnotherProcessHoldsTheLock(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenFloor(dir, FloorOptions{CacheDir: t.TempDir(), EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	first := Floor{Schema: FloorSchema, MinBundleVersion: 4, HeadDigest: strings.Repeat("ab", 32),
		MinDelegationSerial: 2, IndicatorCount: 9, RootGeneration: 1,
		AcceptedAt: fixBundleIssued, CheckedAt: fixBundleIssued}
	if err := s.Save(first); err != nil {
		t.Fatal(err)
	}

	release, err := fsx.Lock(filepath.Join(dir, FloorLockFile), time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	start := time.Now()
	err = s.Save(Floor{Schema: FloorSchema, MinBundleVersion: 5, HeadDigest: strings.Repeat("cd", 32),
		MinDelegationSerial: 2, IndicatorCount: 1, RootGeneration: 1,
		AcceptedAt: fixNow, CheckedAt: fixNow})
	if err == nil {
		t.Fatal("Save wrote the floor while another process held the lock")
	}
	if !strings.Contains(err.Error(), "nothing was written") {
		t.Errorf("the refusal does not say nothing was written: %v", err)
	}
	if time.Since(start) > 30*time.Second {
		t.Fatalf("the wait was not bounded: %v", time.Since(start))
	}

	got, ok, lerr := s.Load()
	if lerr != nil || !ok {
		t.Fatalf("floor unreadable after a refused Save: ok=%v err=%v", ok, lerr)
	}
	if got != first {
		t.Fatalf("a refused Save changed the floor:\n got %+v\nwant %+v", got, first)
	}
}

// Concurrent savers: the floor must end up at the HIGHEST version any of them
// offered, carrying that writer's own metadata.
//
// This is the assertion that needs the lock. Without it, each Save still writes
// one coherent record (writeAtomic), but the monotonicity check is read outside
// any mutual exclusion: writer 8 can pass the check and rename first, then
// writer 5 -- which read the floor before 8 landed -- passes its own stale check
// and renames over it. The floor then records version 5 with 5's indicator
// count, and the next run measures "the count dropped" against the wrong
// number. The floor was never lowered below what any writer offered and never
// torn; what was lost is which writer's metadata survived.
func TestConcurrentFloorSavesLeaveOneCoherentRecord(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "state")
	s, err := OpenFloor(dir, FloorOptions{CacheDir: t.TempDir(), EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	const n = 8
	var wg sync.WaitGroup
	for i := 1; i <= n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			// Each writer's digest and count travel together, so a mixed record
			// is detectable: count i must come with digest built from i. The digit
			// keeps the digest hex -- 'g' is not a hex character and validateFloor
			// would refuse the record before the lock ever mattered.
			_ = s.Save(Floor{
				Schema: FloorSchema, MinBundleVersion: int64(i),
				HeadDigest:          strings.Repeat(string(rune('0'+i)), 64),
				MinDelegationSerial: 1, IndicatorCount: i, RootGeneration: 1,
				AcceptedAt: fixNow, CheckedAt: fixNow,
			})
		}(i)
	}
	wg.Wait()

	got, ok, err := s.Load()
	if err != nil || !ok {
		t.Fatalf("floor after %d concurrent saves: ok=%v err=%v", n, ok, err)
	}
	if got.MinBundleVersion != n {
		t.Fatalf("min_bundle_version %d after %d concurrent saves, want %d: a writer that read "+
			"the floor before a higher one landed overwrote it", got.MinBundleVersion, n, n)
	}
	// And the surviving record is that writer's own, not two writers' halves.
	want := strings.Repeat(string(rune('0'+int(got.MinBundleVersion))), 64)
	if got.HeadDigest != want || got.IndicatorCount != int(got.MinBundleVersion) {
		t.Fatalf("the surviving floor mixes writers: version %d, digest %s, count %d",
			got.MinBundleVersion, short(got.HeadDigest), got.IndicatorCount)
	}
}
