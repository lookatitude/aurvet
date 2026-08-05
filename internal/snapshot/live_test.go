// internal/snapshot/live_test.go
//
// The design claim this package rests on is quantitative -- "a few KB per
// package versus the 88 GB cache holding the same facts" -- so it is measured
// against the real caches rather than asserted. Skipped by default: it reads
// $HOME, which no unit test may depend on.
package snapshot

import (
	"os"
	"path/filepath"
	"sort"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/helper"
)

// TestLiveSnapshotSize captures every clone in the live helper caches into a
// temporary state directory and reports the bytes per record.
//
// AURVET_LIVE_SNAPSHOT=1 reproduces the numbers in the P2 receipt.
func TestLiveSnapshotSize(t *testing.T) {
	if os.Getenv("AURVET_LIVE_SNAPSHOT") != "1" {
		t.Skip("set AURVET_LIVE_SNAPSHOT=1 to measure against the live system")
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME")
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()

	rel, err := filepath.Rel("/", home)
	if err != nil {
		t.Fatal(err)
	}
	det := helper.Detect(root, helper.Config{CacheDirs: helper.DefaultCacheDirs([]string{rel})})
	if !det.Covered() {
		t.Skip("no helper cache on this machine")
	}
	var vcsState []string
	for _, c := range det.Caches {
		vcsState = append(vcsState, filepath.ToSlash(filepath.Join(c.Dir, "vcs.json")))
	}

	var bases []string
	for _, c := range det.Caches {
		for _, cl := range c.Clones {
			bases = append(bases, cl.PkgBase)
		}
	}
	sort.Strings(bases)
	t.Logf("clones: %d", len(bases))

	store := StoreAt(t.TempDir())
	var total, largest int64
	var largestName string
	complete, withGaps, refused, upstreamKnown := 0, 0, 0, 0
	gapCounts := map[string]int{}

	for _, base := range bases {
		if err := ValidPkgBase(base); err != nil {
			refused++
			t.Logf("REFUSED %-40q %v", base, err)
			continue
		}
		rec, err := Capture(root, Config{
			PkgBase:       base,
			Clones:        det.Clones(base),
			VCSStateFiles: vcsState,
			CapturedAt:    time.Now().UTC(),
		})
		if err != nil {
			t.Errorf("Capture(%q): %v", base, err)
			continue
		}
		path, _, err := store.Save(rec, "20260805T100000.000000000Z")
		if err != nil {
			t.Errorf("Save(%q): %v", base, err)
			continue
		}
		fi, err := os.Stat(path)
		if err != nil {
			t.Fatal(err)
		}
		total += fi.Size()
		if fi.Size() > largest {
			largest, largestName = fi.Size(), base
		}
		if rec.Complete() {
			complete++
		} else {
			withGaps++
		}
		for _, g := range rec.Gaps {
			gapCounts[g.RuleID]++
		}
		// The per-record breakdown is what makes an oversized record diagnosable
		// rather than merely surprising: a large record is nearly always a large
		// .SRCINFO (the biggest split base in the cache declares 17 packages) or
		// a long source list, not a defect in the format.
		var pb, si int64
		var srcs, ups int
		for _, c := range rec.Clones {
			if c.PKGBUILD != nil {
				pb += c.PKGBUILD.Bytes
			}
			if c.SRCINFO != nil {
				si += c.SRCINFO.Bytes
			}
			srcs += len(c.Sources)
			ups += len(c.Upstream)
		}
		if ups > 0 {
			upstreamKnown++
		}
		t.Logf("%-40s %6d B  gaps=%-3d pkgbuild=%-6d srcinfo=%-6d sources=%-4d upstream=%d",
			base, fi.Size(), len(rec.Gaps), pb, si, srcs, ups)
	}

	n := int64(complete + withGaps)
	if n == 0 {
		t.Fatal("nothing captured")
	}
	t.Logf("records=%d complete=%d with-gaps=%d refused-key=%d upstream-commit-known=%d",
		n, complete, withGaps, refused, upstreamKnown)
	t.Logf("total=%d B mean=%d B largest=%d B (%s)", total, total/n, largest, largestName)
	for rule, count := range gapCounts {
		t.Logf("gap %-32s %d", rule, count)
	}

	// The claim under test. A snapshot that grew to hundreds of KB would defeat
	// the reason this command exists, so the ceiling fails the test rather than
	// being reported as an interesting number.
	if mean := total / n; mean > 32<<10 {
		t.Errorf("mean record is %d bytes; the design claim is a few KB per package", mean)
	}
}
