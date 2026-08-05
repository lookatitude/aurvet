// internal/pkgmeta/live_test.go
//
// Live measurements against the machine the tests run on. Skipped by default:
// they read /var/lib/pacman and $HOME, which no unit test may depend on.
package pkgmeta

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
)

// TestLiveSplitPackageCount measures splitness four ways and reports all four,
// because the difference between them is the trap this task had to avoid.
//
// The roadmap says 433 of 1409 packages are split and keying on pkgbase is
// therefore mandatory. A first measurement against the LOCAL database says 237
// and looks like the roadmap is wrong. It is not: the local DB cannot see a
// pkgbase's siblings when they are not installed here, and the roadmap's number
// is the repository-side one, which needs SYNC-database metadata. A splitness
// test built on the local DB would miss ~195 packages -- and miss them silently.
//
// Run with AURVET_LIVE_PKGMETA=1.
func TestLiveSplitPackageCount(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGMETA") != "1" {
		t.Skip("set AURVET_LIVE_PKGMETA=1 to measure against the live system")
	}
	pkgs, dbGaps, err := alpm.LoadLocalDB("/var/lib/pacman/local")
	if err != nil {
		t.Fatal(err)
	}

	// (1) %BASE% != %NAME% in the local DB.
	baseNotName := 0
	// (2) installed packages sharing a base with another INSTALLED package.
	installedPerBase := map[string]int{}
	for _, p := range pkgs {
		if p.Base != "" && p.Base != p.Name {
			baseNotName++
		}
		installedPerBase[p.Base]++
	}
	sharedWithInstalled := 0
	either := 0
	for _, p := range pkgs {
		shared := installedPerBase[p.Base] > 1
		if shared {
			sharedWithInstalled++
		}
		if shared || (p.Base != "" && p.Base != p.Name) {
			either++
		}
	}

	// (4) the repository-side definition: a pkgbase that ships more than one
	// package in any configured sync database. This is the roadmap's number and
	// the one this package's IsSplit answers, because a .SRCINFO lists every
	// pkgname the base builds whether or not it is installed here.
	repoPerBase, syncPkgs, err := syncBaseCounts("/var/lib/pacman/sync")
	if err != nil {
		t.Fatal(err)
	}
	repoSplit := 0
	unknownBase := 0
	for _, p := range pkgs {
		n, ok := repoPerBase[p.Base]
		if !ok {
			unknownBase++ // foreign: not in any repository
			continue
		}
		if n > 1 {
			repoSplit++
		}
	}

	t.Logf("installed=%d local-db-gaps=%d sync-entries=%d", len(pkgs), len(dbGaps), syncPkgs)
	t.Logf("(1) %%BASE%% != %%NAME%% in the local DB ............... %d", baseNotName)
	t.Logf("(2) sharing a base with another INSTALLED package ... %d", sharedWithInstalled)
	t.Logf("(3) either of the above ............................ %d", either)
	t.Logf("(4) pkgbase ships >1 package IN THE REPOSITORIES ... %d   <- the definition used", repoSplit)
	t.Logf("    installed packages whose base is in no repository (foreign) = %d", unknownBase)

	if repoSplit <= baseNotName {
		t.Errorf("the repository-side count (%d) must exceed the local-DB count (%d); "+
			"if it does not, the sync databases were not read and the definition silently degraded",
			repoSplit, baseNotName)
	}
}

// syncBaseCounts counts, per pkgbase, how many packages the sync databases ship.
//
// It reads the desc entries out of the gzipped tar databases directly rather
// than going through alpm.LoadSyncNames, which returns names only -- %BASE% is
// exactly the field this measurement needs and that API does not carry.
func syncBaseCounts(syncPath string) (map[string]int, int, error) {
	ents, err := os.ReadDir(syncPath)
	if err != nil {
		return nil, 0, err
	}
	perBase := map[string]int{}
	total := 0
	for _, e := range ents {
		if !strings.HasSuffix(e.Name(), ".db") {
			continue
		}
		f, err := os.Open(filepath.Join(syncPath, e.Name()))
		if err != nil {
			return nil, 0, err
		}
		gz, err := gzip.NewReader(f)
		if err != nil {
			f.Close()
			return nil, 0, err
		}
		tr := tar.NewReader(gz)
		for {
			h, err := tr.Next()
			if errors.Is(err, io.EOF) {
				break
			}
			if err != nil {
				gz.Close()
				f.Close()
				return nil, 0, err
			}
			if !strings.HasSuffix(h.Name, "/desc") {
				continue
			}
			fields, err := alpm.ParseDesc(tr)
			if err != nil {
				continue
			}
			name := firstOf(fields, "NAME")
			base := firstOf(fields, "BASE")
			if base == "" {
				base = name
			}
			if name == "" {
				continue
			}
			total++
			perBase[base]++
		}
		gz.Close()
		f.Close()
	}
	return perBase, total, nil
}

func firstOf(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// TestLiveCachedMetadata reads every .SRCINFO in the helper caches with this
// package's own parser, and every package archive's .BUILDINFO it can reach.
//
// The .BUILDINFO half is expected to be almost entirely coverage gaps -- that
// is the measurement, not a failure: Arch compresses packages with zstd, this
// module takes no third-party decompressor, and the gap is precisely the reason
// `snapshot` exists.
func TestLiveCachedMetadata(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGMETA") != "1" {
		t.Skip("set AURVET_LIVE_PKGMETA=1 to measure against the live system")
	}
	home := os.Getenv("HOME")
	if home == "" {
		t.Skip("no HOME")
	}
	caches := []string{
		filepath.Join(home, ".cache/yay"),
		filepath.Join(home, ".cache/paru/clone"),
		filepath.Join(home, ".cache/pikaur/aur_repos"),
		filepath.Join(home, ".cache/aurutils/sync"),
	}
	var clones []string
	for _, c := range caches {
		ents, err := os.ReadDir(c)
		if err != nil {
			t.Logf("cache %s: %v (coverage gap, not silence)", c, err)
			continue
		}
		for _, e := range ents {
			if e.IsDir() {
				clones = append(clones, filepath.Join(c, e.Name()))
			}
		}
	}

	var srcinfoOK, srcinfoFail, split, vcsSources, archSources, unparsed int
	for _, d := range clones {
		f, err := os.Open(filepath.Join(d, ".SRCINFO"))
		if err != nil {
			srcinfoFail++
			t.Logf(".SRCINFO %-40s gap: %v", filepath.Base(d), err)
			continue
		}
		s, err := ParseSRCINFO(f, Limits{})
		f.Close()
		if err != nil {
			srcinfoFail++
			t.Logf(".SRCINFO %-40s gap: %v", filepath.Base(d), err)
			continue
		}
		srcinfoOK++
		if s.IsSplit() {
			split++
			t.Logf("split    %-40s %d packages", s.PkgBase, len(s.Packages))
		}
		unparsed += len(s.Unparsed)
		for _, src := range s.Sources() {
			if src.IsVCS {
				vcsSources++
			}
			if src.Arch != "" {
				archSources++
			}
		}
	}
	t.Logf(".SRCINFO parsed=%d gaps=%d split-bases=%d vcs-sources=%d arch-suffixed-sources=%d unparsed-lines=%d",
		srcinfoOK, srcinfoFail, split, vcsSources, archSources, unparsed)

	var biOK int
	byAlgo := map[string]int{}
	for _, d := range clones {
		ents, err := os.ReadDir(d)
		if err != nil {
			continue
		}
		for _, e := range ents {
			if e.IsDir() || !strings.Contains(e.Name(), ".pkg.tar") {
				continue
			}
			algo, supported := CompressionOf(e.Name())
			byAlgo[algo]++
			if !supported {
				continue
			}
			f, err := os.Open(filepath.Join(d, e.Name()))
			if err != nil {
				continue
			}
			b, err := BuildInfoFromArchive(e.Name(), f, Limits{})
			f.Close()
			if err != nil {
				t.Logf(".BUILDINFO %-50s gap: %v", e.Name(), err)
				continue
			}
			biOK++
			t.Logf(".BUILDINFO %-50s pkgbase=%s sha256=%.12s builddir=%s",
				e.Name(), b.PkgBase, b.PkgBuildSHA256, b.BuildDir)
		}
	}
	t.Logf("archives by compression=%v readable-buildinfo=%d", byAlgo, biOK)
}
