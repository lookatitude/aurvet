// cmd/aurvet/snapshot.go
//
// `aurvet snapshot <pkgbase>` captures a package's provenance into aurvet's own
// state, because the evidence it reads from does not last: 41% of foreign
// packages on the reference system already have none, and the cache that holds
// the rest is 88 GB, so it gets cleaned.
//
// The subject is a PKGBASE. Not a package name -- 433 of 1409 installed packages
// are split, one recipe builds several of them, and a snapshot records what one
// recipe produced.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/snapshot"
	"github.com/lookatitude/aurvet/internal/surfaces"
)

// snapshotStamp names a stored record. Fixed-width and zero-padded so a
// descending string sort is a descending time sort, which is what
// snapshot.Store.Latest rests on; nanoseconds because two captures inside one
// second would otherwise collide and the rename would silently overwrite.
const snapshotStamp = "20060102T150405.000000000Z"

// runSnapshot captures one pkgbase and persists it when it may.
//
// Exit codes: 2 for a bad invocation (including a pkgbase that is not a usable
// key), 3 when the capture could not get everything it went for, 0 only when the
// record is complete. There is no exit 1 here: a snapshot makes no findings, it
// records evidence. A failure to PERSIST is printed and does not change the code
// -- an unwritable state directory is an operational fact about the host, not an
// analysis that did not run, and manufacturing a 3 for it would train operators
// to ignore the one code that means something.
func runSnapshot(offlineRoot string, jsonOut bool, pkgbase string, stdout, stderr io.Writer) int {
	if err := snapshot.ValidPkgBase(pkgbase); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	euid := os.Geteuid()
	cfg, err := config.Resolve(offlineRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	root, err := os.OpenRoot(cfg.Root)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer root.Close()

	// Cache directories come from the SCANNED ROOT's passwd, never from $HOME:
	// under --offline-root, $HOME answers for the wrong machine (INV-4).
	users, userGaps := surfaces.PasswdUsers(root.FS(), "etc/passwd")
	homes := make([]string, 0, len(users))
	for _, u := range users {
		homes = append(homes, u.Home)
	}
	det := helper.Detect(root, helper.Config{CacheDirs: helper.DefaultCacheDirs(homes)})

	rec, err := snapshot.Capture(root, snapshot.Config{
		PkgBase:       pkgbase,
		Clones:        det.Clones(pkgbase),
		VCSStateFiles: vcsStateFiles(det),
		CapturedAt:    time.Now().UTC(),
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	// The search's own shortfalls are reported, but they are NOT the record's
	// unless they could explain what the record is missing.
	//
	// The distinction is worth the code. "This pkgbase has no clone" and "four
	// caches belonging to other accounts could not be listed" are different
	// facts, and a live unprivileged run produces twenty of the second kind
	// (measured: every system account's ~/.cache is unreadable, times four
	// layouts). Storing those inside a record that DID find its clone would make
	// every snapshot on the machine mostly a copy of the same permissions
	// problem. When no clone was found they are exactly the explanation the
	// record needs, so they travel with it.
	var searchGaps []finding.Gap
	for _, g := range append(userGaps, det.Gaps...) {
		if g.RuleID == helper.RuleCacheAbsent {
			// A helper that was never installed is the normal state of every
			// system; three of those per searched home is noise that buries the
			// gaps that mean something.
			continue
		}
		searchGaps = append(searchGaps, g)
	}
	if len(rec.Clones) == 0 {
		rec.Gaps = append(rec.Gaps, searchGaps...)
	}

	store := snapshot.New(cfg, snapshotStateDir(euid))
	if ok, why := store.Writable(); !ok {
		fmt.Fprintf(stderr, "aurvet: %s\n", why)
	} else if p, wrote, serr := store.Save(rec, time.Now().UTC().Format(snapshotStamp)); serr != nil {
		fmt.Fprintf(stderr, "aurvet: could not persist the snapshot to %s: %v\n", store.Dir(), serr)
	} else if wrote {
		fmt.Fprintf(stderr, "aurvet: snapshot written to %s\n", p)
	} else {
		fmt.Fprintf(stderr, "aurvet: unchanged since %s; no new record written\n", p)
	}

	if jsonOut {
		enc := json.NewEncoder(stdout)
		enc.SetIndent("", "  ")
		if err := enc.Encode(rec); err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
	} else {
		renderSnapshot(stdout, rec)
		renderSearchGaps(stdout, searchGaps)
	}

	// A shortfall in the search counts towards the exit code even when it is not
	// stored in the record: the operator asked for this pkgbase's provenance and
	// part of the machine could not be looked at (INV-3).
	if !rec.Complete() || len(searchGaps) > 0 {
		return exitIncomplete
	}
	return exitClean
}

// renderSearchGaps prints the coverage of the SEARCH, collapsed by rule.
//
// Collapsed because a live unprivileged run produces one per (system account,
// helper layout) pair -- twenty on the reference system -- and twenty
// repetitions of "permission denied" is how a real gap gets missed.
func renderSearchGaps(w io.Writer, gaps []finding.Gap) {
	if len(gaps) == 0 {
		return
	}
	byRule := map[string][]string{}
	var order []string
	for _, g := range gaps {
		if _, seen := byRule[g.RuleID]; !seen {
			order = append(order, g.RuleID)
		}
		byRule[g.RuleID] = append(byRule[g.RuleID], g.Subject)
	}
	sort.Strings(order)
	fmt.Fprintf(w, "\nsearch coverage (%d shortfall(s), not stored in this record):\n", len(gaps))
	for _, rule := range order {
		subjects := byRule[rule]
		shown := subjects
		if len(shown) > 3 {
			shown = shown[:3]
		}
		fmt.Fprintf(w, "  ! %s  %d: %s", rule, len(subjects), strings.Join(shown, ", "))
		if len(subjects) > len(shown) {
			fmt.Fprintf(w, ", and %d more", len(subjects)-len(shown))
		}
		fmt.Fprintln(w)
	}
}

// snapshotStateDir returns the state-directory override, or "" for "wherever
// config.Resolve decided".
//
// It mirrors scanStateDir's environment rule -- honoured, but never as root,
// because otherwise an unprivileged local attacker chooses what a
// root-privileged security tool trusts (spec §11) -- and diverges from it in one
// respect on purpose: an explicit destination OUTSIDE the examined tree is a
// legitimate place to capture to under --offline-root, and snapshot.New is what
// enforces the containment. Refusing outright would mean provenance could never
// be captured from a rescue mount, which is one of the moments it matters most.
func snapshotStateDir(euid int) string {
	if euid != 0 {
		return os.Getenv("AURVET_STATE_DIR")
	}
	return ""
}

// vcsStateFiles derives the helper VCS state files to consult from the caches
// that were actually detected.
//
// The upstream commit a -git package was built from survives in exactly two
// places: the checkout makepkg left beside the PKGBUILD, and the helper's own
// record of what it built. yay writes that record to vcs.json beside its clones;
// paru's clone/ layout puts the equivalent one level up. Both shapes are derived
// from the DETECTED cache directory rather than hardcoded, so a helper that moves
// its clones moves this with it.
func vcsStateFiles(det helper.Detection) []string {
	seen := map[string]bool{}
	var out []string
	for _, c := range det.Caches {
		for _, cand := range []string{
			path.Join(c.Dir, "vcs.json"),
			path.Join(path.Dir(c.Dir), "vcs.json"),
		} {
			if !seen[cand] {
				seen[cand] = true
				out = append(out, cand)
			}
		}
	}
	return out
}

// renderSnapshot prints what was captured and, first, what was not.
//
// The gaps lead. A snapshot's failure mode is being read later as authoritative,
// so a record that could not get .BUILDINFO has to say so where an operator sees
// it -- not in a field they would have to go looking for (INV-6).
func renderSnapshot(w io.Writer, rec snapshot.Record) {
	fmt.Fprintf(w, "pkgbase %s (captured %s)\n", rec.PkgBase, rec.CapturedAt)

	if len(rec.Gaps) > 0 {
		fmt.Fprintf(w, "\nnot established (%d):\n", len(rec.Gaps))
		for _, g := range rec.Gaps {
			fmt.Fprintf(w, "  ! %s  %s\n      %s\n", g.RuleID, g.Subject, g.Reason)
		}
	}

	for _, c := range rec.Clones {
		fmt.Fprintf(w, "\nclone %s (%s)\n", c.Dir, c.Helper)
		if len(c.PkgNames) > 0 {
			fmt.Fprintf(w, "  packages     %v\n", c.PkgNames)
		}
		if c.PKGBUILD != nil {
			fmt.Fprintf(w, "  PKGBUILD     %s (%d bytes)\n", c.PKGBUILD.SHA256, c.PKGBUILD.Bytes)
		}
		if c.SRCINFO != nil {
			fmt.Fprintf(w, "  .SRCINFO     %s (%d bytes)\n", c.SRCINFO.SHA256, c.SRCINFO.Bytes)
		}
		if c.BuildInfo != nil {
			fmt.Fprintf(w, "  .BUILDINFO   %s pkgbuild_sha256sum=%s\n", c.BuildInfo.From, c.BuildInfo.PkgBuildSHA256)
		}
		if c.Git != nil {
			fmt.Fprintf(w, "  head         %s\n", c.Git.Head)
			fmt.Fprintf(w, "  remote       %s\n", c.Git.Remote)
			for _, l := range c.Git.Log {
				fmt.Fprintf(w, "    %s %s %s\n", shortHash(l.Hash), l.Date, l.Subject)
			}
		}
		for _, u := range c.Upstream {
			fmt.Fprintf(w, "  upstream     %s %s (%s)\n", u.URL, u.Commit, u.Origin)
		}
		srcs := make([]string, 0, len(c.Sources))
		for _, s := range c.Sources {
			if s.Origin != snapshot.OriginPKGBUILD {
				continue
			}
			if s.Resolved {
				srcs = append(srcs, s.Raw)
			} else {
				srcs = append(srcs, s.Raw+"  [unresolved]")
			}
		}
		sort.Strings(srcs)
		for _, s := range srcs {
			fmt.Fprintf(w, "  source       %s\n", s)
		}
	}

	for _, n := range rec.Notes {
		fmt.Fprintf(w, "\nnote: %s\n", n)
	}
}

func shortHash(h string) string {
	if len(h) > 12 {
		return h[:12]
	}
	return h
}
