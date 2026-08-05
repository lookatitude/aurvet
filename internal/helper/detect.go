// internal/helper/detect.go
//
// Package helper finds the AUR helper build caches on a system and reports what
// they hold, keyed on pkgbase.
//
// A helper cache is the richest provenance source this tool has: a full git
// clone per pkgbase, carrying the PKGBUILD that was actually built, its
// .SRCINFO, the remote URL, and the author history. It is also the most
// ephemeral one. Measured on the reference system (2026-08-05): ~/.cache/yay
// holds 34 clones and occupies 88 GB, which is why users clean it, and only 23
// of 39 foreign packages still have a clone at all. spec.html §7 is the
// consequence: capture what the cache knows into a few KB per package before it
// is gone.
//
// Two design rules, both of them the difference between a detector and a
// scanner that has quietly stopped working:
//
//   - Layouts are DATA (Config.Layouts, DefaultLayouts). A hardcoded path list
//     stops finding anything the day a helper renames a directory, and it stops
//     without saying so. A layout table can be extended by configuration and
//     is asserted by a test per shape, so no single helper's layout is the only
//     one this package has ever exercised.
//   - An absent cache is a COVERAGE GAP, not silence (INV-9). "I found no
//     helper cache" and "there is no evidence of AUR activity" are different
//     statements and only the first one is true. Detection therefore reports
//     five distinct states -- present, absent, unreadable, present-but-empty,
//     and nothing-searched -- because a caller that cannot tell them apart
//     cannot tell a fresh system from a permissions problem from a cleaned
//     cache.
//
// Everything here is a pure function of (root, cfg) (INV-4) and reads only
// (INV-5). Cache directories live under a user's home and clone directories
// came from an AUR repository, so neither is a trusted path: directory
// traversal goes through os.Root and every file read goes through
// fsx.OpenConfined.
package helper

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// Gap rule identifiers. Each one is a distinct evidence state and they are
// deliberately not collapsed: the remedy for RuleCacheUnreadable (run as the
// right user) has nothing in common with the remedy for RuleNoCache (there is
// nothing to read and provenance must come from a snapshot).
const (
	// RuleCacheAbsent is one configured layout that is not on disk under one
	// searched cache directory.
	RuleCacheAbsent = "helper-cache-absent"

	// RuleCacheUnreadable is a cache directory that exists and could not be
	// listed -- EACCES, or a symlink leaving the scanned root.
	RuleCacheUnreadable = "helper-cache-unreadable"

	// RuleCacheEmpty is a cache directory that exists, was read, and holds no
	// clone. The helper ran on this system and its evidence has been cleaned.
	RuleCacheEmpty = "helper-cache-empty"

	// RuleCacheTruncated is a cache directory with more entries than
	// Limits.MaxClones. The listing is incomplete and says so.
	RuleCacheTruncated = "helper-cache-truncated"

	// RuleCacheDirUnsafe is a Config.CacheDirs entry refused before any
	// syscall: absolute, escaping, or otherwise not a root-relative path.
	RuleCacheDirUnsafe = "helper-cache-dir-unsafe"

	// RuleNoCacheDirs means nothing was searched, which is not the same as
	// having searched and found nothing.
	RuleNoCacheDirs = "helper-cache-nothing-searched"

	// RuleNoCache is the run-level consequence: no helper cache was found
	// anywhere, so cache-derived provenance is unavailable for every package
	// in this run (INV-10).
	RuleNoCache = "helper-cache-none"

	// RuleCloneNoRecipe is a clone directory with no readable PKGBUILD. The
	// clone is still reported -- its git history is readable -- but the absence
	// of PKGBUILD rule hits for it must not read as a clean recipe.
	RuleCloneNoRecipe = "helper-clone-no-pkgbuild"
)

// SubjectHelperCache is the subject kind for cache-scoped gaps, so a report can
// group them without string-matching rule IDs.
const SubjectHelperCache = "helper-cache"

// subjectRun is the Gap.Subject for the two run-scoped gaps. They are not
// attributable to any one path: the fact being reported is about the run.
const subjectRun = "run"

// Layout describes where one helper keeps its per-pkgbase clones, relative to
// a user cache directory.
//
// CacheRel is the helper's own directory ("yay"); ClonesRel is the
// subdirectory inside it that holds one directory per pkgbase, empty when the
// clones sit directly in CacheRel. Splitting the two is what makes paru's
// clone/ layout expressible as data instead of as a special case.
type Layout struct {
	// Name is the helper's name as reported in evidence.
	Name string

	// CacheRel is the helper's directory relative to a searched cache
	// directory.
	CacheRel string

	// ClonesRel is the per-pkgbase clone directory relative to CacheRel.
	// Empty means CacheRel itself.
	ClonesRel string

	// Note describes the shape for evidence output. It exists so a gap can
	// say what was expected at a path that is not there.
	Note string
}

// Dir returns the root-relative directory holding l's clones under cacheDir.
func (l Layout) Dir(cacheDir string) string {
	return path.Join(cacheDir, l.CacheRel, l.ClonesRel)
}

// DefaultLayouts returns the four helpers spec.html §4 names, as data.
//
// Verified against the installed helper (yay 12.x, 2026-08-05) and against
// each project's documented default for the other three. Only pkgbase-keyed
// directories are listed, and that exclusion is the important part of this
// table:
//
//   - pikaur also keeps ~/.cache/pikaur/build/<pkgname>, keyed on the PACKAGE
//     name rather than the base. 432 of 1410 installed packages on the
//     reference system have a pkgbase that ships more than one package, so
//     listing build/ would enter the same recipe under several keys and make
//     Clones(pkgbase) return duplicates for exactly those 432. aur_repos/ is
//     the pkgbase-keyed clone directory and is the one listed.
//   - yay keeps completion.cache and vcs.json alongside its clones. They are
//     not directories, so they are not clones; see clonesIn.
//
// A caller that needs a fifth helper, or a helper that has changed its layout,
// supplies Config.Layouts. That is the whole point: the failure mode of a
// hardcoded list is silence, and silence is the outcome this project treats as
// worse than a false positive.
func DefaultLayouts() []Layout {
	return []Layout{
		{Name: "yay", CacheRel: "yay", Note: "clones directly under the cache directory"},
		{Name: "paru", CacheRel: "paru", ClonesRel: "clone", Note: "clone/ layout"},
		{Name: "pikaur", CacheRel: "pikaur", ClonesRel: "aur_repos",
			Note: "aur_repos/ holds the pkgbase-keyed clones; build/ is pkgname-keyed and deliberately not searched"},
		{Name: "aurutils", CacheRel: "aurutils", ClonesRel: "sync", Note: "sync/ layout (AURDEST)"},
	}
}

// DefaultCacheDirs derives one search directory per home directory.
//
// homes are root-relative paths the caller resolved from the TARGET's passwd
// (see surfaces.PasswdUsers), never from $HOME: reading the environment here
// would make --offline-root read the live machine's cache, which is INV-4's
// exact failure. An XDG_CACHE_HOME override is likewise a Config value the
// caller supplies, not something this package goes looking for.
//
// A leading "/" is trimmed rather than refused so a caller can pass passwd
// entries through unchanged; anything else unsafe is refused by Detect and
// reported as RuleCacheDirUnsafe.
func DefaultCacheDirs(homes []string) []string {
	out := make([]string, 0, len(homes))
	for _, h := range homes {
		h = strings.TrimPrefix(h, "/")
		if h == "" {
			continue
		}
		out = append(out, path.Join(h, ".cache"))
	}
	return out
}

// Limits bounds what an attacker-controlled cache directory can cost. Exported
// and copyable so a test can prove each bound fires on its own.
type Limits struct {
	// MaxClones caps the entries considered in one cache directory. The
	// reference system's yay cache holds 36; the cap exists because a
	// directory under a user's home can hold as many entries as the attacker
	// cares to create, and an unbounded listing of that is not something a
	// security tool gets to have.
	MaxClones int

	// MaxNameBytes caps one clone directory name, which becomes a pkgbase key
	// and is rendered in output. The longest pkgbase on the reference system
	// is 30 bytes.
	MaxNameBytes int
}

// DefaultLimits returns bounds with headroom over the measured worst case
// rather than fitted to it: 36 entries observed, 255 is the filesystem's own
// name ceiling.
func DefaultLimits() Limits {
	return Limits{MaxClones: 100_000, MaxNameBytes: 255}
}

// withDefaults fills unset fields, so a caller can tighten one bound without
// restating the others and a zero Limits means "the defaults".
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxClones <= 0 {
		l.MaxClones = d.MaxClones
	}
	if l.MaxNameBytes <= 0 {
		l.MaxNameBytes = d.MaxNameBytes
	}
	return l
}

// Config is everything Detect is allowed to know. There is no ambient input.
type Config struct {
	// CacheDirs are the root-relative user cache directories to search, in
	// order. Empty is a gap, not a default: guessing a home directory would
	// be an ambient path.
	CacheDirs []string

	// Layouts replaces DefaultLayouts entirely when non-nil. Replacement
	// rather than extension is deliberate -- a caller narrowing the search to
	// one helper must not silently keep three absent-cache gaps for helpers it
	// never asked about.
	Layouts []Layout

	// Limits bounds the traversal. The zero value means DefaultLimits.
	Limits Limits
}

// Clone is one per-pkgbase directory in a helper cache.
//
// The three markers are recorded rather than required: a directory with a .git
// and no PKGBUILD still carries readable history, and reporting it with
// HasPKGBUILD false plus a RuleCloneNoRecipe gap is more honest than dropping
// it. Each marker is the answer for a REGULAR file opened without following a
// symlink, so a symlinked PKGBUILD reads as absent (and gaps) rather than as a
// read of whatever it pointed at.
type Clone struct {
	// PkgBase is the directory name. Helper caches are pkgbase-keyed, and so
	// is every lookup in this package.
	PkgBase string

	// Dir is the root-relative clone directory.
	Dir string

	// Helper is the layout name this clone was found under. A pkgbase can
	// legitimately appear in two helpers' caches with different contents.
	Helper string

	HasPKGBUILD bool
	HasSRCINFO  bool

	// HasGitDir reports a .git DIRECTORY. A .git FILE (a worktree or submodule
	// pointer) reads as false: it names a git directory somewhere else, and
	// following an attacker-supplied pointer out of the clone is not a read
	// this package performs.
	HasGitDir bool
}

// Cache is one detected helper cache.
type Cache struct {
	// Helper is the Layout.Name that matched.
	Helper string

	// Dir is the root-relative directory that holds the clones -- already
	// including any ClonesRel, so a caller never re-joins a layout.
	Dir string

	// Clones are the per-pkgbase directories, sorted by name.
	Clones []Clone
}

// Detection is the evidence Detect produces: what was found, and what could
// not be established.
type Detection struct {
	// Caches are the helper caches that exist and were listed, in
	// Config.CacheDirs order and then Config.Layouts order.
	Caches []Cache

	// Gaps are the coverage shortfalls, as finding.Gap so a caller merging
	// them into a report cannot invent a second format for them.
	Gaps []finding.Gap
}

// Covered reports whether any helper cache was found and read. It is the
// precondition for every cache-derived check (INV-10): false means those
// checks must report unavailable rather than clean.
//
// It is true for a cache that exists and holds nothing -- the directory was
// read, which is a real (if empty) answer, and the emptiness travels as a
// RuleCacheEmpty gap rather than as a false Covered.
func (d Detection) Covered() bool { return len(d.Caches) > 0 }

// Cache returns the detected cache for one helper by name.
func (d Detection) Cache(helper string) (Cache, bool) {
	for _, c := range d.Caches {
		if c.Helper == helper {
			return c, true
		}
	}
	return Cache{}, false
}

// Clones returns every clone recorded for one pkgbase, across all detected
// caches.
//
// The key is the PKGBASE and never a package name. spec.html §7 makes this the
// rule for snapshots and the reference system makes it load-bearing: 432 of
// 1410 installed packages have a pkgbase that ships more than one package, so
// a lookup keyed on a package name misses the clone holding its recipe for
// nearly a third of the system. Note this is the SYNC-database definition of
// splitness (a base that ships >1 package in the repositories); the local DB
// alone reports only 237, because it cannot see siblings that are not
// installed here.
func (d Detection) Clones(pkgbase string) []Clone {
	var out []Clone
	for _, c := range d.Caches {
		for _, cl := range c.Clones {
			if cl.PkgBase == pkgbase {
				out = append(out, cl)
			}
		}
	}
	return out
}

// Detect searches cfg.CacheDirs for every layout in cfg.Layouts.
//
// It is a pure function of (root, cfg): the same arguments produce the same
// Caches in the same order and the same Gaps, with no dependence on the
// process working directory or environment. It never writes (INV-5).
func Detect(root *os.Root, cfg Config) Detection {
	layouts := cfg.Layouts
	if layouts == nil {
		layouts = DefaultLayouts()
	}
	lim := cfg.Limits.withDefaults()

	var d Detection
	if len(cfg.CacheDirs) == 0 {
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleNoCacheDirs,
			Subject: subjectRun,
			Reason: "no cache directories were searched, so no helper cache could be found; " +
				"resolve them from the target's passwd (helper.DefaultCacheDirs) before concluding anything about AUR provenance",
		})
		return d
	}
	if root == nil {
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleNoCacheDirs,
			Subject: subjectRun,
			Reason:  "no filesystem root was supplied, so nothing was searched",
		})
		return d
	}

	fsys := root.FS()
	for _, cacheDir := range cfg.CacheDirs {
		clean, err := safeDir(cacheDir)
		if err != nil {
			d.Gaps = append(d.Gaps, finding.Gap{
				RuleID:  RuleCacheDirUnsafe,
				Subject: cacheDir,
				Reason: fmt.Sprintf("refused as a search directory (%v); it must be a root-relative path, "+
					"so nothing under it was examined", err),
			})
			continue
		}
		for _, l := range layouts {
			d.detectOne(root, fsys, clean, l, lim)
		}
	}

	if !d.Covered() {
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleNoCache,
			Subject: subjectRun,
			Reason: "no AUR helper cache was found under any searched directory, so cache-derived " +
				"provenance (git history, remote URL, built PKGBUILD) is unavailable for every package " +
				"in this run; this is not evidence that no package was built from the AUR",
		})
	}
	return d
}

// detectOne resolves one (cacheDir, layout) pair and appends either a Cache or
// the gap explaining why there is none.
func (d *Detection) detectOne(root *os.Root, fsys fs.FS, cacheDir string, l Layout, lim Limits) {
	dir := l.Dir(cacheDir)

	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		// Absent and unreadable are different answers and are reported
		// separately. fs.ErrNotExist covers a helper that was never installed;
		// everything else -- EACCES, ENOTDIR, a symlink leaving the root --
		// means the path is there and we could not see into it.
		if errors.Is(err, fs.ErrNotExist) {
			d.Gaps = append(d.Gaps, finding.Gap{
				RuleID:  RuleCacheAbsent,
				Subject: dir,
				Reason: fmt.Sprintf("no %s cache directory (%s); this helper's clones cannot be inspected, "+
					"which is not evidence that nothing was built with it", l.Name, describe(l)),
			})
			return
		}
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleCacheUnreadable,
			Subject: dir,
			Reason: fmt.Sprintf("%s cache directory exists but could not be listed: %v; its clones are "+
				"present and unexamined", l.Name, err),
		})
		return
	}

	clones, truncated, skipped := d.clonesIn(root, fsys, dir, l, ents, lim)
	if truncated {
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleCacheTruncated,
			Subject: dir,
			Reason: fmt.Sprintf("%s cache holds more than %d entries; the listing stopped there and the "+
				"remaining clones were not examined", l.Name, lim.MaxClones),
		})
	}
	d.Gaps = append(d.Gaps, skipped...)
	if len(clones) == 0 {
		d.Gaps = append(d.Gaps, finding.Gap{
			RuleID:  RuleCacheEmpty,
			Subject: dir,
			Reason: fmt.Sprintf("%s cache directory exists but holds no clone; the helper ran on this system "+
				"and its evidence is gone (the cache is large, so it gets cleaned)", l.Name),
		})
	}
	d.Caches = append(d.Caches, Cache{Helper: l.Name, Dir: dir, Clones: clones})
}

// clonesIn turns directory entries into clones. fs.ReadDir sorts by name, so
// the result is deterministic without a second sort.
func (d *Detection) clonesIn(root *os.Root, fsys fs.FS, dir string, l Layout, ents []fs.DirEntry, lim Limits) (clones []Clone, truncated bool, gaps []finding.Gap) {
	for _, e := range ents {
		if len(clones) >= lim.MaxClones {
			truncated = true
			break
		}
		name := e.Name()
		if len(name) > lim.MaxNameBytes {
			gaps = append(gaps, finding.Gap{
				RuleID:  RuleCacheTruncated,
				Subject: dir,
				Reason:  fmt.Sprintf("an entry name exceeds %d bytes and was not examined", lim.MaxNameBytes),
			})
			continue
		}
		// A clone is a DIRECTORY. Everything else in a cache directory is the
		// helper's own state -- measured in ~/.cache/yay: 36 entries are 34
		// clones plus completion.cache and vcs.json -- and calling those
		// clones would manufacture two gaps on every yay system.
		//
		// DirEntry.IsDir is an lstat, so a directory reached through a symlink
		// reports false. fs.Stat resolves it (confined to the root), which is
		// what distinguishes "not a directory" from "a directory I reached
		// through a link". A link that leaves the root fails here and is
		// skipped, which is the refusal we want.
		info, err := fs.Stat(fsys, path.Join(dir, name))
		if err != nil || !info.IsDir() {
			continue
		}

		c := Clone{PkgBase: name, Dir: path.Join(dir, name), Helper: l.Name}
		c.HasPKGBUILD = regularFileExists(root, path.Join(c.Dir, "PKGBUILD"))
		c.HasSRCINFO = regularFileExists(root, path.Join(c.Dir, ".SRCINFO"))
		if gi, err := fs.Stat(fsys, path.Join(c.Dir, ".git")); err == nil && gi.IsDir() {
			c.HasGitDir = true
		}
		if !c.HasPKGBUILD {
			gaps = append(gaps, finding.Gap{
				RuleID:  RuleCloneNoRecipe,
				Subject: c.Dir,
				Reason: "clone directory has no readable regular PKGBUILD, so the recipe that was built " +
					"cannot be reviewed from this cache; absence of recipe findings for this pkgbase is not a clean result",
			})
		}
		clones = append(clones, c)
	}
	return clones, truncated, gaps
}

// regularFileExists reports whether rel is a regular file, opened once through
// the confined API and never followed through a symlink. Existence is all this
// package needs; the content is the next reader's business.
func regularFileExists(root *os.Root, rel string) bool {
	f, _, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return false
	}
	f.Close()
	return true
}

// describe renders a layout for a gap reason: the note if it has one, else the
// path shape.
func describe(l Layout) string {
	if l.Note != "" {
		return l.Note
	}
	if l.ClonesRel == "" {
		return "expected " + l.CacheRel + "/"
	}
	return "expected " + l.CacheRel + "/" + l.ClonesRel + "/"
}

// safeDir validates a Config.CacheDirs entry and returns it cleaned.
//
// It is stricter than os.Root on purpose, and for the reason
// fsx.splitConfined is: refusing here keeps the refusal attributable to the
// configured path rather than to whatever errno the kernel produced three
// calls later, and "some lower layer probably catches this" is not a
// guarantee.
func safeDir(dir string) (string, error) {
	if dir == "" {
		return "", errors.New("empty path")
	}
	if strings.HasPrefix(dir, "/") {
		return "", errors.New("absolute path")
	}
	if strings.ContainsRune(dir, 0) {
		// A NUL truncates the path at the syscall boundary, so the path Go
		// reports and the path the kernel opens would differ.
		return "", errors.New("contains NUL")
	}
	for _, p := range strings.Split(dir, "/") {
		switch p {
		case "", ".", "..":
			// Refused rather than normalised away: normalising a path is a
			// second interpretation of it.
			return "", errors.New("has an empty, . or .. component")
		}
	}
	return dir, nil
}
