// internal/snapshot/snapshot.go
//
// Package snapshot captures the small artifacts that carry a foreign package's
// provenance, before the evidence that holds them disappears.
//
// # Why this exists at all
//
// Provenance is ephemeral, and the numbers are the argument. 16 of 39 foreign
// packages on the reference system (41%) already have neither a helper cache
// clone nor a retained artifact, so nothing can be said about how they were
// built. The evidence that does still exist is expensive to keep: ~/.cache/yay
// is 88 GB for 34 clones (measured 2026-08-05), which is exactly why helpers and
// users clean it -- and when it goes, the PKGBUILD that was built, its history,
// its remote and the upstream commit go with it. A snapshot is a few KB holding
// the same facts, which is the whole trade (spec §7).
//
// # Keyed on pkgbase, never pkgname
//
// One recipe produces one record. 433 of 1409 installed packages on the
// reference system are split, so a record keyed on a package name files one
// recipe under several keys -- and those records then disagree about their own
// provenance while describing the same PKGBUILD. The definition matters and has
// a trap in it: `%BASE% != %NAME%` in the local database counts 237, sharing a
// base with another installed package counts 269, either counts 296, and a base
// that ships more than one package IN THE REPOSITORIES counts 432 of 1410. The
// last is the roadmap's number and the one that describes the risk, because the
// siblings that are not installed here still share the recipe.
//
// Nothing in this package infers a base from a name, and a .SRCINFO or
// .BUILDINFO declaring a different base than the directory it sits in is
// RECORDED as a mismatch rather than adopted as the key: adopting it would let a
// hostile recipe choose which record it overwrites.
//
// # Two halves, and only one of them writes
//
// Capture is a pure function of (root, cfg) -> Record (INV-4) that writes
// nothing (INV-5). Store is the deliberate exception: it writes, only ever
// inside the state directory, and refuses when that directory is inside a tree
// being examined with --offline-root. See store.go.
//
// # Nothing here executes anything
//
// INV-2 covers the obvious temptations and the non-obvious one. There is no call
// to makepkg (not even --printsrcinfo, which would evaluate the recipe being
// captured), no call to pacman, and no call to git: the git reads go through
// internal/vcs, which parses the object store, because pointing git at an
// attacker-controlled repository executes that repository's own configuration.
//
// # What a snapshot cannot say
//
// Every shortfall is a coverage gap attributable to the pkgbase (INV-9), never
// silence: an absent clone, a clone with no history, a .BUILDINFO that exists
// only inside a zstd archive the standard library cannot open, a source URL that
// does not resolve from the recipe's own text, an unknowable upstream commit. A
// record that omitted any of those quietly would later read as "there was
// none", which is a claim this capture is not entitled to make (INV-6).
package snapshot

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/pkgbuild"
	"github.com/lookatitude/aurvet/internal/pkgmeta"
	"github.com/lookatitude/aurvet/internal/vcs"
)

// SchemaVersion is the on-disk record version. A record written by a schema this
// build does not recognise reads as absent rather than as trusted (see
// Store.Latest), so this constant is the only thing a format change has to move.
const SchemaVersion = 1

// Gap rule identifiers. Each is a distinct evidence state with a distinct
// remedy, which is why they are not collapsed into one "incomplete snapshot":
// the answer to RuleNoClone is "capture at install time, this is gone", and the
// answer to RuleBuildInfo-from-zstd is "read the archive with something else".
const (
	// RuleNoClone is a pkgbase with no helper clone to capture from.
	RuleNoClone = "snapshot-no-clone"

	// RuleRecipe is a PKGBUILD that is absent, unreadable, or whose text does
	// not fully resolve.
	RuleRecipe = "snapshot-pkgbuild"

	// RuleSRCINFO is a .SRCINFO that is absent or could not be parsed.
	RuleSRCINFO = "snapshot-srcinfo"

	// RuleBuildInfo is a .BUILDINFO that could not be captured -- absent, or
	// present only inside an archive whose compression is not readable here.
	RuleBuildInfo = "snapshot-buildinfo"

	// RuleGit is history, a remote or a HEAD that could not be read.
	RuleGit = "snapshot-git"

	// RuleUpstream is a VCS source whose built commit is unknown, or two
	// sources of that commit that disagree.
	RuleUpstream = "snapshot-upstream-commit"

	// RuleKeyMismatch is a recorded pkgbase that differs from the key. Never
	// reconciled.
	RuleKeyMismatch = "snapshot-pkgbase-mismatch"

	// RuleNotRetained is a file that was digested but whose bytes were not
	// retained, because retaining them would have exceeded a bound.
	RuleNotRetained = "snapshot-content-not-retained"

	// RuleVCSState is a helper VCS state file (yay/paru vcs.json) that could not
	// be read or parsed.
	RuleVCSState = "snapshot-helper-vcs-state"
)

// SubjectPkgBase is the subject kind for gaps from this package. It names the
// unit a snapshot describes, which is the base and never the package name.
const SubjectPkgBase = "pkgbase"

// Origins for a captured source entry and for a captured upstream commit. They
// are recorded because two origins can disagree, and a record that did not say
// where a commit came from could not report the disagreement.
const (
	// OriginPKGBUILD is a source resolved from the recipe's own text.
	OriginPKGBUILD = "pkgbuild"

	// OriginSRCINFO is a source as .SRCINFO declares it -- what makepkg
	// actually consumed.
	OriginSRCINFO = "srcinfo"

	// OriginSrcdirClone is an upstream commit read from the VCS checkout
	// makepkg left beside the PKGBUILD.
	OriginSrcdirClone = "srcdir-clone"

	// OriginHelperVCSState is an upstream commit read from a helper's own
	// record of what it built (yay's vcs.json). The path is appended.
	OriginHelperVCSState = "helper-vcs-state"
)

// Limits bounds everything an attacker-controlled clone sizes. Exported and
// copyable so a caller can tighten one bound and a test can prove each fires.
type Limits struct {
	// MaxFileBytes caps one metadata file READ. Measured over the 34 cached
	// clones on the reference system (2026-08-05): the largest .SRCINFO is
	// 17,715 B and the largest PKGBUILD 31,869 B (both `flutter`, a base that
	// builds 17 packages), and a desktop .BUILDINFO runs to ~120 KiB.
	MaxFileBytes int64

	// MaxRetainBytes caps the bytes RETAINED verbatim for one file. Above it the
	// digest is still recorded and the omission becomes a RuleNotRetained gap --
	// a snapshot must not be a way to grow the state directory to the size of a
	// hostile recipe.
	MaxRetainBytes int64

	// MaxClones caps the clones captured for one pkgbase. A base legitimately
	// appears in two helpers' caches with different contents; more than a
	// handful is not a real system.
	MaxClones int

	// MaxLogCommits caps the commit summary. The longest history in the
	// reference cache is 565 commits; the summary is evidence of who touched
	// the recipe recently, not a mirror of the repository.
	MaxLogCommits int

	// MaxSources caps the recorded source entries across both origins.
	MaxSources int

	// MaxPkgDirEntries caps the pkg/<pkgname> directories searched for a
	// .BUILDINFO.
	MaxPkgDirEntries int

	// MaxArchives caps the package archives recorded and inspected.
	MaxArchives int

	// MaxVCSStateBytes caps one helper VCS state file (yay's vcs.json).
	MaxVCSStateBytes int64

	// MaxUpstreamRepos caps the VCS source checkouts opened in one clone.
	MaxUpstreamRepos int
}

// DefaultLimits returns bounds with headroom over the measured worst case
// rather than fitted to it.
func DefaultLimits() Limits {
	return Limits{
		MaxFileBytes:     8 << 20,
		MaxRetainBytes:   256 << 10,
		MaxClones:        8,
		MaxLogCommits:    10,
		MaxSources:       256,
		MaxPkgDirEntries: 4096,
		MaxArchives:      64,
		MaxVCSStateBytes: 16 << 20,
		MaxUpstreamRepos: 16,
	}
}

// withDefaults fills unset fields, so a caller can tighten one bound without
// restating the rest and the zero Limits means "the defaults".
func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxRetainBytes <= 0 {
		l.MaxRetainBytes = d.MaxRetainBytes
	}
	if l.MaxClones <= 0 {
		l.MaxClones = d.MaxClones
	}
	if l.MaxLogCommits <= 0 {
		l.MaxLogCommits = d.MaxLogCommits
	}
	if l.MaxSources <= 0 {
		l.MaxSources = d.MaxSources
	}
	if l.MaxPkgDirEntries <= 0 {
		l.MaxPkgDirEntries = d.MaxPkgDirEntries
	}
	if l.MaxArchives <= 0 {
		l.MaxArchives = d.MaxArchives
	}
	if l.MaxVCSStateBytes <= 0 {
		l.MaxVCSStateBytes = d.MaxVCSStateBytes
	}
	if l.MaxUpstreamRepos <= 0 {
		l.MaxUpstreamRepos = d.MaxUpstreamRepos
	}
	return l
}

// Config is everything Capture is allowed to know. There is no ambient input:
// no environment, no working directory, no $HOME (INV-4).
type Config struct {
	// PkgBase is the key. Validated before it reaches a path.
	PkgBase string

	// Clones are the clone directories to capture from, which the caller
	// obtained from helper.Detection.Clones(PkgBase) -- already pkgbase-keyed.
	// Empty is a coverage gap, not an empty record.
	Clones []helper.Clone

	// VCSStateFiles are root-relative helper VCS state files (yay's
	// vcs.json), in the order to consult them. They are supplied rather than
	// guessed: which helper keeps what where is configuration
	// (helper.DefaultLayouts), and a hardcoded path stops working silently.
	VCSStateFiles []string

	// CapturedAt stamps the record. Supplied so a capture is reproducible and
	// the record's content digest does not depend on the clock.
	CapturedAt time.Time

	// Limits bounds the traversal. The zero value means DefaultLimits.
	Limits Limits

	// VCS bounds the git reads. The zero value means vcs.DefaultLimits.
	VCS vcs.Limits

	// PkgMeta bounds the .SRCINFO / .BUILDINFO parses. The zero value means
	// pkgmeta.DefaultLimits.
	PkgMeta pkgmeta.Limits
}

// FileRecord is one captured file: always its digest and size, and its bytes
// when they fit under Limits.MaxRetainBytes.
//
// Retained is explicit rather than inferred from an empty Text, because an empty
// file and a file whose text was dropped are different facts and only the second
// one comes with a gap.
type FileRecord struct {
	Path     string `json:"path"`
	Bytes    int64  `json:"bytes"`
	SHA256   string `json:"sha256"`
	Text     string `json:"text,omitempty"`
	Retained bool   `json:"retained"`
}

// BuildInfoRecord is the part of a .BUILDINFO worth keeping.
//
// pkgbuild_sha256sum is the reason this file matters at all: it is the only
// local evidence that the recipe on disk is the recipe that was built, and it
// exists nowhere in the pacman local database. The `installed` list is COUNTED
// and not retained -- it is the bulk of the file (~120 KiB on a desktop build)
// and it describes the build host's package set, which the baseline records
// anyway.
type BuildInfoRecord struct {
	Path   string `json:"path"`
	Bytes  int64  `json:"bytes"`
	SHA256 string `json:"sha256"`

	// From is where the file was read from: a path in the clone, or the
	// archive member it came out of.
	From string `json:"from"`

	Format         string `json:"format,omitempty"`
	PkgName        string `json:"pkgname,omitempty"`
	PkgBase        string `json:"pkgbase,omitempty"`
	PkgVer         string `json:"pkgver,omitempty"`
	PkgArch        string `json:"pkgarch,omitempty"`
	Packager       string `json:"packager,omitempty"`
	PkgBuildSHA256 string `json:"pkgbuild_sha256sum,omitempty"`
	BuildDir       string `json:"builddir,omitempty"`
	StartDir       string `json:"startdir,omitempty"`
	BuildTool      string `json:"buildtool,omitempty"`
	BuildToolVer   string `json:"buildtoolver,omitempty"`
	BuildDateRaw   string `json:"builddate,omitempty"`

	// InstalledCount is the length of the unretained `installed` list.
	InstalledCount int `json:"installed_count"`

	// Missing names the fields a provenance check depends on and did not get.
	Missing []string `json:"missing,omitempty"`
}

// CommitRecord is one line of the git log summary. The full message is not
// retained (see Record.Notes): the subject is what a review renders for a range.
type CommitRecord struct {
	Hash string `json:"hash"`

	// Author is "Name <email>", as the commit wrote it.
	Author string `json:"author"`

	// Date is RFC3339 carrying the offset the COMMIT was written with, never
	// the reader's zone: a date rewritten into the reader's zone is evidence
	// about the reader.
	Date string `json:"date"`

	Subject string `json:"subject"`
}

// GitRecord is the clone's own history summary.
type GitRecord struct {
	// Dir is the root-relative repository directory.
	Dir string `json:"dir"`

	Head string `json:"head,omitempty"`

	// Remote is the origin URL VERBATIM. It is never normalised and never
	// acted on: a URL like "ext::sh -c ..." is evidence, and reporting it as
	// written is the point.
	Remote string `json:"remote,omitempty"`

	Log []CommitRecord `json:"log,omitempty"`

	// LogTruncated reports that the history is longer than the summary.
	LogTruncated bool `json:"log_truncated,omitempty"`
}

// SourceRecord is one source entry as captured.
type SourceRecord struct {
	// Origin is OriginPKGBUILD or OriginSRCINFO. Both are recorded: the recipe
	// text is what resolves and .SRCINFO is what makepkg consumed, and a
	// difference between them is itself worth seeing.
	Origin string `json:"origin"`

	Arch string `json:"arch,omitempty"`
	Raw  string `json:"raw"`
	Name string `json:"name,omitempty"`
	URL  string `json:"url,omitempty"`

	VCS      string `json:"vcs,omitempty"`
	Fragment string `json:"fragment,omitempty"`
	Local    bool   `json:"local,omitempty"`

	// Resolved is false when the entry could not be resolved from the recipe's
	// text; Reason then states what defeated it (INV-6).
	Resolved bool   `json:"resolved"`
	Reason   string `json:"reason,omitempty"`
}

// UpstreamRecord is the upstream commit that was built for one VCS source.
//
// This is what makes a -git approval possible at all: the recipe is stable while
// the source moves, so an approval keyed on the recipe alone blesses every
// future commit. The recorded commit is the left end of the range a later review
// shows.
type UpstreamRecord struct {
	// Source is the source entry's local name.
	Source string `json:"source,omitempty"`

	URL      string `json:"url,omitempty"`
	VCS      string `json:"vcs,omitempty"`
	Fragment string `json:"fragment,omitempty"`

	Commit string `json:"commit"`

	// Origin says where the commit came from, because two origins can
	// disagree and a record that did not say could not report it.
	Origin string `json:"origin"`
}

// CloneRecord is everything captured from one clone directory.
type CloneRecord struct {
	// Helper is the layout the clone was found under.
	Helper string `json:"helper"`

	// Dir is the root-relative clone directory.
	Dir string `json:"dir"`

	PKGBUILD  *FileRecord      `json:"pkgbuild,omitempty"`
	SRCINFO   *FileRecord      `json:"srcinfo,omitempty"`
	BuildInfo *BuildInfoRecord `json:"buildinfo,omitempty"`

	// SRCINFOPkgBase and RecipePkgBase are the bases the two files declare,
	// recorded verbatim. A difference from Record.PkgBase is a gap, never a
	// re-key.
	SRCINFOPkgBase string `json:"srcinfo_pkgbase,omitempty"`
	RecipePkgBase  string `json:"pkgbuild_pkgbase,omitempty"`

	// PkgNames are the output packages this one recipe builds. For a split
	// base there are several, and that is exactly why the record is keyed on
	// the base above them.
	PkgNames []string `json:"pkgnames,omitempty"`

	Git      *GitRecord       `json:"git,omitempty"`
	Sources  []SourceRecord   `json:"sources,omitempty"`
	Upstream []UpstreamRecord `json:"upstream,omitempty"`

	// Archives are the package archive file names present in the clone. They
	// are recorded even when unreadable here: naming them is what turns "no
	// .BUILDINFO" into "a .BUILDINFO exists in a file I could not open".
	Archives []string `json:"archives,omitempty"`
}

// Record is one snapshot: one pkgbase, one point in time.
type Record struct {
	SchemaVersion int    `json:"schema_version"`
	PkgBase       string `json:"pkgbase"`

	// CapturedAt is RFC3339 UTC.
	CapturedAt string `json:"captured_at"`

	Clones []CloneRecord `json:"clones,omitempty"`

	// Notes state what this record deliberately does not hold, so a later
	// reader does not mistake a bounded capture for the whole truth (INV-6).
	Notes []string `json:"notes,omitempty"`

	// Gaps are the shortfalls, as finding.Gap so a caller merging them into a
	// report cannot invent a second format.
	Gaps []finding.Gap `json:"gaps,omitempty"`
}

// Complete reports whether the capture got everything it went looking for. A
// snapshot with gaps is still worth storing -- it is more than the cache will
// hold tomorrow -- but it must not be presented as a full record.
func (r Record) Complete() bool { return len(r.Gaps) == 0 }

// Digest is a stable content digest of the record with CapturedAt cleared, so
// two captures of an unchanged clone digest the same. That is what lets Store
// skip a write instead of adding a file per scan.
func (r Record) Digest() string {
	r.CapturedAt = ""
	blob, err := json.Marshal(r)
	if err != nil {
		// Every field is a string, number, bool or slice thereof, so this is
		// unreachable; a digest of the error is still stable and still differs
		// from any real record's.
		return sha256hex([]byte("snapshot: unmarshalable record: " + err.Error()))
	}
	return sha256hex(blob)
}

func sha256hex(b []byte) string {
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}

// Capture reads the provenance of one pkgbase out of the clones it was given.
//
// It is a pure function of (root, cfg): the same arguments produce the same
// record, byte for byte, with no dependence on the clock, the environment or the
// working directory. It writes nothing (INV-5).
//
// The error return is for a request that cannot be honoured at all -- no root,
// or a pkgbase that is not a usable key. Everything else that goes wrong is a
// gap on the returned record, because a partial snapshot of a disappearing cache
// is worth more than a refusal.
func Capture(root *os.Root, cfg Config) (Record, error) {
	if root == nil {
		return Record{}, errors.New("snapshot: no filesystem root supplied, so nothing was captured")
	}
	if err := ValidPkgBase(cfg.PkgBase); err != nil {
		return Record{}, err
	}
	lim := cfg.Limits.withDefaults()

	rec := Record{
		SchemaVersion: SchemaVersion,
		PkgBase:       cfg.PkgBase,
		CapturedAt:    cfg.CapturedAt.UTC().Format(time.RFC3339),
	}
	rec.Notes = append(rec.Notes,
		fmt.Sprintf("commit messages are summarised to their subject line and the log is capped at %d commits", lim.MaxLogCommits),
		"the .BUILDINFO `installed` list is counted, not retained: it describes the build host's package set and is the bulk of the file",
	)

	if len(cfg.Clones) == 0 {
		rec.gap(RuleNoClone, cfg.PkgBase,
			"no helper cache clone was found for this pkgbase, so the PKGBUILD that was built, its history, "+
				"its remote and the upstream commit could not be captured; this is the ephemerality this command "+
				"exists to fix and it has already happened here")
		return rec, nil
	}

	clones := cfg.Clones
	if len(clones) > lim.MaxClones {
		rec.gap(RuleNoClone, cfg.PkgBase,
			fmt.Sprintf("pkgbase appears in more than %d clone directories; the rest were not captured", lim.MaxClones))
		clones = clones[:lim.MaxClones]
	}

	state := readVCSState(root, cfg, lim, &rec)

	for _, cl := range clones {
		rec.Clones = append(rec.Clones, captureClone(root, cfg, lim, cl, state, &rec))
	}
	return rec, nil
}

// gap appends a shortfall, de-duplicated so a repeated cause does not read as
// several independent ones.
func (r *Record) gap(rule, subject, reason string) {
	g := finding.Gap{RuleID: rule, Subject: subject, Reason: reason}
	for _, have := range r.Gaps {
		if have == g {
			return
		}
	}
	r.Gaps = append(r.Gaps, g)
}

// captureClone reads one clone directory.
func captureClone(root *os.Root, cfg Config, lim Limits, cl helper.Clone, state vcsState, rec *Record) CloneRecord {
	out := CloneRecord{Helper: cl.Helper, Dir: cl.Dir}

	// --- the recipe -------------------------------------------------------
	var res pkgbuild.Resolution
	if f, ok := captureFile(root, path.Join(cl.Dir, "PKGBUILD"), lim, rec, RuleRecipe); ok {
		out.PKGBUILD = f
		// The recipe is only tokenised and resolved. Nothing in it is
		// evaluated: pkgbuild.Lex parses shell, it does not run it.
		if f.Retained {
			res = pkgbuild.Resolve(pkgbuild.Lex([]byte(f.Text)), pkgbuild.ResolveConfig{})
			out.RecipePkgBase = res.Pkgbase
			for _, u := range res.Unresolved {
				rec.gap(RuleRecipe, cl.Dir,
					fmt.Sprintf("a value in PKGBUILD could not be resolved from the recipe's own text (%q: %s); "+
						"the source list captured here is incomplete", firstN(u.Raw, 80), u.Reason))
			}
		}
	} else {
		rec.gap(RuleRecipe, cl.Dir,
			"no readable PKGBUILD in this clone, so the recipe that was built cannot be captured or diffed later")
	}

	// --- .SRCINFO ---------------------------------------------------------
	if f, ok := captureFile(root, path.Join(cl.Dir, ".SRCINFO"), lim, rec, RuleSRCINFO); ok {
		out.SRCINFO = f
		si, err := pkgmeta.SRCINFOFromFile(root, path.Join(cl.Dir, ".SRCINFO"), cfg.PkgMeta)
		if err != nil {
			rec.gap(RuleSRCINFO, cl.Dir, fmt.Sprintf(".SRCINFO could not be parsed (%v), so the declared "+
				"packages and sources were not captured; the file's digest is still recorded", err))
		} else {
			out.SRCINFOPkgBase = si.PkgBase
			out.PkgNames = si.PkgNames()
			for _, g := range si.Gaps(cl.Dir) {
				rec.gap(RuleSRCINFO, g.Subject, g.Reason)
			}
		}
	} else {
		rec.gap(RuleSRCINFO, cl.Dir,
			"no readable .SRCINFO in this clone, so the declared package set and sources were not captured; "+
				"it is NOT regenerated here, because that would mean executing the recipe (INV-2)")
	}

	// The key is never re-derived from what the files claim.
	for _, claim := range []struct{ what, base string }{
		{".SRCINFO", out.SRCINFOPkgBase},
		{"PKGBUILD", out.RecipePkgBase},
	} {
		if claim.base != "" && claim.base != cfg.PkgBase {
			rec.gap(RuleKeyMismatch, cfg.PkgBase,
				fmt.Sprintf("%s in %s declares pkgbase %q while the clone is filed under %q; the record stays "+
					"keyed on the clone directory and the declared value is recorded as-is, because adopting it "+
					"would let a recipe choose which snapshot it overwrites",
					claim.what, cl.Dir, firstN(claim.base, 80), cfg.PkgBase))
		}
	}

	// --- .BUILDINFO -------------------------------------------------------
	out.Archives = archivesIn(root, cl.Dir, lim)
	out.BuildInfo = captureBuildInfo(root, cfg, lim, cl, out.Archives, rec)
	if out.BuildInfo != nil && out.BuildInfo.PkgBase != "" && out.BuildInfo.PkgBase != cfg.PkgBase {
		rec.gap(RuleKeyMismatch, cfg.PkgBase,
			fmt.Sprintf(".BUILDINFO in %s declares pkgbase %q while the clone is filed under %q; recorded, not reconciled",
				cl.Dir, firstN(out.BuildInfo.PkgBase, 80), cfg.PkgBase))
	}

	// --- git --------------------------------------------------------------
	out.Git = captureGit(root, cfg, lim, cl, rec)

	// --- sources and the upstream commit ----------------------------------
	out.Sources = captureSources(root, cfg, lim, cl, res, rec)
	out.Upstream = captureUpstream(root, cfg, lim, cl, out.Sources, state, rec)
	return out
}

// captureFile reads one file under the clone, digests all of it, and retains its
// bytes when they fit.
func captureFile(root *os.Root, rel string, lim Limits, rec *Record, rule string) (*FileRecord, bool) {
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		if !errors.Is(err, fs.ErrNotExist) {
			rec.gap(rule, rel, fmt.Sprintf("could not be opened: %v; a symlink or non-regular file here is "+
				"refused unresolved rather than followed", err))
		}
		return nil, false
	}
	defer f.Close()

	if st.Size > lim.MaxFileBytes {
		rec.gap(rule, rel, fmt.Sprintf("is %d bytes, over the %d byte cap, and was not read at all", st.Size, lim.MaxFileBytes))
		return nil, false
	}
	// LimitReader rather than trusting the fstat size: a file can grow between
	// the fstat and the read, and the cap is the thing that has to hold.
	data, err := io.ReadAll(io.LimitReader(f, lim.MaxFileBytes+1))
	if err != nil {
		rec.gap(rule, rel, fmt.Sprintf("could not be read: %v", err))
		return nil, false
	}
	if int64(len(data)) > lim.MaxFileBytes {
		rec.gap(rule, rel, fmt.Sprintf("exceeds the %d byte cap", lim.MaxFileBytes))
		return nil, false
	}

	out := &FileRecord{Path: rel, Bytes: int64(len(data)), SHA256: sha256hex(data)}
	if int64(len(data)) <= lim.MaxRetainBytes {
		out.Text = string(data)
		out.Retained = true
	} else {
		rec.gap(RuleNotRetained, rel, fmt.Sprintf("is %d bytes, over the %d byte retention cap; its digest is "+
			"recorded but its contents are not, so a later diff against this record cannot show the text",
			len(data), lim.MaxRetainBytes))
	}
	return out, true
}

// archivesIn lists the built package archives sitting in the clone, sorted.
func archivesIn(root *os.Root, dir string, lim Limits) []string {
	ents, err := fs.ReadDir(root.FS(), dir)
	if err != nil {
		return nil
	}
	var out []string
	for _, e := range ents {
		name := e.Name()
		if !strings.Contains(name, ".pkg.tar") || e.IsDir() {
			continue
		}
		if len(out) >= lim.MaxArchives {
			break
		}
		out = append(out, name)
	}
	sort.Strings(out)
	return out
}

// captureBuildInfo finds a .BUILDINFO for this clone, in order of how directly
// it describes the build: the clone root, then a build directory left behind
// under pkg/<pkgname>/, then inside a package archive.
//
// The archive path is where this gets honest about a limitation. .BUILDINFO is
// archive-only for an installed package, and Arch's archives are zstd, which the
// standard library cannot decompress -- so on the reference system this normally
// ends in a gap NAMING zstd rather than in a captured file. That is the right
// outcome: "there is a .BUILDINFO in a file I cannot open" and "there is no
// .BUILDINFO" are different statements, and only the first is true.
func captureBuildInfo(root *os.Root, cfg Config, lim Limits, cl helper.Clone, archives []string, rec *Record) *BuildInfoRecord {
	for _, rel := range buildInfoCandidates(root, cl.Dir, lim) {
		f, ok := captureFile(root, rel, lim, rec, RuleBuildInfo)
		if !ok {
			continue
		}
		bi, err := pkgmeta.BuildInfoFromFile(root, rel, cfg.PkgMeta)
		if err != nil {
			rec.gap(RuleBuildInfo, rel, fmt.Sprintf(".BUILDINFO could not be parsed: %v", err))
			continue
		}
		return buildInfoRecord(f, rel, bi, rec)
	}

	// Unreadable archives are counted per algorithm and reported ONCE, not once
	// each. Measured on the reference system: brave-bin keeps 28 old
	// .pkg.tar.zst archives and cursor-bin 41, so a gap per archive made the
	// record mostly repetitions of one sentence -- 267 gaps across 34 clones,
	// against 34 distinct facts. A gap an operator scrolls past is a gap that
	// does not work.
	unreadable := map[string][]string{}
	for _, name := range archives {
		rel := path.Join(cl.Dir, name)
		algo, supported := pkgmeta.CompressionOf(name)
		if !supported {
			unreadable[algo] = append(unreadable[algo], name)
			continue
		}
		af, _, err := fsx.OpenConfined(root, rel)
		if err != nil {
			rec.gap(RuleBuildInfo, rel, fmt.Sprintf("package archive could not be opened: %v", err))
			continue
		}
		bi, err := pkgmeta.BuildInfoFromArchive(name, af, cfg.PkgMeta)
		af.Close()
		if err != nil {
			rec.gap(RuleBuildInfo, rel, fmt.Sprintf(".BUILDINFO could not be read out of the archive: %v", err))
			continue
		}
		// The archive member's bytes are not re-read for a digest: the parse
		// consumed the stream, and a second pass over a decompressed archive is
		// not a cost a snapshot needs to pay for a digest of a member.
		return buildInfoRecord(&FileRecord{Path: rel}, rel+"!"+".BUILDINFO", bi, rec)
	}

	algos := make([]string, 0, len(unreadable))
	for algo := range unreadable {
		algos = append(algos, algo)
	}
	sort.Strings(algos)
	for _, algo := range algos {
		names := unreadable[algo]
		rec.gap(RuleBuildInfo, cl.Dir, fmt.Sprintf("%d built package archive(s) in this clone are %s-compressed "+
			"(e.g. %s), which is not decompressible with the standard library, so the .BUILDINFO inside them -- "+
			"and with it pkgbuild_sha256sum, the only local evidence that this recipe is the recipe that was "+
			"built -- was not captured; this is a gap, not an absent .BUILDINFO",
			len(names), algo, strings.Join(names[:min(len(names), 2)], ", ")))
	}

	rec.gap(RuleBuildInfo, cl.Dir, "no .BUILDINFO was found for this pkgbase, so pkgbuild_sha256sum -- the only "+
		"local evidence that the captured recipe is the recipe that was built -- is unavailable; absence of a "+
		"recipe-mismatch finding for this package is therefore not a clean result")
	return nil
}

// buildInfoCandidates lists the .BUILDINFO paths to try inside a clone.
func buildInfoCandidates(root *os.Root, dir string, lim Limits) []string {
	out := []string{path.Join(dir, ".BUILDINFO")}
	ents, err := fs.ReadDir(root.FS(), path.Join(dir, "pkg"))
	if err != nil {
		return out
	}
	n := 0
	for _, e := range ents {
		if !e.IsDir() {
			continue
		}
		if n++; n > lim.MaxPkgDirEntries {
			break
		}
		out = append(out, path.Join(dir, "pkg", e.Name(), ".BUILDINFO"))
	}
	return out
}

func buildInfoRecord(f *FileRecord, from string, bi pkgmeta.BuildInfo, rec *Record) *BuildInfoRecord {
	out := &BuildInfoRecord{
		Path:           f.Path,
		Bytes:          f.Bytes,
		SHA256:         f.SHA256,
		From:           from,
		Format:         bi.Format,
		PkgName:        bi.PkgName,
		PkgBase:        bi.PkgBase,
		PkgVer:         bi.PkgVer,
		PkgArch:        bi.PkgArch,
		Packager:       bi.Packager,
		PkgBuildSHA256: bi.PkgBuildSHA256,
		BuildDir:       bi.BuildDir,
		StartDir:       bi.StartDir,
		BuildTool:      bi.BuildTool,
		BuildToolVer:   bi.BuildToolVer,
		BuildDateRaw:   bi.BuildDateRaw,
		InstalledCount: len(bi.Installed),
		Missing:        bi.Missing(),
	}
	for _, g := range bi.Gaps(from) {
		rec.gap(RuleBuildInfo, g.Subject, g.Reason)
	}
	return out
}

// captureGit reads HEAD, the remote and a bounded log summary.
//
// internal/vcs takes a directory PATH rather than an *os.Root, so the absolute
// path is derived from root.Name(). A root opened with a relative path would
// make that path depend on the process working directory, which is the ambient
// input INV-4 forbids -- so it is refused as a gap rather than resolved against
// the CWD.
func captureGit(root *os.Root, cfg Config, lim Limits, cl helper.Clone, rec *Record) *GitRecord {
	if !cl.HasGitDir && !hasBareLayout(root, cl.Dir) {
		rec.gap(RuleGit, cl.Dir, "clone has no git directory, so the recipe's history, its author and its remote "+
			"could not be captured; a clone whose .git is a FILE pointing elsewhere reads as absent here and is "+
			"deliberately not followed")
		return nil
	}
	abs, ok := absDir(root, cl.Dir)
	if !ok {
		rec.gap(RuleGit, cl.Dir, "the scanned root was not opened with an absolute path, so no repository path "+
			"could be derived without consulting the process working directory; the history was not read")
		return nil
	}

	r, err := vcs.Open(abs, cfg.VCS)
	if err != nil {
		rec.gap(RuleGit, cl.Dir, fmt.Sprintf("git directory could not be opened: %v", err))
		return nil
	}
	defer r.Close()

	out := &GitRecord{Dir: cl.Dir}
	if head, err := r.Head(); err != nil {
		rec.gap(RuleGit, cl.Dir, fmt.Sprintf("HEAD did not resolve: %v; the commit of the recipe that was built is unknown", err))
	} else {
		out.Head = head
	}
	if remote, err := r.Remote(); err != nil {
		rec.gap(RuleGit, cl.Dir, fmt.Sprintf("no origin remote could be read: %v; the URL this recipe came from is unknown", err))
	} else {
		out.Remote = remote
	}

	// One more than the cap, so a longer history is reported as truncated
	// rather than as ending where the summary does.
	commits, err := r.Log("", lim.MaxLogCommits+1)
	if err != nil {
		rec.gap(RuleGit, cl.Dir, fmt.Sprintf("the commit history could not be fully read: %v", err))
	}
	if len(commits) > lim.MaxLogCommits {
		commits = commits[:lim.MaxLogCommits]
		out.LogTruncated = true
	}
	for _, c := range commits {
		out.Log = append(out.Log, CommitRecord{
			Hash:    c.Hash,
			Author:  fmt.Sprintf("%s <%s>", c.Author.Name, c.Author.Email),
			Date:    c.Author.When.Format(time.RFC3339),
			Subject: c.Subject,
		})
	}
	for _, g := range r.Gaps() {
		rec.gap(RuleGit, g.Subject, g.Reason)
	}
	return out
}

// hasBareLayout reports a git directory sitting directly in dir. helper.Clone
// only records a .git DIRECTORY, and a VCS source checkout is bare.
func hasBareLayout(root *os.Root, dir string) bool {
	fsys := root.FS()
	if st, err := fs.Stat(fsys, path.Join(dir, "HEAD")); err != nil || !st.Mode().IsRegular() {
		return false
	}
	st, err := fs.Stat(fsys, path.Join(dir, "objects"))
	return err == nil && st.IsDir()
}

// absDir joins a root-relative path onto the root's own path, refusing to do so
// when the root was opened relatively (see captureGit).
func absDir(root *os.Root, rel string) (string, bool) {
	name := root.Name()
	if !filepath.IsAbs(name) {
		return "", false
	}
	return filepath.Join(name, filepath.FromSlash(rel)), true
}

// captureSources records the source list from both the resolved recipe and
// .SRCINFO.
func captureSources(root *os.Root, cfg Config, lim Limits, cl helper.Clone, res pkgbuild.Resolution, rec *Record) []SourceRecord {
	var out []SourceRecord
	add := func(s SourceRecord) {
		if len(out) >= lim.MaxSources {
			rec.gap(RuleRecipe, cl.Dir, fmt.Sprintf("more than %d source entries; the rest were not captured", lim.MaxSources))
			return
		}
		out = append(out, s)
	}

	for _, s := range res.Sources {
		add(SourceRecord{
			Origin:   OriginPKGBUILD,
			Arch:     s.Arch,
			Raw:      s.Value.Raw,
			Name:     s.Name,
			URL:      s.URL,
			VCS:      s.VCS,
			Fragment: s.Fragment,
			Local:    s.Local,
			Resolved: s.Value.OK(),
			Reason:   s.Value.Reason,
		})
	}

	si, err := pkgmeta.SRCINFOFromFile(root, path.Join(cl.Dir, ".SRCINFO"), cfg.PkgMeta)
	if err == nil {
		for _, s := range si.Sources() {
			add(SourceRecord{
				Origin:   OriginSRCINFO,
				Arch:     s.Arch,
				Raw:      s.Raw,
				Name:     s.Name,
				URL:      s.Location,
				VCS:      s.VCS,
				Fragment: s.Fragment,
				Local:    !s.IsRemote && !s.IsVCS,
				Resolved: true,
			})
		}
	}
	return out
}

// captureUpstream records the upstream commit built for every VCS source, from
// each independent origin that knows it.
//
// Two origins exist and they are consulted separately on purpose. The srcdir
// checkout beside the PKGBUILD is the most direct evidence and is the first
// thing a `git clean` removes; the helper's own vcs.json survives that but only
// says what the helper last recorded. When both answer and they disagree, both
// are recorded and the disagreement is a gap: picking one would manufacture a
// fact, and a force-pushed or swapped upstream is exactly the case worth seeing.
func captureUpstream(root *os.Root, cfg Config, lim Limits, cl helper.Clone, sources []SourceRecord, state vcsState, rec *Record) []UpstreamRecord {
	var out []UpstreamRecord
	opened := 0
	seenSource := map[string]bool{}

	for _, s := range sources {
		if s.VCS == "" || s.URL == "" || seenSource[s.Name+"\x00"+s.URL] {
			continue
		}
		seenSource[s.Name+"\x00"+s.URL] = true

		var found []UpstreamRecord
		if s.Name != "" && opened < lim.MaxUpstreamRepos {
			if sha, ok := srcdirCommit(root, cfg, cl.Dir, s.Name); ok {
				opened++
				found = append(found, UpstreamRecord{
					Source: s.Name, URL: s.URL, VCS: s.VCS, Fragment: s.Fragment,
					Commit: sha, Origin: OriginSrcdirClone,
				})
			}
		}
		for _, e := range state.lookup(cfg.PkgBase, s.URL) {
			found = append(found, UpstreamRecord{
				Source: s.Name, URL: s.URL, VCS: s.VCS, Fragment: s.Fragment,
				Commit: e.sha, Origin: OriginHelperVCSState + ":" + e.from,
			})
		}

		if len(found) == 0 {
			rec.gap(RuleUpstream, cl.Dir, fmt.Sprintf("source %q is a %s checkout and the commit that was built "+
				"is not recorded anywhere reachable (no checkout beside the PKGBUILD, nothing in a helper's VCS "+
				"state); the recipe is stable while this source moves, so an approval of the recipe alone would "+
				"bless every future commit", firstN(s.URL, 80), s.VCS))
		}
		if distinct(found) > 1 {
			rec.gap(RuleUpstream, cl.Dir, fmt.Sprintf("two records of the upstream commit for %q disagree (%s); "+
				"both are recorded and neither is preferred", firstN(s.URL, 80), describe(found)))
		}
		out = append(out, found...)
	}
	return out
}

func distinct(recs []UpstreamRecord) int {
	seen := map[string]bool{}
	for _, r := range recs {
		seen[r.Commit] = true
	}
	return len(seen)
}

func describe(recs []UpstreamRecord) string {
	parts := make([]string, 0, len(recs))
	for _, r := range recs {
		parts = append(parts, fmt.Sprintf("%s says %s", r.Origin, firstN(r.Commit, 12)))
	}
	return strings.Join(parts, ", ")
}

// srcdirCommit reads HEAD out of the VCS checkout makepkg leaves beside the
// PKGBUILD. The name comes from the source entry, so it is attacker-influenced
// and is refused unless it is a single safe path component.
func srcdirCommit(root *os.Root, cfg Config, dir, name string) (string, bool) {
	if !safeComponent(name) {
		return "", false
	}
	rel := path.Join(dir, name)
	if !hasBareLayout(root, rel) {
		if st, err := fs.Stat(root.FS(), path.Join(rel, ".git")); err != nil || !st.IsDir() {
			return "", false
		}
	}
	abs, ok := absDir(root, rel)
	if !ok {
		return "", false
	}
	r, err := vcs.Open(abs, cfg.VCS)
	if err != nil {
		return "", false
	}
	defer r.Close()
	sha, err := r.Head()
	if err != nil {
		return "", false
	}
	return sha, true
}

// safeComponent accepts a single path component with nothing in it that changes
// where a path points.
func safeComponent(s string) bool {
	if s == "" || s == "." || s == ".." || len(s) > 255 {
		return false
	}
	return !strings.ContainsAny(s, "/\x00")
}

// --- helper VCS state -----------------------------------------------------

// vcsEntry is one recorded upstream commit and the file it came from.
type vcsEntry struct {
	sha  string
	from string
}

// vcsState is the parsed helper VCS state: pkgbase -> repository -> entry.
//
// This is yay's vcs.json shape, and it is read as DATA -- json.Unmarshal into a
// map, no execution, no path taken from the file. Measured on the reference
// system: one entry, `viewmd` -> github.com/rabfulton/ViewMD.git -> sha, which is
// the only place the upstream commit built survives once makepkg's srcdir is
// cleaned.
type vcsState struct {
	byBase map[string]map[string]vcsEntry
}

func (v vcsState) lookup(pkgbase, url string) []vcsEntry {
	repos := v.byBase[pkgbase]
	if len(repos) == 0 {
		return nil
	}
	// The keys are the helper's own normalisation of the URL (host + path, no
	// scheme), so the lookup compares on that shape rather than on the raw
	// string. Both directions are tried and nothing is rewritten in the record.
	want := normaliseRepoURL(url)
	var out []vcsEntry
	keys := make([]string, 0, len(repos))
	for k := range repos {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	for _, k := range keys {
		if normaliseRepoURL(k) == want {
			out = append(out, repos[k])
		}
	}
	return out
}

// normaliseRepoURL reduces a URL to host and path for comparison only. The
// recorded URL is always the one the recipe wrote.
func normaliseRepoURL(u string) string {
	s := u
	if i := strings.Index(s, "://"); i >= 0 {
		s = s[i+3:]
	}
	s = strings.TrimSuffix(s, "/")
	return strings.TrimSuffix(s, ".git")
}

// readVCSState parses every configured helper VCS state file.
func readVCSState(root *os.Root, cfg Config, lim Limits, rec *Record) vcsState {
	state := vcsState{byBase: map[string]map[string]vcsEntry{}}
	for _, rel := range cfg.VCSStateFiles {
		f, st, err := fsx.OpenConfined(root, rel)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				rec.gap(RuleVCSState, rel, fmt.Sprintf("helper VCS state file could not be opened: %v; the "+
					"upstream commits it records were not read", err))
			}
			continue
		}
		if st.Size > lim.MaxVCSStateBytes {
			f.Close()
			rec.gap(RuleVCSState, rel, fmt.Sprintf("helper VCS state file is %d bytes, over the %d byte cap, "+
				"and was not read", st.Size, lim.MaxVCSStateBytes))
			continue
		}
		data, err := io.ReadAll(io.LimitReader(f, lim.MaxVCSStateBytes+1))
		f.Close()
		if err != nil || int64(len(data)) > lim.MaxVCSStateBytes {
			rec.gap(RuleVCSState, rel, "helper VCS state file could not be read within its cap")
			continue
		}

		// The shape is map[pkgbase]map[repo]{sha,branch,protocols}. Unknown
		// fields are ignored and a wrong shape is a gap, never a panic.
		var parsed map[string]map[string]struct {
			SHA string `json:"sha"`
		}
		if err := json.Unmarshal(data, &parsed); err != nil {
			rec.gap(RuleVCSState, rel, fmt.Sprintf("helper VCS state file is not the expected JSON shape (%v), "+
				"so the upstream commits it records were not read", err))
			continue
		}
		for base, repos := range parsed {
			for repo, v := range repos {
				if v.SHA == "" {
					continue
				}
				if state.byBase[base] == nil {
					state.byBase[base] = map[string]vcsEntry{}
				}
				// First file wins, and the origin says which one it was.
				if _, exists := state.byBase[base][repo]; !exists {
					state.byBase[base][repo] = vcsEntry{sha: v.SHA, from: rel}
				}
			}
		}
	}
	return state
}

func firstN(s string, n int) string {
	if len(s) <= n {
		return s
	}
	return s[:n]
}
