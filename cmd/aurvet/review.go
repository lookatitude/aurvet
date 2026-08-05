// cmd/aurvet/review.go
//
// `aurvet review <dir|pkgbase>` analyses a recipe and never builds it (INV-2).
//
// # What the output leads with, and why that is the whole feature
//
// Rule hits first, then a diff against the last approved recipe. Never the
// PKGBUILD. A gate that prints a 400-line recipe has not helped anyone decide
// anything: the operator scrolls, learns nothing, and approves. The full text is
// available with -show-recipe -- on request, not by default.
//
// The diff is possible because internal/gate's approval store records the last
// approved recipe's per-file digests, and internal/snapshot retains the PKGBUILD
// text of what was captured. When those two agree -- the retained text digests to
// the approved digest -- the diff is line-level. When they do not (no snapshot,
// or the text was too large to retain), the diff degrades to the file manifest
// and SAYS so (INV-6) rather than silently showing less than it claims.
//
// # Nothing here is a second code path for --offline-root
//
// The root, the state directory and the network are parameters (INV-4). review
// writes nothing at all -- not even an approval, which is `install`'s business --
// so INV-5 costs it nothing.
package main

import (
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"sort"
	"strings"

	"golang.org/x/sys/unix"

	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/gate"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/pkgbuild"
	"github.com/lookatitude/aurvet/internal/pkgmeta"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/snapshot"
	"github.com/lookatitude/aurvet/internal/surfaces"
)

// Rule identifiers this command owns. They name shortfalls in the REVIEW
// itself, distinct from the recipe rules (internal/check) and from the approval
// store's own gaps (internal/gate).
const (
	// ruleNoRecipe is a subject with no readable PKGBUILD: an unknown pkgbase,
	// a cleaned cache, a directory that is not a recipe. Never silence (INV-9).
	ruleNoRecipe = "review-no-recipe"

	// ruleRecipeUnreadable is a PKGBUILD that exists and could not be read in
	// full -- a symlink, a fifo, an over-cap file.
	ruleRecipeUnreadable = "review-recipe-unreadable"

	// ruleAuxSkipped is a file the recipe names that could not enter the digest
	// because its name is not a plain name inside the recipe directory. The
	// approval then covers less than the recipe does, and that must be said.
	ruleAuxSkipped = "review-recipe-aux-skipped"

	// ruleDiffUnavailable is a changed recipe whose approved TEXT is not
	// retained anywhere, so only the file manifest can be compared.
	ruleDiffUnavailable = "review-diff-text-unavailable"
)

// maxRecipeBytes bounds one PKGBUILD read for review. The largest in the
// reference cache is 31,869 B (flutter); the cap is three orders of magnitude
// above that and exists because the input is attacker-controlled.
const maxRecipeBytes = 8 << 20

// maxDiffLines bounds the rendered diff. A recipe rewritten wholesale is one
// fact ("this is a different recipe"), not four hundred, and an unbounded diff
// is a denial of service against the person reading it.
const maxDiffLines = 200

// diffContext is the unchanged lines shown around a change. Three is diff(1)'s
// default and is what a reviewer's eye expects.
const diffContext = 3

// reviewOpts carries review's inputs. Every field is a parameter; nothing is
// read from the environment here (INV-4).
type reviewOpts struct {
	offlineRoot string
	jsonOut     bool
	minSeverity string
	showRecipe  bool

	// subject is a pkgbase or a root-relative recipe directory.
	subject string
}

// recipeReview is one reviewed recipe: what fired, what changed, what could not
// be established.
type recipeReview struct {
	PkgBase string `json:"pkgbase"`
	Dir     string `json:"dir"`
	Helper  string `json:"helper,omitempty"`

	Digest string            `json:"digest,omitempty"`
	Files  []gate.RecipeFile `json:"files,omitempty"`

	// Approval is the store's status verbatim. StatusApproved is the only one
	// that may be rendered quietly, and gate.Decision.Silent is the only place
	// that rule lives.
	Approval gate.Status    `json:"approval"`
	Prior    *gate.Approval `json:"prior_approval,omitempty"`

	// Diff is the rendered change against the last approved recipe.
	Diff []string `json:"diff,omitempty"`

	// DiffLimit states what the diff does not cover, when it does not cover
	// everything (INV-6).
	DiffLimit string `json:"diff_limit,omitempty"`

	// Delta lines are the VCS delta review's own rendering, one per line.
	Delta []string `json:"vcs_delta,omitempty"`

	// Limits are the analysis limits the recipe verdict states.
	Limits []string `json:"limits,omitempty"`

	// Result carries this recipe's findings and gaps. It is merged into the
	// run-level result by the caller, never rendered from here alone.
	Result finding.Result `json:"-"`

	// Text is the recipe as read, retained only so -show-recipe can print it.
	Text string `json:"-"`

	// fd and at are the descriptor the PKGBUILD was READ from and its stat at
	// open, retained by install so the bytes reviewed can be proven unchanged
	// immediately before handover. nil for review, which hands nothing over.
	fd *os.File
	at unix.Stat_t
}

// runReview resolves the subject, reviews every recipe it names and returns the
// contractual exit code (spec §14). It builds nothing and writes nothing.
func runReview(opts reviewOpts, stdout, stderr io.Writer) int {
	euid := os.Geteuid()
	cfg, err := config.Resolve(opts.offlineRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	cfg = withStateOverride(cfg, euid)

	floorStr := opts.minSeverity
	if floorStr == "" {
		floorStr = cfg.MinSeverity
	}
	floor, err := report.ParseSeverity(floorStr)
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

	targets, searchGaps, err := resolveSubject(root, cfg, opts.subject)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	rv := newReviewer(cfg, euid)
	defer rv.close()

	res := finding.Result{Gaps: searchGaps}
	reviews := make([]recipeReview, 0, len(targets))
	for _, tg := range targets {
		one := rv.review(root, tg)
		reviews = append(reviews, one)
		res.Findings = append(res.Findings, one.Result.Findings...)
		res.Gaps = append(res.Gaps, one.Result.Gaps...)
	}

	if opts.jsonOut {
		if err := renderReviewJSON(stdout, opts.subject, reviews, res); err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			if code := report.ExitCode(res, floor); code != exitClean {
				return code
			}
			return exitUsage
		}
	} else {
		renderReview(stdout, opts.subject, reviews, res, opts.showRecipe)
	}
	return report.ExitCode(res, floor)
}

// withStateOverride applies the AURVET_STATE_DIR override to the resolved
// config, so the approval store and the snapshot store are read from the same
// place `snapshot` writes to.
//
// It mirrors snapshotStateDir's rule exactly -- honoured, but never as root,
// because otherwise an unprivileged local attacker chooses where a
// root-privileged security tool looks for the approvals it trusts (spec §11).
func withStateOverride(cfg config.Config, euid int) config.Config {
	if dir := snapshotStateDir(euid); dir != "" {
		cfg.StateDir = dir
	}
	return cfg
}

// target is one recipe to review.
type target struct {
	PkgBase string
	Dir     string
	Helper  string
}

// resolveSubject turns `<dir|pkgbase>` into the recipes to review.
//
// A subject containing a path separator is a DIRECTORY, interpreted relative to
// the examined root -- which is what makes --offline-root a parameter rather
// than a second code path (INV-4). Anything else is a pkgbase and is looked up
// in the detected helper caches, keyed on pkgbase because 433 of 1409 packages
// on the reference system are split and a review decision is taken over one
// recipe, not one output package.
//
// An absent recipe is NOT an error return: it is a coverage gap, so the command
// still renders and still exits 3 (INV-9). The error return is reserved for a
// subject that cannot be used at all.
func resolveSubject(root *os.Root, cfg config.Config, subject string) ([]target, []finding.Gap, error) {
	if subject == "" {
		return nil, nil, fmt.Errorf("no subject: pass a recipe directory or a pkgbase")
	}

	if looksLikePath(subject) {
		rel, err := rootRelative(cfg.Root, subject)
		if err != nil {
			return nil, nil, err
		}
		pkgbase := recipePkgBase(root, rel)
		return []target{{PkgBase: pkgbase, Dir: rel, Helper: "path"}}, nil, nil
	}

	if err := gate.ValidPkgBase(subject); err != nil {
		return nil, nil, err
	}

	// Cache directories come from the SCANNED ROOT's passwd, never from $HOME:
	// under --offline-root, $HOME answers for the wrong machine (INV-4).
	users, userGaps := surfaces.PasswdUsers(root.FS(), "etc/passwd")
	homes := make([]string, 0, len(users))
	for _, u := range users {
		homes = append(homes, u.Home)
	}
	det := helper.Detect(root, helper.Config{CacheDirs: helper.DefaultCacheDirs(homes)})

	var gaps []finding.Gap
	for _, g := range append(userGaps, det.Gaps...) {
		if g.RuleID == helper.RuleCacheAbsent {
			// A helper that was never installed is the normal state of every
			// system; three of those per searched home buries what matters.
			continue
		}
		gaps = append(gaps, g)
	}

	clones := det.Clones(subject)
	if len(clones) == 0 {
		gaps = append(gaps, finding.Gap{
			RuleID:  ruleNoRecipe,
			Subject: subject,
			Reason: "no recipe was found for this pkgbase in any detected helper cache, so nothing about it was " +
				"reviewed; this is an absence of evidence and not a clean review",
		})
		return nil, gaps, nil
	}
	out := make([]target, 0, len(clones))
	for _, c := range clones {
		out = append(out, target{PkgBase: subject, Dir: c.Dir, Helper: c.Helper})
	}
	return out, gaps, nil
}

// looksLikePath distinguishes a directory subject from a pkgbase. A pkgbase can
// contain @ . _ + - and alphanumerics and nothing else (gate.ValidPkgBase), so a
// separator, a leading dot or a leading dash is unambiguously not one.
func looksLikePath(s string) bool {
	return strings.ContainsRune(s, '/') || s == "." || s == ".." || strings.HasPrefix(s, ".")
}

// rootRelative maps a caller-supplied directory onto a path inside the examined
// root. Under --offline-root a relative path is relative to that root, which is
// the only reading that keeps the two modes one code path.
func rootRelative(rootDir, subject string) (string, error) {
	rel := subject
	if filepath.IsAbs(subject) {
		abs, err := filepath.Abs(rootDir)
		if err != nil {
			return "", err
		}
		r, err := filepath.Rel(abs, filepath.Clean(subject))
		if err != nil || strings.HasPrefix(r, "..") {
			return "", fmt.Errorf("%s is not inside the examined root %s", subject, rootDir)
		}
		rel = r
	} else if rootDir == "/" {
		// A live run resolves a relative path against the working directory,
		// because that is what a user typing `aurvet review .` means.
		abs, err := filepath.Abs(subject)
		if err != nil {
			return "", err
		}
		rel = strings.TrimPrefix(abs, "/")
	}
	rel = strings.TrimPrefix(filepath.Clean(rel), "./")
	if rel == "." || rel == "" {
		return "", fmt.Errorf("%q does not name a directory inside the examined root", subject)
	}
	for _, p := range strings.Split(rel, "/") {
		if p == ".." {
			return "", fmt.Errorf("%q leaves the examined root", subject)
		}
	}
	return rel, nil
}

// recipePkgBase reads the pkgbase a directory declares, so a path subject is
// still keyed on the recipe's own identity. An unreadable or refused value
// yields "", and reviewOne then reports the recipe under its directory with a
// gap rather than inventing a key.
func recipePkgBase(root *os.Root, dir string) string {
	if s, err := pkgmeta.SRCINFOFromFile(root, path.Join(dir, ".SRCINFO"), pkgmeta.Limits{}); err == nil {
		if gate.ValidPkgBase(s.PkgBase) == nil {
			return s.PkgBase
		}
	}
	return ""
}

// reviewer holds the two stores a review consults. Both are read-only here.
type reviewer struct {
	cfg       config.Config
	approvals *gate.Store
	snapshots *snapshot.Store
	storeErr  error

	// keepOpen retains the descriptor each PKGBUILD was read from, which is
	// what lets install prove at handover that the bytes it reviewed are the
	// bytes it is handing over. review closes them immediately.
	keepOpen bool
	open     []*os.File
}

func newReviewer(cfg config.Config, euid int) *reviewer {
	rv := &reviewer{cfg: cfg}
	st, err := gate.OpenStore(cfg)
	if err != nil {
		rv.storeErr = err
	} else {
		rv.approvals = st
	}
	rv.snapshots = snapshot.New(cfg, snapshotStateDir(euid))
	return rv
}

func (rv *reviewer) close() {
	for _, f := range rv.open {
		f.Close()
	}
	rv.open = nil
}

// review analyses one recipe.
//
// Order matters only in that everything is evidence: a failure at any step is a
// gap on the returned result, never an early return that leaves the caller with
// a blank review it could read as clean.
func (rv *reviewer) review(root *os.Root, tg target) recipeReview {
	out := recipeReview{PkgBase: tg.PkgBase, Dir: tg.Dir, Helper: tg.Helper}
	subject := tg.PkgBase
	if subject == "" {
		subject = tg.Dir
	}
	gap := func(rule, reason string) {
		out.Result.Gaps = append(out.Result.Gaps, finding.Gap{RuleID: rule, Subject: subject, Reason: reason})
	}

	f, st, err := fsx.OpenConfined(root, path.Join(tg.Dir, "PKGBUILD"))
	if err != nil {
		if os.IsNotExist(err) {
			gap(ruleNoRecipe, fmt.Sprintf("no PKGBUILD at %s, so this subject was not reviewed: %v", tg.Dir, err))
		} else {
			gap(ruleRecipeUnreadable, fmt.Sprintf("the PKGBUILD at %s could not be opened, so it was not analysed: %v", tg.Dir, err))
		}
		return out
	}
	if rv.keepOpen {
		rv.open = append(rv.open, f)
		out.fd, out.at = f, st
	} else {
		defer f.Close()
	}

	if st.Size > maxRecipeBytes {
		gap(ruleRecipeUnreadable, fmt.Sprintf("the PKGBUILD at %s is %d bytes, over the %d cap, and was not analysed",
			tg.Dir, st.Size, int64(maxRecipeBytes)))
		return out
	}
	src, err := io.ReadAll(io.LimitReader(f, maxRecipeBytes))
	if err != nil {
		gap(ruleRecipeUnreadable, fmt.Sprintf("the PKGBUILD at %s could not be read in full, so it was not analysed: %v", tg.Dir, err))
		return out
	}
	if err := fsx.CheckUnchanged(f, st); err != nil {
		// The bytes read were consistent with nothing in particular. Analysing
		// them would publish a verdict about a file that no longer exists in
		// that form.
		gap(ruleRecipeUnreadable, fmt.Sprintf("the PKGBUILD at %s changed while it was being read, so no verdict was formed: %v", tg.Dir, err))
		return out
	}
	out.Text = string(src)

	lexed := pkgbuild.Lex(src)
	res := pkgbuild.Resolve(lexed, pkgbuild.ResolveConfig{})
	if out.PkgBase == "" && gate.ValidPkgBase(res.Pkgbase) == nil {
		out.PkgBase = res.Pkgbase
		subject = res.Pkgbase
	}
	verdict := pkgbuild.Assess(out.PkgBase, lexed, res)
	out.Limits = verdict.Limits

	// check.PKGBUILD REQUIRES the verdict and merges its gaps: an
	// eval-generated or unparsable recipe must never read as clean (INV-3).
	hits := check.PKGBUILD(lexed, res, verdict, check.PKGBUILDConfig{})
	out.Result.Findings = append(out.Result.Findings, hits.Findings...)
	out.Result.Gaps = append(out.Result.Gaps, hits.Gaps...)

	if out.PkgBase == "" {
		gap(ruleNoRecipe, fmt.Sprintf("the recipe at %s declares no usable pkgbase, so no approval could be looked "+
			"up or recorded for it and its review cannot be remembered", tg.Dir))
		return out
	}

	aux, skipped := auxFiles(res)
	for _, s := range skipped {
		gap(ruleAuxSkipped, fmt.Sprintf("the recipe names %q, which is not a plain file name beside the PKGBUILD; "+
			"it is not covered by the approval digest, so a change to it would not re-prompt", s))
	}
	// An aux file the recipe names and the directory does not hold is dropped
	// from the digest rather than sinking it.
	//
	// Measured on a real recipe: google-chrome's source=() names
	// google-chrome-stable.sh, and a clone (or an AUR tarball) that does not
	// carry it made gate.DigestRecipe fail for the WHOLE recipe -- so the
	// package could never be approved, the store could never go silent for it,
	// and the operator would be re-prompted for ever. Dropping the file and
	// saying so keeps the approval useful and keeps its narrower coverage
	// visible (INV-6).
	readable := make([]string, 0, len(aux))
	for _, name := range aux {
		if af, _, err := fsx.OpenConfined(root, path.Join(tg.Dir, name)); err == nil {
			af.Close()
			readable = append(readable, name)
			continue
		} else {
			gap(ruleAuxSkipped, fmt.Sprintf("the recipe names the local file %q, which could not be read here (%v); "+
				"it is NOT covered by the approval digest, so a change to it would not re-prompt", name, err))
		}
	}
	aux = readable
	recipe, err := gate.DigestRecipe(root, gate.RecipeRequest{PkgBase: out.PkgBase, Dir: tg.Dir, Aux: aux})
	if err != nil {
		gap(ruleRecipeUnreadable, fmt.Sprintf("the recipe at %s could not be digested, so no approval could be "+
			"looked up for it: %v", tg.Dir, err))
		return out
	}
	out.Digest, out.Files = recipe.Digest, recipe.Files

	if rv.approvals == nil {
		gap(gate.RuleStoreUnreadable, fmt.Sprintf("the approval store could not be located, so this recipe is "+
			"neither known-approved nor known-unapproved: %v", rv.storeErr))
	} else {
		dec := rv.approvals.Lookup(out.PkgBase, recipe.Digest)
		out.Approval = dec.Status
		out.Prior = dec.Prior
		out.Result.Gaps = append(out.Result.Gaps, dec.Gaps...)
		if dec.Status == gate.StatusChanged {
			out.Diff, out.DiffLimit = rv.diff(dec.Prior, recipe, out.Text)
			if out.DiffLimit != "" {
				gap(ruleDiffUnavailable, out.DiffLimit)
			}
		}
	}

	rv.vcsDelta(root, &out, res)
	return out
}

// auxFiles derives the additional recipe files the approval digest must cover:
// install= scriptlets and local source=() entries. Both are part of the recipe
// in every sense a reviewer cares about -- a .install runs as root at install
// time -- and neither is the file an eye lands on.
//
// A name that is not plain (a traversal, an absolute path) is REPORTED rather
// than digested: gate.DigestRecipe would refuse the whole recipe over it, and
// losing the approval for every other file is a worse outcome than naming the
// one that could not be covered.
func auxFiles(r pkgbuild.Resolution) (aux, skipped []string) {
	add := func(name string) {
		if name == "" {
			return
		}
		if !plainName(name) {
			skipped = append(skipped, name)
			return
		}
		aux = append(aux, name)
	}
	if v, ok := r.Vars["install"]; ok {
		for _, val := range v.Values {
			if val.OK() {
				add(val.Text)
			}
		}
	}
	for _, s := range r.Sources {
		if s.Local && s.Value.OK() {
			add(s.Name)
		}
	}
	sort.Strings(aux)
	return aux, skipped
}

// plainName reports whether name is a file beside the PKGBUILD and nothing
// else. source=(../../etc/shadow) is a real shape.
func plainName(name string) bool {
	if name == "" || strings.ContainsRune(name, 0) || strings.ContainsRune(name, '/') {
		return false
	}
	return name != "." && name != ".."
}

// diff renders what changed since the last approved recipe.
//
// It prefers a LINE diff, which needs the approved TEXT: the approval store
// keeps digests (a record of a decision, not a copy of the AUR), and the
// snapshot store keeps the retained PKGBUILD. When the retained text digests to
// the approved digest the two agree and the diff is exact. When no such text
// exists the comparison degrades to the file manifest and returns the limit,
// which the caller raises as a coverage gap -- "the recipe changed and I cannot
// show you how" is a shortfall, not a detail.
func (rv *reviewer) diff(prior *gate.Approval, now gate.Recipe, text string) ([]string, string) {
	var lines []string
	manifest := manifestDiff(prior, now)

	wantSHA := fileSHA(prior.Files, "PKGBUILD")
	nowSHA := fileSHA(now.Files, "PKGBUILD")
	if wantSHA != "" && wantSHA != nowSHA {
		old, ok := rv.approvedText(now.PkgBase, wantSHA)
		if !ok {
			return manifest, fmt.Sprintf("the approved PKGBUILD (%s) is not retained in any snapshot for %s, so the "+
				"change is shown at file-digest level only and the review cannot say WHAT changed",
				short12(wantSHA), now.PkgBase)
		}
		lines = append(lines, fmt.Sprintf("PKGBUILD  %s -> %s", short12(wantSHA), short12(nowSHA)))
		body, note := lineDiff(splitLines(old), splitLines(text), diffContext, maxDiffLines)
		lines = append(lines, body...)
		lines = append(lines, manifest...)
		return lines, note
	}
	return manifest, ""
}

// approvedText finds the retained PKGBUILD whose digest is the approved one.
//
// The digest check is the point: a snapshot is only usable as "the approved
// text" if it IS the approved text, and a snapshot taken after the recipe moved
// would otherwise be diffed as though it were the baseline.
func (rv *reviewer) approvedText(pkgbase, wantSHA string) (string, bool) {
	if rv.snapshots == nil {
		return "", false
	}
	rec, ok, err := rv.snapshots.Latest(pkgbase)
	if err != nil || !ok {
		return "", false
	}
	for _, c := range rec.Clones {
		if c.PKGBUILD != nil && c.PKGBUILD.Retained && c.PKGBUILD.SHA256 == wantSHA {
			return c.PKGBUILD.Text, true
		}
	}
	return "", false
}

// manifestDiff reports the file set difference: added, removed, changed. It is
// the part of the diff that is always available, and for a .install scriptlet
// appearing out of nowhere it is the line that matters most.
func manifestDiff(prior *gate.Approval, now gate.Recipe) []string {
	was := map[string]string{}
	for _, f := range prior.Files {
		was[f.Name] = f.SHA256
	}
	is := map[string]string{}
	for _, f := range now.Files {
		is[f.Name] = f.SHA256
	}
	names := map[string]bool{}
	for n := range was {
		names[n] = true
	}
	for n := range is {
		names[n] = true
	}
	ordered := make([]string, 0, len(names))
	for n := range names {
		ordered = append(ordered, n)
	}
	sort.Strings(ordered)

	var out []string
	for _, n := range ordered {
		switch {
		case was[n] == is[n]:
		case was[n] == "":
			out = append(out, fmt.Sprintf("+ %s is NEW in this recipe (%s)", n, short12(is[n])))
		case is[n] == "":
			out = append(out, fmt.Sprintf("- %s is GONE from this recipe (was %s)", n, short12(was[n])))
		case n != "PKGBUILD":
			out = append(out, fmt.Sprintf("~ %s changed (%s -> %s)", n, short12(was[n]), short12(is[n])))
		}
	}
	return out
}

func fileSHA(files []gate.RecipeFile, name string) string {
	for _, f := range files {
		if f.Name == name {
			return f.SHA256
		}
	}
	return ""
}

// vcsDelta reviews the upstream commit range for every VCS source, because for
// a -git package the recipe is stable while the source moves: approving once
// would bless unbounded future commits.
//
// The anchor is the position the last decision was taken at -- the approval's
// own record first, then the latest snapshot's upstream commit. With neither,
// the range is unknown and that is a gap, not "no changes".
func (rv *reviewer) vcsDelta(root *os.Root, out *recipeReview, res pkgbuild.Resolution) {
	for _, s := range res.Sources {
		if s.VCS == "" {
			continue
		}
		subject := out.PkgBase
		if s.VCS != "git" {
			out.Result.Gaps = append(out.Result.Gaps, finding.Gap{
				RuleID:  gate.RuleVCSUnreadable,
				Subject: subject,
				Reason: fmt.Sprintf("source %q is a %s checkout; this tool reads git objects only, so the commit "+
					"range built from it was not reviewed", s.Name, s.VCS),
			})
			continue
		}
		anchor := rv.anchor(out, s.URL)
		dir := path.Join(out.Dir, s.Name)
		abs := filepath.Join(rv.cfg.Root, dir)
		if !plainName(s.Name) || !isDir(root, dir) {
			out.Result.Gaps = append(out.Result.Gaps, finding.Gap{
				RuleID:  gate.RuleVCSNoAnchor,
				Subject: subject,
				Reason: fmt.Sprintf("no upstream checkout for VCS source %q beside the recipe, so the commits since "+
					"%s were not listed; the recipe is unchanged and the source is not covered by that",
					s.Name, shortAnchor(anchor.Commit)),
			})
			continue
		}
		d := gate.ReviewDelta(gate.Request{PkgBase: subject, Dir: abs, Anchor: anchor})
		out.Delta = append(out.Delta, d.Lines()...)
		dr := d.Result()
		out.Result.Findings = append(out.Result.Findings, dr.Findings...)
		out.Result.Gaps = append(out.Result.Gaps, dr.Gaps...)
	}
}

// anchor is the upstream position the last review decision was taken at.
func (rv *reviewer) anchor(out *recipeReview, url string) gate.Anchor {
	if out.Prior != nil && out.Prior.VCS != nil {
		return *out.Prior.VCS
	}
	if rv.snapshots != nil && out.PkgBase != "" {
		if rec, ok, err := rv.snapshots.Latest(out.PkgBase); err == nil && ok {
			for _, c := range rec.Clones {
				for _, u := range c.Upstream {
					if u.Commit != "" && (url == "" || u.URL == url) {
						return gate.Anchor{Commit: u.Commit, Remote: u.URL}
					}
				}
			}
		}
	}
	return gate.Anchor{}
}

func shortAnchor(sha string) string {
	if sha == "" {
		return "the last review (no position was ever recorded)"
	}
	return short12(sha)
}

func isDir(root *os.Root, rel string) bool {
	fi, err := root.Stat(rel)
	return err == nil && fi.IsDir()
}

// --- rendering --------------------------------------------------------------

// renderReview prints the review: rule hits first, then the diff, then what
// could not be established. The recipe body is printed only on request.
func renderReview(w io.Writer, subject string, reviews []recipeReview, res finding.Result, showRecipe bool) {
	fmt.Fprintf(w, "review %s: %d rule hit(s), %d coverage gap(s) across %d recipe(s)\n",
		subject, len(res.Findings), len(res.Gaps), len(reviews))

	for _, rv := range reviews {
		fmt.Fprintf(w, "\nrecipe %s", rv.Dir)
		if rv.PkgBase != "" {
			fmt.Fprintf(w, "  pkgbase %s", rv.PkgBase)
		}
		if rv.Helper != "" {
			fmt.Fprintf(w, "  (%s)", rv.Helper)
		}
		fmt.Fprintln(w)
		if rv.Approval != "" {
			fmt.Fprintf(w, "  approval: %s", rv.Approval)
			if rv.Prior != nil {
				fmt.Fprintf(w, " (last approved %s by %s)", rv.Prior.ApprovedAt.UTC().Format("2006-01-02 15:04:05Z"),
					sanitiseText(rv.Prior.By, 32))
			}
			fmt.Fprintln(w)
		}

		// The hits lead. Everything below this block is context for them.
		fmt.Fprintf(w, "\n  rule hits (%d):\n", len(rv.Result.Findings))
		if len(rv.Result.Findings) == 0 {
			fmt.Fprintln(w, "    none of the shipped recipe rules fired on the parts of this recipe that were analysed")
		}
		for _, f := range sortFindings(rv.Result.Findings) {
			fmt.Fprintf(w, "    [%s] %s  %s\n", f.Severity, f.RuleID, f.Summary)
			for _, e := range f.Evidence {
				fmt.Fprintf(w, "        %s\n", sanitiseText(e, 200))
			}
			if f.Limits != "" {
				fmt.Fprintf(w, "        limits: %s\n", f.Limits)
			}
		}

		if len(rv.Diff) > 0 {
			fmt.Fprintf(w, "\n  recipe diff vs last approved:\n")
			for _, l := range rv.Diff {
				fmt.Fprintf(w, "    %s\n", sanitiseText(l, 200))
			}
		}
		if rv.DiffLimit != "" {
			fmt.Fprintf(w, "    ! %s\n", rv.DiffLimit)
		}

		if len(rv.Delta) > 0 {
			fmt.Fprintf(w, "\n  upstream since the reviewed position:\n")
			for _, l := range rv.Delta {
				fmt.Fprintf(w, "    %s\n", sanitiseText(l, 200))
			}
		}

		if len(rv.Result.Gaps) > 0 {
			fmt.Fprintf(w, "\n  not established (%d):\n", len(rv.Result.Gaps))
			for _, g := range rv.Result.Gaps {
				fmt.Fprintf(w, "    ! %s  %s\n        %s\n", g.RuleID, g.Subject, sanitiseText(g.Reason, 400))
			}
		}
		if len(rv.Limits) > 0 {
			fmt.Fprintf(w, "\n  limits:\n")
			for _, l := range rv.Limits {
				fmt.Fprintf(w, "    - %s\n", l)
			}
		}
		if showRecipe && rv.Text != "" {
			fmt.Fprintf(w, "\n  PKGBUILD (%d bytes, as read):\n", len(rv.Text))
			for _, l := range splitLines(rv.Text) {
				fmt.Fprintf(w, "  | %s\n", sanitiseText(l, 400))
			}
		}
	}

	// Run-level gaps that belong to no single recipe -- an unreadable cache, an
	// absent clone -- are printed last and never dropped (INV-9).
	//
	// Collapsed by rule, for the reason snapshot's renderSearchGaps records: a
	// live unprivileged run produces one per (system account, helper layout)
	// pair -- twenty on the reference system, measured -- and twenty repetitions
	// of "permission denied" is how the one gap that mattered gets missed.
	if extra := runLevelGaps(reviews, res); len(extra) > 0 {
		fmt.Fprintf(w, "\nreview coverage (%d shortfall(s)):\n", len(extra))
		byRule := map[string][]string{}
		var order []string
		for _, g := range extra {
			if _, seen := byRule[g.RuleID]; !seen {
				order = append(order, g.RuleID)
			}
			byRule[g.RuleID] = append(byRule[g.RuleID], g.Subject)
		}
		sort.Strings(order)
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
			// One reason per rule: they differ only in the path, which is
			// already listed above.
			for _, g := range extra {
				if g.RuleID == rule {
					fmt.Fprintf(w, "      %s\n", sanitiseText(g.Reason, 400))
					break
				}
			}
		}
	}
	if !showRecipe {
		fmt.Fprintln(w, "\nthe recipe text is not printed by default; re-run with -show-recipe to read it in full")
	}
}

// runLevelGaps is res.Gaps minus the ones already printed under a recipe.
func runLevelGaps(reviews []recipeReview, res finding.Result) []finding.Gap {
	seen := map[finding.Gap]bool{}
	for _, rv := range reviews {
		for _, g := range rv.Result.Gaps {
			seen[g] = true
		}
	}
	var out []finding.Gap
	for _, g := range res.Gaps {
		if !seen[g] {
			out = append(out, g)
		}
	}
	return out
}

// sortFindings orders severity-descending so the worst hit is the first thing
// read, with a stable tiebreak on rule then subject.
func sortFindings(in []finding.Finding) []finding.Finding {
	out := make([]finding.Finding, len(in))
	copy(out, in)
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Severity != out[j].Severity {
			return out[i].Severity > out[j].Severity
		}
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

type reviewJSON struct {
	Subject  string         `json:"subject"`
	Recipes  []recipeReview `json:"recipes"`
	Findings []jsonFinding  `json:"findings"`
	Gaps     []jsonGap      `json:"gaps"`
}

type jsonFinding struct {
	RuleID      string   `json:"rule_id"`
	SubjectKind string   `json:"subject_kind"`
	Subject     string   `json:"subject"`
	Severity    string   `json:"severity"`
	Summary     string   `json:"summary"`
	Evidence    []string `json:"evidence,omitempty"`
	Limits      string   `json:"limits,omitempty"`
}

type jsonGap struct {
	RuleID  string `json:"rule_id"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

func renderReviewJSON(w io.Writer, subject string, reviews []recipeReview, res finding.Result) error {
	out := reviewJSON{Subject: subject, Recipes: reviews}
	for _, f := range sortFindings(res.Findings) {
		out.Findings = append(out.Findings, jsonFinding{
			RuleID: f.RuleID, SubjectKind: f.SubjectKind, Subject: f.Subject,
			Severity: f.Severity.String(), Summary: f.Summary, Evidence: f.Evidence, Limits: f.Limits,
		})
	}
	for _, g := range res.Gaps {
		out.Gaps = append(out.Gaps, jsonGap{RuleID: g.RuleID, Subject: g.Subject, Reason: g.Reason})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}

// --- the diff itself --------------------------------------------------------

func splitLines(s string) []string {
	s = strings.TrimSuffix(s, "\n")
	if s == "" {
		return nil
	}
	return strings.Split(s, "\n")
}

// maxDiffCells bounds the LCS table. 1e6 cells covers every recipe in the
// reference corpus (the largest is 1,003 lines) at a bounded cost; beyond it
// the diff degrades to a stated limit rather than allocating whatever a hostile
// recipe asks for.
const maxDiffCells = 1 << 20

// lineDiff renders a unified-style diff of old -> new, bounded in both table
// size and output length. The second return is the limit to state when the
// rendering is not the whole change (INV-6).
func lineDiff(old, new []string, ctx, max int) ([]string, string) {
	if len(old)*len(new) > maxDiffCells {
		return []string{fmt.Sprintf("(%d -> %d lines: too large to diff under the %d-cell bound)",
				len(old), len(new), maxDiffCells)},
			fmt.Sprintf("the approved and incoming recipes are %d and %d lines; the line diff was not computed, "+
				"so the change is reported at digest level only", len(old), len(new))
	}

	keep := lcs(old, new)
	type edit struct {
		op   byte // ' ', '-', '+'
		text string
	}
	var edits []edit
	i, j := 0, 0
	for _, k := range keep {
		for i < k.a {
			edits = append(edits, edit{'-', old[i]})
			i++
		}
		for j < k.b {
			edits = append(edits, edit{'+', new[j]})
			j++
		}
		edits = append(edits, edit{' ', old[i]})
		i++
		j++
	}
	for ; i < len(old); i++ {
		edits = append(edits, edit{'-', old[i]})
	}
	for ; j < len(new); j++ {
		edits = append(edits, edit{'+', new[j]})
	}

	// Keep only the changes and ctx lines of context around them: the unchanged
	// bulk is exactly what nobody reads.
	show := make([]bool, len(edits))
	for n, e := range edits {
		if e.op == ' ' {
			continue
		}
		lo, hi := n-ctx, n+ctx
		if lo < 0 {
			lo = 0
		}
		if hi >= len(edits) {
			hi = len(edits) - 1
		}
		for k := lo; k <= hi; k++ {
			show[k] = true
		}
	}

	var out []string
	skipped, dropped := 0, 0
	for n, e := range edits {
		if !show[n] {
			skipped++
			continue
		}
		if skipped > 0 {
			out = append(out, fmt.Sprintf("  @@ %d unchanged line(s) @@", skipped))
			skipped = 0
		}
		if len(out) >= max {
			dropped++
			continue
		}
		// diff(1)'s own shape: the marker occupies column one and the line
		// follows verbatim, so leading whitespace in the recipe is visible.
		out = append(out, string(e.op)+e.text)
	}
	if dropped > 0 {
		return out, fmt.Sprintf("the diff was truncated at %d lines; %d further changed or context line(s) are not "+
			"shown, so this rendering is a floor on what changed", max, dropped)
	}
	return out, ""
}

// pair is one matched line position in the LCS.
type pair struct{ a, b int }

// lcs returns the longest common subsequence of a and b as matched index pairs.
// Plain DP: bounded by maxDiffCells at the call site, and correctness here is
// what the diff's honesty rests on.
func lcs(a, b []string) []pair {
	n, m := len(a), len(b)
	if n == 0 || m == 0 {
		return nil
	}
	// table[i][j] = LCS length of a[i:] and b[j:], stored as a flat slice.
	table := make([]int32, (n+1)*(m+1))
	at := func(i, j int) int32 { return table[i*(m+1)+j] }
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if a[i] == b[j] {
				table[i*(m+1)+j] = at(i+1, j+1) + 1
			} else if at(i+1, j) >= at(i, j+1) {
				table[i*(m+1)+j] = at(i+1, j)
			} else {
				table[i*(m+1)+j] = at(i, j+1)
			}
		}
	}
	var out []pair
	for i, j := 0, 0; i < n && j < m; {
		switch {
		case a[i] == b[j]:
			out = append(out, pair{i, j})
			i++
			j++
		case at(i+1, j) >= at(i, j+1):
			i++
		default:
			j++
		}
	}
	return out
}

func short12(sha string) string {
	if len(sha) > 12 {
		return sha[:12]
	}
	if sha == "" {
		return "(none)"
	}
	return sha
}

// sanitiseText bounds untrusted text and strips control bytes. A PKGBUILD line,
// a commit subject and a gap reason all carry attacker-supplied bytes, and an
// ANSI escape in any of them could redraw a review prompt.
func sanitiseText(s string, max int) string {
	var b strings.Builder
	for _, r := range s {
		if b.Len() >= max {
			b.WriteString("…")
			break
		}
		if r < 0x20 || r == 0x7f {
			b.WriteByte(' ')
			continue
		}
		b.WriteRune(r)
	}
	return b.String()
}
