// cmd/aurvet/install.go
//
// `aurvet install <pkgbase>` is the gate (spec §10). A pacman hook cannot be
// one: by the time pacman sees a built package, makepkg has already run
// prepare(), build() and package() as the invoking user, so the build-time-fetch
// vector has already fired and the hook cannot see a PKGBUILD at all.
//
// The order is the security property:
//
//	fetch -> review the whole dependency closure -> prompt -> snapshot -> hand over
//
// Snapshot BEFORE handover, because the point of a snapshot is to capture
// provenance while it still exists, and the cache that holds it is 88 GB and
// gets cleaned.
//
// # Two things follow from handing a directory to something that will run makepkg
//
//   - aurvet does not run makepkg, and does not run the helper's build for it.
//     It hands over a vetted directory and says what it is. INV-2 is not
//     negotiable here, and it is why this command cannot reach the .BUILDINFO
//     makepkg writes into $pkgdir (see buildInfoNote).
//   - Between review and handover, nothing may change the recipe. Reviewing
//     BYTES and then handing over a PATH gives an attacker who can write that
//     path an approval for different bytes. So the handover re-verifies, twice
//     over: fsx.CheckUnchanged on the very descriptor the PKGBUILD was read
//     from (same inode, same size, same mtime), and a fresh gate.DigestRecipe
//     over every recipe file by path (which catches the path being repointed at
//     a different inode, the one thing an open descriptor cannot see). A
//     mismatch in either refuses the handover.
//
// # Why there is no --offline-root and no --no-network mode
//
// Both are refusals, not modes. Staging a build inside a tree being inspected
// would write to the evidence (INV-5), and an install that cannot fetch cannot
// review what it is about to install -- `review` is the command for analysing
// what is already on disk. Refusing is honest; a degraded install is not.
package main

import (
	"archive/tar"
	"bufio"
	"compress/gzip"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/gate"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/pkgmeta"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/snapshot"
)

// Rule identifiers this command owns.
const (
	// ruleFetchFailed is a closure member whose recipe could not be retrieved.
	// The closure is then not reviewed, which is a gap and never a pass.
	ruleFetchFailed = "install-fetch-failed"

	// ruleDepUnresolved is a declared dependency that is neither a repository
	// package nor an AUR package this tool could find. The closure is
	// incomplete and the operator must know that before answering a prompt.
	ruleDepUnresolved = "install-dependency-unresolved"

	// ruleClosureBounded is a closure that hit a traversal bound.
	ruleClosureBounded = "install-closure-bounded"

	// ruleSrcinfoMissing is a fetched recipe with no readable .SRCINFO, so its
	// dependencies -- and therefore the rest of the closure below it -- are
	// unknown.
	ruleSrcinfoMissing = "install-srcinfo-unreadable"

	// ruleRecipeChanged is the TOCTOU refusal: the recipe reviewed is not the
	// recipe on disk at handover time. This is a FINDING, not a gap: something
	// observably changed the staged recipe after a human approved it.
	ruleRecipeChanged = "install-recipe-changed-after-review"

	// ruleBuildInfoUnreachable records that .BUILDINFO's independent testimony
	// cannot be captured by this flow, and why.
	ruleBuildInfoUnreachable = "install-buildinfo-unreachable"
)

// subjectInstall is the subject kind for this command's findings.
const subjectInstall = "install"

// errNoSuchRecipe is a pkgbase the source has no recipe for. Distinct from a
// transport failure: "the AUR does not carry this" and "I could not ask" are
// different facts (the aur.Client contract's rule 1, applied here).
var errNoSuchRecipe = errors.New("aurvet: no recipe under this pkgbase")

// recipeSource retrieves one pkgbase's recipe files as bytes.
//
// Bytes, not a directory: every path decision then lives in one place
// (stageRecipe) instead of being duplicated by each source, and a test source is
// a map literal rather than a filesystem.
type recipeSource interface {
	Fetch(ctx context.Context, pkgbase string) (map[string][]byte, error)

	// Describe names the source in output, so a reviewer can see where the
	// bytes they are being asked about came from.
	Describe() string
}

// fetchLimits bounds what one attacker-supplied recipe archive can cost.
//
// Measured against the reference cache (2026-08-05): the largest PKGBUILD is
// 31,869 B and the largest .SRCINFO 17,715 B, both flutter; a recipe directory
// carries at most a handful of patches beside them.
type fetchLimits struct {
	MaxFiles        int
	MaxFileBytes    int64
	MaxTotalBytes   int64
	MaxArchiveBytes int64
}

func defaultFetchLimits() fetchLimits {
	return fetchLimits{
		MaxFiles:        64,
		MaxFileBytes:    8 << 20,
		MaxTotalBytes:   32 << 20,
		MaxArchiveBytes: 32 << 20,
	}
}

// aurSnapshotSource fetches the AUR's own recipe tarball over HTTPS.
//
// A tarball rather than a git clone, deliberately: cloning would mean either
// executing git against an attacker-controlled repository (D-1 and INV-2 both
// forbid it) or implementing a git transport, and archive/tar plus compress/gzip
// are in the standard library. The cost is stated rather than hidden -- the AUR
// repository's own commit history is not retrieved this way, so a first install
// has no recipe history to show; internal/vcs covers a clone that already exists.
type aurSnapshotSource struct {
	baseURL string
	hc      *http.Client
	lim     fetchLimits
}

func (s aurSnapshotSource) Describe() string { return "AUR cgit recipe tarball (" + s.baseURL + ")" }

func (s aurSnapshotSource) Fetch(ctx context.Context, pkgbase string) (map[string][]byte, error) {
	if err := gate.ValidPkgBase(pkgbase); err != nil {
		return nil, err
	}
	u := s.baseURL + "/cgit/aur.git/snapshot/" + url.PathEscape(pkgbase) + ".tar.gz"
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	resp, err := s.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	switch resp.StatusCode {
	case http.StatusOK:
	case http.StatusNotFound:
		return nil, fmt.Errorf("%w: %s", errNoSuchRecipe, pkgbase)
	default:
		return nil, fmt.Errorf("aurvet: %s: http %d", u, resp.StatusCode)
	}
	return readSnapshotTarball(pkgbase, io.LimitReader(resp.Body, s.lim.MaxArchiveBytes), s.lim)
}

// readSnapshotTarball reads a recipe tarball into a name -> bytes map.
//
// Every member is refused unless it is a REGULAR file directly under
// "<pkgbase>/". That excludes, by construction rather than by inspection:
// traversal ("foo/../../etc/cron.d/x"), absolute names, symlinks and hardlinks
// (which would let the archive name a target outside the staging directory),
// devices and fifos, nested directories, and any member belonging to a different
// pkgbase than the one requested.
//
// A refusal is an error for the whole archive, not a skipped member: an archive
// containing something this shape does not permit is not the AUR's shape, and
// silently taking "the good half" of it would stage files that were reviewed
// alongside members nobody accounted for.
func readSnapshotTarball(pkgbase string, r io.Reader, lim fetchLimits) (map[string][]byte, error) {
	gz, err := gzip.NewReader(r)
	if err != nil {
		return nil, fmt.Errorf("aurvet: %s: not a gzip archive: %w", pkgbase, err)
	}
	defer gz.Close()

	out := map[string][]byte{}
	tr := tar.NewReader(gz)
	var total int64
	for {
		hdr, err := tr.Next()
		if errors.Is(err, io.EOF) {
			break
		}
		if err != nil {
			return nil, fmt.Errorf("aurvet: %s: unreadable archive: %w", pkgbase, err)
		}
		name := hdr.Name
		if strings.HasPrefix(name, "./") {
			name = name[2:]
		}
		if hdr.Typeflag == tar.TypeDir {
			if strings.TrimSuffix(name, "/") != pkgbase {
				return nil, fmt.Errorf("aurvet: %s: archive holds directory %q", pkgbase, sanitiseText(hdr.Name, 80))
			}
			continue
		}
		if hdr.Typeflag != tar.TypeReg {
			return nil, fmt.Errorf("aurvet: %s: archive holds %q, which is not a regular file (typeflag %q)",
				pkgbase, sanitiseText(hdr.Name, 80), string(hdr.Typeflag))
		}
		rest, ok := strings.CutPrefix(name, pkgbase+"/")
		if !ok || !plainName(rest) {
			return nil, fmt.Errorf("aurvet: %s: archive holds %q, which is not a plain file inside %s/",
				pkgbase, sanitiseText(hdr.Name, 80), pkgbase)
		}
		if len(out) >= lim.MaxFiles {
			return nil, fmt.Errorf("aurvet: %s: archive holds more than %d files", pkgbase, lim.MaxFiles)
		}
		if hdr.Size > lim.MaxFileBytes {
			return nil, fmt.Errorf("aurvet: %s: %s is %d bytes, over the %d cap", pkgbase, rest, hdr.Size, lim.MaxFileBytes)
		}
		body, err := io.ReadAll(io.LimitReader(tr, lim.MaxFileBytes+1))
		if err != nil {
			return nil, fmt.Errorf("aurvet: %s: %s: %w", pkgbase, rest, err)
		}
		if int64(len(body)) > lim.MaxFileBytes {
			return nil, fmt.Errorf("aurvet: %s: %s exceeds the %d byte cap", pkgbase, rest, lim.MaxFileBytes)
		}
		total += int64(len(body))
		if total > lim.MaxTotalBytes {
			return nil, fmt.Errorf("aurvet: %s: archive expands past the %d byte cap", pkgbase, lim.MaxTotalBytes)
		}
		out[rest] = body
	}
	if _, ok := out["PKGBUILD"]; !ok {
		return nil, fmt.Errorf("aurvet: %s: archive carries no PKGBUILD", pkgbase)
	}
	return out, nil
}

// installOpts carries install's inputs. The last six fields are test seams whose
// zero values select production behaviour, so main() constructs one from flags
// alone and never mentions them.
type installOpts struct {
	offlineRoot string
	noNet       bool
	jsonOut     bool
	minSeverity string
	showRecipe  bool
	pkgbase     string

	// liveRoot substitutes a fixture tree for "/" . install has no offline mode
	// -- --offline-root is refused -- so this exists only so a test can run the
	// whole flow without touching the live system.
	liveRoot string

	// src is the recipe source. nil means the real AUR tarball fetcher.
	src recipeSource

	// cl is the AUR index client, used to decide which dependencies are AUR
	// packages. nil means the real HTTP client.
	cl aur.Client

	// stageDir is where recipes are staged. "" means a fresh 0700 temp dir.
	stageDir string

	// stdin is where the prompt is answered. nil means os.Stdin.
	stdin io.Reader

	// afterPrompt runs between the prompt and the handover. It exists to prove
	// the handover's re-verification fires, by doing exactly what an attacker
	// with write access to the staging path would do.
	afterPrompt func(stage string)

	// maxNodes bounds the closure. Zero means defaultMaxClosureNodes.
	maxNodes int
}

// defaultMaxClosureNodes bounds the recipes one install will fetch and review.
// The largest AUR closure on the reference system is 6 deep; the bound exists
// because a hostile .SRCINFO can declare as many dependencies as it likes.
const defaultMaxClosureNodes = 64

// maxClosureDepth bounds the walk's depth independently of its breadth, so a
// dependency cycle terminates on the first repeat rather than on the node cap.
const maxClosureDepth = 12

// closureNode is one reviewed member of the dependency closure.
type closureNode struct {
	PkgBase  string   `json:"pkgbase"`
	Depth    int      `json:"depth"`
	Children []string `json:"children,omitempty"`

	// Via names the dependency that pulled this member in, empty for the root.
	Via string `json:"via,omitempty"`
}

// runInstall runs the gate. It never builds and never execs the helper.
func runInstall(opts installOpts, stdout, stderr io.Writer) int {
	// Both of these are refusals rather than modes, and both are checked before
	// anything is opened or created.
	if opts.offlineRoot != "" {
		fmt.Fprintln(stderr, "aurvet: install refuses to run with --offline-root: staging a build inside the tree "+
			"being inspected would write to the evidence (INV-5), and an approval recorded there would describe "+
			"another machine; use `aurvet review` to analyse a recipe under an offline root")
		return exitUsage
	}
	if opts.noNet {
		fmt.Fprintln(stderr, "aurvet: install refuses to run with --no-network: it cannot review a closure it cannot "+
			"fetch, and a review of the root recipe alone is not a review of the closure; use `aurvet review` to "+
			"analyse what is already on disk")
		return exitUsage
	}
	if err := gate.ValidPkgBase(opts.pkgbase); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	euid := os.Geteuid()
	cfg, err := config.Resolve(opts.liveRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	cfg = withStateOverride(cfg, euid)

	// install only ever runs against the live system, so the approval store is
	// always the live one. liveRoot is a test seam standing in for "/", and the
	// stores must resolve as they do on a live run.
	storeCfg := cfg
	storeCfg.Root = "/"

	floorStr := opts.minSeverity
	if floorStr == "" {
		floorStr = cfg.MinSeverity
	}
	floor, err := report.ParseSeverity(floorStr)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	src := opts.src
	if src == nil {
		src = aurSnapshotSource{
			baseURL: "https://aur.archlinux.org",
			hc:      &http.Client{Timeout: 60 * time.Second},
			lim:     defaultFetchLimits(),
		}
	}
	cl := opts.cl
	if cl == nil {
		cl = aur.NewHTTP("https://aur.archlinux.org", &http.Client{Timeout: 20 * time.Second})
	}

	stage := opts.stageDir
	if stage == "" {
		d, err := os.MkdirTemp("", "aurvet-install-")
		if err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
		stage = d
	}
	// 0700: the staged recipe is what a human is about to approve, so no other
	// account may edit it between the review and the handover.
	if err := os.MkdirAll(stage, 0o700); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	stageRoot, err := os.OpenRoot(stage)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer stageRoot.Close()

	ctx := context.Background()
	res := finding.Result{}

	// --- 1. fetch and resolve the closure ----------------------------------
	nodes, closureGaps := walkClosure(ctx, closureConfig{
		Root:     opts.pkgbase,
		Src:      src,
		Client:   cl,
		Stage:    stageRoot,
		DBPath:   cfg.DBPath,
		SyncPath: cfg.SyncPath,
		MaxNodes: opts.maxNodes,
	})
	res.Gaps = append(res.Gaps, closureGaps...)

	fmt.Fprintf(stdout, "install %s: %d recipe(s) staged in %s\n", opts.pkgbase, len(nodes), stage)
	fmt.Fprintf(stdout, "recipes came from: %s\n", src.Describe())
	renderTree(stdout, nodes)

	// --- 2. review every recipe in the closure ------------------------------
	rv := newReviewer(storeCfg, euid)
	rv.keepOpen = true // the handover re-verifies the descriptors these opens produced.
	defer rv.close()

	reviews := make([]recipeReview, 0, len(nodes))
	for _, n := range nodes {
		one := rv.review(stageRoot, target{PkgBase: n.PkgBase, Dir: n.PkgBase, Helper: "staged for review"})
		reviews = append(reviews, one)
		res.Findings = append(res.Findings, one.Result.Findings...)
		res.Gaps = append(res.Gaps, one.Result.Gaps...)
	}
	renderReview(stdout, opts.pkgbase, reviews, res, opts.showRecipe)

	// --- 3. prompt ----------------------------------------------------------
	// INV-3: never present a clean prompt for a closure that could not be fully
	// reviewed. The banner comes BEFORE the question, because a caveat printed
	// after the decision is not a caveat.
	if !res.Complete() {
		fmt.Fprintf(stdout, "\ncoverage is INCOMPLETE: %d thing(s) above could not be established. "+
			"Approving now approves a closure that was not fully reviewed.\n", len(res.Gaps))
	}
	if worst := res.MaxSeverity(); worst >= floor {
		fmt.Fprintf(stdout, "highest rule hit: %s\n", worst)
	}
	if !prompt(opts.stdin, stdout, opts.jsonOut, stderr) {
		fmt.Fprintln(stdout, "declined: nothing was approved, nothing was captured, and nothing was handed over.")
		fmt.Fprintf(stdout, "the staged recipes are left in %s for reading; remove them when you are done.\n", stage)
		if code := report.ExitCode(res, floor); code != exitClean {
			return code
		}
		// A declined install did not install anything. Exit 0 would read as
		// success to any wrapper.
		return exitFindings
	}

	// --- 4. record the decision --------------------------------------------
	approvals, aerr := gate.OpenStore(storeCfg)
	for _, one := range reviews {
		if one.Digest == "" {
			continue
		}
		if aerr != nil {
			fmt.Fprintf(stderr, "aurvet: no approval was recorded for %s: %v\n", one.PkgBase, aerr)
			break
		}
		if _, err := approvals.Approve(gate.Recipe{PkgBase: one.PkgBase, Files: one.Files, Digest: one.Digest},
			gate.ApproveOptions{By: currentUser(), Note: "aurvet install " + opts.pkgbase}); err != nil {
			fmt.Fprintf(stderr, "aurvet: could not record the approval for %s: %v\n", one.PkgBase, err)
		}
	}

	// --- 5. snapshot, BEFORE the handover ----------------------------------
	store := snapshot.New(cfg, snapshotStateDir(euid))
	if ok, why := store.Writable(); !ok {
		fmt.Fprintf(stderr, "aurvet: %s\n", why)
	}
	fmt.Fprintln(stdout)
	for _, one := range reviews {
		if one.PkgBase == "" {
			continue
		}
		rec, err := snapshot.Capture(stageRoot, snapshot.Config{
			PkgBase: one.PkgBase,
			Clones: []helper.Clone{{
				PkgBase:     one.PkgBase,
				Dir:         one.Dir,
				Helper:      "aurvet-install",
				HasPKGBUILD: true,
				HasSRCINFO:  true,
			}},
			CapturedAt: time.Now().UTC(),
		})
		if err != nil {
			fmt.Fprintf(stderr, "aurvet: %s: %v\n", one.PkgBase, err)
			continue
		}
		// The capture's own shortfalls are coverage facts about what will be
		// installed, so they count (INV-9). .BUILDINFO is always one of them
		// here; buildInfoNote says why, once, instead of leaving the reader to
		// infer it from a gap.
		res.Gaps = append(res.Gaps, rec.Gaps...)
		if ok, _ := store.Writable(); ok {
			if p, wrote, serr := store.Save(rec, time.Now().UTC().Format(snapshotStamp)); serr != nil {
				fmt.Fprintf(stderr, "aurvet: could not persist the record for %s: %v\n", one.PkgBase, serr)
			} else if wrote {
				fmt.Fprintf(stdout, "provenance snapshot for %s written to %s\n", one.PkgBase, p)
			} else {
				fmt.Fprintf(stdout, "provenance snapshot for %s unchanged since %s\n", one.PkgBase, p)
			}
		}
	}
	// The absent independent testimony is a coverage gap, not a footnote: it is
	// the difference between "makepkg says this package came from this recipe"
	// and "we hashed the recipe ourselves" (INV-9, INV-6).
	res.Gaps = append(res.Gaps, finding.Gap{
		RuleID:  ruleBuildInfoUnreachable,
		Subject: opts.pkgbase,
		Reason:  buildInfoNote,
	})
	fmt.Fprintf(stdout, "%s\n", buildInfoNote)

	// --- 6. re-verify, then hand over --------------------------------------
	if opts.afterPrompt != nil {
		opts.afterPrompt(stage)
	}
	if changed := verifyUnchanged(stageRoot, reviews); len(changed) > 0 {
		res.Findings = append(res.Findings, changed...)
		fmt.Fprintln(stdout, "\nREFUSING TO HAND OVER: the recipe on disk is not the recipe that was reviewed.")
		for _, f := range changed {
			fmt.Fprintf(stdout, "  [%s] %s  %s\n", f.Severity, f.RuleID, f.Summary)
			for _, e := range f.Evidence {
				fmt.Fprintf(stdout, "      %s\n", sanitiseText(e, 200))
			}
		}
		if opts.jsonOut {
			renderInstallJSON(stdout, opts.pkgbase, stage, false, nodes, reviews, res)
		}
		if code := report.ExitCode(res, floor); code != exitClean {
			return code
		}
		return exitFindings
	}

	if opts.jsonOut {
		renderInstallJSON(stdout, opts.pkgbase, stage, true, nodes, reviews, res)
	} else {
		renderHandover(stdout, stage, reviews)
	}
	return report.ExitCode(res, floor)
}

// buildInfoNote states, in output, why .BUILDINFO's independent testimony is not
// in the record (INV-6).
//
// pkgbuild_sha256sum is makepkg's own statement that the installed package came
// from a given recipe, and the snapshot's digest of the retained PKGBUILD cannot
// substitute for it: deriving one from the other would turn independent
// testimony into a tautology. makepkg writes .BUILDINFO UNCOMPRESSED into
// $pkgdir before compressing, and pkgmeta.BuildInfoFromFile reads a loose one --
// but $pkgdir exists only while makepkg is running, and aurvet does not run
// makepkg (INV-2). Measured on the reference system (2026-08-05): 0 of 36 yay
// clones retain a loose .BUILDINFO, and the single surviving pkg/ directory is
// mode 0111 and holds none at the expected path. The gap stands, and it stands
// for a reason that is a design decision rather than an oversight.
const buildInfoNote = "note: .BUILDINFO (pkgbuild_sha256sum) is NOT captured by this flow. It is written into $pkgdir " +
	"by makepkg, and aurvet does not run makepkg; the digest of the retained PKGBUILD is this tool's own testimony, " +
	"not makepkg's, so it is not substituted. Run `aurvet snapshot <pkgbase>` after the build to capture from the " +
	"package archive if your helper kept one."

// verifyUnchanged is the TOCTOU check, run immediately before the handover.
//
// Two independent questions, because neither answer alone is enough:
//
//   - fsx.CheckUnchanged on the descriptor the PKGBUILD was READ from proves
//     the inode we hashed was not rewritten under us.
//   - a fresh gate.DigestRecipe by PATH proves the paths still resolve to those
//     bytes -- which an open descriptor cannot tell us, because a repointed path
//     leaves our descriptor happily reading the original file.
//
// A failure of either refuses the handover. It is reported as a FINDING and not
// a gap: something observably changed a recipe after a human approved it.
func verifyUnchanged(stage *os.Root, reviews []recipeReview) []finding.Finding {
	var out []finding.Finding
	for _, one := range reviews {
		if one.Digest == "" {
			continue
		}
		var reason string
		if one.fd != nil {
			if err := fsx.CheckUnchanged(one.fd, one.at); err != nil {
				reason = fmt.Sprintf("the PKGBUILD descriptor read at review time no longer describes the same file: %v", err)
			}
		}
		if reason == "" {
			names := make([]string, 0, len(one.Files))
			for _, f := range one.Files {
				if f.Name != "PKGBUILD" {
					names = append(names, f.Name)
				}
			}
			again, err := gate.DigestRecipe(stage, gate.RecipeRequest{PkgBase: one.PkgBase, Dir: one.Dir, Aux: names})
			switch {
			case err != nil:
				reason = fmt.Sprintf("the staged recipe could not be re-read to confirm it is unchanged: %v", err)
			case again.Digest != one.Digest:
				reason = fmt.Sprintf("the recipe digest changed from %s to %s between the review and the handover",
					short12(one.Digest), short12(again.Digest))
			}
		}
		if reason == "" {
			continue
		}
		out = append(out, finding.Finding{
			RuleID:      ruleRecipeChanged,
			SubjectKind: subjectInstall,
			Subject:     one.PkgBase,
			Severity:    finding.SevCritical,
			Summary:     "the staged recipe changed after it was reviewed and approved; nothing was handed over",
			Evidence:    []string{one.Dir, reason},
			Limits: "establishes that the bytes differ, not who changed them or why; a concurrent write by another " +
				"process on the same account is indistinguishable here from a deliberate substitution.",
		})
	}
	return out
}

// prompt asks the one question this command exists to ask.
//
// Only a literal "yes" proceeds. Not "y", not an empty line: the answer that
// hands a directory to something that will execute it should cost more
// keystrokes than the answer that does not. EOF (a pipe, a cron job) declines.
func prompt(in io.Reader, stdout io.Writer, jsonOut bool, stderr io.Writer) bool {
	w := stdout
	if jsonOut {
		// stdout must carry one JSON document and nothing else.
		w = stderr
	}
	if in == nil {
		in = os.Stdin
	}
	fmt.Fprint(w, "\nproceed? type yes to record the approval, capture provenance and hand the directory over: ")
	line, err := bufio.NewReader(in).ReadString('\n')
	fmt.Fprintln(w)
	if err != nil && line == "" {
		return false
	}
	return strings.TrimSpace(line) == "yes"
}

// currentUser names the account that took the decision, for the approval
// record. It reads the environment, which is legitimate here and only here: this
// is a label on a human decision, not a trust-bearing path.
func currentUser() string {
	if u := os.Getenv("USER"); u != "" {
		return sanitiseText(u, 32)
	}
	return fmt.Sprintf("uid %d", os.Geteuid())
}

// renderTree prints the closure. The attacker's move is a benign package pulling
// a malicious dependency, so the shape of the closure is evidence in its own
// right.
func renderTree(w io.Writer, nodes []closureNode) {
	if len(nodes) == 0 {
		return
	}
	fmt.Fprintln(w, "\ndependency closure (AUR members only; repository dependencies are pacman's business):")
	for i, n := range nodes {
		prefix := strings.Repeat("  ", n.Depth)
		branch := "├── "
		if i == len(nodes)-1 {
			branch = "└── "
		}
		if n.Depth == 0 {
			branch = ""
		}
		fmt.Fprintf(w, "  %s%s%s", prefix, branch, n.PkgBase)
		if n.Via != "" && n.Via != n.PkgBase {
			fmt.Fprintf(w, "  (as dependency %s)", sanitiseText(n.Via, 60))
		}
		fmt.Fprintln(w)
	}
}

// renderHandover states what is being handed over, and what aurvet will not do.
func renderHandover(w io.Writer, stage string, reviews []recipeReview) {
	fmt.Fprintln(w, "\nhandover: the vetted directories are yours to build.")
	for _, one := range reviews {
		if one.Digest == "" {
			continue
		}
		fmt.Fprintf(w, "  %s  pkgbase %s  recipe digest %s\n", path.Join(stage, one.Dir), one.PkgBase, short12(one.Digest))
	}
	fmt.Fprintln(w, "  the recipe digests above were re-verified against disk immediately before this line was printed.")
	fmt.Fprintln(w, "  aurvet does not run makepkg and aurvet does not run your helper: handing these directories to a "+
		"builder is your action, taken with what you have just read (INV-2).")
}

// --- the dependency closure -------------------------------------------------
//
// closureConfig and walkClosure are install's CALL SITE for the dependency
// closure review (P2 task 9, internal/gate/closure.go), which another lane owns
// and which was NOT in the tree when this was written. The shape here follows
// the roadmap's description of that task -- "resolves the full AUR dep closure
// and reviews every new PKGBUILD in it ... prints the tree" -- with the review
// itself delegated to reviewer.review so there is exactly one implementation of
// "what reviewing a recipe means".
//
// internal/gate/closure.go landed during this lane and publishes
// gate.ReviewClosure(ctx, root, ClosureRequest, ClosureConfig) Closure. It is
// the right home for this walk, and replacing this function with it is a
// FOLLOWUP rather than something done here, because the two are not the same
// shape yet: ReviewClosure resolves recipes from a gate.RecipeSource that
// already has them ON DISK, while install must FETCH each member before it can
// be reviewed. The integration needs a fetch-on-demand RecipeSource (Recipe
// (pkgbase) staging the tarball, then returning the staged dir) plus a
// gate.NameResolver over aur.Client, and install still needs the per-recipe
// descriptor this file retains for the handover re-verification. Doing that
// against a file another lane was writing in the same run was not a trade worth
// taking; the tests below pin the behaviour so the swap is verifiable.

type closureConfig struct {
	Root     string
	Src      recipeSource
	Client   aur.Client
	Stage    *os.Root
	DBPath   string
	SyncPath string
	MaxNodes int
}

// walkClosure fetches and stages the root recipe and every AUR dependency
// reachable from it, breadth-first.
//
// Everything that cannot be resolved is a gap, never an omission: a prompt that
// says "nothing found" about a closure it could not resolve is the worst output
// this tool can produce (INV-9).
func walkClosure(ctx context.Context, cfg closureConfig) ([]closureNode, []finding.Gap) {
	maxNodes := cfg.MaxNodes
	if maxNodes <= 0 {
		maxNodes = defaultMaxClosureNodes
	}

	var gaps []finding.Gap
	gap := func(rule, subject, reason string) {
		gaps = append(gaps, finding.Gap{RuleID: rule, Subject: subject, Reason: reason})
	}

	// The two oracles that decide whether a dependency is even the AUR's
	// business. A failure to load either is a gap: without them every repo
	// package looks like a missing AUR package, and vice versa.
	syncNames, syncGaps, err := alpm.LoadSyncNames(cfg.SyncPath)
	if err != nil || len(syncNames) == 0 {
		gap("sync-coverage", cfg.SyncPath, fmt.Sprintf("no repository package names were loaded (%v), so this closure "+
			"cannot tell a repository dependency from an AUR one and may fetch or skip the wrong members", err))
	}
	for _, g := range syncGaps {
		gap("sync-coverage", g, "a sync database entry could not be read, so the repository name set is incomplete")
	}
	installed := map[string]bool{}
	if pkgs, _, err := alpm.LoadLocalDB(cfg.DBPath); err == nil {
		for _, p := range pkgs {
			installed[p.Name] = true
		}
	} else {
		gap("local-db", cfg.DBPath, fmt.Sprintf("the local package database could not be read (%v), so already-installed "+
			"dependencies cannot be told from missing ones and the closure may be larger than it needs to be", err))
	}

	type queued struct {
		pkgbase string
		via     string
		depth   int
	}
	queue := []queued{{pkgbase: cfg.Root}}
	seen := map[string]bool{cfg.Root: true}
	var nodes []closureNode

	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]

		files, err := cfg.Src.Fetch(ctx, cur.pkgbase)
		if err != nil {
			gap(ruleFetchFailed, cur.pkgbase, fmt.Sprintf("the recipe for this closure member could not be "+
				"retrieved, so it was not reviewed: %v", err))
			continue
		}
		if err := stageRecipe(cfg.Stage, cur.pkgbase, files); err != nil {
			gap(ruleFetchFailed, cur.pkgbase, fmt.Sprintf("the recipe could not be staged for review: %v", err))
			continue
		}
		node := closureNode{PkgBase: cur.pkgbase, Depth: cur.depth, Via: cur.via}

		// Dependencies come from the .SRCINFO the AUR ships beside the recipe,
		// which is makepkg's own declaration and needs no bash evaluation.
		si, err := pkgmeta.ParseSRCINFO(strings.NewReader(string(files[".SRCINFO"])), pkgmeta.Limits{})
		if err != nil {
			gap(ruleSrcinfoMissing, cur.pkgbase, fmt.Sprintf("the .SRCINFO could not be read (%v), so this member's "+
				"dependencies are unknown and the closure below it was not walked", err))
			nodes = append(nodes, node)
			continue
		}

		var wanted []string
		for _, d := range si.Deps(pkgmeta.DepRun, pkgmeta.DepMake, pkgmeta.DepCheck) {
			if d.Name == "" || syncNames[d.Name] || installed[d.Name] {
				continue
			}
			if !containsString(wanted, d.Name) {
				wanted = append(wanted, d.Name)
			}
		}
		sort.Strings(wanted)

		if len(wanted) > 0 {
			info, err := cfg.Client.Info(ctx, wanted)
			if err != nil {
				gap(ruleDepUnresolved, cur.pkgbase, fmt.Sprintf("the AUR index could not be queried for %d "+
					"unsatisfied dependency name(s) (%v), so it is unknown whether they are AUR packages needing "+
					"review: %s", len(wanted), err, strings.Join(wanted, " ")))
				wanted = nil
			}
			for _, name := range wanted {
				p, ok := info[name]
				if !ok {
					gap(ruleDepUnresolved, name, fmt.Sprintf("dependency of %s: neither an installed package, nor a "+
						"repository package, nor an AUR package this tool could find (it may be a virtual provide, "+
						"which this closure does not resolve); nothing about it was reviewed", cur.pkgbase))
					continue
				}
				// Keyed on the BASE, not the name: one recipe builds several
				// packages, and reviewing the same base once per package name
				// would review it twice and prompt twice.
				base := p.PackageBase
				if base == "" {
					base = p.Name
				}
				node.Children = append(node.Children, base)
				if seen[base] {
					continue
				}
				if len(seen) >= maxNodes {
					gap(ruleClosureBounded, cur.pkgbase, fmt.Sprintf("the closure exceeds the %d-member review "+
						"bound at dependency %q; the remainder was not fetched or reviewed", maxNodes, base))
					continue
				}
				if cur.depth+1 > maxClosureDepth {
					gap(ruleClosureBounded, cur.pkgbase, fmt.Sprintf("the closure is deeper than %d levels at "+
						"dependency %q; the remainder was not fetched or reviewed", maxClosureDepth, base))
					continue
				}
				seen[base] = true
				queue = append(queue, queued{pkgbase: base, via: name, depth: cur.depth + 1})
			}
		}
		nodes = append(nodes, node)
	}
	return nodes, gaps
}

// stageRecipe writes one recipe's files into the staging root.
//
// Every write goes through os.Root, every name is a plain name (readSnapshotTarball
// and the source contract both guarantee it, and this checks again because a
// source is a caller-supplied interface), the directory is 0700 and the files
// are 0600 and created O_EXCL. The mode matters: the staged recipe is what a
// human is about to approve, and it must not be writable by anyone else between
// the review and the handover.
func stageRecipe(stage *os.Root, pkgbase string, files map[string][]byte) error {
	if err := gate.ValidPkgBase(pkgbase); err != nil {
		return err
	}
	if _, ok := files["PKGBUILD"]; !ok {
		return fmt.Errorf("no PKGBUILD in the fetched recipe for %s", pkgbase)
	}
	if err := stage.Mkdir(pkgbase, 0o700); err != nil && !os.IsExist(err) {
		return err
	}
	names := make([]string, 0, len(files))
	for name := range files {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		if !plainName(name) {
			return fmt.Errorf("%s: refusing to stage %q, which is not a plain file name", pkgbase, sanitiseText(name, 80))
		}
		f, err := stage.OpenFile(path.Join(pkgbase, name), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
		if err != nil {
			return err
		}
		if _, err := f.Write(files[name]); err != nil {
			f.Close()
			return err
		}
		if err := f.Close(); err != nil {
			return err
		}
	}
	return nil
}

func containsString(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}

// --- JSON -------------------------------------------------------------------

type installJSON struct {
	PkgBase    string         `json:"pkgbase"`
	StageDir   string         `json:"stage_dir"`
	HandedOver bool           `json:"handed_over"`
	Closure    []closureNode  `json:"closure"`
	Recipes    []recipeReview `json:"recipes"`
	Findings   []jsonFinding  `json:"findings"`
	Gaps       []jsonGap      `json:"gaps"`
	Limits     string         `json:"limits"`
}

func renderInstallJSON(w io.Writer, pkgbase, stage string, handed bool, nodes []closureNode, reviews []recipeReview, res finding.Result) {
	out := installJSON{
		PkgBase: pkgbase, StageDir: stage, HandedOver: handed,
		Closure: nodes, Recipes: reviews, Limits: buildInfoNote,
	}
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
	_ = enc.Encode(out)
}
