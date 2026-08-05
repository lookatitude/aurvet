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

	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/gate"
	"github.com/lookatitude/aurvet/internal/helper"
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
		name := strings.TrimPrefix(hdr.Name, "./")
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
	maxNodes := opts.maxNodes
	if maxNodes <= 0 {
		maxNodes = defaultMaxClosureNodes
	}
	fetcher := newStagingSource(ctx, src, stageRoot)
	closure := gate.ReviewClosure(ctx, stageRoot, gate.ClosureRequest{PkgBase: opts.pkgbase}, gate.ClosureConfig{
		Source:   fetcher,
		Repo:     repoIndex(cfg.SyncPath, &res),
		Resolver: aurResolver{cl: cl},
		Limits:   gate.ClosureLimits{MaxNodes: maxNodes, MaxDepth: maxClosureDepth},
	})
	res.Gaps = append(res.Gaps, fetcher.gaps()...)
	res.Gaps = append(res.Gaps, closureGaps(closure, fetcher)...)
	nodes := closureNodes(closure)

	fmt.Fprintf(stdout, "install %s: %d recipe(s) staged in %s\n", opts.pkgbase, len(fetcher.staged), stage)
	fmt.Fprintf(stdout, "recipes came from: %s\n", src.Describe())
	renderTree(stdout, closure)

	// --- 2. review every recipe in the closure ------------------------------
	rv := newReviewer(storeCfg, euid)
	rv.keepOpen = true // the handover re-verifies the descriptors these opens produced.
	defer rv.close()

	reviews := make([]recipeReview, 0, len(nodes))
	for _, n := range closure.Nodes {
		if n.Kind != gate.KindAUR || n.Dir == "" {
			// An AUR member with no staged recipe is already a gap from the
			// fetcher; reviewing a directory that does not exist would add a
			// second, vaguer one saying the same thing.
			continue
		}
		one := rv.review(stageRoot, target{PkgBase: n.PkgBase, Dir: n.Dir, Helper: "staged for review"})
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
//
// The tree is gate.Closure's own rendering, not a second one: a tree drawn from
// a different traversal than the one that decided what to review is a picture of
// something other than what happened.
func renderTree(w io.Writer, c gate.Closure) {
	if len(c.Nodes) == 0 {
		return
	}
	n := c.Counts()
	fmt.Fprintf(w, "\ndependency closure of %s: %d package(s) -- %d from the AUR, %d from repositories, %d unresolved\n",
		sanitiseText(c.Root, 64), n.Nodes, n.AUR, n.Repo+n.RepoProvided, n.Unresolved)
	for _, line := range c.Tree() {
		fmt.Fprintf(w, "  %s\n", sanitiseText(line, 200))
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
// The walk is internal/gate's ReviewClosure (P2 task 9) and nothing here
// re-implements it. install once carried its own breadth-first walker, written
// while closure.go was being written by another lane; two traversals of an
// attacker-controlled dependency graph drift, and the one that drifts is the one
// that mis-traverses -- a dependency reviewed by one path and skipped by the
// other is exactly the bypass the closure review exists to close.
//
// ReviewClosure resolves recipes from a gate.RecipeSource that already has them
// ON DISK, and install must fetch each member first. Three pieces bridge that,
// and only three:
//
//   - stagingSource, a fetch-on-demand RecipeSource: Recipe(pkgbase) fetches the
//     tarball, stages it, and returns the staged directory.
//   - aurResolver, a gate.NameResolver over aur.Client.
//   - the per-recipe review stays with reviewer.review, which RETAINS the
//     descriptor each PKGBUILD was read from. That descriptor is what
//     verifyUnchanged proves the handover against; ReviewClosure's own read is a
//     traversal read and is not handed anything.
//
// The cost of that last point is stated rather than hidden: each staged recipe
// is read twice, once by the walk to find its dependencies and once by the
// reviewer that produces the verdict, the diff and the retained descriptor. The
// second read is over a file this process staged at 0600 moments earlier, and
// paying for it buys the TOCTOU proof.

// stagingSource is the fetch-on-demand gate.RecipeSource.
//
// The context lives on the struct because gate.RecipeSource.Recipe takes none --
// it was written for a source that only looks at disk. That is the whole of the
// impedance mismatch, and it is recorded here rather than papered over by
// widening an interface that internal/gate's own callers do not need widened.
//
// A member that cannot be fetched or staged is remembered, not fetched again,
// and reported as a gap keyed on install's own rule (INV-9). It is never a
// silent absence: gate then sees "no recipe" and refuses to call the node
// reviewed, which is the same conclusion by a different route.
type stagingSource struct {
	ctx   context.Context
	src   recipeSource
	stage *os.Root

	// staged maps pkgbase -> staged root-relative directory.
	staged map[string]string

	// failed maps pkgbase -> the reason nothing was staged, and order keeps
	// those reasons in fetch order so the output of one (root, cfg) is stable.
	failed map[string]string
	order  []string
}

func newStagingSource(ctx context.Context, src recipeSource, stage *os.Root) *stagingSource {
	return &stagingSource{ctx: ctx, src: src, stage: stage, staged: map[string]string{}, failed: map[string]string{}}
}

func (s *stagingSource) Recipe(pkgbase string) (string, bool) {
	if dir, ok := s.staged[pkgbase]; ok {
		return dir, true
	}
	if _, bad := s.failed[pkgbase]; bad {
		return "", false
	}
	files, err := s.src.Fetch(s.ctx, pkgbase)
	if err != nil {
		s.fail(pkgbase, fmt.Sprintf("the recipe for this closure member could not be retrieved, so it was not "+
			"reviewed: %v", err))
		return "", false
	}
	if err := stageRecipe(s.stage, pkgbase, files); err != nil {
		s.fail(pkgbase, fmt.Sprintf("the recipe could not be staged for review: %v", err))
		return "", false
	}
	s.staged[pkgbase] = pkgbase
	return pkgbase, true
}

func (s *stagingSource) fail(pkgbase, reason string) {
	s.failed[pkgbase] = reason
	s.order = append(s.order, pkgbase)
}

// gaps reports every member whose recipe never reached the staging directory.
func (s *stagingSource) gaps() []finding.Gap {
	out := make([]finding.Gap, 0, len(s.order))
	for _, pkgbase := range s.order {
		out = append(out, finding.Gap{RuleID: ruleFetchFailed, Subject: pkgbase, Reason: s.failed[pkgbase]})
	}
	return out
}

// aurResolver adapts aur.Client to gate.NameResolver.
//
// The two contracts agree on the point that matters: a non-nil error is a FAILED
// LOOKUP and never an absence, so this returns the error untouched rather than
// an empty map, which the walk would read as "the AUR does not have these".
type aurResolver struct{ cl aur.Client }

func (r aurResolver) Bases(ctx context.Context, names []string) (map[string]string, error) {
	info, err := r.cl.Info(ctx, names)
	if err != nil {
		return nil, err
	}
	out := make(map[string]string, len(info))
	for name, p := range info {
		// Keyed on the BASE, not the name: one recipe builds several packages,
		// and reviewing the same base once per package name would review it
		// twice and prompt twice.
		base := p.PackageBase
		if base == "" {
			base = p.Name
		}
		out[name] = base
	}
	return out, nil
}

// repoIndex loads the binary-repository index and records its shortfalls.
//
// An empty index is a gap even when nothing errored: with no repository names
// every repo dependency looks like a missing AUR package and vice versa, so the
// closure that follows may fetch or skip the wrong members.
func repoIndex(syncPath string, res *finding.Result) gate.RepoSet {
	repo, gaps := gate.SyncIndex(syncPath)
	for _, g := range gaps {
		res.Gaps = append(res.Gaps, finding.Gap{RuleID: "sync-coverage", Subject: g.Subject, Reason: g.Reason})
	}
	if len(repo.Names) == 0 {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID:  "sync-coverage",
			Subject: syncPath,
			Reason: "no repository package names were loaded, so this closure cannot tell a repository dependency " +
				"from an AUR one and may fetch or skip the wrong members",
		})
	}
	return repo
}

// closureRuleNames maps the walk's rule identifiers onto install's own, so this
// command reports one vocabulary whatever resolves its closure. Both names are
// carried: the mapped id leads, and the walk's own id stays in the reason so a
// gap here and the same gap under `review` can still be tied together.
var closureRuleNames = map[string]string{
	gate.RuleDepUnresolved:    ruleDepUnresolved,
	gate.RuleLookupFailed:     ruleDepUnresolved,
	gate.RuleNoResolver:       ruleDepUnresolved,
	gate.RuleTruncated:        ruleClosureBounded,
	gate.RuleFanOut:           ruleClosureBounded,
	gate.RuleDepthBound:       ruleClosureBounded,
	gate.RuleRecipeUnreadable: ruleFetchFailed,
	gate.RuleDepsUnreadable:   ruleSrcinfoMissing,
}

// closureGaps translates the walk's coverage gaps into install's vocabulary.
//
// gate.RuleRecipeUnavailable for a member the fetcher already failed on is
// DROPPED, and only then: the fetcher's gap names the same node with the actual
// transport error, and two gaps for one fact inflate the count the prompt puts
// in front of the operator.
func closureGaps(c gate.Closure, s *stagingSource) []finding.Gap {
	var out []finding.Gap
	for _, g := range c.Gaps {
		if g.RuleID == gate.RuleRecipeUnavailable {
			if _, failed := s.failed[g.Subject]; failed {
				continue
			}
		}
		if mapped, ok := closureRuleNames[g.RuleID]; ok {
			g = finding.Gap{RuleID: mapped, Subject: g.Subject, Reason: g.Reason + " [" + g.RuleID + "]"}
		}
		out = append(out, g)
	}
	// Per-node gaps from the walk's own read are NOT merged: every staged
	// recipe is reviewed again below by reviewer.review, which raises the same
	// shortfalls against the same files. Merging both would double-count them.
	return out
}

// closureNodes projects the closure's AUR members into the JSON shape this
// command publishes. Only AUR members appear: a repository dependency is
// pacman's business and was neither fetched nor reviewed.
func closureNodes(c gate.Closure) []closureNode {
	var out []closureNode
	for _, n := range c.Nodes {
		if n.Kind != gate.KindAUR {
			continue
		}
		node := closureNode{PkgBase: n.PkgBase, Depth: n.Depth}
		for _, name := range n.Names {
			if name != n.PkgBase {
				node.Via = name
				break
			}
		}
		for _, e := range n.Deps {
			if e.To == "" {
				continue
			}
			if to, ok := c.Node(e.To); ok && to.Kind == gate.KindAUR && !containsString(node.Children, to.Key) {
				node.Children = append(node.Children, to.Key)
			}
		}
		out = append(out, node)
	}
	return out
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
