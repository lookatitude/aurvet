// internal/gate/closure.go
//
// Dependency-closure review (P2 task 9).
//
// # Why the closure, and not the package the user typed
//
// A gate that reviews only the named package has a documented bypass, and it is
// the cheapest one in the ecosystem: publish something innocuous, give it
// depends=('helpful-lib'), and put the payload in helpful-lib. The operator
// reviews the recipe they asked about, sees nothing, and approves a build whose
// makedepends will fetch and execute code they never looked at. Reviewing the
// closure is the feature; reviewing the named package is the demo.
//
// So this file walks the declared dependencies, decides for each one whether it
// is somebody else's problem or this tool's, reviews every AUR recipe in the
// second category, and prints the tree it walked.
//
// # The three-way split, and the direction it must fail in
//
// Each dependency lands in exactly one bucket:
//
//  1. a BINARY REPOSITORY package -- not reviewed, not recursed into. pacman's
//     signature chain covers it, and recursing turns a five-node closure into
//     thousands of nodes that no rule in this project has anything to say about.
//  2. an AUR package already approved AT ITS CURRENT RECIPE DIGEST -- silent,
//     which is approve.go's contract and the only silence this file permits.
//  3. an AUR package that is new or changed -- reviewed, and shown.
//
// Bucket 1 is the dangerous one, and only in one direction. Over-reviewing a
// repository package wastes a reader's attention; UNDER-reviewing an AUR package
// because something claimed to be a repository package is a silent skip of
// exactly the node an attacker would choose. Hence the identity rule below.
//
// # Identity comes from where a package LIVES, never from what it CLAIMS
//
// A name is repository-satisfied only when it is a package NAME in a sync
// database (internal/alpm reads those names out of the signed .db archives), or
// when a package in a sync database DECLARES provides= for it. Both of those
// facts come from repository metadata that pacman's signature chain covers.
//
// The provides= array of an AUR package is never consulted for this decision.
// A hostile PKGBUILD can say provides=('openssl') for free; if that could stand
// in for an identity, the attacker writes one line and the review goes quiet on
// the package it most needed to read. And when a name is BOTH a live AUR package
// and a virtual name some repository package provides, the AUR package wins and
// is reviewed -- the other precedence is the same silent skip by a slower route.
//
// # pkgbase, not pkgname
//
// A dependency names a PKGNAME; a review and an approval are taken over a
// PKGBASE, because one recipe is one build and one decision. 433 of 1409
// packages on the reference system are split, so keying the closure on pkgname
// would prompt an operator once per output package of a single recipe -- and a
// prompt an operator has learned to click through is not a control. Every AUR
// node here is keyed on its pkgbase and records each pkgname that reached it.
//
// # Bounds, and why a bound is a coverage gap
//
// Depth, node count and per-node fan-out are all bounded, and cycles -- which
// real AUR dependency graphs contain -- are detected as well, because neither a
// bound nor a cycle check alone is enough: a bound without cycle detection
// re-reviews the same three packages until it gives up, and a cycle check
// without a bound walks a hostile 10,000-dependency .SRCINFO. Every bound that
// fires becomes a coverage gap (INV-9), because a silently truncated closure is
// a reviewed-looking closure that was not reviewed.
//
// Nothing here executes anything (INV-2): no makepkg --printsrcinfo, no
// pacman -Si, no git. Everything is a pure function of (root, cfg) plus an
// explicit network seam (INV-4), and nothing writes (INV-5).
package gate

import (
	"context"
	"fmt"
	"io"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/helper"
	"github.com/lookatitude/aurvet/internal/pkgbuild"
	"github.com/lookatitude/aurvet/internal/pkgmeta"
)

// Rule identifiers for the closure walk. They are separate rules because the
// remedies differ: a truncated fan-out is a bound the operator can raise, an
// unresolvable dependency is a package that does not exist, and a failed AUR
// lookup is a network problem. Collapsing them into "closure incomplete" would
// tell nobody what to do.
const (
	// RuleDepUnresolved is a declared dependency that is neither a repository
	// package nor an AUR package this run could find.
	RuleDepUnresolved = "closure-dep-unresolved"

	// RuleCycle is a dependency edge that closes a cycle. The edge is shown and
	// the walk stops there.
	RuleCycle = "closure-cycle-cut"

	// RuleTruncated is the whole-closure node bound.
	RuleTruncated = "closure-node-bound"

	// RuleFanOut is one node's dependency-list bound.
	RuleFanOut = "closure-fanout-bound"

	// RuleDepthBound is the depth bound: nodes deeper than it were never
	// enumerated.
	RuleDepthBound = "closure-depth-bound"

	// RuleRecipeUnavailable is an AUR node with no recipe on this system, so it
	// could be named but not read.
	RuleRecipeUnavailable = "closure-recipe-unavailable"

	// RuleRecipeUnreadable is a recipe that is present and could not be read.
	RuleRecipeUnreadable = "closure-recipe-unreadable"

	// RuleDepsUnreadable is a node whose dependency metadata could not be read,
	// so its subtree is unknown.
	RuleDepsUnreadable = "closure-deps-unreadable"

	// RuleLookupFailed is an AUR lookup that failed. Never an absence.
	RuleLookupFailed = "closure-aur-lookup-failed"

	// RuleNoResolver is a run with no AUR lookup available at all, so names not
	// present locally could not be classified.
	RuleNoResolver = "closure-no-aur-lookup"

	// RuleRepoIndexUnavailable is a run with no repository index, so no name
	// could be dismissed as repository-satisfied.
	RuleRepoIndexUnavailable = "closure-repo-index-unavailable"
)

// maxPKGBUILDBytes bounds one recipe read for review. The largest PKGBUILD in
// the reference cache is under 16 KB.
const maxPKGBUILDBytes = 4 << 20

// ClosureLimits bounds what an attacker-controlled dependency graph can cost.
// Exported and copyable so a test can prove each bound fires on its own.
type ClosureLimits struct {
	// MaxDepth is the deepest level enumerated. The root is depth 0.
	MaxDepth int

	// MaxNodes bounds the whole closure.
	MaxNodes int

	// MaxDepsPerNode bounds one .SRCINFO's dependency list.
	MaxDepsPerNode int
}

// DefaultClosureLimits returns bounds with headroom over the measured worst
// case rather than fitted to it. The reference system's deepest AUR closure
// reachable from a cached clone is a handful of levels; 8 leaves room and still
// terminates, and 512 nodes is far beyond any honest recipe while remaining a
// list a machine can hold and a report can summarise.
func DefaultClosureLimits() ClosureLimits {
	return ClosureLimits{MaxDepth: 8, MaxNodes: 512, MaxDepsPerNode: 256}
}

func (l ClosureLimits) withDefaults() ClosureLimits {
	d := DefaultClosureLimits()
	if l.MaxDepth <= 0 {
		l.MaxDepth = d.MaxDepth
	}
	if l.MaxNodes <= 0 {
		l.MaxNodes = d.MaxNodes
	}
	if l.MaxDepsPerNode <= 0 {
		l.MaxDepsPerNode = d.MaxDepsPerNode
	}
	return l
}

// DefaultDepKinds are the dependency arrays the closure walks.
//
// optdepends is deliberately absent: pacman does not install them, so a closure
// that walked them would review packages that will never be on the machine and
// would inflate every tree with recommendations. makedepends and checkdepends
// ARE walked, and that is the important half -- they execute code on the
// operator's machine at build time and then disappear, which is the most
// attractive place in the graph to hide a payload.
var DefaultDepKinds = []pkgmeta.DepKind{pkgmeta.DepRun, pkgmeta.DepMake, pkgmeta.DepCheck}

// RepoSet is the binary-repository index: the names pacman can satisfy without
// building anything.
//
// It is plain data rather than an interface because it is derived once per run
// from the sync databases and then only queried. Loaded is not a formality: a
// zero RepoSet means the index was never read, and every name must then be
// treated as un-dismissed rather than as not-in-the-repositories.
type RepoSet struct {
	// Names are package NAMES present in a sync database.
	Names map[string]bool

	// Providers maps a virtual name to the repository packages that declare
	// provides= for it. Repository metadata only -- see the package comment.
	Providers map[string][]string

	// Loaded records that the index was actually read.
	Loaded bool
}

func (s RepoSet) has(name string) bool { return s.Loaded && s.Names[name] }

func (s RepoSet) providers(name string) []string {
	if !s.Loaded {
		return nil
	}
	return s.Providers[name]
}

// SyncIndex loads a RepoSet from a pacman sync database directory.
//
// It is a thin adapter over internal/alpm so a caller does not have to know
// that the name set comes out of the signed .db archives -- which is the whole
// basis for treating those names as somebody else's problem. Unreadable
// archives come back as gaps.
//
// Note the deliberate limitation, stated rather than hidden: alpm.LoadSyncNames
// reads package NAMES, not provides=. So Providers is empty here and a purely
// virtual dependency will be reported unresolved rather than dismissed. That is
// the safe direction (a gap, not a silence), and a caller with a provides index
// can supply one.
func SyncIndex(syncPath string) (RepoSet, []finding.Gap) {
	names, failed, err := alpm.LoadSyncNames(syncPath)
	if err != nil {
		return RepoSet{}, []finding.Gap{{
			RuleID:  RuleRepoIndexUnavailable,
			Subject: syncPath,
			Reason: fmt.Sprintf("the pacman sync databases could not be read (%v), so no dependency can be "+
				"dismissed as covered by a signed repository; every name will be treated as un-dismissed", err),
		}}
	}
	var gaps []finding.Gap
	for _, f := range failed {
		gaps = append(gaps, finding.Gap{
			RuleID:  RuleRepoIndexUnavailable,
			Subject: f,
			Reason: "this sync database could not be read in full, so a dependency it satisfies may be " +
				"reported as unresolved",
		})
	}
	return RepoSet{Names: names, Loaded: true}, gaps
}

// RecipeSource locates the recipe directory for a pkgbase.
//
// It is an interface because the two real sources are different things: a
// helper cache found on disk, and the directory `install` has just cloned for
// the package being installed. Neither one is allowed to be a path this package
// invents.
type RecipeSource interface {
	// Recipe returns the ROOT-RELATIVE directory holding pkgbase's recipe, and
	// false when this source has none. It performs no I/O beyond what it needs
	// to answer that.
	Recipe(pkgbase string) (dir string, ok bool)
}

// CloneSource adapts a helper.Detection into a RecipeSource. A pkgbase present
// in two helpers' caches resolves to the first clone that has a PKGBUILD, since
// a clone without one cannot be reviewed.
type CloneSource helper.Detection

func (s CloneSource) Recipe(pkgbase string) (string, bool) {
	clones := helper.Detection(s).Clones(pkgbase)
	for _, c := range clones {
		if c.HasPKGBUILD {
			return c.Dir, true
		}
	}
	if len(clones) > 0 {
		return clones[0].Dir, true
	}
	return "", false
}

// NameResolver maps dependency NAMES to the AUR pkgbase that builds them.
//
// The batch shape is not an optimisation: the AUR's RPC answers many names in
// one request, and asking it once per dependency would both be slow and
// disclose the closure one name at a time.
type NameResolver interface {
	// Bases returns name -> pkgbase for every name the AUR knows. A name absent
	// from the map is not in the AUR. A NON-NIL ERROR IS A FAILED LOOKUP AND
	// NEVER AN ABSENCE -- the caller records a gap and must not conclude that
	// the names are unknown to the AUR.
	Bases(ctx context.Context, names []string) (map[string]string, error)
}

// LocalNames builds the pkgname -> pkgbase map from the .SRCINFO files in the
// detected helper caches.
//
// This is what makes an offline closure possible at all, and it is the reason
// split packages resolve to one node: a base that builds seventeen packages
// contributes seventeen entries pointing at one recipe.
func LocalNames(root *os.Root, det helper.Detection, lim pkgmeta.Limits) (map[string]string, []finding.Gap) {
	out := map[string]string{}
	var gaps []finding.Gap
	for _, c := range det.Caches {
		for _, cl := range c.Clones {
			if !cl.HasSRCINFO {
				continue
			}
			si, err := pkgmeta.SRCINFOFromFile(root, path.Join(cl.Dir, ".SRCINFO"), lim)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleDepsUnreadable,
					Subject: cl.PkgBase,
					Reason: fmt.Sprintf("the .SRCINFO in %s could not be read (%v), so the package names this "+
						"recipe builds are unknown and a dependency on one of them may resolve elsewhere or not at all", cl.Dir, err),
				})
				continue
			}
			// The pkgbase is keyed too: a dependency can name the base itself.
			out[si.PkgBase] = si.PkgBase
			for _, n := range si.PkgNames() {
				out[n] = si.PkgBase
			}
		}
	}
	return out, gaps
}

// NodeKind is how one node in the closure is satisfied.
type NodeKind string

const (
	// KindAUR is a package that must be built from a recipe, and therefore
	// reviewed.
	KindAUR NodeKind = "aur"

	// KindRepo is a package NAME present in a sync database.
	KindRepo NodeKind = "repo"

	// KindRepoProvided is a virtual name a repository package provides.
	KindRepoProvided NodeKind = "repo-provides"

	// KindUnresolved is a name this run could not place. Always a gap.
	KindUnresolved NodeKind = "unresolved"
)

// Edge is one declared dependency, from the node that declared it.
type Edge struct {
	// Name is the dependency name with any version constraint removed.
	Name string

	// Constraint is the version constraint as written, or "".
	Constraint string

	// Kind is the dependency array it came from. A makedepend and a depend are
	// not the same fact.
	Kind pkgmeta.DepKind

	// To is the key of the node this edge resolved to, or "" when the name was
	// refused or the node bound stopped it.
	To string

	// Cycle records that To is a STRICT ancestor of the declaring node: the
	// edge is real, the walk stopped there, and whatever was reachable only
	// through it was not enumerated.
	Cycle bool

	// Self records an edge back to the declaring node itself, which is what a
	// split package depending on a sibling pkgname looks like: one recipe, one
	// build, one review. Nothing is beyond such an edge, so it is NOT a cut and
	// NOT a coverage gap -- measured on the reference system, flutter (17
	// packages) declares five of them, and gapping on those would put an honest
	// package at exit 3 for having been split.
	Self bool

	// Repeat records that To was already reached by another path, so it is
	// reviewed once and shown once.
	Repeat bool
}

// Node is one package in the closure.
type Node struct {
	// Key is the pkgbase for an AUR node and the dependency name for every
	// other kind.
	Key string

	// PkgBase is set for AUR nodes only. Review and approval are keyed on it.
	PkgBase string

	// Names are the dependency names that resolved to this node, sorted. A
	// split package collects several.
	Names []string

	Kind NodeKind

	// Depth is the distance from the subject; the subject is 0.
	Depth int

	// Dir is the root-relative recipe directory, when one was found.
	Dir string

	// Reviewed reports that a recipe was read and the rules were run over it.
	// False with Kind == KindAUR is a coverage gap, never a clean result.
	Reviewed bool

	// Result is the rule output for this recipe, gaps included.
	Result finding.Result

	// Approval is the store's answer for this recipe. The zero value means no
	// store was consulted, which is not approval.
	Approval Decision

	// Providers are the repository packages that provide this name, for
	// KindRepoProvided.
	Providers []string

	// Deps are the outgoing edges, in declaration order.
	Deps []Edge

	// parent is the discovery parent's index, -1 for the subject. Unexported:
	// it is the print tree's spine and an ancestor test, not evidence.
	parent int

	// raw holds the declared dependencies before classification.
	raw []pkgmeta.Dep
}

// Approved reports whether this node may be silent.
func (n Node) Approved() bool { return n.Approval.Status == StatusApproved }

// Counts summarises a closure for a receipt or a header line.
type Counts struct {
	Nodes        int
	AUR          int
	Repo         int
	RepoProvided int
	Unresolved   int
	Reviewed     int
	Approved     int
	Reviewable   int
	CyclesCut    int
	MaxDepth     int
}

// Closure is the reviewed dependency closure of one package.
type Closure struct {
	// Root is the subject pkgbase.
	Root string

	// Nodes are every package reached, in discovery order with the subject
	// first. The order is deterministic for a given (root, cfg).
	Nodes []Node

	// Gaps are the walk's own coverage gaps. Per-node gaps live on the node's
	// Result and are merged by Result().
	Gaps []finding.Gap

	// Limits states what this closure does not prove (INV-6).
	Limits string

	index map[string]int
}

const closureLimits = "the closure is what the recipes DECLARE, resolved against this machine's sync databases and the AUR as they are right now: " +
	"a dependency that resolves to a repository package today can resolve to an AUR package tomorrow, a name added to a recipe after this review is not in it, " +
	"and optional dependencies are not walked. Repository packages are not reviewed at all -- they are covered by pacman's signature chain, not by this tool."

// Node returns one node by key.
func (c Closure) Node(key string) (Node, bool) {
	i, ok := c.index[key]
	if !ok {
		return Node{}, false
	}
	return c.Nodes[i], true
}

// Reviewable returns the AUR nodes a human must still decide on: reviewed, and
// not approved at this exact recipe digest. This is the set review output leads
// with.
func (c Closure) Reviewable() []Node {
	var out []Node
	for _, n := range c.Nodes {
		if n.Kind == KindAUR && !n.Approved() {
			out = append(out, n)
		}
	}
	return out
}

// Counts summarises the walk.
func (c Closure) Counts() Counts {
	var n Counts
	n.Nodes = len(c.Nodes)
	for _, node := range c.Nodes {
		switch node.Kind {
		case KindAUR:
			n.AUR++
		case KindRepo:
			n.Repo++
		case KindRepoProvided:
			n.RepoProvided++
		case KindUnresolved:
			n.Unresolved++
		}
		if node.Reviewed {
			n.Reviewed++
		}
		if node.Approved() {
			n.Approved++
		}
		if node.Depth > n.MaxDepth {
			n.MaxDepth = node.Depth
		}
		for _, e := range node.Deps {
			if e.Cycle {
				n.CyclesCut++
			}
		}
	}
	n.Reviewable = len(c.Reviewable())
	return n
}

// Result merges every node's findings and gaps.
//
// Findings from APPROVED nodes are omitted, and that is approve.go's contract
// rather than a shortcut: the operator saw that exact recipe and said yes, and
// a store that keeps shouting about an approved decision is a store whose output
// gets ignored. Gaps are never omitted -- an approval is a decision about a
// recipe, not a licence to stop reporting what could not be read.
func (c Closure) Result() finding.Result {
	res := finding.Result{Gaps: append([]finding.Gap(nil), c.Gaps...)}
	for _, n := range c.Nodes {
		if !n.Approved() {
			res.Findings = append(res.Findings, n.Result.Findings...)
		}
		res.Gaps = append(res.Gaps, n.Result.Gaps...)
		res.Gaps = append(res.Gaps, n.Approval.Gaps...)
	}
	return res
}

// --- the walk ----------------------------------------------------------------

// ClosureRequest names the package to review.
type ClosureRequest struct {
	// PkgBase is the subject.
	PkgBase string

	// Dir overrides the RecipeSource for the subject only, so `install` can
	// review the directory it has just cloned before that directory is in any
	// helper's cache.
	Dir string
}

// ClosureConfig is everything the walk is allowed to know. No ambient input:
// no CWD, no $HOME, no environment (INV-4).
type ClosureConfig struct {
	// Source locates recipes on disk.
	Source RecipeSource

	// Repo is the binary-repository index.
	Repo RepoSet

	// Local maps pkgname -> pkgbase from recipes already on disk (LocalNames).
	Local map[string]string

	// Resolver is the AUR lookup. Nil means this run has no network, which is a
	// coverage gap for every name Local and Repo could not place -- never a
	// silent absence.
	Resolver NameResolver

	// Store is the approval store. Nil means no approval is consulted, so every
	// AUR node is reviewable.
	Store *Store

	// Kinds are the dependency arrays to walk. Nil means DefaultDepKinds.
	Kinds []pkgmeta.DepKind

	// Check parameterises the PKGBUILD rules.
	Check check.PKGBUILDConfig

	// Resolve parameterises PKGBUILD resolution (architecture scope).
	Resolve pkgbuild.ResolveConfig

	// Meta bounds .SRCINFO parsing.
	Meta pkgmeta.Limits

	// Limits bounds the walk.
	Limits ClosureLimits
}

// ReviewClosure resolves the dependency closure of req.PkgBase and reviews every
// AUR recipe in it.
//
// It never returns an error. Every failure is a node kind plus a coverage gap,
// because a dependency this tool could not resolve says nothing about whether
// the package is safe, and an error return invites a caller to log it and carry
// on as though the closure had been reviewed.
func ReviewClosure(ctx context.Context, root *os.Root, req ClosureRequest, cfg ClosureConfig) Closure {
	lim := cfg.Limits.withDefaults()
	kinds := cfg.Kinds
	if len(kinds) == 0 {
		kinds = DefaultDepKinds
	}

	c := Closure{Root: req.PkgBase, Limits: closureLimits, index: map[string]int{}}

	if err := ValidPkgBase(req.PkgBase); err != nil {
		c.gap(RulePkgBaseRefused, safeQuote(req.PkgBase), fmt.Sprintf(
			"the subject names a pkgbase this tool refuses to use as an identity (%v), so no closure was resolved for it", err))
		return c
	}
	if !cfg.Repo.Loaded {
		c.gap(RuleRepoIndexUnavailable, req.PkgBase,
			"no binary-repository index was supplied, so no dependency could be dismissed as covered by a signed "+
				"repository; names not found in a local recipe or in the AUR are reported unresolved rather than assumed to be repository packages")
	}

	w := &walker{c: &c, root: root, cfg: cfg, kinds: kinds, lim: lim, byName: map[string]int{}}

	rootIdx := w.addAUR(req.PkgBase, req.PkgBase, 0, -1, req.Dir)
	if rootIdx < 0 {
		return c
	}
	frontier := []int{rootIdx}

	for depth := 1; len(frontier) > 0; depth++ {
		if depth > lim.MaxDepth {
			w.gapDepth(frontier, depth-1)
			break
		}
		frontier = w.expand(ctx, frontier, depth)
	}
	return c
}

// walker carries the mutable state of one walk. It exists so the walk's helpers
// do not each take eight arguments, not to make anything shared: one walker is
// created per ReviewClosure call and never escapes it.
type walker struct {
	c     *Closure
	root  *os.Root
	cfg   ClosureConfig
	kinds []pkgmeta.DepKind
	lim   ClosureLimits

	// byName maps every dependency name already placed to its node index, so a
	// split package's second pkgname joins the node its recipe already made.
	byName map[string]int

	// noResolverReported keeps the "no AUR lookup" gap to one per run rather
	// than one per unplaceable name.
	noResolverReported bool
}

// expand turns one level's declared dependencies into the next level's nodes.
//
// The whole level is classified together so the AUR lookup is ONE request for
// the level rather than one per dependency.
func (w *walker) expand(ctx context.Context, frontier []int, depth int) []int {
	type ref struct {
		from int
		dep  pkgmeta.Dep
	}
	var refs []ref
	for _, from := range frontier {
		seen := map[string]bool{}
		n := 0
		for _, d := range w.c.Nodes[from].raw {
			if d.Name == "" || seen[d.Name] {
				continue
			}
			seen[d.Name] = true
			if n >= w.lim.MaxDepsPerNode {
				w.c.gap(RuleFanOut, w.c.Nodes[from].Key, fmt.Sprintf(
					"this recipe declares more than %d distinct dependencies; the list was cut there and the remaining "+
						"dependencies were neither resolved nor reviewed", w.lim.MaxDepsPerNode))
				break
			}
			n++
			refs = append(refs, ref{from: from, dep: d})
		}
	}
	if len(refs) == 0 {
		return nil
	}

	// One lookup for the level, for the names nothing local could place.
	var ask []string
	askSeen := map[string]bool{}
	for _, r := range refs {
		nm := r.dep.Name
		if ValidPkgBase(nm) != nil {
			continue
		}
		if _, placed := w.byName[nm]; placed {
			continue
		}
		if w.cfg.Repo.has(nm) {
			continue
		}
		if _, ok := w.cfg.Local[nm]; ok {
			continue
		}
		if !askSeen[nm] {
			askSeen[nm] = true
			ask = append(ask, nm)
		}
	}
	sort.Strings(ask)
	remote := map[string]string{}
	lookupFailed := false
	switch {
	case len(ask) == 0:
	case w.cfg.Resolver == nil:
		if !w.noResolverReported {
			w.noResolverReported = true
			w.c.gap(RuleNoResolver, w.c.Root, fmt.Sprintf(
				"no AUR lookup was available on this run, so %d dependency name(s) that are not in a local recipe and not "+
					"in a sync database could not be classified: %s. They are reported unresolved; that is this run's blind spot, not a statement about those packages",
				len(ask), sanitise(strings.Join(ask, ", "), 200)))
		}
	default:
		got, err := w.cfg.Resolver.Bases(ctx, ask)
		if err != nil {
			lookupFailed = true
			w.c.gap(RuleLookupFailed, w.c.Root, fmt.Sprintf(
				"the AUR lookup for %d dependency name(s) failed (%v); those names are NOT thereby absent from the AUR, "+
					"they are unclassified, and any AUR recipe among them was not reviewed: %s",
				len(ask), err, sanitise(strings.Join(ask, ", "), 200)))
		}
		for k, v := range got {
			remote[k] = v
		}
	}

	var next []int
	for _, r := range refs {
		idx := w.place(r.from, r.dep, depth, remote, lookupFailed)
		if idx >= 0 && w.c.Nodes[idx].Kind == KindAUR && w.c.Nodes[idx].Depth == depth {
			next = append(next, idx)
		}
	}
	return next
}

// place classifies one dependency and attaches the edge.
func (w *walker) place(from int, d pkgmeta.Dep, depth int, remote map[string]string, lookupFailed bool) int {
	e := Edge{Name: d.Name, Constraint: d.Constraint, Kind: d.Kind}
	defer func() { w.c.Nodes[from].Deps = append(w.c.Nodes[from].Deps, e) }()

	// A dependency name is attacker-controlled text on its way to a path and to
	// a report line. It is refused HERE, before either.
	if err := ValidPkgBase(d.Name); err != nil {
		w.c.gap(RulePkgBaseRefused, w.c.Nodes[from].Key, fmt.Sprintf(
			"declares a dependency this tool refuses to use as an identity (%v); it was not resolved and not reviewed", err))
		return -1
	}

	// Already placed by another path: one recipe is reviewed once.
	if idx, ok := w.byName[d.Name]; ok {
		e.To = w.c.Nodes[idx].Key
		switch {
		case idx == from:
			// A recipe naming one of its own output packages. Its dependencies
			// are this node's dependencies and they are already being walked.
			e.Self = true
		case w.ancestor(idx, from):
			e.Cycle = true
			w.c.gap(RuleCycle, w.c.Nodes[from].Key, fmt.Sprintf(
				"depends on %s, which is already on this dependency path; the cycle is real and the walk stopped there, "+
					"so anything reachable only THROUGH that edge was not enumerated", sanitise(w.c.Nodes[idx].Key, 64)))
		default:
			e.Repeat = true
		}
		w.addName(idx, d.Name)
		return idx
	}

	// 1. A package name in a sync database. Somebody else's problem, and not
	// recursed into.
	if w.cfg.Repo.has(d.Name) {
		return w.attach(&e, w.addPlain(d.Name, KindRepo, depth, from, nil))
	}

	// 2. An AUR package: local recipe first, then the AUR itself. This precedes
	// the provides check on purpose -- see the package comment.
	if base, ok := w.cfg.Local[d.Name]; ok {
		return w.attach(&e, w.addAUR(base, d.Name, depth, from, ""))
	}
	if base, ok := remote[d.Name]; ok {
		if err := ValidPkgBase(base); err != nil {
			w.c.gap(RulePkgBaseRefused, d.Name, fmt.Sprintf(
				"the AUR reports pkgbase %q for this dependency, which this tool refuses to use as an identity (%v)",
				safeQuote(base), err))
			return -1
		}
		return w.attach(&e, w.addAUR(base, d.Name, depth, from, ""))
	}

	// 3. A virtual name a REPOSITORY package provides. Last, so it can never
	// pre-empt a real AUR recipe.
	if p := w.cfg.Repo.providers(d.Name); len(p) > 0 {
		return w.attach(&e, w.addPlain(d.Name, KindRepoProvided, depth, from, p))
	}

	// 4. Nothing placed it. That is a coverage gap, never "fine" (INV-9). The
	// gap for a failed or absent lookup was already recorded once for the level;
	// this one names the dependency.
	idx := w.addPlain(d.Name, KindUnresolved, depth, from, nil)
	if !lookupFailed && w.cfg.Resolver != nil {
		w.c.gap(RuleDepUnresolved, w.c.Nodes[from].Key, fmt.Sprintf(
			"depends on %s, which is neither a package in a sync database nor a package the AUR knows; it could not be "+
				"reviewed, and a dependency that resolves to nothing today may resolve to something tomorrow",
			sanitise(d.Name, 64)))
	}
	return w.attach(&e, idx)
}

func (w *walker) attach(e *Edge, idx int) int {
	if idx >= 0 {
		e.To = w.c.Nodes[idx].Key
	}
	return idx
}

// ancestor reports whether a is on the discovery path of b (or is b itself,
// which is the self-dependency case).
func (w *walker) ancestor(a, b int) bool {
	for i := b; i >= 0; i = w.c.Nodes[i].parent {
		if i == a {
			return true
		}
	}
	return false
}

// addName records another dependency name that reached an existing node.
func (w *walker) addName(idx int, name string) {
	n := &w.c.Nodes[idx]
	for _, existing := range n.Names {
		if existing == name {
			return
		}
	}
	n.Names = append(n.Names, name)
	sort.Strings(n.Names)
	w.byName[name] = idx
}

// addPlain creates a node that is not reviewed: a repository package, a virtual
// name, or a name nothing placed.
func (w *walker) addPlain(key string, kind NodeKind, depth, parent int, providers []string) int {
	if idx, ok := w.c.index[key]; ok {
		w.addName(idx, key)
		return idx
	}
	if !w.room(key) {
		return -1
	}
	idx := len(w.c.Nodes)
	w.c.Nodes = append(w.c.Nodes, Node{
		Key: key, Names: []string{key}, Kind: kind, Depth: depth,
		Providers: providers, parent: parent,
	})
	w.c.index[key] = idx
	w.byName[key] = idx
	return idx
}

// addAUR creates and reviews an AUR node, keyed on its PKGBASE.
//
// name is the dependency name that led here, which for a split package is one
// of several and is not the key.
func (w *walker) addAUR(pkgbase, name string, depth, parent int, dirOverride string) int {
	if idx, ok := w.c.index[pkgbase]; ok {
		w.addName(idx, name)
		return idx
	}
	if !w.room(pkgbase) {
		return -1
	}

	n := Node{Key: pkgbase, PkgBase: pkgbase, Kind: KindAUR, Depth: depth, parent: parent}
	if name != "" {
		n.Names = []string{name}
	}

	dir, ok := dirOverride, dirOverride != ""
	if !ok && w.cfg.Source != nil {
		dir, ok = w.cfg.Source.Recipe(pkgbase)
	}
	switch {
	case !ok:
		w.c.gap(RuleRecipeUnavailable, pkgbase, fmt.Sprintf(
			"%s is built from the AUR and no recipe for it is on this system, so it could be named but not read; "+
				"its own dependencies are unknown and nothing about it is clean", sanitise(pkgbase, 64)))
	default:
		if _, err := safeRel(dir); err != nil {
			w.c.gap(RuleRecipeUnreadable, pkgbase, fmt.Sprintf(
				"the recipe directory reported for this package (%q) is not a usable root-relative path (%v)", safeQuote(dir), err))
			dir = ""
		} else {
			n.Dir = dir
		}
	}

	idx := len(w.c.Nodes)
	w.c.Nodes = append(w.c.Nodes, n)
	w.c.index[pkgbase] = idx
	w.byName[pkgbase] = idx
	if name != "" {
		w.byName[name] = idx
	}
	if n.Dir != "" {
		w.review(idx)
	}
	return idx
}

// room enforces the whole-closure node bound.
func (w *walker) room(key string) bool {
	if len(w.c.Nodes) < w.lim.MaxNodes {
		return true
	}
	w.c.gap(RuleTruncated, w.c.Root, fmt.Sprintf(
		"the closure reached the %d-node bound at %s; the remaining dependencies were not resolved and not reviewed, "+
			"so this closure is a floor on what would be built, not the whole of it", w.lim.MaxNodes, sanitise(key, 64)))
	return false
}

// review reads one node's recipe, runs the rules, reads its dependencies, and
// asks the approval store about it.
func (w *walker) review(idx int) {
	n := &w.c.Nodes[idx]
	dir := n.Dir

	src, err := readConfined(w.root, path.Join(dir, "PKGBUILD"), maxPKGBUILDBytes)
	if err != nil {
		n.Result.Gaps = append(n.Result.Gaps, finding.Gap{
			RuleID:  RuleRecipeUnreadable,
			Subject: n.Key,
			Reason: fmt.Sprintf("the PKGBUILD at %s could not be read (%v); this package's recipe was not reviewed and "+
				"the absence of findings for it is not a clean result", dir, err),
		})
	} else {
		f := pkgbuild.Lex(src)
		r := pkgbuild.Resolve(f, w.cfg.Resolve)
		v := pkgbuild.Assess(n.PkgBase, f, r)
		n.Result = check.PKGBUILD(f, r, v, w.cfg.Check)
		n.Reviewed = true
		n.raw = append(n.raw, w.pkgbuildDeps(r)...)

		if w.cfg.Store != nil {
			rec, derr := DigestRecipe(w.root, RecipeRequest{PkgBase: n.PkgBase, Dir: dir, Aux: recipeAux(r)})
			if derr != nil {
				n.Approval = Decision{
					PkgBase: n.PkgBase,
					Status:  StatusIndeterminate,
					Limits:  "the recipe could not be digested, so it is neither known-approved nor known-unapproved",
					Gaps: []finding.Gap{{
						RuleID:  RuleRecipeUnreadable,
						Subject: n.Key,
						Reason:  derr.Error(),
					}},
				}
			} else {
				n.Approval = w.cfg.Store.Lookup(n.PkgBase, rec.Digest)
			}
		}
	}

	// The declared dependencies. .SRCINFO is the file every helper reads, so it
	// is the primary source; the PKGBUILD's own arrays are UNIONED in rather
	// than used as a fallback, because a .SRCINFO that understates the recipe it
	// sits beside is an evasion route and the union closes it in the safe
	// direction.
	si, serr := pkgmeta.SRCINFOFromFile(w.root, path.Join(dir, ".SRCINFO"), w.cfg.Meta)
	switch {
	case serr != nil:
		n.Result.Gaps = append(n.Result.Gaps, finding.Gap{
			RuleID:  RuleDepsUnreadable,
			Subject: n.Key,
			Reason: fmt.Sprintf("the .SRCINFO in %s could not be read (%v), so this package's declared dependencies "+
				"come from its PKGBUILD text alone; dependencies computed at build time or declared inside a package "+
				"function are not visible there and were not walked", dir, serr),
		})
	default:
		n.raw = append(si.Deps(w.kinds...), n.raw...)
		n.Result.Gaps = append(n.Result.Gaps, si.Gaps(n.Key)...)
	}
}

// pkgbuildDeps reads the dependency arrays out of a resolved PKGBUILD.
//
// Only RESOLVED values are returned: an unresolvable dependency entry is already
// a coverage gap from pkgbuild.Assess, and inventing a package name out of a
// half-expanded ${_pkg} would send the walk looking for something that does not
// exist.
func (w *walker) pkgbuildDeps(r pkgbuild.Resolution) []pkgmeta.Dep {
	var out []pkgmeta.Dep
	for _, kind := range w.kinds {
		for name, v := range r.Vars {
			base, _, ok := strings.Cut(name, "_")
			if name != string(kind) && !(ok && base == string(kind)) {
				continue
			}
			for _, val := range v.Values {
				if !val.OK() || val.Text == "" {
					continue
				}
				d := parseDepName(val.Text)
				d.Kind = kind
				out = append(out, d)
			}
		}
	}
	// r.Vars is a map, so the order above is not stable. The walk's output must
	// be (INV-4).
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Name < out[j].Name
	})
	return out
}

// parseDepName splits `foo>=1.2` into a name and a constraint. A constraint that
// made a name unmatchable would remove a node from the closure without saying
// so, which is the quietest possible way to skip a review.
func parseDepName(raw string) pkgmeta.Dep {
	d := pkgmeta.Dep{Raw: raw}
	for _, op := range []string{">=", "<=", "=", ">", "<"} {
		if i := strings.Index(raw, op); i > 0 {
			d.Name = strings.TrimSpace(raw[:i])
			d.Constraint = strings.TrimSpace(raw[i:])
			return d
		}
	}
	d.Name = strings.TrimSpace(raw)
	return d
}

// recipeAux names the files beside the PKGBUILD that the approval digest must
// cover: every local source entry and the install scriptlet. See approve.go for
// the argument -- a .install runs as root and is not the file an eye lands on.
func recipeAux(r pkgbuild.Resolution) []string {
	var out []string
	seen := map[string]bool{}
	add := func(s string) {
		if s == "" || seen[s] || safeName(s) != nil {
			return
		}
		seen[s] = true
		out = append(out, s)
	}
	for _, s := range r.Sources {
		if !s.Local {
			continue
		}
		add(s.Name)
	}
	if v, ok := r.Vars["install"]; ok {
		for _, val := range v.Values {
			if val.OK() {
				add(val.Text)
			}
		}
	}
	sort.Strings(out)
	return out
}

// gapDepth reports that the walk stopped at the depth bound with dependencies
// still unenumerated.
func (w *walker) gapDepth(frontier []int, depth int) {
	var pending []string
	for _, i := range frontier {
		if len(w.c.Nodes[i].raw) > 0 {
			pending = append(pending, w.c.Nodes[i].Key)
		}
	}
	if len(pending) == 0 {
		return
	}
	sort.Strings(pending)
	w.c.gap(RuleDepthBound, w.c.Root, fmt.Sprintf(
		"the walk stopped at depth %d; the dependencies of %s were not resolved and anything below them was not reviewed",
		depth, sanitise(strings.Join(pending, ", "), 200)))
}

func (c *Closure) gap(rule, subject, reason string) {
	c.Gaps = append(c.Gaps, finding.Gap{RuleID: rule, Subject: subject, Reason: reason})
}

// readConfined reads a whole file through the confined API, bounded.
func readConfined(root *os.Root, rel string, max int64) ([]byte, error) {
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, fmt.Errorf("%d bytes, over the %d cap", st.Size, max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// --- output --------------------------------------------------------------------

// Lines renders the closure for a terminal.
//
// The order is the point. A 200-line tree with one critical buried in it has
// hidden the critical, so the reviewable set and the findings come first and the
// tree comes last, after the reader already knows what they are looking for.
func (c Closure) Lines() []string {
	res := c.Result()
	n := c.Counts()

	out := []string{fmt.Sprintf(
		"dependency closure of %s: %d package(s) -- %d from the AUR (%d to review, %d already approved), %d from repositories, %d unresolved",
		sanitise(c.Root, 64), n.Nodes, n.AUR, n.Reviewable, n.Approved, n.Repo+n.RepoProvided, n.Unresolved)}

	if rev := c.Reviewable(); len(rev) > 0 {
		names := make([]string, 0, len(rev))
		for _, node := range rev {
			label := sanitise(node.Key, 64)
			if sev := node.Result.MaxSeverity(); sev != finding.SevInfo {
				label += " [" + sev.String() + "]"
			}
			if !node.Reviewed {
				label += " [NOT REVIEWED]"
			}
			if node.Approval.Status == StatusChanged {
				label += " [recipe changed since approval]"
			}
			names = append(names, label)
		}
		out = append(out, "to review: "+strings.Join(names, ", "))
	} else {
		out = append(out, "to review: nothing -- every AUR recipe in this closure is approved at its current digest")
	}

	for _, f := range res.Findings {
		out = append(out, fmt.Sprintf("  %-10s %s  %s: %s", f.Severity, f.RuleID, sanitise(f.Subject, 40), sanitise(f.Summary, 160)))
	}
	for _, g := range res.Gaps {
		out = append(out, fmt.Sprintf("  gap [%s] %s: %s", g.RuleID, sanitise(g.Subject, 40), sanitise(g.Reason, 200)))
	}

	out = append(out, "", "dependency tree:")
	out = append(out, c.Tree()...)
	out = append(out, "", "limits: "+c.Limits)
	return out
}

// Tree renders the closure as a tree.
//
// Each node is printed once, at the position it was discovered. A second edge to
// an already-printed node is a leaf naming it, marked as a cycle when the target
// is an ancestor and as a repeat otherwise. That is what makes the print
// terminate on a graph that is not one.
func (c Closure) Tree() []string {
	if len(c.Nodes) == 0 {
		return nil
	}
	var out []string
	c.treeNode(0, "", "", &out)
	return out
}

func (c Closure) treeNode(idx int, prefix, connector string, out *[]string) {
	*out = append(*out, prefix+connector+c.label(idx))

	childPrefix := prefix
	if connector != "" {
		if strings.HasPrefix(connector, "`-") {
			childPrefix += "   "
		} else {
			childPrefix += "|  "
		}
	}

	// Every outgoing edge is a line: either the child's own subtree, or a
	// reference to a node printed elsewhere.
	type item struct {
		child int
		edge  Edge
	}
	var items []item
	printed := map[int]bool{}
	for _, e := range c.Nodes[idx].Deps {
		ci := -1
		if e.To != "" {
			if j, ok := c.index[e.To]; ok && c.Nodes[j].parent == idx && !printed[j] {
				ci = j
				printed[j] = true
			}
		}
		items = append(items, item{child: ci, edge: e})
	}
	for i, it := range items {
		conn := "|- "
		if i == len(items)-1 {
			conn = "`- "
		}
		switch {
		case it.child >= 0:
			c.treeNode(it.child, childPrefix, conn, out)
		default:
			*out = append(*out, childPrefix+conn+c.edgeLabel(it.edge))
		}
	}
}

func (c Closure) label(idx int) string {
	n := c.Nodes[idx]
	s := sanitise(n.Key, 64)
	switch n.Kind {
	case KindAUR:
		s += " (aur"
		switch {
		case !n.Reviewed:
			s += ", NOT REVIEWED"
		case n.Approved():
			s += ", approved"
		default:
			s += ", to review"
		}
		if sev := n.Result.MaxSeverity(); sev != finding.SevInfo && !n.Approved() {
			s += ", " + sev.String()
		}
		s += ")"
	case KindRepo:
		s += " (repo)"
	case KindRepoProvided:
		s += " (repo, provided by " + sanitise(strings.Join(n.Providers, " "), 64) + ")"
	case KindUnresolved:
		s += " (UNRESOLVED -- not reviewed)"
	}
	if idx == 0 {
		s += " [subject]"
	}
	return s
}

func (c Closure) edgeLabel(e Edge) string {
	s := sanitise(e.Name, 64) + sanitise(e.Constraint, 24)
	switch {
	case e.To == "":
		return s + " (refused or beyond a bound -- not reviewed)"
	case e.Self:
		return s + " (the same recipe -- one build, reviewed once)"
	case e.Cycle:
		return s + " (cycle: already on this path, walk stopped)"
	default:
		return s + " (shown above)"
	}
}
