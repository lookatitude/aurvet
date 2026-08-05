// internal/correlate/correlate.go
//
// Package correlate is the only place in P1-C that may rate a finding
// SevCritical, and it earns that by grouping facts rather than by believing any
// one of them harder.
//
// Every check in internal/surfaces deliberately stops at SevSuspicious. That
// asymmetry is the design: one unowned path is weak evidence -- a hand-written
// administrator unit is indistinguishable from a planted one -- while three
// unowned paths reachable from one another, in a directory a package owns, and
// timed with one foreign package's install, is not. This package builds those
// groups and states, in the finding itself, exactly how much they prove.
//
// # What it does NOT prove, said here and in every finding it emits (INV-6)
//
// Correlation does not survive a competent attacker. A payload built into its
// own $pkgdir and shipped with an ordinary-looking unit produces no unowned
// files, a self-consistent mtree, and an ExecStart resolving to a package-owned
// binary. Every check in this phase then goes silent, including this one -- there
// are no facts left to correlate. This phase catches SLOPPY malware; the real
// incidents were sloppy, but needn't have been. A clean result here is not
// evidence of a clean system, and a tool that overstates what correlation proves
// teaches its user to trust a clean result that was never earned.
//
// # Invariants
//
// INV-2: nothing here is executed. Unit commands, hook Exec values and preload
// entries arrive as strings from internal/surfaces and are compared as strings.
// INV-4: Correlate is a pure function of (root, cfg). It reads no environment,
// no process working directory and -- the one that matters most for a
// correlation engine -- no wall clock. Every timestamp comes from the recorded
// evidence (%INSTALLDATE%, a file's own mtime, an optional transaction time), so
// the same tree yields the same clusters on any day. A rule keyed on "now" would
// make findings drift with the calendar and nothing would be reproducible.
// INV-5: no writes. Files are opened read-only through internal/fsx.
// INV-9: a fact whose attribution could not be DETERMINED is a coverage gap, not
// a member quietly dropped from a cluster. Dropping it is how a correlated
// critical silently becomes a correlated suspicious.
package correlate

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
	"github.com/lookatitude/aurvet/internal/surfaces"
	"golang.org/x/sys/unix"
)

// Rule identifiers. One rule emits the cluster; one carries every coverage
// shortfall, so a consumer suppressing cluster findings cannot also suppress the
// admission that a cluster could not be evaluated.
const (
	RuleCluster  = "correlated-cluster"
	RuleCoverage = "correlate-coverage"
)

// Fact families. A cluster must span at least two of these to be a cluster at
// all: three restatements of one unowned file are one fact, not three.
const (
	FamilyUnitExec   = "unit-execstart"
	FamilyEnablement = "enablement-link"
	FamilyHook       = "pacman-hook"
	FamilyPreload    = "ld-so-preload"
	FamilyGenerator  = "systemd-generator"
	FamilyProfile    = "shell-profile"
	FamilyAutostart  = "xdg-autostart"
)

// DefaultWindow is the temporal key's tolerance, and the number is measured
// rather than chosen for looking round.
//
// Three clocks are being compared and they disagree LEGITIMATELY: an mtree
// time= is a BUILD time, %INSTALLDATE% is an INSTALL time, and a pacman.log
// entry is a LOG time. Too tight a window silently drops real clusters (one
// transaction's evidence splits across two windows and neither reaches two
// facts); too loose a window merges unrelated transactions into a single
// fabricated incident. Both failures are silent, so the number needs a
// justification with numbers in it.
//
// Measured on the reference system (2026-08-05, 1410 installed packages, 348
// distinct %INSTALLDATE% values):
//
//   - the largest step between two consecutive %INSTALLDATE% values INSIDE one
//     pacman transaction is 650 s. A window at or below that splits a real
//     transaction.
//   - the smallest step between two DIFFERENT transactions is 903 s. A window at
//     or above that fuses two of them.
//
// So any window in (650 s, 903 s) reproduces the reference system's 139
// transactions exactly. DefaultWindow is 720 s: inside that band and toward its
// LOWER edge, which is the error this package prefers. Missing a cluster costs
// one detection; fabricating one costs the user's trust in every other finding,
// and a security tool that cries wolf is worse than one that stays quiet. A
// quarter of an hour (900 s) would also fit the band, but with a 3 s margin
// against fusing two real transactions on this machine -- too close to a number
// this package would have to defend.
//
// For contrast, at 3600 s the same data collapses 139 transactions into 124 and
// the widest "transaction" spans 11,942 s: fifteen fabricated incidents.
const DefaultWindow = 720 * time.Second

// The two measured bounds DefaultWindow sits between, kept as named constants so
// a test can pin the relationship rather than the literal. A future change to
// DefaultWindow that leaves this band is a change that has to argue with these
// numbers.
const (
	MeasuredMaxIntraTransactionStep = 650 * time.Second
	MeasuredMinInterTransactionGap  = 903 * time.Second
)

// adminTerritory lists the directories a distribution INTENDS an administrator
// to write into. An unowned file in one of them is ordinary local
// administration; an unowned file in a package's own directory is not, and that
// difference is what keeps a correlated critical off a cruft-laden but honest
// system.
//
// Each entry is here for a stated reason, because an allowlist is where
// detection quietly disappears:
//
//   - etc/systemd/system, etc/systemd/user: systemd's documented location for
//     LOCAL units. The reference system's one hand-written unit lives here.
//   - etc/pacman.d/hooks: exists so administrators can write hooks.
//   - etc/profile.d, etc/xdg/autostart: drop-in directories for local shell and
//     session configuration.
//   - usr/local, opt: reserved for software not managed by the package manager,
//     by the FHS and by pacman's own conventions. pip, `npm -g` and hand-built
//     tools land here.
//   - home, root, srv: user and service data. No package owns anything here.
//
// Note what this list does NOT do: it does not stop a fact in admin territory
// from JOINING a cluster or from being reported by internal/surfaces. It only
// declines to treat "unowned file in a packaged directory" as a masquerade when
// the packaged directory is one an administrator is supposed to use.
var adminTerritory = []string{
	"etc/systemd/system",
	"etc/systemd/user",
	"etc/pacman.d/hooks",
	"etc/profile.d",
	"etc/xdg/autostart",
	"usr/local",
	"opt",
	"home",
	"root",
	"srv",
}

// clusterLimit is the honesty requirement, carried in the finding rather than
// only in this file's doc comment (INV-6).
const clusterLimit = "What this cluster proves is bounded, and the bound is large. Correlation does not " +
	"survive a competent attacker: a payload built into its own $pkgdir and shipped inside the package's " +
	"own file list produces NO unowned files, a self-consistent mtree (the mtree came from that build, so " +
	"the recorded hash is the payload's own), and an ExecStart resolving to a package-owned binary -- and " +
	"then every check in this phase, including this one, goes silent, because there are no facts left to " +
	"correlate. This phase catches SLOPPY malware; the real incidents were sloppy, but needn't have been, " +
	"and a clean result here is not evidence of a clean system. Two narrower limits: the individual facts " +
	"below are each individually weak and each has a legitimate explanation (a hand-written unit, a " +
	"locally built library, an administrator's hook), so the cluster is a reason to LOOK and not a verdict " +
	"on intent; and the temporal key rests on file mtimes, which whoever planted the files could have " +
	"rewritten -- doing so costs the attacker this rating but not the cluster itself. " +
	"One asymmetry to know about when reading a SUSPICIOUS cluster: reaching critical requires a " +
	"masquerade, meaning at least one file planted where a PACKAGE owns the directory. A cluster living " +
	"entirely in territory an administrator is meant to write into -- a home directory, /usr/local, " +
	"/etc/systemd/system -- is capped at suspicious however many surfaces it spans, because an honest " +
	"machine full of hand-built software looks exactly like that. The cost is that user-level " +
	"persistence, which is what an AUR build is positioned to install because it runs as the user and " +
	"needs no package directory at all, does not escalate here. A suspicious cluster spanning several " +
	"families inside a single home is therefore worth more attention than its rating suggests."

// Transaction is one pacman.log transaction fact, supplied by the caller.
//
// It is an INPUT rather than something parsed here: pacman.log parsing is a
// separate task with its own hazards (two UTC offsets in one file, entries
// naming another root, rotation), and a correlation engine that half-parses a
// log would make its own third clock unreliable. When no transactions are
// supplied the temporal key runs on %INSTALLDATE% alone and every cluster says
// so.
type Transaction struct {
	Time time.Time
	Op   string
	Pkg  string
}

// Config is Correlate's whole input besides the root.
type Config struct {
	// Owners is the ownership oracle, built with own.IndexIn over the SAME root
	// so that symlinks resolve. An oracle built without a root answers Unowned
	// for everything reached through a link, which would turn this package into
	// a false-positive engine.
	Owners *own.Owners

	// Pkgs is the installed set, for %INSTALLDATE% and for the foreign/native
	// split.
	Pkgs []alpm.Package

	// SyncNames is the set of package names the configured repositories offer.
	// A nil or empty map means "unknown", NOT "nothing is in a repository":
	// without it no package can be called foreign, so no cluster can be
	// attributed, and that is a coverage gap rather than a silent downgrade
	// (INV-3).
	SyncNames map[string]bool

	// Transactions are optional pacman.log transaction times.
	Transactions []Transaction

	// Window is the temporal tolerance; 0 means DefaultWindow.
	Window time.Duration

	// UnitDirs are the systemd unit search directories; nil means
	// surfaces.DefaultUnitDirs.
	UnitDirs []string

	// Misc names the remaining surface paths. Its zero value is usable.
	Misc surfaces.MiscConfig

	// DBPath is where install scriptlets are looked for, relative to the root.
	// Empty means "var/lib/pacman/local".
	DBPath string
}

func (c Config) window() time.Duration {
	if c.Window <= 0 {
		return DefaultWindow
	}
	return c.Window
}

func (c Config) unitDirs() []string {
	if c.UnitDirs == nil {
		return surfaces.DefaultUnitDirs
	}
	return c.UnitDirs
}

func (c Config) dbPath() string {
	if c.DBPath == "" {
		return "var/lib/pacman/local"
	}
	return c.DBPath
}

// Fact is one piece of host-side evidence, reduced to the fields correlation
// keys are computed from. It is built from the STRUCTURED output of
// internal/surfaces -- WantsEntry, Unit.Exec, HookReport -- and never by parsing
// a finding's rendered evidence strings, which would make this package depend on
// another's prose.
type Fact struct {
	Family string
	RuleID string

	// Path is the fact's own subject: the file that is there and unowned.
	Path string

	// Target is the path the fact POINTS AT when it points at one -- a resolved
	// ExecStart, an enablement link's target. Empty otherwise.
	Target string

	Severity finding.Severity
	Summary  string
	Evidence []string

	// Time is the mtime of Target if that could be read, else of Path, in
	// seconds. TimeFrom names which. TimeKnown false means the temporal key
	// could not be applied to this fact at all, which is an inability and is
	// reported as one.
	Time      float64
	TimeKnown bool
	TimeFrom  string
	TimeErr   error
}

// paths returns the fact's own path and its target, for the joins and the
// masquerade test.
func (f Fact) paths() []string {
	if f.Target == "" {
		return []string{f.Path}
	}
	return []string{f.Path, f.Target}
}

// Candidate is one package a cluster may be attributable to.
type Candidate struct {
	Pkg          string
	Base         string
	Foreign      bool
	HasScriptlet bool
	InstallDate  time.Time

	// Keys are the rendered attribution reasons, each carrying the number
	// behind it.
	Keys []string

	// Strong reports that at least one key was the temporal key or the
	// path-name key. A scriptlet alone is corroboration, never attribution:
	// measured on the reference system 7 of 39 foreign packages carry one, so
	// "has a scriptlet" narrows the field and identifies nobody.
	Strong bool
}

// Cluster is a group of facts joined by at least one correlation key.
type Cluster struct {
	Subject     string
	SubjectKind string
	Facts       []Fact
	Families    []string

	// Joins record which key merged which pair, so an operator can see WHY
	// these facts are one cluster rather than several.
	Joins []string

	// Masquerade lists the member paths that are unowned inside a package-owned
	// directory OUTSIDE administrator territory. This is the shape that
	// separates a planted file from a local one, and a cluster without it never
	// reaches critical.
	Masquerade []string

	Candidates []Candidate
	Severity   finding.Severity

	// Unattributed records why attribution could not be completed, when the
	// reason was an inability rather than a negative answer. Non-empty here
	// with Severity below critical is a coverage gap, never a silent downgrade.
	Unattributed []string

	// Notes carry facts about the EVALUATION rather than about the system --
	// which clocks took part, above all. A reader of a cluster deserves to know
	// that the third clock was absent rather than silent.
	Notes []string
}

// Correlate runs the P1-C surface checks over root and returns their findings
// together with the cluster findings correlation earns.
//
// The underlying findings are returned unchanged, at the severity their own
// rules chose. This package adds; it never rewrites another rule's verdict.
func Correlate(root *os.Root, cfg Config) finding.Result {
	facts, res := Facts(root, cfg)
	clusters, gaps := Clusters(root, cfg, facts)
	res.Gaps = append(res.Gaps, gaps...)
	for _, c := range clusters {
		res.Findings = append(res.Findings, c.Finding())
	}
	return res
}

// Facts runs the surface checks and reduces what they found to correlation
// input. The finding.Result it returns is the surfaces' own output, so a caller
// that wants both the raw findings and the clusters pays for the scan once.
//
// Only facts at SevSuspicious or above become correlation input. The excluded
// population is meaningful rather than incidental: internal/surfaces rates an
// ExecStart naming an ABSENT file at info, because nothing can be executed from
// a path that holds no file -- 3 of the reference system's 4 unowned unit
// commands are exactly that. Feeding them to a correlation engine would let
// packaged units naming files their optional dependencies no longer ship build
// clusters out of nothing.
func Facts(root *os.Root, cfg Config) ([]Fact, finding.Result) {
	var (
		res   finding.Result
		facts []Fact
	)
	if root == nil || cfg.Owners == nil {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID:  RuleCoverage,
			Subject: "/",
			Reason: "no scanned root or no ownership index was supplied, so no persistence surface was " +
				"examined and no correlation was attempted",
		})
		return nil, res
	}
	owners := cfg.Owners

	// Units. The fact is derived from Unit.Exec rather than from
	// UnitFindings' prose, and the two are kept consistent deliberately: the
	// same three conditions (resolvable value, unowned target, file actually
	// present) decide both.
	units, unitGaps := surfaces.LoadUnits(root, cfg.unitDirs())
	res.Gaps = append(res.Gaps, unitGaps...)
	unitFindings, ownerGaps := surfaces.UnitFindings(root, units, owners)
	res.Findings = append(res.Findings, unitFindings...)
	res.Gaps = append(res.Gaps, ownerGaps...)

	for _, u := range units {
		seen := map[string]bool{}
		for _, e := range u.Exec {
			if !e.Resolvable {
				// A relative or unexpanded command: UnitFindings already
				// either resolved it against systemd's search path or gapped
				// it. Not re-gapped here -- two gaps for one shortfall trains
				// an operator to skim.
				continue
			}
			bin := strings.TrimPrefix(e.Bin, "/")
			if seen[bin] {
				continue
			}
			seen[bin] = true
			if _, st, _ := owners.Resolve(bin); st != own.Unowned {
				continue
			}
			if absent(root, bin) {
				// surfaces rates an ExecStart naming an ABSENT file at info --
				// nothing can be executed from a path that holds no file -- and
				// this mirrors that, so the two layers cannot disagree about
				// what is suspicious. Note the test is ABSENCE and not "the
				// stat failed": EACCES means "I could not tell", which surfaces
				// keeps at suspicious and which must therefore stay a fact
				// here (INV-9).
				continue
			}
			ev := []string{
				fmt.Sprintf("%s = %s%s (from %s)", e.Directive, e.Prefixes, e.Raw, e.Origin),
				fmt.Sprintf("/%s is present and owned by no installed package", bin),
			}
			if u.ShadowedBy != "" {
				ev = append(ev, fmt.Sprintf("this unit is shadowed by %s, which is the file systemd loads",
					u.ShadowedBy))
			}
			if len(u.DropIns) > 0 {
				ev = append(ev, fmt.Sprintf("drop-ins merged into this unit: %s", strings.Join(u.DropIns, ", ")))
			}
			facts = append(facts, Fact{
				Family:   FamilyUnitExec,
				RuleID:   surfaces.RuleUnitExecUnowned,
				Path:     u.Path,
				Target:   bin,
				Severity: finding.SevSuspicious,
				Summary:  fmt.Sprintf("unit %s runs /%s, which no installed package owns", u.Path, bin),
				Evidence: ev,
			})
		}
	}

	// Enablement links.
	wants, wantsGaps := surfaces.SurveyWants(root, owners, cfg.unitDirs())
	res.Gaps = append(res.Gaps, wantsGaps...)
	res.Findings = append(res.Findings, wants.Findings()...)
	for _, e := range wants.Subjects {
		facts = append(facts, Fact{
			Family:   FamilyEnablement,
			RuleID:   surfaces.RuleWantsUnowned,
			Path:     e.Path,
			Target:   e.Target,
			Severity: finding.SevSuspicious,
			Summary: fmt.Sprintf("%s enables a unit that no installed package owns",
				path.Base(path.Dir(e.Path))),
			Evidence: []string{
				fmt.Sprintf("link text, read verbatim: %s", e.Link),
				fmt.Sprintf("target resolved against the scanned root: %s", e.Target),
			},
		})
	}

	// Hooks, from the structured report: an unowned hook pacman would actually
	// run, and a file suppressing a packaged one.
	rep, hookRes := surfaces.ScanHooks(root, owners)
	res.Findings = append(res.Findings, hookRes.Findings...)
	res.Gaps = append(res.Gaps, hookRes.Gaps...)
	hookFact := map[string]int{}
	for _, h := range rep.Hooks {
		if h.State != own.Unowned || !h.Active {
			continue
		}
		hookFact[h.Path] = len(facts)
		facts = append(facts, Fact{
			Family:   FamilyHook,
			RuleID:   surfaces.RuleHookUnowned,
			Path:     h.Path,
			Severity: finding.SevSuspicious,
			Summary: fmt.Sprintf("pacman hook %s is owned by no installed package and runs as root on the "+
				"next transaction", h.Path),
			Evidence: []string{fmt.Sprintf("hook directory: %s (%s)", h.Dir.Path, h.Dir.Source)},
		})
	}
	for _, sup := range rep.Suppressed {
		if sup.WinnerState == own.Owned {
			// Two packages claiming one hook name is a packaging matter, and
			// surfaces rates it info. Not correlation input.
			continue
		}
		note := fmt.Sprintf("this file suppresses the package-owned hook %s (shipped by %s): %s",
			sup.Shadowed, sup.ShadowedPkg, sup.Kind)
		if i, ok := hookFact[sup.Winner]; ok {
			facts[i].Evidence = append(facts[i].Evidence, note)
			continue
		}
		facts = append(facts, Fact{
			Family:   FamilyHook,
			RuleID:   surfaces.RuleHookSuppressed,
			Path:     sup.Winner,
			Severity: finding.SevSuspicious,
			Summary: fmt.Sprintf("the package-owned pacman hook %s (%s) no longer runs", sup.Name,
				sup.ShadowedPkg),
			Evidence: []string{note},
		})
	}

	// The remaining surfaces. Their findings' Subject IS the structured path,
	// so no prose is parsed here either. An autostart entry is the one fact
	// with no usable Target: surfaces resolves the Exec program but reports
	// only the entry, so this fact joins by its own path and by the package key
	// and never by its Exec target. Stated rather than worked around.
	miscRes := surfaces.Misc(root, owners, cfg.Misc)
	res.Findings = append(res.Findings, miscRes.Findings...)
	res.Gaps = append(res.Gaps, miscRes.Gaps...)
	for _, f := range miscRes.Findings {
		fam, ok := miscFamily(f.RuleID)
		if !ok || f.Severity < finding.SevSuspicious {
			continue
		}
		facts = append(facts, Fact{
			Family:   fam,
			RuleID:   f.RuleID,
			Path:     strings.TrimPrefix(f.Subject, "/"),
			Severity: f.Severity,
			Summary:  f.Summary,
			Evidence: f.Evidence,
		})
	}

	// Timestamps last, in one pass, so every fact is timed the same way: the
	// TARGET's mtime when there is a target (that is the planted file), else
	// the fact's own path.
	for i := range facts {
		timeFact(root, &facts[i])
	}

	sort.SliceStable(facts, func(i, j int) bool {
		if facts[i].Path != facts[j].Path {
			return facts[i].Path < facts[j].Path
		}
		return facts[i].Family < facts[j].Family
	})
	return facts, res
}

// miscFamily maps a misc rule to its fact family. An unknown rule is not
// silently folded into a family: it is skipped and stays a finding on its own,
// because a fact filed under the wrong family changes what "two families"
// means.
func miscFamily(ruleID string) (string, bool) {
	switch ruleID {
	case surfaces.RulePreload:
		return FamilyPreload, true
	case surfaces.RuleGenerator:
		return FamilyGenerator, true
	case surfaces.RuleProfileD:
		return FamilyProfile, true
	case surfaces.RuleAutostart:
		return FamilyAutostart, true
	}
	return "", false
}

// timeFact fills in the temporal key's input for one fact.
func timeFact(root *os.Root, f *Fact) {
	if f.TimeKnown {
		return
	}
	cands := []string{}
	if f.Target != "" {
		cands = append(cands, f.Target)
	}
	cands = append(cands, f.Path)
	var firstErr error
	for _, c := range cands {
		st, err := statConfined(root, c)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		f.Time, f.TimeKnown, f.TimeFrom = mtimeSeconds(st), true, c
		return
	}
	f.TimeErr = firstErr
}

// statConfined answers "what does the kernel say about this path" through the
// confined opener and nothing else: resolved once through the root, O_NOFOLLOW
// on the leaf, regular files only. A symlink or a directory is refused, which is
// why a fact's TARGET is preferred over its own path -- an enablement link is a
// symlink, and the unit behind it is the file with a meaningful mtime.
//
// os.Stat is not used and could not be: under --offline-root it would resolve
// against the running filesystem.
func statConfined(root *os.Root, rel string) (unix.Stat_t, error) {
	f, st, err := fsx.OpenConfined(root, strings.TrimPrefix(rel, "/"))
	if err != nil {
		return unix.Stat_t{}, err
	}
	f.Close()
	return st, nil
}

// mtimeSeconds folds a stat's mtime into seconds WITHOUT losing the fraction.
// mtree's time= carries a fractional part on every one of the reference
// system's 461,601 entries, and truncating to whole seconds would make ordering
// lie; the same float form is used here so the two clocks compare directly.
func mtimeSeconds(st unix.Stat_t) float64 {
	return float64(st.Mtim.Sec) + float64(st.Mtim.Nsec)/1e9
}

// absent reports that nothing exists at rel. It is deliberately narrower than
// "the stat failed": ENOENT and ENOTDIR are facts about the filesystem, while
// EACCES, ELOOP and a refused path are inabilities, and treating an inability as
// absence is how a check goes quiet about the file it could read least.
func absent(root *os.Root, rel string) bool {
	_, err := statConfined(root, rel)
	if err == nil {
		return false
	}
	return errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR)
}

// Clusters groups facts and rates each group.
//
// Only groups of two or more are returned. A group of one is the underlying
// finding restated, and restating a suspicious finding as a suspicious cluster
// would double every count in the report for no added information.
//
// # The three keys, and what each is allowed to do
//
// PACKAGE. Two facts attributed to the same package are one cluster. This is the
// key the spec names first and the one the persistence class cannot be reached
// with alone: these files are unowned by definition, so there is no owning
// package to scope to and attribution has to be inferred from the other two
// keys before this one can group anything.
//
// TEMPORAL. A fact's file mtime within cfg.Window of a FOREIGN package's
// %INSTALLDATE% attributes that fact to that package. Restricted to foreign
// packages on purpose: a repository package's install date matching an unowned
// file's mtime is the ordinary case (any of hundreds of scriptlets, or the
// administrator who was at the keyboard during that upgrade), so allowing native
// packages here would attribute half of /etc to whatever was installed that
// afternoon. It is NEVER a join key on its own -- every file on a fresh install
// shares one mtime, so fact-to-fact temporal joining would merge an entire
// system into one cluster.
//
// PATH ATTRIBUTION. Two things, and the second is the one the malicious fixture
// is built to exercise:
//
//   - the shared DIRECTORY: two unowned facts whose paths sit in the same
//     package-owned directory outside administrator territory are one cluster.
//     That shared directory is what makes three findings one incident instead of
//     three unrelated alerts.
//   - the NAME: a resolved ExecStart's filename stem, or its directory's name,
//     matching a foreign package's name attributes the fact to that package with
//     no clock involved at all.
//
// # What escalates, and what refuses to
//
// A cluster reaches SevCritical only when all three of these hold:
//
//  1. two or more facts from two or more FAMILIES. Three restatements of one
//     unowned file are one fact.
//  2. a strong attribution: a foreign package reached by the temporal or the
//     name key. A scriptlet alone does not count -- 7 of the reference system's
//     39 foreign packages have one, so it narrows the field and identifies
//     nobody.
//  3. a masquerade: at least one member unowned inside a PACKAGE-OWNED directory
//     that is not administrator territory. This is what separates the malicious
//     fixture from the cruft one, and the separation is load-bearing rather than
//     decorative: cruft's hand-written unit is genuinely enabled through a
//     *.wants link and genuinely runs an unowned binary, so conditions 1 and 2
//     can both hold on an honest system. What it does not do is plant files in a
//     directory a package owns -- it uses /etc/systemd/system and
//     /usr/local/bin, which is where local software is supposed to live.
//
// When 1 and 3 hold and 2 fails because something could not be DETERMINED --
// the repository name set was not supplied, a member's mtime could not be read,
// a foreign package records no %INSTALLDATE% -- the shortfall is a coverage gap
// (INV-3, INV-9). A cluster assembled from partial inputs must not read as a
// quiet suspicious. When 2 fails because the timestamps were read and did not
// match, that is an answer and not a gap.
func Clusters(root *os.Root, cfg Config, facts []Fact) ([]Cluster, []finding.Gap) {
	if len(facts) == 0 || cfg.Owners == nil {
		return nil, nil
	}
	cands := packageCandidates(root, cfg)
	syncKnown := len(cfg.SyncNames) > 0

	// Per-fact attribution first: the package key needs it before it can join
	// anything.
	attributed := make([]map[string]Candidate, len(facts))
	for i := range facts {
		attributed[i] = attribute(cfg, cands, facts[i], syncKnown)
	}

	uf := newUnionFind(len(facts))
	var joins []string
	join := func(i, j int, why string) {
		if uf.union(i, j) {
			joins = append(joins, why)
		}
	}
	for i := 0; i < len(facts); i++ {
		for j := i + 1; j < len(facts); j++ {
			a, b := facts[i], facts[j]

			// Path attribution, the reachability half: one fact points at the
			// other's file, or both point at the same file.
			if a.Target != "" && a.Target == b.Target {
				join(i, j, fmt.Sprintf("%s and %s both resolve to %s", a.Path, b.Path, a.Target))
			}
			if a.Target != "" && a.Target == b.Path {
				join(i, j, fmt.Sprintf("%s resolves to %s", a.Path, b.Path))
			}
			if b.Target != "" && b.Target == a.Path {
				join(i, j, fmt.Sprintf("%s resolves to %s", b.Path, a.Path))
			}

			// Path attribution, the shared-directory half.
			if d, ok := sharedOwnedDir(cfg.Owners, a, b); ok {
				join(i, j, fmt.Sprintf("%s and %s are both unowned files in %s, which %s owns",
					a.Path, b.Path, d.dir, d.pkg))
			}

			// The package key.
			if pkg, ok := sharedStrongPkg(attributed[i], attributed[j]); ok {
				join(i, j, fmt.Sprintf("%s and %s are both attributed to %s", a.Path, b.Path, pkg))
			}
		}
	}

	groups := map[int][]int{}
	for i := range facts {
		r := uf.find(i)
		groups[r] = append(groups[r], i)
	}

	var (
		out  []Cluster
		gaps []finding.Gap
	)
	for _, members := range groups {
		if len(members) < 2 {
			continue
		}
		sort.Ints(members)
		c := Cluster{}
		fams := map[string]bool{}
		merged := map[string]Candidate{}
		for _, i := range members {
			f := facts[i]
			c.Facts = append(c.Facts, f)
			fams[f.Family] = true
			for pkg, cand := range attributed[i] {
				if prev, ok := merged[pkg]; ok {
					cand.Keys = append(prev.Keys, cand.Keys...)
					cand.Strong = prev.Strong || cand.Strong
				}
				merged[pkg] = cand
			}
			for _, p := range f.paths() {
				if d, ok := masquerade(cfg.Owners, p); ok {
					c.Masquerade = append(c.Masquerade, fmt.Sprintf("%s is unowned inside %s, owned by %s",
						p, d.dir, d.pkg))
				}
			}
		}
		for fam := range fams {
			c.Families = append(c.Families, fam)
		}
		sort.Strings(c.Families)
		sort.Strings(c.Masquerade)
		c.Masquerade = dedup(c.Masquerade)
		for _, cand := range merged {
			cand.Keys = dedup(cand.Keys)
			c.Candidates = append(c.Candidates, cand)
		}
		sort.Slice(c.Candidates, func(i, j int) bool { return c.Candidates[i].Pkg < c.Candidates[j].Pkg })

		// Only the joins that name a member of this cluster.
		for _, j := range joins {
			if joinMentions(j, c.Facts) {
				c.Joins = append(c.Joins, j)
			}
		}
		sort.Strings(c.Joins)

		strong := strongCandidates(c.Candidates)
		switch {
		case len(c.Families) >= 2 && len(c.Masquerade) > 0 && len(strong) > 0:
			c.Severity = finding.SevCritical
		default:
			c.Severity = finding.SevSuspicious
		}
		switch {
		case len(strong) == 1:
			c.Subject, c.SubjectKind = strong[0].Pkg, "package"
		default:
			// No attribution, or an ambiguous one. The subject is then the
			// cluster's anchor path rather than an arbitrary pick from the
			// candidates: naming one of several packages as THE subject would
			// print a guess in the field an operator acts on.
			c.Subject, c.SubjectKind = c.Facts[0].Path, "path"
		}
		if len(strong) > 1 {
			c.Joins = append(c.Joins, fmt.Sprintf("attribution is AMBIGUOUS: %d foreign packages match, "+
				"so the cluster names all of them and none as its subject", len(strong)))
		}

		// INV-9: separate "could not tell" from "told, and the answer was no".
		if len(strong) == 0 {
			if !syncKnown {
				c.Unattributed = append(c.Unattributed, "the set of package names the repositories offer was "+
					"not supplied, so no installed package could be classified as foreign and no cluster "+
					"could be attributed to one")
			}
			for _, f := range c.Facts {
				if !f.TimeKnown {
					c.Unattributed = append(c.Unattributed, fmt.Sprintf("the mtime of %s could not be read "+
						"(%v), so the temporal key could not be applied to it", f.Path, f.TimeErr))
				}
			}
			for _, cand := range cands {
				if cand.Foreign && cand.InstallDate.IsZero() {
					c.Unattributed = append(c.Unattributed, fmt.Sprintf("the foreign package %s records no "+
						"%%INSTALLDATE%%, so the temporal key cannot reach it", cand.Pkg))
				}
			}
		}
		sort.Strings(c.Unattributed)
		c.Unattributed = dedup(c.Unattributed)

		// The gap fires only where the shortfall CHANGED the outcome: a cluster
		// that would otherwise have been evaluated for critical and could not
		// be. Gapping every unreadable mtime anywhere would bury the one that
		// mattered.
		if len(c.Unattributed) > 0 && len(c.Families) >= 2 && len(c.Masquerade) > 0 {
			gaps = append(gaps, finding.Gap{
				RuleID:  RuleCoverage,
				Subject: c.Facts[0].Path,
				Reason: fmt.Sprintf("%d correlated persistence facts could not be attributed to a package, so "+
					"this cluster was rated %v rather than evaluated for a correlated critical: %s",
					len(c.Facts), c.Severity, strings.Join(c.Unattributed, "; ")),
			})
		}
		if len(cfg.Transactions) == 0 {
			c.Notes = append(c.Notes, "no pacman.log transaction times were supplied, so the temporal key "+
				"rests on %INSTALLDATE% and file mtimes alone; the third clock did not participate")
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].Subject != out[j].Subject {
			return out[i].Subject < out[j].Subject
		}
		return out[i].Facts[0].Path < out[j].Facts[0].Path
	})
	return out, gaps
}

// Finding renders one cluster. The Subject is a package name when attribution is
// unambiguous and a path otherwise; both are version-independent, which is what
// finding.Fingerprint's contract requires of a caller and cannot check.
func (c Cluster) Finding() finding.Finding {
	ev := []string{
		fmt.Sprintf("%d correlated facts across %d persistence surfaces: %s",
			len(c.Facts), len(c.Families), strings.Join(c.Families, ", ")),
	}
	for _, f := range c.Facts {
		line := fmt.Sprintf("[%s] %s: %s", f.Family, f.Severity, f.Summary)
		if f.TimeKnown {
			line += fmt.Sprintf(" (mtime of %s: %.0f)", f.TimeFrom, f.Time)
		}
		ev = append(ev, line)
		for _, e := range f.Evidence {
			ev = append(ev, "    "+e)
		}
	}
	for _, j := range c.Joins {
		ev = append(ev, "correlation key: "+j)
	}
	for _, m := range c.Masquerade {
		ev = append(ev, "masquerade: "+m)
	}
	for _, cand := range c.Candidates {
		ev = append(ev, fmt.Sprintf("candidate package %s (base %s, foreign=%v, install scriptlet=%v): %s",
			cand.Pkg, cand.Base, cand.Foreign, cand.HasScriptlet, strings.Join(cand.Keys, "; ")))
	}
	for _, u := range c.Unattributed {
		ev = append(ev, "not attributed: "+u)
	}
	ev = append(ev, c.Notes...)

	summary := fmt.Sprintf("%d persistence facts across %d surfaces correlate onto %s",
		len(c.Facts), len(c.Families), c.Subject)
	if c.Severity == finding.SevCritical {
		summary = fmt.Sprintf("%d persistence facts across %d surfaces correlate onto the foreign package %s, "+
			"including files planted in a directory another package owns", len(c.Facts), len(c.Families), c.Subject)
	}
	return finding.Finding{
		RuleID:      RuleCluster,
		SubjectKind: c.SubjectKind,
		Subject:     c.Subject,
		Severity:    c.Severity,
		Summary:     summary,
		Evidence:    ev,
		Limits:      clusterLimit,
	}
}

// packageCandidates builds the per-package facts attribution needs: the
// foreign/native split, %INSTALLDATE%, and whether the package ships an install
// scriptlet.
//
// The scriptlet is probed by PRESENCE and never read or run (INV-2). It matters
// because it is the recorded mechanism by which a file lands on disk outside any
// %FILES% list: pacman knows nothing about what a scriptlet created, which is
// exactly why ownership rather than `pacman -Qo` has to be the oracle.
func packageCandidates(root *os.Root, cfg Config) []Candidate {
	out := make([]Candidate, 0, len(cfg.Pkgs))
	syncKnown := len(cfg.SyncNames) > 0
	for _, p := range cfg.Pkgs {
		c := Candidate{
			Pkg:         p.Name,
			Base:        p.Base,
			Foreign:     syncKnown && !cfg.SyncNames[p.Name],
			InstallDate: p.InstallDate,
		}
		if c.Base == "" {
			c.Base = p.Name
		}
		if root != nil && p.Version != "" {
			rel := path.Join(cfg.dbPath(), p.Name+"-"+p.Version, "install")
			c.HasScriptlet = !absent(root, rel)
		}
		out = append(out, c)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Pkg < out[j].Pkg })
	return out
}

// attribute answers "which foreign packages does this fact point at", by the
// temporal key and by the name key. Both are restricted to foreign packages;
// see Clusters' doc comment for why.
func attribute(cfg Config, cands []Candidate, f Fact, syncKnown bool) map[string]Candidate {
	out := map[string]Candidate{}
	if !syncKnown {
		return out
	}
	win := cfg.window().Seconds()
	tokens := pathTokens(f)

	for _, cand := range cands {
		if !cand.Foreign {
			continue
		}
		hit := cand
		hit.Keys = nil

		if f.TimeKnown && !cand.InstallDate.IsZero() {
			delta := f.Time - float64(cand.InstallDate.Unix())
			if delta < 0 {
				delta = -delta
			}
			if delta <= win {
				hit.Strong = true
				hit.Keys = append(hit.Keys, fmt.Sprintf("temporal: the mtime of %s is %.0f s from %s's "+
					"%%INSTALLDATE%% (%d), inside the %.0f s window",
					f.TimeFrom, delta, cand.Pkg, cand.InstallDate.Unix(), win))
			}
		}
		for _, tok := range tokens {
			if nameMatches(tok.token, cand.Pkg) || nameMatches(tok.token, cand.Base) {
				hit.Strong = true
				hit.Keys = append(hit.Keys, fmt.Sprintf("path attribution: %s of %s matches the foreign "+
					"package name %s", tok.kind, tok.from, cand.Pkg))
			}
		}
		if len(hit.Keys) == 0 {
			continue
		}
		if hit.HasScriptlet {
			hit.Keys = append(hit.Keys, fmt.Sprintf("corroboration: %s ships an install scriptlet, which is "+
				"the recorded mechanism by which a file appears outside a package's own file list; the "+
				"scriptlet was never run (INV-2)", cand.Pkg))
		}
		for _, tr := range cfg.Transactions {
			if tr.Pkg != cand.Pkg || !f.TimeKnown {
				continue
			}
			d := f.Time - float64(tr.Time.Unix())
			if d < 0 {
				d = -d
			}
			if d <= win {
				hit.Keys = append(hit.Keys, fmt.Sprintf("corroboration: a pacman.log %s of %s at %d is %.0f s "+
					"from the same mtime", tr.Op, tr.Pkg, tr.Time.Unix(), d))
			}
		}
		out[cand.Pkg] = hit
	}
	return out
}

// pathToken is one name a fact offers for matching, with provenance so the
// evidence can say which string matched.
type pathToken struct {
	kind  string
	from  string
	token string
}

// pathTokens returns the directory names and filename stems a fact's paths
// offer. The roadmap's phrasing is "match the directory or the filename stem
// against foreign package names", and both halves are here: a payload named
// after the package, and a payload in a directory named after it.
func pathTokens(f Fact) []pathToken {
	var out []pathToken
	for _, p := range f.paths() {
		if p == "" {
			continue
		}
		base := path.Base(p)
		stem := strings.TrimSuffix(base, path.Ext(base))
		out = append(out,
			pathToken{kind: "the filename stem", from: p, token: stem},
			pathToken{kind: "the directory name", from: p, token: path.Base(path.Dir(p))},
		)
	}
	return out
}

// minNameTokenLen is the floor below which a name match means nothing. "bin",
// "lib", "etc" and "tool" are directory and file names on every system, and a
// package called any of them would otherwise be attributed the whole
// filesystem. Five characters is where the false matches measurably stop being
// worth the true ones.
const minNameTokenLen = 5

// aurNameSuffixes are the packaging suffixes that describe how a package was
// built rather than what it installs. `librewolf-fix-bin` installs
// `librewolf-fix`, so a match has to see through them.
var aurNameSuffixes = []string{
	"-bin", "-git", "-hg", "-svn", "-bzr", "-cvs", "-nightly", "-beta", "-dev", "-debug", "-appimage",
}

// nameMatches is EXACT equality after normalisation, and nothing looser.
//
// A prefix or substring test was considered and rejected: "mailer" would then
// match "mailertool", every package whose name is a common English word would
// match dozens of unrelated paths, and the attribution this package prints as a
// package name in a critical finding would be a guess. Exact-after-normalisation
// misses real matches (a payload named `agent` planted by `foo-bin` is not
// caught by this key) and says so; the temporal key is what covers that case.
func nameMatches(token, pkg string) bool {
	t, p := normalizeName(token), normalizeName(pkg)
	if len(t) < minNameTokenLen || len(p) < minNameTokenLen {
		return false
	}
	return t == p
}

func normalizeName(s string) string {
	s = strings.ToLower(strings.TrimSpace(s))
	for _, sfx := range aurNameSuffixes {
		if strings.HasSuffix(s, sfx) && len(s) > len(sfx) {
			return strings.TrimSuffix(s, sfx)
		}
	}
	return s
}

// ownedDir is a package-owned directory holding an unowned file.
type ownedDir struct {
	dir string
	pkg string
}

// masquerade reports that p is unowned, its parent directory IS package-owned,
// and that directory is not administrator territory. See adminTerritory for why
// the last clause is not a loophole.
func masquerade(owners *own.Owners, p string) (ownedDir, bool) {
	p = strings.TrimPrefix(p, "/")
	if p == "" || isAdminTerritory(p) {
		return ownedDir{}, false
	}
	dir := path.Dir(p)
	if dir == "." || dir == "/" {
		return ownedDir{}, false
	}
	pkg, st, _ := owners.Resolve(dir)
	if st != own.Owned {
		return ownedDir{}, false
	}
	if _, st, _ := owners.Resolve(p); st != own.Unowned {
		return ownedDir{}, false
	}
	return ownedDir{dir: dir, pkg: pkg}, true
}

// sharedOwnedDir reports the package-owned directory two facts have in common,
// if any. Administrator territory is excluded here as well as in masquerade: in
// /etc/systemd/system every local unit shares a directory, so the shared
// directory says nothing there. In a package's own directory it says a great
// deal.
func sharedOwnedDir(owners *own.Owners, a, b Fact) (ownedDir, bool) {
	for _, pa := range a.paths() {
		da, ok := masquerade(owners, pa)
		if !ok {
			continue
		}
		for _, pb := range b.paths() {
			db, ok := masquerade(owners, pb)
			if !ok || db.dir != da.dir {
				continue
			}
			if strings.TrimPrefix(pa, "/") == strings.TrimPrefix(pb, "/") {
				continue
			}
			return da, true
		}
	}
	return ownedDir{}, false
}

// sharedStrongPkg reports a package both facts are strongly attributed to.
func sharedStrongPkg(a, b map[string]Candidate) (string, bool) {
	names := make([]string, 0, len(a))
	for pkg := range a {
		names = append(names, pkg)
	}
	sort.Strings(names)
	for _, pkg := range names {
		if !a[pkg].Strong {
			continue
		}
		if cb, ok := b[pkg]; ok && cb.Strong {
			return pkg, true
		}
	}
	return "", false
}

func strongCandidates(cands []Candidate) []Candidate {
	var out []Candidate
	for _, c := range cands {
		if c.Strong {
			out = append(out, c)
		}
	}
	return out
}

func joinMentions(join string, facts []Fact) bool {
	for _, f := range facts {
		if strings.Contains(join, f.Path) {
			return true
		}
	}
	return false
}

func dedup(in []string) []string {
	if len(in) == 0 {
		return nil
	}
	out := in[:0]
	seen := map[string]bool{}
	for _, s := range in {
		if seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// isAdminTerritory reports whether a path lies in a directory the distribution
// intends an administrator to write into. See adminTerritory.
func isAdminTerritory(p string) bool {
	p = strings.TrimPrefix(path.Clean(p), "/")
	for _, t := range adminTerritory {
		if p == t || strings.HasPrefix(p, t+"/") {
			return true
		}
	}
	return false
}

// unionFind groups facts without an ordering assumption: joins arrive in
// whatever order the pairwise scan produces them, and a cluster must not depend
// on that order (INV-4 covers the ORDER of the evidence as well as its content).
type unionFind struct{ parent []int }

func newUnionFind(n int) *unionFind {
	p := make([]int, n)
	for i := range p {
		p[i] = i
	}
	return &unionFind{parent: p}
}

func (u *unionFind) find(i int) int {
	for u.parent[i] != i {
		u.parent[i] = u.parent[u.parent[i]]
		i = u.parent[i]
	}
	return i
}

func (u *unionFind) union(i, j int) bool {
	ri, rj := u.find(i), u.find(j)
	if ri == rj {
		return false
	}
	if ri < rj {
		u.parent[rj] = ri
	} else {
		u.parent[ri] = rj
	}
	return true
}
