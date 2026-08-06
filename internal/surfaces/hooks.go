// internal/surfaces/hooks.go
//
// Pacman hooks as a persistence surface.
//
// A hook is a root-privileged command pacman runs on the next transaction. That
// makes the hook directories a persistence surface in the ordinary sense --
// something added there runs later, as src, without anyone asking -- and it
// makes them a surface in a second, quieter sense that neither design review
// caught: a hook that pacman was supposed to run can be stopped from running.
// This file covers both directions.
//
//	ADDED       an unowned hook file in a directory pacman reads
//	SUPPRESSED  a package-owned hook that pacman no longer runs, because a
//	            same-named file in a higher-priority directory replaced it --
//	            with hostile content, with an empty file, or with the documented
//	            /dev/null symlink
//
// What this file does NOT do is decide anything by asking pacman. There is no
// `pacman-conf --listdir hookdir`, no `pacman -Qo`: the hook set is read off
// disk, hook bodies are parsed and never run (INV-2), and ownership comes from
// internal/own. An --offline-root is a parameter, not a second code path
// (INV-4), so everything here is a pure function of (src, owners) and reaches
// the filesystem only through the confined API.
//
// Severity, written down weaker than it looks. An unowned hook is suspicious,
// never critical: /etc/pacman.d/hooks exists so administrators can write hooks,
// and masking a hook is documented practice. Correlation earns critical and
// happens elsewhere. More importantly, a hook shipped INSIDE a package's own
// file list is owned, and every check here goes silent on it -- which is what an
// attacker who builds the payload into $pkgdir gets for free. Every finding says
// so (INV-6), because a check that overstates what ownership proves teaches its
// reader to trust a clean result that was never earned.
package surfaces

import (
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/hook"
	"github.com/lookatitude/aurvet/internal/own"
)

// Rule and gap identifiers. RuleHookCoverage is deliberately the identifier
// internal/hook already emits its load gaps under: a hook this file could not
// read and a hook the loader could not read are the same coverage shortfall, and
// giving them two names would let a consumer handle one and miss the other.
const (
	RuleHookUnowned    = "hook-unowned"
	RuleHookSuppressed = "hook-suppressed"
	RuleHookCoverage   = "hook-coverage"
	RuleHookDirs       = "hook-dirs"
)

// Subject kinds, so a report can group hook findings without string-matching
// rule IDs.
const (
	SubjectHook    = "pacman-hook"
	SubjectHookDir = "pacman-hook-dir"
)

// Where a hook directory came from. Provenance is reported because "aurvet
// looked at three directories" is only checkable if it also says why.
const (
	// HookDirSourceSystem is libalpm's compiled-in directory. It is added
	// unconditionally and cannot be configured away, which is why it is first
	// and why it is always scanned.
	HookDirSourceSystem = "system-default"
	// HookDirSourceAdmin is the compiled-in admin directory, which applies only
	// when the configuration names no HookDir of its own.
	HookDirSourceAdmin = "admin-default"
	// HookDirSourceConfig is a HookDir read out of pacman.conf.
	HookDirSourceConfig = "pacman.conf HookDir"
)

// systemHookDir and adminHookDir mirror libalpm's SYSHOOKDIR and pacman's
// compiled-in HOOKDIR, root-relative.
const (
	systemHookDir = "usr/share/libalpm/hooks"
	adminHookDir  = "etc/pacman.d/hooks"
	pacmanConf    = "etc/pacman.conf"
)

// maxConfBytes bounds one configuration file. Real pacman.conf files are a few
// KiB; the ceiling exists because this is attacker-writable input and an
// unbounded read of attacker-writable input is not a thing this tool gets to
// have.
const maxConfBytes = 1 << 20

// maxIncludeDepth bounds Include recursion. pacman itself has a similar bound;
// without one, two files including each other turn a scan into a hang.
const maxIncludeDepth = 8

// HookDir is one directory pacman reads hooks from, in ascending priority.
type HookDir struct {
	// Path is root-relative, slash-separated, with no trailing slash.
	Path string
	// Source records which rule put this directory in the list.
	Source string
	// Present distinguishes "this directory is not there" from "this directory
	// is empty". Absence is the ordinary case for etc/pacman.d/hooks and is a
	// fact to record, not a finding and not a gap; a directory that exists but
	// cannot be listed is neither, and produces a RuleHookCoverage gap.
	Present bool
}

// HookEntry is one hook file found on disk, with its ownership answered.
type HookEntry struct {
	// Hook is the parsed body. Never executed.
	Hook hook.Hook
	// Path is the hook's root-relative path.
	Path string
	// Dir is the HookDir it was found in.
	Dir HookDir
	// Pkg is the owning package, empty unless State is own.Owned.
	Pkg string
	// State is own.Owned, own.Unowned or own.Unresolved. Unresolved is a
	// coverage gap and never a finding (INV-9).
	State own.State
	// Active reports that this is the copy pacman would run: the last one, in
	// directory priority order, of every file with this name.
	Active bool
	// Parsed distinguishes a hook whose body was read from one known only by
	// its name in a directory listing. An EMPTY hook and an UNREADABLE hook are
	// indistinguishable by Exec alone and mean different things -- one is known
	// to run nothing, the other is unknown -- so the difference is recorded
	// rather than inferred.
	Parsed bool
}

// SuppressKind names how a packaged hook stopped running. The distinction is
// not cosmetic: the kinds differ in what the tool can claim to know.
type SuppressKind int

const (
	// SuppressReplaced: the winning file has its own Exec. Whatever the
	// packaged hook did, something else is done instead.
	SuppressReplaced SuppressKind = iota
	// SuppressEmpty: the winning file parses to no Exec at all (an empty file,
	// or one with no [Action] Exec). The packaged hook's work simply stops.
	SuppressEmpty
	// SuppressMasked: the winning file is a symlink to /dev/null -- the
	// documented way to disable a hook, and also how an attacker disables one.
	SuppressMasked
	// SuppressUnreadable: the winning file could not be read, so what pacman
	// now runs is unknown. The suppression is certain; the replacement is not.
	// This kind always keeps its coverage gap.
	SuppressUnreadable
)

func (k SuppressKind) String() string {
	switch k {
	case SuppressReplaced:
		return "replaced"
	case SuppressEmpty:
		return "emptied"
	case SuppressMasked:
		return "masked with /dev/null"
	case SuppressUnreadable:
		return "replaced by something unreadable"
	default:
		return "unknown"
	}
}

// Suppression is one package-owned hook that pacman no longer runs.
type Suppression struct {
	// Name is the hook file name, which is the identity pacman resolves on.
	Name string
	// Winner is the root-relative path of the file pacman runs instead.
	Winner      string
	WinnerPkg   string
	WinnerState own.State
	// Shadowed is the root-relative path of the package-owned hook that stopped
	// running, and ShadowedPkg the package that shipped it.
	Shadowed    string
	ShadowedPkg string
	Kind        SuppressKind
	// WinnerLink is the symlink target of Winner, verbatim, when Winner is a
	// symlink. Carried as a string and never resolved.
	WinnerLink string
}

// HookReport is the evidence ScanHooks gathered, independent of what was worth
// reporting. A consumer that wants to say "57 hooks in 1 directory, nothing
// suppressed" reads this; findings are the subset that needed an operator.
type HookReport struct {
	Dirs       []HookDir
	Hooks      []HookEntry
	Suppressed []Suppression
}

// Suppression returns the suppression recorded for a hook file name.
func (r HookReport) Suppression(name string) (Suppression, bool) {
	for _, s := range r.Suppressed {
		if s.Name == name {
			return s, true
		}
	}
	return Suppression{}, false
}

// ActiveHooks returns the hooks pacman would actually run, in priority order.
func (r HookReport) ActiveHooks() []HookEntry {
	out := make([]HookEntry, 0, len(r.Hooks))
	for _, h := range r.Hooks {
		if h.Active {
			out = append(out, h)
		}
	}
	return out
}

// ScanHooks reads every hook directory pacman would read and reports what is
// there that no package shipped, and what a package shipped that no longer runs.
//
// It is a pure function of (src, owners): no ambient paths, no environment, no
// dependence on the process working directory (INV-4), and no writes (INV-5).
func ScanHooks(src fsx.Source, owners *own.Owners) (HookReport, finding.Result) {
	var res finding.Result

	dirs, dirGaps := ResolveHookDirs(src)
	res.Gaps = append(res.Gaps, dirGaps...)

	fsys := src.FS()
	rep := HookReport{Dirs: make([]HookDir, 0, len(dirs))}

	// Per-directory loading, through internal/hook. One parser, deliberately:
	// LoadHooks already collapses same-named hooks to the winner, so calling it
	// per directory is what keeps the LOSERS visible -- and the losers are the
	// suppressed hooks this file exists to find.
	var loaded []HookEntry
	for _, d := range dirs {
		if st, err := fs.Stat(fsys, d.Path); err == nil && st.IsDir() {
			d.Present = true
		}
		rep.Dirs = append(rep.Dirs, d)

		hooks, gaps := hook.LoadHooks(fsys, []string{d.Path})
		res.Gaps = append(res.Gaps, gaps...)
		for _, h := range hooks {
			loaded = append(loaded, HookEntry{Hook: h, Path: path.Join(d.Path, h.Name), Dir: d, Parsed: true})
		}
	}

	// Every hook FILE on disk, including the ones LoadHooks could not read: a
	// file it choked on is still a file pacman will try to run, so it must take
	// part in the shadowing comparison. Without this, replacing a packaged hook
	// with an unreadable file would suppress it invisibly.
	present := map[string]bool{}
	for _, h := range loaded {
		present[h.Path] = true
	}
	for _, d := range rep.Dirs {
		if !d.Present {
			continue
		}
		ents, err := fs.ReadDir(fsys, d.Path)
		if err != nil {
			// LoadHooks already gapped this directory; do not gap it twice.
			continue
		}
		for _, ent := range ents {
			if !strings.HasSuffix(ent.Name(), ".hook") || ent.IsDir() {
				continue
			}
			p := path.Join(d.Path, ent.Name())
			if present[p] {
				continue
			}
			loaded = append(loaded, HookEntry{
				Hook: hook.Hook{Name: ent.Name(), Dir: d.Path},
				Path: p,
				Dir:  d,
			})
		}
	}

	// Ownership. own.Resolve has three states and the third one is not a
	// verdict: an unresolvable hook becomes a gap, because "unowned" here is
	// what this file reports on, and printing a coverage gap as a finding is
	// exactly INV-9's failure mode.
	for i := range loaded {
		pkg, st, err := owners.Resolve(loaded[i].Path)
		loaded[i].Pkg, loaded[i].State = pkg, st
		if st == own.Unresolved {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID:  RuleHookCoverage,
				Subject: loaded[i].Path,
				Reason: fmt.Sprintf("this hook's ownership could not be resolved (%v), so whether any "+
					"package shipped it is unknown; it is neither reported as unowned nor treated as owned", err),
			})
		}
	}

	// Priority: within a file name, the last directory read wins. That is
	// pacman's rule, and it is the whole mechanism behind suppression.
	winner := map[string]int{}
	for i, h := range loaded {
		winner[h.Hook.Name] = i
	}
	for _, i := range winner {
		loaded[i].Active = true
	}
	rep.Hooks = loaded

	// Suppression: a package-owned loser under a name some other file wins.
	//
	// suppressor records the winning paths, so a file already reported as
	// suppressing a packaged hook is not ALSO reported as merely unowned. The
	// suppression finding states the ownership fact in its own evidence and is
	// strictly the more informative of the two; two findings about one path
	// would be the sort of duplication that trains an operator to skim.
	suppressor := map[string]bool{}
	for i, loser := range loaded {
		w := winner[loser.Hook.Name]
		if w == i {
			continue
		}
		if loser.State != own.Owned {
			// An unowned hook shadowed by another unowned hook suppresses
			// nothing a package shipped; the files themselves are reported
			// below on their own merits. An UNRESOLVED loser is different --
			// it may well have been packaged -- so it gets a gap rather than
			// being quietly dropped into the same bucket.
			if loser.State == own.Unresolved {
				res.Gaps = append(res.Gaps, finding.Gap{
					RuleID:  RuleHookCoverage,
					Subject: loser.Path,
					Reason: fmt.Sprintf("this hook is shadowed by %s, but its own ownership could not be "+
						"resolved, so whether a PACKAGED hook stopped running is unknown", loaded[w].Path),
				})
			}
			continue
		}
		sup := classifySuppression(src, loaded[w], loser)
		rep.Suppressed = append(rep.Suppressed, sup)
		res.Findings = append(res.Findings, suppressionFinding(sup, loaded[w]))
		suppressor[sup.Winner] = true
		if sup.Kind == SuppressMasked {
			// The mask is understood, not unreadable. The confined reader
			// refuses to follow an absolute symlink target -- correctly: under
			// --offline-src, following /dev/null would read the HOST's device
			// while scanning someone else's disk -- so LoadHooks reported the
			// file as unreadable. readlinkat told us it is /dev/null, and a hook
			// whose body is /dev/null demonstrably runs nothing. Leaving the gap
			// would report "I could not look" about the one file we know most
			// about, and would raise exit 3 on a system whose admin did nothing
			// wrong. Every other unreadable replacement KEEPS its gap.
			res.Gaps = dropGap(res.Gaps, RuleHookCoverage, sup.Winner)
		}
	}

	// Unowned hook files. Reported at suspicious when pacman would run them and
	// at info when it would not, because a hook that is itself shadowed is not
	// a live surface.
	for _, h := range loaded {
		if h.State != own.Unowned || suppressor[h.Path] {
			continue
		}
		res.Findings = append(res.Findings, unownedFinding(h))
	}

	return rep, res
}

// classifySuppression decides HOW a packaged hook stopped running, reading the
// winning file's own bytes only through what has already been parsed plus one
// readlinkat. It never follows the link.
func classifySuppression(src fsx.Source, win, loser HookEntry) Suppression {
	sup := Suppression{
		Name:        loser.Hook.Name,
		Winner:      win.Path,
		WinnerPkg:   win.Pkg,
		WinnerState: win.State,
		Shadowed:    loser.Path,
		ShadowedPkg: loser.Pkg,
	}

	// fsx.ReadLinkConfined, not os.Readlink and not filepath.EvalSymlinks: the
	// parent directory is resolved once through the src, so no component can be
	// swapped for a link leading out of the tree, and the target is returned
	// verbatim rather than resolved.
	if target, err := src.ReadLink(win.Path); err == nil {
		sup.WinnerLink = target
		if path.Clean(target) == "/dev/null" {
			sup.Kind = SuppressMasked
			return sup
		}
	}

	// A file the loader could not read has no body to judge. This is decided
	// from HookEntry.Parsed rather than from the empty Exec such a file leaves
	// behind, because an EMPTY hook and an UNREADABLE hook are indistinguishable
	// by Exec alone and mean different things: one is known to run nothing, the
	// other is unknown.
	if !win.Parsed {
		sup.Kind = SuppressUnreadable
		return sup
	}
	if strings.TrimSpace(win.Hook.Exec) == "" {
		sup.Kind = SuppressEmpty
		return sup
	}
	sup.Kind = SuppressReplaced
	return sup
}

func suppressionFinding(sup Suppression, win HookEntry) finding.Finding {
	sev := finding.SevSuspicious
	if win.State == own.Owned {
		// Two packages claiming one hook file name is a packaging matter, not a
		// suppression an operator has to act on.
		sev = finding.SevInfo
	}

	ev := []string{
		fmt.Sprintf("pacman resolves hooks by FILE NAME across its hook directories, later directories winning: %s", sup.Name),
		fmt.Sprintf("runs: %s (%s)", sup.Winner, ownerText(win.State, win.Pkg)),
		fmt.Sprintf("no longer runs: %s (shipped by %s)", sup.Shadowed, sup.ShadowedPkg),
		fmt.Sprintf("suppression: %s", sup.Kind),
	}
	if sup.WinnerLink != "" {
		ev = append(ev, fmt.Sprintf("symlink target, read verbatim and never followed: %s", sup.WinnerLink))
	}
	if sup.Kind == SuppressReplaced {
		ev = append(ev, fmt.Sprintf("replacement Exec, parsed and never executed: %s", win.Hook.Exec))
	}

	limits := "Suppressing a hook is a legitimate, documented administrative action -- a /dev/null " +
		"symlink is how the manual says to disable one -- and this check cannot tell an administrator " +
		"from an attacker, which is why it is never critical on its own. It also proves nothing about " +
		"intent: the replacement's contents are parsed, never run. And it catches sloppy suppression " +
		"only -- a hook shipped inside a package's own file list is owned, so a package that replaces " +
		"another package's hook from within its own file list leaves no unowned file and nothing here " +
		"fires. Like the rest of this phase, this check catches sloppy malware; a clean result is not " +
		"evidence of a clean system."

	return finding.Finding{
		RuleID:      RuleHookSuppressed,
		SubjectKind: SubjectHook,
		Subject:     sup.Winner,
		Severity:    sev,
		Summary: fmt.Sprintf("the package-owned pacman hook %s (%s) no longer runs: %s %s it",
			sup.Name, sup.ShadowedPkg, sup.Winner, suppressVerb(sup.Kind)),
		Evidence: ev,
		Limits:   limits,
	}
}

func suppressVerb(k SuppressKind) string {
	switch k {
	case SuppressMasked:
		return "masks"
	case SuppressEmpty:
		return "empties"
	default:
		return "shadows"
	}
}

func unownedFinding(h HookEntry) finding.Finding {
	sev := finding.SevSuspicious
	summary := fmt.Sprintf("pacman hook %s is owned by no installed package and runs as root on the next transaction", h.Path)
	if !h.Active {
		sev = finding.SevInfo
		summary = fmt.Sprintf("pacman hook %s is owned by no installed package, and is itself shadowed by a "+
			"same-named hook in a higher-priority directory, so pacman does not run it", h.Path)
	}

	ev := []string{
		fmt.Sprintf("hook directory: %s (%s)", h.Dir.Path, h.Dir.Source),
		fmt.Sprintf("no installed package records %s", h.Path),
	}
	if h.Hook.When != "" {
		ev = append(ev, fmt.Sprintf("When = %s", h.Hook.When))
	}
	if h.Hook.Exec != "" {
		ev = append(ev, fmt.Sprintf("Exec, parsed and never executed: %s", h.Hook.Exec))
	}
	for _, tr := range h.Hook.Triggers {
		ev = append(ev, fmt.Sprintf("Trigger: Type=%s Operation=%s Target=%s",
			tr.Type, strings.Join(tr.Operations, ","), strings.Join(tr.Targets, ",")))
	}

	limits := "Unowned means only that no installed package's file list records this path -- it is not " +
		"evidence of anything by itself. /etc/pacman.d/hooks exists so that administrators can write " +
		"hooks, and locally written hooks are ordinary; so are hooks in an extra HookDir under " +
		"/usr/local. This check is also blind in the direction that matters most: a hook shipped INSIDE " +
		"a package's own file list is owned, with a self-consistent mtree, and nothing here fires on it. " +
		"It catches sloppy malware only, and a clean result is not evidence of a clean system."

	return finding.Finding{
		RuleID:      RuleHookUnowned,
		SubjectKind: SubjectHook,
		Subject:     h.Path,
		Severity:    sev,
		Summary:     summary,
		Evidence:    ev,
		Limits:      limits,
	}
}

func ownerText(st own.State, pkg string) string {
	if st == own.Owned {
		return "shipped by " + pkg
	}
	return "owned by no installed package"
}

func dropGap(gaps []finding.Gap, ruleID, subject string) []finding.Gap {
	out := gaps[:0]
	for _, g := range gaps {
		if g.RuleID == ruleID && g.Subject == subject {
			continue
		}
		out = append(out, g)
	}
	return out
}

// ResolveHookDirs returns the hook directories pacman would read, in ascending
// priority, together with the coverage gaps for whatever it could not determine.
//
// The list mirrors pacman's own construction rather than a convenient
// approximation of it:
//
//   - libalpm's compiled-in system directory is added unconditionally and is
//     therefore always first. It cannot be configured away.
//   - a HookDir in pacman.conf REPLACES the compiled-in admin directory. That is
//     pacman's behaviour (it defaults the list only when the configuration named
//     nothing), and inventing a directory pacman does not read would be a
//     different kind of wrong from missing one.
//   - HookDir may appear more than once, and may appear in an Included file,
//     because that is where an attacker would put one.
//
// Nothing here is expanded (INV-2). An Include this parser cannot pin to exactly
// one file is a gap, not a guess: the honest answer to "which directories does
// pacman read" is then "I do not fully know", and INV-9 requires that be said.
func ResolveHookDirs(src fsx.Source) ([]HookDir, []finding.Gap) {
	dirs := []HookDir{{Path: systemHookDir, Source: HookDirSourceSystem}}

	fromConf, gaps := hookDirsFromConf(src, pacmanConf, 0, map[string]bool{})
	if len(fromConf) == 0 {
		dirs = append(dirs, HookDir{Path: adminHookDir, Source: HookDirSourceAdmin})
		return dirs, gaps
	}
	seen := map[string]bool{systemHookDir: true}
	for _, p := range fromConf {
		if seen[p] {
			continue
		}
		seen[p] = true
		dirs = append(dirs, HookDir{Path: p, Source: HookDirSourceConfig})
	}
	return dirs, gaps
}

// hookDirsFromConf reads HookDir values out of one configuration file, following
// Include directives encountered inside [options].
//
// It reads only [options], because that is the only section in which a HookDir
// means anything; an Include reached from another section is left alone rather
// than followed, and a HookDir found outside [options] is not one pacman would
// honour.
func hookDirsFromConf(src fsx.Source, rel string, depth int, visited map[string]bool) ([]string, []finding.Gap) {
	var (
		out  []string
		gaps []finding.Gap
	)
	if depth > maxIncludeDepth {
		return nil, []finding.Gap{{
			RuleID:  RuleHookDirs,
			Subject: rel,
			Reason: fmt.Sprintf("pacman configuration includes nest more than %d deep; the rest was not read, "+
				"so a HookDir declared below this point would not be scanned", maxIncludeDepth),
		}}
	}
	if visited[rel] {
		// A cycle, not an error to report twice: the file has already been read
		// and its HookDirs are already in the list.
		return nil, nil
	}
	visited[rel] = true

	data, err := readConfined(src, rel)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			// No pacman.conf (or no such include) means the compiled-in
			// defaults apply. That is the ordinary case for an offline root
			// assembled from a package archive, and it is not a gap.
			return nil, nil
		}
		return nil, []finding.Gap{{
			RuleID:  RuleHookDirs,
			Subject: rel,
			Reason: fmt.Sprintf("pacman configuration could not be read (%v), so a HookDir declared there "+
				"is unknown and its hooks were not examined; the compiled-in directories were still scanned", err),
		}}
	}

	section := ""
	for _, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.Trim(line, "[]"))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		// An included file inherits the section it was included from, and
		// pacman's own included option fragments carry no [options] header of
		// their own -- so at depth > 0 an unsectioned line is an options line.
		inOptions := section == "options" || (section == "" && depth > 0)
		if !inOptions {
			continue
		}
		switch key {
		case "HookDir":
			p, gap := confPath(rel, "HookDir", val)
			if gap != nil {
				gaps = append(gaps, *gap)
				continue
			}
			out = append(out, p)
		case "Include":
			p, gap := confPath(rel, "Include", val)
			if gap != nil {
				gaps = append(gaps, *gap)
				continue
			}
			sub, subGaps := hookDirsFromConf(src, p, depth+1, visited)
			out = append(out, sub...)
			gaps = append(gaps, subGaps...)
		}
	}
	return out, gaps
}

// confMeta are the characters whose presence means a configuration value does
// not name one concrete path. This parser expands nothing, so a value carrying
// any of them yields a gap instead of a directory.
const confMeta = "*?[]{}$`"

// confPath turns a pacman.conf value into a root-relative path, or explains why
// it could not.
func confPath(inFile, key, val string) (string, *finding.Gap) {
	switch {
	case val == "":
		return "", &finding.Gap{
			RuleID:  RuleHookDirs,
			Subject: inFile,
			Reason:  fmt.Sprintf("%s in %s has an empty value, so the directory it names is unknown", key, inFile),
		}
	case strings.ContainsAny(val, confMeta):
		return "", &finding.Gap{
			RuleID:  RuleHookDirs,
			Subject: strings.TrimSuffix(strings.TrimPrefix(val, "/"), "/"),
			Reason: fmt.Sprintf("%s = %s (in %s) contains shell metacharacters; this parser does not expand "+
				"anything (INV-2), so the files it names were not read and a HookDir declared in them would "+
				"not be scanned", key, val, inFile),
		}
	case !strings.HasPrefix(val, "/"):
		return "", &finding.Gap{
			RuleID:  RuleHookDirs,
			Subject: inFile,
			Reason: fmt.Sprintf("%s = %s (in %s) is not an absolute path; resolving it against the process "+
				"working directory would be an ambient path (INV-4), so it was not scanned", key, val, inFile),
		}
	case strings.ContainsRune(val, 0):
		return "", &finding.Gap{
			RuleID:  RuleHookDirs,
			Subject: inFile,
			Reason:  fmt.Sprintf("%s in %s contains a NUL byte and was refused", key, inFile),
		}
	}
	p := strings.TrimSuffix(strings.TrimPrefix(path.Clean(val), "/"), "/")
	if p == "" || p == "." {
		return "", &finding.Gap{
			RuleID:  RuleHookDirs,
			Subject: inFile,
			Reason:  fmt.Sprintf("%s = %s (in %s) names the root itself and was refused", key, val, inFile),
		}
	}
	for _, c := range strings.Split(p, "/") {
		if c == ".." {
			return "", &finding.Gap{
				RuleID:  RuleHookDirs,
				Subject: inFile,
				Reason: fmt.Sprintf("%s = %s (in %s) has a %q component; normalising it away would be a "+
					"second interpretation of the path, so it was refused", key, val, inFile, ".."),
			}
		}
	}
	return p, nil
}

// readConfined reads a configuration file through the confined API, bounded.
// fsx.OpenConfined refuses a symlink leaf and anything that is not a regular
// file, so a pacman.conf replaced by a fifo is a gap rather than a hang.
func readConfined(src fsx.Source, rel string) ([]byte, error) {
	data, _, err := src.ReadFile(rel)
	if err != nil {
		return nil, err
	}
	if len(data) > maxConfBytes {
		return nil, fmt.Errorf("configuration file exceeds %d bytes", maxConfBytes)
	}
	return data, nil
}
