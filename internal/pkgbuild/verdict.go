// internal/pkgbuild/verdict.go
//
// The could-not-analyse verdict: INV-9 made concrete.
//
// Three outcomes exist for a recipe, and the third is why this file exists:
//
//	analysed, nothing found  -> clean          (the rules in internal/check)
//	analysed, something found -> finding       (the rules in internal/check)
//	COULD NOT BE ANALYSED    -> coverage gap   (here)
//
// A recipe that defeats the parser must produce a finding.Gap a user can act on
// -- "this recipe generates its package functions with eval; the generated
// bodies were not analysed" -- and must not produce silence, and must not
// produce a critical. Under INV-3 exit 3 outranks exit 1, so an unanalysable
// recipe must never report clean.
//
// Nothing here rates anything. eval is in 3 of 34 legitimate cached recipes and
// an external `source` in 1: a tool that called those suspicious would cry wolf
// on a tenth of the AUR. They are coverage, not evidence.
package pkgbuild

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
)

// Rule IDs for coverage gaps. They are stable identifiers: a suppression bound
// to one must keep meaning the same thing across releases.
const (
	RuleGeneratedCode    = "pkgbuild-generated-code"
	RuleExternalInclude  = "pkgbuild-external-include"
	RuleUnparsed         = "pkgbuild-unparsed"
	RuleUnresolvedValue  = "pkgbuild-unresolved-value"
	RuleGeneratedPackage = "pkgbuild-generated-package-function"
	RuleArchNotAnalysed  = "pkgbuild-arch-not-analysed"
	RuleNothingAnalysed  = "pkgbuild-nothing-analysed"
)

// maxGaps bounds the report. A crafted recipe with fifty thousand evals is one
// coverage problem, not fifty thousand, and an unbounded report is a denial of
// service against the person reading it.
const maxGaps = 24

// maxGapLines bounds how many line numbers one gap enumerates.
const maxGapLines = 12

// Verdict is what analysis could and could not establish about one recipe.
type Verdict struct {
	// Subject is the pkgbase (or the caller's identifier) every gap is attributed
	// to. Keyed on pkgbase, not pkgname: 433 of 1409 packages on the reference
	// system are split, and the recipe is the base's.
	Subject string
	// Gaps are the coverage gaps, in a stable order.
	Gaps []finding.Gap
	// Limits state what this analysis cannot prove even when it is complete
	// (INV-6). They are rendered in output, not left to documentation.
	Limits []string
}

// Complete reports whether the recipe was fully analysed. A caller deriving an
// exit code must treat false as exit 3 (INV-3): incomplete coverage outranks a
// clean sweep and must never be reported as one.
func (v Verdict) Complete() bool { return len(v.Gaps) == 0 }

// Assess derives the coverage verdict for one recipe from the tokeniser's notes
// and the resolver's unresolved values.
//
// subject is normally the pkgbase; when empty, the recipe's own pkgbase is used,
// falling back to its first pkgname.
func Assess(subject string, f File, r Resolution) Verdict {
	if subject == "" {
		subject = r.Pkgbase
	}
	v := Verdict{Subject: subject}
	add := func(rule, reason string) {
		if len(v.Gaps) >= maxGaps {
			return
		}
		if len(v.Gaps) == maxGaps-1 {
			v.Gaps = append(v.Gaps, finding.Gap{
				RuleID:  RuleUnparsed,
				Subject: subject,
				Reason: fmt.Sprintf("more than %d distinct coverage gaps were found in this recipe; "+
					"the list is truncated, so the analysis of this recipe should be treated as unusable rather than partial", maxGaps),
			})
			return
		}
		v.Gaps = append(v.Gaps, finding.Gap{RuleID: rule, Subject: subject, Reason: reason})
	}

	// 1. What the tokeniser could not read or could not follow.
	for _, gk := range groupNotes(f.Notes) {
		rule, reason := noteGap(gk)
		if rule == "" {
			continue
		}
		add(rule, reason)
	}

	// 2. Values that could not be resolved. Grouped by reason so that a recipe
	// with twenty sources built from one unknown mirror yields one gap.
	for _, g := range groupUnresolved(r) {
		add(RuleUnresolvedValue, g)
	}

	// 3. Split packages whose package functions are not in the text. This is the
	// measured floor of static bash analysis: zero cached PKGBUILDs contain a
	// literal package_*() although 31% of installed packages are split, because
	// the functions are generated. Treating them as ABSENT would report the
	// recipe clean while its actual package step was never read.
	if missing := missingPackageFunctions(f, r); len(missing) > 0 {
		reason := fmt.Sprintf("the recipe declares %d split packages but defines no package function for %s; "+
			"makepkg's package step for %s was not analysed",
			len(r.Pkgnames), quoteList(missing), plural(len(missing), "it", "them"))
		if f.Note(NoteEval) {
			reason += " (the recipe uses eval, which is how a PKGBUILD generates these functions at run time)"
		}
		add(RuleGeneratedPackage, reason)
	}

	// 4. Architectures the recipe declares that this run did not resolve. A
	// scoped review is legitimate; reporting it as a whole review is not.
	for _, arch := range declaredNotTargeted(r) {
		add(RuleArchNotAnalysed, fmt.Sprintf("the recipe declares architecture %s but this run resolved only %s; "+
			"the sources and checksums for %s were not examined",
			arch, quoteList(r.Targets), arch))
	}

	// 5. Nothing analysable at all. An empty file, a comment, or bytes that are
	// not a recipe must not read as a clean recipe.
	if nothingAnalysed(f, r) {
		add(RuleNothingAnalysed, "no package name, no sources and no build functions could be read from this file; "+
			"it was not analysed at all, which is not the same as having nothing to report")
	}

	v.Limits = limits(f, r)
	return v
}

// noteGap maps a group of tokeniser notes to a gap. Notes that are not coverage
// problems return an empty rule.
func noteGap(g noteGroup) (string, string) {
	where := lineList(g.lines)
	switch g.kind {
	case NoteEval:
		return RuleGeneratedCode, fmt.Sprintf("the recipe builds and runs code with eval (%s); "+
			"whatever it generates is not in the recipe text and was not analysed. "+
			"eval appears in 3 of 34 legitimate cached recipes, so this is a limit of static analysis, not a sign of malice", where)
	case NoteExternalSource:
		return RuleExternalInclude, fmt.Sprintf("the recipe sources an external file at build time (%s: %s); "+
			"that file is not part of the recipe and its contents were not analysed", where, g.detail)
	case NoteTruncated:
		return RuleUnparsed, fmt.Sprintf("the file is larger than this tool will read (%d bytes); "+
			"everything past that point was not analysed", maxInputBytes)
	case NoteUnterminatedQuote, NoteUnterminatedHeredoc, NoteUnterminatedSubstitution, NoteUnterminatedFunction:
		return RuleUnparsed, fmt.Sprintf("the recipe does not parse as bash (%s at %s); "+
			"what follows was read in the wrong context, so this analysis cannot be relied on", g.kind, where)
	case NoteLimit:
		return RuleUnparsed, fmt.Sprintf("a parser bound was reached (%s: %s); the rest of the construct was not read", where, g.detail)
	}
	return "", ""
}

type noteGroup struct {
	kind   NoteKind
	lines  []int
	detail string
	first  int
}

// groupNotes collapses notes of the same kind, preserving first-appearance
// order so the verdict is deterministic.
func groupNotes(notes []Note) []noteGroup {
	var (
		order []NoteKind
		by    = map[NoteKind]*noteGroup{}
	)
	for _, n := range notes {
		g, ok := by[n.Kind]
		if !ok {
			g = &noteGroup{kind: n.Kind, detail: n.Detail, first: n.Line}
			by[n.Kind] = g
			order = append(order, n.Kind)
		}
		if len(g.lines) < maxGapLines {
			g.lines = append(g.lines, n.Line)
		}
	}
	out := make([]noteGroup, 0, len(order))
	for _, k := range order {
		out = append(out, *by[k])
	}
	return out
}

// groupUnresolved collapses unresolved source values by reason, naming the
// source entries affected. A reason is stated once with its lines, because
// twenty sources built from one unknown variable are one problem.
func groupUnresolved(r Resolution) []string {
	type group struct {
		reason string
		where  []string
	}
	var (
		order []string
		by    = map[string]*group{}
	)
	for _, s := range r.Sources {
		vals := []struct {
			what string
			v    Value
		}{{"source entry", s.Value}}
		for _, in := range s.Integrity {
			vals = append(vals, struct {
				what string
				v    Value
			}{in.Algo + "sums entry", in.Value})
		}
		for _, item := range vals {
			if item.v.OK() {
				continue
			}
			g, ok := by[item.v.Reason]
			if !ok {
				g = &group{reason: item.v.Reason}
				by[item.v.Reason] = g
				order = append(order, item.v.Reason)
			}
			if len(g.where) < maxGapLines {
				label := fmt.Sprintf("%s %d", item.what, s.Index)
				if s.Arch != "" {
					label += " (" + s.Arch + ")"
				}
				g.where = append(g.where, label)
			}
		}
	}
	out := make([]string, 0, len(order))
	for _, reason := range order {
		g := by[reason]
		out = append(out, fmt.Sprintf("%s could not be resolved: %s. "+
			"No value is reported for it rather than a partly expanded one, so nothing downstream checked it",
			strings.Join(g.where, ", "), reason))
	}
	return out
}

// missingPackageFunctions returns the declared package names that have no
// package function in the text. It reports nothing for a single-package recipe
// (which uses package()) and nothing when every function is present.
func missingPackageFunctions(f File, r Resolution) []string {
	if len(r.Pkgnames) < 2 {
		return nil
	}
	var missing []string
	for _, n := range r.Pkgnames {
		if !n.OK() {
			// The name itself is unknown; the unresolved-value gap covers it.
			continue
		}
		if _, ok := f.Function("package_" + n.Text); !ok {
			if len(missing) < maxGapLines {
				missing = append(missing, n.Text)
			}
		}
	}
	// A split recipe with a single package() is unusual but legal; makepkg would
	// apply it to every split package, and it IS in the text, so it is analysed.
	if _, ok := f.Function("package"); ok && len(missing) == len(r.Pkgnames) {
		return nil
	}
	return missing
}

// declaredNotTargeted lists architectures the recipe declares that this run did
// not resolve.
func declaredNotTargeted(r Resolution) []string {
	if len(r.Arches) == 0 {
		return nil
	}
	targeted := map[string]bool{}
	for _, t := range r.Targets {
		targeted[t] = true
	}
	var out []string
	for _, a := range r.Arches {
		if a == "any" || targeted[a] {
			continue
		}
		// Only a real blind spot if the recipe actually keys sources on it.
		out = append(out, a)
	}
	sort.Strings(out)
	return out
}

// nothingAnalysed reports a file from which nothing that describes a package
// could be read. Stray commands do not count: a file of NUL bytes tokenises to
// a "command" and describes no package, and calling that clean would be the
// false clean INV-3 exists to prevent.
func nothingAnalysed(f File, r Resolution) bool {
	return r.Pkgbase == "" && len(r.Sources) == 0 && len(f.Functions) == 0
}

// limits states, in output, what this analysis cannot prove even when it found
// nothing (INV-6).
func limits(f File, r Resolution) []string {
	out := []string{
		"the recipe was read as text and never executed, so a build step that computes what it runs " +
			"(from a fetched file, an environment variable, or makepkg.conf) is outside what this analysis can see",
	}
	if len(r.Targets) > 0 {
		out = append(out, "sources were resolved for architecture(s) "+quoteList(r.Targets))
	} else if len(r.Sources) > 0 {
		out = append(out, "the recipe declares no architecture suffix, so its sources apply to every architecture")
	}
	if r.PkgverDynamic {
		out = append(out, "pkgver() computes the version at build time, so anything built from $pkgver "+
			"describes the recipe as written and not necessarily what a build will fetch")
	}
	if len(f.Heredocs) > 0 {
		out = append(out, fmt.Sprintf("%d here-document(s) were read as data, not as commands; "+
			"a script the recipe WRITES is analysed as file content, not as a build step", len(f.Heredocs)))
	}
	if n := substCommands(f); n > 0 {
		out = append(out, fmt.Sprintf("%d command(s) appear inside command substitutions; their text was analysed "+
			"but the values they produce were not resolved", n))
	}
	return out
}

func substCommands(f File) int {
	var n int
	for _, c := range f.Commands {
		if c.SubstDepth > 0 {
			n++
		}
	}
	return n
}

func lineList(lines []int) string {
	if len(lines) == 0 {
		return "line unknown"
	}
	parts := make([]string, 0, len(lines))
	for _, l := range lines {
		parts = append(parts, fmt.Sprint(l))
	}
	if len(lines) == 1 {
		return "line " + parts[0]
	}
	return "lines " + strings.Join(parts, ", ")
}

func quoteList(items []string) string {
	if len(items) == 0 {
		return "none"
	}
	return strings.Join(items, ", ")
}

func plural(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
