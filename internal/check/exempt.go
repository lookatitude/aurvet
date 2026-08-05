// internal/check/exempt.go
//
// Mutable-file exemptions, DERIVED rather than hand-maintained.
//
// Some packaged files legitimately differ from their recorded digest on every
// system: pacman's own hooks rewrite them after the transaction that installed
// them, and %BACKUP% marks the configuration files pacman expects the
// administrator to edit. `pacman -Qkk` already exempts %BACKUP%; nothing here
// claims that half as new. What this file adds is the other half, computed from
// what is actually installed: the hook set on THIS system, parsed, with the
// output paths its Exec lines name.
//
// The derivation matters more than the coverage it buys. A hand-written list of
// "files that always differ" rots silently: a hook that is removed upstream
// leaves an entry behind, and every stale entry is a permanent blind spot in a
// tool whose whole value is that its silence means something. A derived set
// shrinks when the system does.
//
// Parsing what pacman ships is internal/hook's job; deciding what that implies
// for verification is this file's. INV-2 holds across the seam: hook Exec lines
// are TOKENISED, never executed, and the tokeniser is deliberately incapable of
// expansion -- a token carrying a glob, a brace or a variable yields no
// exemption at all, because an exemption we cannot pin to one concrete path is
// a hole of unknown size.
package check

import (
	"fmt"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/hook"
	"github.com/lookatitude/aurvet/internal/mtree"
)

// Exemption records one exempted path and why it is exempt. The reason is
// carried, not implied: an exemption is a deliberate hole in coverage, and a
// hole nobody can enumerate is indistinguishable from a bug.
type Exemption struct {
	Path   string // root-relative, no leading "/" or "./"
	Reason string
	Source string // "hook:<file>" or "backup:<package>"
}

// Exemptions is the derived set. The zero value is usable and exempts nothing,
// which is the correct default for a caller that failed to derive anything.
type Exemptions struct {
	byPath map[string]Exemption
}

// DeriveExemptions computes the exempt set from the installed hooks and the
// installed packages' %BACKUP% lists. It is a pure function of its inputs
// (INV-4): no filesystem access, no ambient state.
func DeriveExemptions(hooks []hook.Hook, pkgs []alpm.Package) Exemptions {
	ex := Exemptions{byPath: map[string]Exemption{}}
	for _, h := range hooks {
		if h.Exec == "" {
			continue
		}
		when := h.When
		if when == "" {
			when = "unspecified"
		}
		for _, lit := range hook.ExecPathLiterals(h.Exec) {
			p, ok := normalizeExemptPath(lit)
			if !ok {
				continue
			}
			ex.add(Exemption{
				Path: p,
				Reason: fmt.Sprintf("named as an output path by installed pacman hook %s (%s); "+
					"pacman regenerates it after transactions", h.Name, when),
				Source: "hook:" + h.Name,
			})
		}
	}
	// Sorted so the derivation is reproducible when two packages back the same
	// path -- first writer wins, and which one that is must not depend on map
	// iteration order.
	names := make([]string, 0, len(pkgs))
	idx := map[string]int{}
	for i, p := range pkgs {
		names = append(names, p.Name)
		idx[p.Name] = i
	}
	sort.Strings(names)
	for _, name := range names {
		p := pkgs[idx[name]]
		backups := make([]string, 0, len(p.Backup))
		for b := range p.Backup {
			backups = append(backups, b)
		}
		sort.Strings(backups)
		for _, b := range backups {
			pp, ok := normalizeExemptPath(b)
			if !ok {
				continue
			}
			ex.add(Exemption{
				Path: pp,
				Reason: fmt.Sprintf("listed in %%BACKUP%% of package %s; pacman itself expects "+
					"local modification of this file", p.Name),
				Source: "backup:" + p.Name,
			})
		}
	}
	return ex
}

func (e *Exemptions) add(x Exemption) {
	if e.byPath == nil {
		e.byPath = map[string]Exemption{}
	}
	if _, seen := e.byPath[x.Path]; seen {
		return
	}
	e.byPath[x.Path] = x
}

// Lookup reports the exemption for a root-relative path, accepting either the
// "./usr/..." form mtree records or a bare "usr/...".
func (e Exemptions) Lookup(p string) (Exemption, bool) {
	n, ok := normalizeExemptPath(p)
	if !ok {
		return Exemption{}, false
	}
	x, ok := e.byPath[n]
	return x, ok
}

// Applies reports the exemption covering one mtree entry.
//
// It is deliberately stricter than Lookup: an entry the PACKAGE ITSELF records
// as executable is never exempt, whatever the derivation said. The paths
// pacman's hooks regenerate are caches and databases, never executables, so
// this costs no measurable coverage -- and it is the second line of defence
// behind the command-position rule in hook.ExecPathLiterals. If a hostile or
// merely odd hook ever named a binary as an argument, the effect would otherwise
// be to take that binary out of digest verification entirely, which is a far
// worse outcome than the noise the exemption was meant to suppress.
//
// A hook-named DIRECTORY does not exempt the files inside it. That is a measured
// decision, and it was RATIFIED rather than merely left alone (lead ruling,
// 2026-08-05): an exemption trades permanent, silent coverage loss for a finding
// that is visible and adjudicable, and an exemption must stay DERIVED from what
// pacman itself regenerates -- hook Target/Exec pairs plus %BACKUP% -- never
// chosen as a pattern that happens to quiet a rule. A prefix match is the
// latter, and it is the same move as downgrading a severity to make a noisy rule
// agreeable, applied to coverage instead of to severity.
//
// The numbers behind that ruling: seven of the derived exemptions on the
// reference system are directories a hook regenerates content in (notably
// usr/share/mime, usr/share/glib-2.0/schemas and usr/lib/vlc/plugins).
// Extending the match to their contents would exempt 168 of 458,724 recorded
// entries -- 151 of them the .gschema.xml files glib-compile-schemas READS
// rather than writes -- to silence exactly one finding
// (usr/lib/vlc/plugins/plugins.dat). So the exemption keys stay exact paths.
// The remaining false positive is recorded rather than engineered away; the rule
// that would fix it properly derives outputs from Target/Exec pairs and is a
// followup, not a widened prefix.
func (e Exemptions) Applies(ent mtree.Entry) (Exemption, bool) {
	if ent.Mode&0o7111 != 0 {
		return Exemption{}, false
	}
	return e.Lookup(ent.Path)
}

// Len reports how many paths are exempt.
func (e Exemptions) Len() int { return len(e.byPath) }

// All returns the exemptions sorted by path, so `explain` and `doctor` can
// print the entire hole in coverage rather than describing it.
func (e Exemptions) All() []Exemption {
	out := make([]Exemption, 0, len(e.byPath))
	for _, x := range e.byPath {
		out = append(out, x)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].Path < out[j].Path })
	return out
}

// normalizeExemptPath reduces the several spellings of one path to a single
// key: "/etc/ld.so.cache" from a hook Exec, "etc/pacman.conf" from %BACKUP%
// and "./etc/ld.so.cache" from an mtree record all become "etc/ld.so.cache".
//
// A path containing a ".." component is refused rather than cleaned. Cleaning
// is a second interpretation of a path, and the only thing an exemption key can
// do with a ".." is name a file other than the one the reader thinks it names.
func normalizeExemptPath(p string) (string, bool) {
	if p == "" || strings.ContainsRune(p, 0) {
		return "", false
	}
	p = strings.TrimPrefix(p, "./")
	p = strings.TrimPrefix(p, "/")
	p = strings.TrimSuffix(p, "/")
	if p == "" || p == "." {
		return "", false
	}
	for _, part := range strings.Split(p, "/") {
		switch part {
		case "", ".", "..":
			return "", false
		}
	}
	return p, true
}
