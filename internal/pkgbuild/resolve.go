// internal/pkgbuild/resolve.go
//
// Variable and parameter-expansion resolution, performed by SUBSTITUTING TEXT
// (INV-2). Nothing here runs a shell, so anything the recipe computes is
// admitted as Unresolvable rather than guessed at.
//
// Two decisions are load-bearing enough to state up front.
//
//  1. Every value is Resolved or Unresolvable, and an Unresolvable value carries
//     NO text. A half-expanded URL -- "https://${host}/x.tar.gz" rendered as
//     "https:///x.tar.gz" -- looks analysable, passes a host check, and is a lie.
//     Resolution therefore fails whole values, never partially.
//
//  2. The target architecture is a PARAMETER, never runtime.GOARCH. 10 of 34
//     cached recipes carry their real sources in source_x86_64 / source_aarch64
//     (a 29% blind spot if unhandled), and a scanner that reads only the running
//     machine's suffix cannot review an aarch64-only payload from an x86_64
//     host. The default is EVERY architecture the recipe declares, which is the
//     only default under which "the sources were reviewed" is true.
package pkgbuild

import (
	"fmt"
	"strings"
)

// maxValueBytes bounds one resolved value. Pattern operators are quadratic in
// the value length in the worst case, so the bound is what keeps a crafted
// recipe from turning resolution into a hang. The longest source URL in the
// measured corpus is 158 bytes.
const (
	maxValueBytes = 8 << 10
	maxPatternLen = 1 << 10
	// maxSources bounds the emitted source list across all architectures.
	maxSources = 4096
)

// Status is a resolution outcome. There are two, deliberately: a third
// ("partially resolved") would be a value a caller could mistake for a fact.
type Status string

const (
	Resolved     Status = "resolved"
	Unresolvable Status = "unresolvable"
)

// Value is one resolved -- or explicitly unresolved -- string.
type Value struct {
	// Raw is the text as written, always present, so a report can quote what
	// the recipe actually says even when nothing could be made of it.
	Raw string
	// Text is the resolved value. It is EMPTY unless Status is Resolved.
	Text   string
	Status Status
	// Reason states what defeated resolution, in terms a user can act on
	// (INV-6). Empty when Status is Resolved.
	Reason string
	Line   int
}

// OK reports whether the value resolved.
func (v Value) OK() bool { return v.Status == Resolved }

// Var is a resolved variable: a scalar is an array of one.
type Var struct {
	Name   string
	Array  bool
	Values []Value
	Line   int
}

// Integrity is one checksum paired positionally with a source entry. Absent
// integrity is an empty slice, never a zero value that could read as a pass.
type Integrity struct {
	Algo  string
	Value Value
	// Skip records the literal SKIP. Mandatory for VCS sources and a finding on
	// a fixed URL -- which is a distinction only the paired Source can make, so
	// this type records the fact and rates nothing.
	Skip bool
}

// Source is one entry of a source array, parsed as far as text allows.
type Source struct {
	// Arch is "" for an entry from the unsuffixed source array (applying to
	// every architecture) or the suffix it came from.
	Arch  string
	Index int
	// Value is the whole entry. When it is Unresolvable, every derived field
	// below is empty: there is nothing to derive from a string we do not have.
	Value Value
	// Name is the local file name makepkg will use: the rename:: prefix, or the
	// URL's last path element, or the literal for a local file.
	Name string
	// URL is the fetch URL with any VCS prefix and fragment removed. Empty for a
	// local file.
	URL      string
	Scheme   string
	Host     string
	VCS      string // git, hg, svn, bzr, fossil; "" for a plain fetch
	Fragment string
	// Local marks an entry that names a file shipped beside the PKGBUILD rather
	// than something fetched.
	Local     bool
	Integrity []Integrity
}

// ResolveConfig parameterises resolution. It exists so that architecture and
// nothing else varies between runs (INV-4): no environment, no CWD, no GOARCH.
type ResolveConfig struct {
	// Arches limits the analysis to these architecture suffixes. Empty -- the
	// default -- means every architecture the recipe declares, because a review
	// that skips the aarch64 sources has not reviewed the recipe.
	Arches []string
}

// Resolution is the resolved view of a recipe.
type Resolution struct {
	Pkgbase  string
	Pkgnames []Value
	// Arches are the architectures the recipe declares in arch=().
	Arches []string
	// Targets are the architecture suffixes this resolution actually looked at.
	Targets []string
	Vars    map[string]Var
	Sources []Source
	// PkgverDynamic records that a pkgver() function computes the version at
	// build time, so the declared pkgver is a stale placeholder and anything
	// built from it is not knowable from the text.
	PkgverDynamic bool
	// Unresolved lists every value that could not be resolved, in source order.
	// verdict.go turns these into coverage gaps (INV-9).
	Unresolved []Value
}

// sumAlgos are makepkg's integrity arrays, longest name first so that matching
// is unambiguous.
var sumAlgos = []string{"sha512", "sha384", "sha256", "sha224", "sha1", "md5", "b2", "ck"}

// Resolve substitutes what can be substituted from the recipe's own text.
//
// It is a pure function of (File, ResolveConfig). Nothing is executed, no
// process environment is read, and no value is emitted half-expanded.
func Resolve(f File, cfg ResolveConfig) Resolution {
	r := Resolution{Vars: map[string]Var{}}
	r.PkgverDynamic = false
	if _, ok := f.Function("pkgver"); ok {
		r.PkgverDynamic = true
	}

	// Declared architectures, then the targets to analyse.
	r.Arches = declaredArches(f)
	r.Targets = targets(f, cfg, r.Arches)

	// The arch-independent pass populates Vars and the unsuffixed sources. CARCH
	// is unknown here: an entry that depends on it is architecture-specific by
	// definition and is resolved in the per-target passes below.
	env := newEnv("")
	r.Vars = env.build(f, r.PkgverDynamic)

	r.Pkgnames = env.list("pkgname")
	r.Pkgbase = firstText(env.list("pkgbase"))
	if r.Pkgbase == "" {
		r.Pkgbase = firstText(r.Pkgnames)
	}

	r.Sources = append(r.Sources, sourcesFor(f, env, "")...)
	for _, arch := range r.Targets {
		archEnv := newEnv(arch)
		archEnv.build(f, r.PkgverDynamic)
		r.Sources = append(r.Sources, sourcesFor(f, archEnv, arch)...)
	}
	if len(r.Sources) > maxSources {
		r.Sources = r.Sources[:maxSources]
	}

	for _, s := range r.Sources {
		if !s.Value.OK() {
			r.Unresolved = append(r.Unresolved, s.Value)
		}
		for _, in := range s.Integrity {
			if !in.Value.OK() {
				r.Unresolved = append(r.Unresolved, in.Value)
			}
		}
	}
	return r
}

// declaredArches reads arch=(), dropping "any" (which declares no suffix).
func declaredArches(f File) []string {
	a, ok := f.Assign("arch")
	if !ok {
		return nil
	}
	var out []string
	for _, w := range a.Values {
		lit, ok := w.Literal()
		if !ok || lit == "" || lit == "any" {
			continue
		}
		out = append(out, lit)
	}
	return out
}

// targets decides which architecture suffixes to resolve. Configured arches win
// outright; otherwise every architecture the recipe declares, plus any suffix it
// actually assigns to (a recipe with source_aarch64 but no arch=() entry for it
// is malformed, and skipping the suffix would be the worse of the two errors).
func targets(f File, cfg ResolveConfig, declared []string) []string {
	seen := map[string]bool{}
	var out []string
	add := func(a string) {
		if a == "" || a == "any" || seen[a] {
			return
		}
		seen[a] = true
		out = append(out, a)
	}
	if len(cfg.Arches) > 0 {
		for _, a := range cfg.Arches {
			add(a)
		}
		return out
	}
	for _, a := range declared {
		add(a)
	}
	for _, as := range f.Assignments {
		if as.Func == "" && as.Arch != "" {
			add(as.Arch)
		}
	}
	return out
}

func firstText(vs []Value) string {
	for _, v := range vs {
		if v.OK() {
			return v.Text
		}
	}
	return ""
}

// env holds the variables resolved so far. It is built strictly in source order,
// because that is what bash would see: a value can only refer to what is already
// assigned above it.
type env struct {
	vars  map[string]Var
	carch string
}

func newEnv(carch string) *env {
	e := &env{vars: map[string]Var{}, carch: carch}
	return e
}

// build walks the top-level assignments in order and resolves each one against
// what came before it. Assignments inside a function are locals and are
// deliberately ignored: a `source=` inside build() is not a declaration.
func (e *env) build(f File, pkgverDynamic bool) map[string]Var {
	if e.carch != "" {
		e.vars["CARCH"] = Var{Name: "CARCH", Values: []Value{{Raw: e.carch, Text: e.carch, Status: Resolved}}}
	}
	for _, a := range f.Assignments {
		if a.Func != "" {
			continue
		}
		vals := make([]Value, 0, len(a.Values))
		for _, w := range a.Values {
			vals = append(vals, e.expand(w))
		}
		if pkgverDynamic && a.Name == "pkgver" {
			// A pkgver() function recomputes this at build time, so whatever the
			// text says is a placeholder. Refusing it here is what makes every
			// URL built from it Unresolvable instead of stale-but-plausible.
			for i := range vals {
				vals[i] = Value{Raw: vals[i].Raw, Status: Unresolvable, Line: a.Line,
					Reason: "pkgver is computed at build time by a pkgver() function, so the declared value is a placeholder"}
			}
		}
		cur, exists := e.vars[a.Name]
		switch {
		case a.Append && exists && cur.Array:
			cur.Values = append(cur.Values, vals...)
			cur.Array = cur.Array || a.Array
			e.vars[a.Name] = cur
		case a.Append && exists && !cur.Array && len(vals) == 1 && len(cur.Values) == 1:
			e.vars[a.Name] = Var{Name: a.Name, Line: cur.Line, Values: []Value{concat(cur.Values[0], vals[0])}}
		default:
			e.vars[a.Name] = Var{Name: a.Name, Array: a.Array, Values: vals, Line: a.Line}
		}
	}
	return e.vars
}

// concat joins two scalar values, failing whole if either half is unknown.
func concat(a, b Value) Value {
	out := Value{Raw: a.Raw + b.Raw, Line: a.Line, Status: Resolved}
	if !a.OK() {
		return Value{Raw: out.Raw, Line: a.Line, Status: Unresolvable, Reason: a.Reason}
	}
	if !b.OK() {
		return Value{Raw: out.Raw, Line: a.Line, Status: Unresolvable, Reason: b.Reason}
	}
	out.Text = a.Text + b.Text
	return out
}

func (e *env) list(name string) []Value {
	return e.vars[name].Values
}

// expand resolves one word. It returns Unresolvable, with no text, the moment
// any segment cannot be pinned down.
func (e *env) expand(w Word) Value {
	out := Value{Raw: w.Raw, Line: w.Line, Status: Resolved}
	var b strings.Builder
	for _, s := range w.Segs {
		if b.Len() > maxValueBytes {
			return unresolvable(w, fmt.Sprintf("the value is longer than %d bytes and was not resolved", maxValueBytes))
		}
		switch s.Kind {
		case SegLiteral:
			b.WriteString(s.Text)
		case SegCommandSub:
			return unresolvable(w, "the value is built by a command substitution, which this tool will not run")
		case SegArith:
			return unresolvable(w, "the value is built by an arithmetic expansion, which this tool does not evaluate")
		case SegVar:
			txt, err := e.expandVar(s)
			if err != "" {
				return unresolvable(w, err)
			}
			b.WriteString(txt)
		}
	}
	if b.Len() > maxValueBytes {
		return unresolvable(w, fmt.Sprintf("the value is longer than %d bytes and was not resolved", maxValueBytes))
	}
	out.Text = b.String()
	return out
}

func unresolvable(w Word, reason string) Value {
	return Value{Raw: w.Raw, Line: w.Line, Status: Unresolvable, Reason: reason}
}

// expandVar resolves one ${...}. It returns the text, or a reason it could not.
func (e *env) expandVar(s Segment) (string, string) {
	// Variables makepkg sets that name build directories. They are real paths at
	// build time and unknowable here; a rule about writes outside $pkgdir works
	// on the unexpanded form, so refusing them is correct rather than limiting.
	switch s.Var {
	case "srcdir", "pkgdir", "startdir", "BUILDDIR", "SRCDEST", "PKGDEST":
		return "", fmt.Sprintf("$%s is a build-time directory, never assigned in the recipe", s.Var)
	}
	v, ok := e.vars[s.Var]
	if !ok {
		// An unset variable is EMPTY to bash, and expanding it as such is how
		// "https://${host}/x" becomes the plausible-looking lie "https:///x".
		// The one exception is an operator whose whole job is the unset case:
		// ${undef:-fallback} is a value the recipe states outright.
		switch s.Op {
		case ":-", ":=", ":+":
			return applyOp(s, "")
		}
		return "", fmt.Sprintf("$%s is never assigned in the recipe (it may come from the environment, makepkg.conf, or a sourced file)", s.Var)
	}
	// Pick the element the expansion asks for.
	var base Value
	switch s.Index {
	case "":
		if len(v.Values) == 0 {
			base = Value{Status: Resolved}
			break
		}
		base = v.Values[0]
	case "@", "*":
		var parts []string
		for _, el := range v.Values {
			if !el.OK() {
				return "", fmt.Sprintf("${%s[@]} contains a value that could not be resolved: %s", s.Var, el.Reason)
			}
			parts = append(parts, el.Text)
		}
		base = Value{Status: Resolved, Text: strings.Join(parts, " ")}
	default:
		idx, err := atoiBounded(s.Index)
		if err != "" {
			return "", fmt.Sprintf("array index %q of $%s is not a plain number, so the element is unknown", s.Index, s.Var)
		}
		if idx < 0 || idx >= len(v.Values) {
			return "", fmt.Sprintf("array index %d of $%s is out of range (%d elements)", idx, s.Var, len(v.Values))
		}
		base = v.Values[idx]
	}
	if !base.OK() {
		return "", fmt.Sprintf("$%s could not be resolved: %s", s.Var, base.Reason)
	}
	return applyOp(s, base.Text)
}

// atoiBounded parses a small non-negative integer without importing surprises.
func atoiBounded(s string) (int, string) {
	if s == "" || len(s) > 6 {
		return 0, "not a number"
	}
	n := 0
	for i := 0; i < len(s); i++ {
		if s[i] < '0' || s[i] > '9' {
			return 0, "not a number"
		}
		n = n*10 + int(s[i]-'0')
	}
	return n, ""
}

// applyOp performs the parameter-expansion operator textually. The operators
// implemented are the ones the measured corpus uses; everything else is
// Unresolvable rather than approximated, because an approximated URL is the
// failure mode this package exists to avoid.
func applyOp(s Segment, val string) (string, string) {
	if s.Op == "" {
		return val, ""
	}
	if len(s.Arg) > maxPatternLen {
		return "", fmt.Sprintf("the ${%s%s...} operand is longer than %d bytes and was not applied", s.Var, s.Op, maxPatternLen)
	}
	switch s.Op {
	case "//", "/":
		pat, rep, hasRep := cutUnescaped(s.Arg, '/')
		if !hasRep {
			rep = ""
		}
		if strings.HasPrefix(pat, "#") || strings.HasPrefix(pat, "%") {
			// Anchored replacement. Applying it as an unanchored pattern would
			// silently produce the wrong string.
			return "", fmt.Sprintf("the anchored substitution ${%s%s%s} is not supported", s.Var, s.Op, s.Arg)
		}
		if len(val) > maxValueBytes {
			return "", fmt.Sprintf("the value is longer than %d bytes and was not resolved", maxValueBytes)
		}
		return substitute(val, pat, rep, s.Op == "//"), ""
	case "#", "##":
		return stripPrefix(val, s.Arg, s.Op == "##"), ""
	case "%", "%%":
		return stripSuffix(val, s.Arg, s.Op == "%%"), ""
	case ":-", ":=":
		if val != "" {
			return val, ""
		}
		if strings.ContainsAny(s.Arg, "$`") {
			return "", fmt.Sprintf("the default in ${%s%s%s} is itself expanded and was not resolved", s.Var, s.Op, s.Arg)
		}
		return s.Arg, ""
	case ":+":
		if val == "" {
			return "", ""
		}
		if strings.ContainsAny(s.Arg, "$`") {
			return "", fmt.Sprintf("the alternate in ${%s%s%s} is itself expanded and was not resolved", s.Var, s.Op, s.Arg)
		}
		return s.Arg, ""
	case "^^":
		return strings.ToUpper(val), ""
	case ",,":
		return strings.ToLower(val), ""
	case "^":
		return upperFirst(val), ""
	case ",":
		return lowerFirst(val), ""
	case ":":
		off, length, hasLen := cutUnescaped(s.Arg, ':')
		// ${v::1} omits the offset, meaning 0. hyprshade builds its PyPI URL
		// that way (${pkgname::1}), so the empty offset is the corpus's, not a
		// hypothetical.
		if strings.TrimSpace(off) == "" {
			off = "0"
		}
		i, err := atoiBounded(strings.TrimSpace(off))
		if err != "" || i > len(val) {
			return "", fmt.Sprintf("the substring offset in ${%s:%s} is not a plain number in range", s.Var, s.Arg)
		}
		out := val[i:]
		if hasLen {
			n, err := atoiBounded(strings.TrimSpace(length))
			if err != "" || n > len(out) {
				return "", fmt.Sprintf("the substring length in ${%s:%s} is not a plain number in range", s.Var, s.Arg)
			}
			out = out[:n]
		}
		return out, ""
	case "#len":
		return "", fmt.Sprintf("${#%s} is a length; this tool does not compute one", s.Var)
	case "!":
		return "", fmt.Sprintf("${!%s} is an indirect expansion, which cannot be resolved without evaluating", s.Var)
	case ":?":
		return "", fmt.Sprintf("${%s:?} aborts the build when unset; the value is not determined by the text", s.Var)
	}
	return "", fmt.Sprintf("the parameter expansion ${%s%s%s} is not supported and was not approximated", s.Var, s.Op, s.Arg)
}

func upperFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToUpper(s[:1]) + s[1:]
}

func lowerFirst(s string) string {
	if s == "" {
		return s
	}
	return strings.ToLower(s[:1]) + s[1:]
}

// cutUnescaped splits on the first unescaped occurrence of sep.
func cutUnescaped(s string, sep byte) (before, after string, found bool) {
	for i := 0; i < len(s); i++ {
		if s[i] == '\\' {
			i++
			continue
		}
		if s[i] == sep {
			return s[:i], s[i+1:], true
		}
	}
	return s, "", false
}

// substitute replaces glob-pattern matches in val. all=false replaces only the
// first, matching ${v/p/r}; all=true matches ${v//p/r}. Bounded by
// maxValueBytes at the call site.
func substitute(val, pat, rep string, all bool) string {
	if pat == "" {
		return val
	}
	if !hasGlobMeta(pat) {
		if all {
			return strings.ReplaceAll(val, pat, rep)
		}
		return strings.Replace(val, pat, rep, 1)
	}
	var b strings.Builder
	for i := 0; i < len(val); {
		// Bash takes the longest match at each position.
		end := -1
		for j := len(val); j >= i; j-- {
			if globMatch(pat, val[i:j]) {
				end = j
				break
			}
		}
		if end > i {
			b.WriteString(rep)
			i = end
			if !all {
				b.WriteString(val[i:])
				return b.String()
			}
			continue
		}
		b.WriteByte(val[i])
		i++
	}
	return b.String()
}

// stripPrefix implements ${v#pat} and ${v##pat}.
func stripPrefix(val, pat string, longest bool) string {
	if pat == "" {
		return val
	}
	if longest {
		for i := len(val); i >= 0; i-- {
			if globMatch(pat, val[:i]) {
				return val[i:]
			}
		}
		return val
	}
	for i := 0; i <= len(val); i++ {
		if globMatch(pat, val[:i]) {
			return val[i:]
		}
	}
	return val
}

// stripSuffix implements ${v%pat} and ${v%%pat}.
func stripSuffix(val, pat string, longest bool) string {
	if pat == "" {
		return val
	}
	if longest {
		for i := 0; i <= len(val); i++ {
			if globMatch(pat, val[i:]) {
				return val[:i]
			}
		}
		return val
	}
	for i := len(val); i >= 0; i-- {
		if globMatch(pat, val[i:]) {
			return val[:i]
		}
	}
	return val
}

func hasGlobMeta(pat string) bool { return strings.ContainsAny(pat, "*?[") }

// globMatch matches a bash filename-style pattern against a whole string. It is
// iterative with a single backtrack point -- no recursion, so no stack to blow
// on a crafted pattern, and linear-ish rather than exponential on `a*a*a*a*`.
func globMatch(pat, s string) bool {
	var (
		p, i       int
		star       = -1
		starMatch  int
		iterations int
	)
	const maxIterations = 1 << 20
	for i < len(s) {
		if iterations++; iterations > maxIterations {
			return false
		}
		switch {
		case p < len(pat) && pat[p] == '\\' && p+1 < len(pat):
			if pat[p+1] == s[i] {
				p += 2
				i++
				continue
			}
		case p < len(pat) && pat[p] == '*':
			star = p
			p++
			starMatch = i
			continue
		case p < len(pat) && pat[p] == '?':
			p++
			i++
			continue
		case p < len(pat) && pat[p] == '[':
			if n, ok := matchClass(pat[p:], s[i]); ok {
				p += n
				i++
				continue
			}
		case p < len(pat) && pat[p] == s[i]:
			p++
			i++
			continue
		}
		if star >= 0 {
			p = star + 1
			starMatch++
			i = starMatch
			continue
		}
		return false
	}
	for p < len(pat) && pat[p] == '*' {
		p++
	}
	return p == len(pat)
}

// matchClass matches one [...] bracket expression against a byte, returning the
// pattern length consumed.
func matchClass(pat string, c byte) (int, bool) {
	if len(pat) < 2 {
		return 0, false
	}
	i := 1
	negate := false
	if pat[i] == '!' || pat[i] == '^' {
		negate = true
		i++
	}
	matched := false
	first := true
	for i < len(pat) {
		if pat[i] == ']' && !first {
			i++
			if negate {
				return i, !matched
			}
			return i, matched
		}
		first = false
		if i+2 < len(pat) && pat[i+1] == '-' && pat[i+2] != ']' {
			if c >= pat[i] && c <= pat[i+2] {
				matched = true
			}
			i += 3
			continue
		}
		if pat[i] == c {
			matched = true
		}
		i++
	}
	// Unterminated class: not a match, and not an error worth failing over.
	return 0, false
}

// sourcesFor resolves the source array for one architecture group, pairing each
// entry with the checksums declared for the same group.
//
// The unsuffixed array is emitted once, under Arch "", rather than repeated per
// architecture: makepkg's effective list for arch T is (source ∪ source_T), and
// duplicating the shared half would double-count every finding against it.
func sourcesFor(f File, e *env, arch string) []Source {
	entries := arrayFor(f, e, "source", arch)
	if len(entries) == 0 {
		return nil
	}
	sums := map[string][]Value{}
	for _, algo := range sumAlgos {
		if vs := arrayFor(f, e, algo+"sums", arch); len(vs) > 0 {
			sums[algo] = vs
		}
	}
	out := make([]Source, 0, len(entries))
	for i, v := range entries {
		s := Source{Arch: arch, Index: i, Value: v}
		if v.OK() {
			parseSourceEntry(&s, v.Text)
		}
		for _, algo := range sumAlgos {
			vs, ok := sums[algo]
			if !ok || i >= len(vs) {
				// A sums array shorter than the source array leaves this entry
				// with no integrity at all. Reported by absence; inventing one
				// would report an unverified download as verified.
				continue
			}
			s.Integrity = append(s.Integrity, Integrity{
				Algo:  algo,
				Value: vs[i],
				Skip:  vs[i].OK() && strings.EqualFold(vs[i].Text, "SKIP"),
			})
		}
		out = append(out, s)
	}
	return out
}

// arrayFor collects the values of base (+= folded in) for one architecture
// group, in declaration order.
func arrayFor(f File, e *env, base, arch string) []Value {
	name := base
	if arch != "" {
		name = base + "_" + arch
	}
	v, ok := e.vars[name]
	if !ok {
		return nil
	}
	return v.Values
}

// vcsPrefixes are makepkg's VCS source protocols.
var vcsPrefixes = []string{"git", "hg", "svn", "bzr", "fossil"}

// parseSourceEntry splits `name::proto+url#fragment` without fetching anything.
//
// The "::" cut is on the FIRST occurrence, deliberately, and it must stay that
// way even though it mis-splits a URL carrying an IPv6 literal:
// "http://[2001:db8::1]/x.tar.gz" yields the name "http://[2001:db8" and the
// remainder "1]/x.tar.gz". That looks like a bug worth fixing. It is not.
//
// makepkg's own get_filename (/usr/share/makepkg/util/source.sh) is:
//
//	if [[ $netfile = *::* ]]; then printf "%s\n" "${netfile%%::*}"
//
// which is the same first-occurrence cut and produces the same two halves --
// verified against the installed makepkg. Two consequences follow, and the
// second is the one that matters:
//
//   - such a source cannot be fetched by makepkg either, so it is not an
//     evasion route; the recipe simply would not build.
//   - the analysis must describe what will ACTUALLY happen when makepkg runs
//     this recipe. A parser that is more correct than makepkg about URL syntax
//     disagrees with the tool that does the fetching, and that divergence is
//     exploitable in the worse direction: an attacker could craft an entry this
//     package reads as host A while makepkg downloads from host B, which is a
//     confidently wrong verdict rather than an admitted gap.
//
// So agreeing with makepkg outranks agreeing with RFC 3986 here. The
// consequence is handled honestly rather than papered over: such an entry ends
// up with no scheme and no host, and internal/check emits a coverage gap
// (INV-9) rather than a finding, because a bare-IP source is exactly what the
// paste-host rule exists to catch and "I could not parse this" must not read as
// "there is nothing here".
func parseSourceEntry(s *Source, text string) {
	rest := text
	if name, after, ok := strings.Cut(rest, "::"); ok {
		s.Name = name
		rest = after
	}
	if frag, ok := cutLast(rest, '#'); ok {
		s.Fragment = rest[len(frag)+1:]
		rest = frag
	}
	// A VCS prefix (git+https://) or a VCS scheme (git://).
	scheme, after, hasScheme := strings.Cut(rest, "://")
	if hasScheme {
		if proto, real, ok := strings.Cut(scheme, "+"); ok && contains(vcsPrefixes, proto) {
			s.VCS = proto
			scheme = real
		} else if contains(vcsPrefixes, scheme) {
			s.VCS = scheme
		}
		s.Scheme = scheme
		s.URL = scheme + "://" + after
		host := after
		if at := strings.LastIndexByte(hostPart(host), '@'); at >= 0 {
			host = hostPart(host)[at+1:]
		} else {
			host = hostPart(host)
		}
		if colon := strings.IndexByte(host, ':'); colon >= 0 {
			host = host[:colon]
		}
		s.Host = host
		if s.Name == "" {
			s.Name = lastPath(after)
		}
		return
	}
	// No scheme: a local file shipped with the PKGBUILD.
	s.Local = true
	if s.Name == "" {
		s.Name = rest
	}
}

// hostPart returns everything before the first '/' of an authority.
func hostPart(s string) string {
	if i := strings.IndexByte(s, '/'); i >= 0 {
		return s[:i]
	}
	return s
}

func lastPath(s string) string {
	s = hostAndPath(s)
	if i := strings.LastIndexByte(s, '/'); i >= 0 {
		return s[i+1:]
	}
	return s
}

func hostAndPath(s string) string {
	if i := strings.IndexByte(s, '?'); i >= 0 {
		return s[:i]
	}
	return s
}

// cutLast splits at the last occurrence of sep.
func cutLast(s string, sep byte) (string, bool) {
	if i := strings.LastIndexByte(s, sep); i >= 0 {
		return s[:i], true
	}
	return s, false
}

func contains(list []string, s string) bool {
	for _, v := range list {
		if v == s {
			return true
		}
	}
	return false
}
