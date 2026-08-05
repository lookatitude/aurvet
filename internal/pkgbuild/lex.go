// internal/pkgbuild/lex.go
//
// A PKGBUILD is a bash script an attacker wrote and wants makepkg to run. This
// file reads one WITHOUT RUNNING IT (INV-2): no source, no eval, no
// makepkg --printsrcinfo, not behind a flag and not for the hard cases -- the
// hard cases are the attack.
//
// What that buys, and what it costs, are both stated here rather than in
// documentation. It buys: assignments, functions, commands, heredoc bodies and
// the shape of every expansion, all with line numbers, from text alone. It
// costs: anything the recipe COMPUTES. `eval "package_$_p() {` -- present in 3
// of 34 cached recipes -- generates functions whose bodies are not in the file.
// This package therefore records what defeated it (Note) and resolve.go/
// verdict.go turn that into a coverage gap (INV-9), never into silence and
// never into a critical.
//
// Every loop here is bounded and nothing recurses without a depth counter. The
// input is attacker-controlled, so a panic is a denial of service against a
// security tool and a hang is worse (spec §11.3).
package pkgbuild

import (
	"fmt"
	"strings"
)

// Limits bound the tokeniser against hostile input. They are constants rather
// than configuration: a caller who could raise them could turn a crafted
// recipe into a hang, and no legitimate PKGBUILD comes near any of them (the
// largest of the 34 measured is 716 lines).
const (
	maxInputBytes  = 4 << 20 // 4 MiB; the largest cached PKGBUILD is 24 KiB
	maxCommands    = 100000
	maxWords       = 4096 // per command
	maxSegments    = 4096 // per word
	maxArrayValues = 65536
	maxSubstDepth  = 4 // $( $( $( $( -- 2 of 34 nest at all, none past 2
	maxFrameDepth  = 128
	maxHeredocs    = 4096
	maxNotes       = 512
)

// NoteKind names a construct that defeated static analysis. A Note is not a
// finding: it is the raw material verdict.go turns into a coverage gap.
type NoteKind string

const (
	// NoteEval marks an eval. Deliberately not suspicious on its own: eval is
	// in 3 of 34 legitimate cached recipes (9%), so rating it would cry wolf on
	// a tenth of the AUR. What it generates is simply not analysable.
	NoteEval NoteKind = "eval"
	// NoteExternalSource marks the bash `source`/`.` BUILTIN pulling in another
	// file -- a statement, not the `source=()` assignment. The included file is
	// not in front of us.
	NoteExternalSource           NoteKind = "external-source"
	NoteUnterminatedQuote        NoteKind = "unterminated-quote"
	NoteUnterminatedHeredoc      NoteKind = "unterminated-heredoc"
	NoteUnterminatedFunction     NoteKind = "unterminated-function"
	NoteUnterminatedSubstitution NoteKind = "unterminated-substitution"
	NoteTruncated                NoteKind = "input-truncated"
	// NoteLimit marks a bound being hit. Bounds exist to stop a hang, and
	// hitting one means the tail of the file was not read.
	NoteLimit NoteKind = "limit-reached"
)

// Note records one thing the tokeniser could not resolve or could not read.
type Note struct {
	Kind   NoteKind
	Line   int
	Detail string
}

// SegKind classifies one piece of a word.
type SegKind int

const (
	// SegLiteral is text that needs no expansion: it is exactly itself.
	SegLiteral SegKind = iota
	// SegVar is a variable reference, possibly with a parameter-expansion
	// operator. Resolution may or may not be able to pin it down.
	SegVar
	// SegCommandSub is $(...) or `...`. Its VALUE is unknowable without running
	// it, and running it is forbidden; its TEXT is tokenised as commands.
	SegCommandSub
	// SegArith is $((...)). Not resolved: arithmetic can reference variables and
	// this package does not evaluate.
	SegArith
)

// Segment is one piece of a word. A word is a sequence of segments so that
// resolution can expand what it can and leave the rest explicitly unresolved --
// never a half-expanded string that looks analysable and is not.
type Segment struct {
	Kind SegKind
	// Text is the literal bytes for SegLiteral, or the raw inner source for the
	// other kinds (without the $( ) or ${ } wrapper).
	Text string
	// Var, Index, Op and Arg describe a SegVar: ${Var[Index]Op Arg}, e.g.
	// ${pkgver//_/-} is Var=pkgver Op="//" Arg="_/-".
	Var   string
	Index string
	Op    string
	Arg   string
}

// Word is one shell word with its structure preserved.
type Word struct {
	// Raw is the word exactly as written, quotes included.
	Raw  string
	Line int
	Segs []Segment
}

// Literal returns the word's text when the word needs no expansion at all, and
// ok=false when any part of it does. A caller must not use the string when ok
// is false: a partially expanded URL is worse than an admitted unknown.
func (w Word) Literal() (string, bool) {
	var b strings.Builder
	for _, s := range w.Segs {
		if s.Kind != SegLiteral {
			return "", false
		}
		b.WriteString(s.Text)
	}
	return b.String(), true
}

// HasExpansion reports whether any part of the word needs expansion.
func (w Word) HasExpansion() bool {
	_, lit := w.Literal()
	return !lit
}

// Assignment is one variable assignment. Name is as written; Base and Arch
// split an arch suffix off it, because 10 of 34 cached recipes put their real
// sources in source_x86_64 / source_aarch64 and reading only `source` is a 29%
// blind spot.
type Assignment struct {
	Name   string
	Base   string
	Arch   string
	Append bool // +=
	Array  bool
	Values []Word
	Line   int
	// Func is the enclosing function, "" for a top-level assignment. Only
	// top-level assignments describe the package; one inside build() is a local
	// and must not be mistaken for a declaration.
	Func string
}

// Command is one simple command. Nothing here is ever run.
type Command struct {
	Words []Word
	Line  int
	// Func is the enclosing function name, "" at top level.
	Func string
	// Sep is the operator that terminated this command: "", "\n", ";", "|",
	// "&&", "||", "&". A rule for "download piped into a shell" needs the pipe,
	// so the separator is evidence, not punctuation.
	Sep string
	// SubstDepth is 0 for a command in the file's own text and >0 for one found
	// inside a command substitution.
	SubstDepth int
	// Assigns are the VAR=value prefixes of this command (`make CC=gcc` has
	// none; `CC=gcc make` has one).
	Assigns []Assignment
}

// shellKeywords never name a command. `if ! grep -q x` runs grep.
var shellKeywords = map[string]bool{
	"if": true, "then": true, "else": true, "elif": true, "fi": true,
	"for": true, "while": true, "until": true, "do": true, "done": true,
	"case": true, "esac": true, "in": true, "select": true, "function": true,
	"!": true, "time": true, "{": true, "}": true, "[[": true, "]]": true,
	"coproc": true,
}

// Name returns the command name, skipping shell keywords and negations. It
// returns "" for a command that has no name (a bare assignment, or nothing but
// keywords).
func (c Command) Name() string {
	for _, w := range c.Words {
		lit, ok := w.Literal()
		if !ok {
			// A computed command name. Not a name we can report, and reporting
			// the raw text as if it were one would be a guess.
			return ""
		}
		if shellKeywords[lit] {
			continue
		}
		return lit
	}
	return ""
}

// Args returns the words after the command name.
func (c Command) Args() []Word {
	for i, w := range c.Words {
		lit, ok := w.Literal()
		if ok && shellKeywords[lit] {
			continue
		}
		return c.Words[i+1:]
	}
	return nil
}

// Heredoc is a here-document. Its body is DATA: flutter-bin writes three
// wrapper scripts whose bodies contain `source /opt/flutter/bin/aur_init.sh`,
// and parsing those bodies as commands invents two external includes that the
// recipe never executes at build time.
type Heredoc struct {
	Delim string
	// Expand is false for <<'EOF' and <<"EOF", where bash performs no expansion.
	Expand     bool
	Line       int
	Body       string
	Terminated bool
	Func       string
}

// Function is a shell function definition found in the TEXT. Functions a recipe
// generates at runtime (via eval) are absent by construction, which is why
// verdict.go cross-checks pkgname against the package functions present.
type Function struct {
	Name    string
	Line    int
	EndLine int
	Body    string
}

// File is everything the tokeniser could see, plus everything that defeated it.
type File struct {
	Assignments []Assignment
	Functions   []Function
	Commands    []Command
	Heredocs    []Heredoc
	Notes       []Note
	// Truncated reports that the input exceeded maxInputBytes and the tail was
	// not read at all.
	Truncated bool
}

// Assign returns the last top-level assignment of an exact name. Last wins,
// because that is what bash would end up with; += is folded in by resolve.go,
// which is where value semantics live.
func (f File) Assign(name string) (Assignment, bool) {
	var (
		out   Assignment
		found bool
	)
	for _, a := range f.Assignments {
		if a.Func == "" && a.Name == name {
			out, found = a, true
		}
	}
	return out, found
}

// Function returns the named function.
func (f File) Function(name string) (Function, bool) {
	for _, fn := range f.Functions {
		if fn.Name == name {
			return fn, true
		}
	}
	return Function{}, false
}

// Note reports whether any note of the kind was recorded.
func (f File) Note(kind NoteKind) bool {
	for _, n := range f.Notes {
		if n.Kind == kind {
			return true
		}
	}
	return false
}

// archSuffixes are the architectures makepkg honours as variable suffixes.
// Fixed, not derived from runtime.GOARCH: an x86_64 host must still be able to
// review an aarch64-only payload (INV-4).
var archSuffixes = []string{"x86_64", "i686", "aarch64", "armv7h", "armv6h", "arm", "pentium4", "riscv64", "loong64"}

// splitArch splits a variable name into its base and architecture suffix.
func splitArch(name string) (base, arch string) {
	for _, a := range archSuffixes {
		if strings.HasSuffix(name, "_"+a) {
			return strings.TrimSuffix(name, "_"+a), a
		}
	}
	return name, ""
}

// Lex tokenises a PKGBUILD. It never fails: hostile input yields a File whose
// Notes say what could not be read, because refusing to return anything would
// hide the analysable half of a crafted recipe.
func Lex(src []byte) File {
	lx := &lexer{f: &File{}, budget: &budget{}}
	if len(src) > maxInputBytes {
		src = src[:maxInputBytes]
		lx.f.Truncated = true
		lx.note(NoteTruncated, 1, fmt.Sprintf("input exceeds %d bytes; the tail was not read", maxInputBytes))
	}
	lx.src = src
	lx.line = 1
	lx.run()
	lx.closeFrames()
	return *lx.f
}

// budget is the shared bound across the top-level lexer and every sub-lexer it
// spawns for a command substitution, so a crafted file cannot multiply the cap
// by nesting.
type budget struct {
	commands int
	heredocs int
	notes    int
	stopped  bool
}

// frame is an open { } block. A function frame carries the name so commands can
// be attributed to it.
type frame struct {
	fn        string
	bodyStart int
	line      int
	isFunc    bool
}

type lexer struct {
	src    []byte
	i      int
	line   int
	f      *File
	budget *budget
	frames []frame
	depth  int // command-substitution depth
	// pending heredocs registered on the current logical line, consumed at its
	// newline.
	pending []pendingHeredoc
}

type pendingHeredoc struct {
	delim  string
	expand bool
	strip  bool // <<- strips leading tabs
	line   int
}

func (lx *lexer) note(kind NoteKind, line int, detail string) {
	if lx.budget.notes >= maxNotes {
		return
	}
	lx.budget.notes++
	lx.f.Notes = append(lx.f.Notes, Note{Kind: kind, Line: line, Detail: detail})
}

// fn returns the innermost enclosing function name.
func (lx *lexer) fn() string {
	for i := len(lx.frames) - 1; i >= 0; i-- {
		if lx.frames[i].isFunc {
			return lx.frames[i].fn
		}
	}
	return ""
}

func (lx *lexer) run() {
	for lx.i < len(lx.src) && !lx.budget.stopped {
		lx.skipSeparators()
		if lx.i >= len(lx.src) {
			return
		}
		lx.command()
	}
}

// closeFrames notes any function left open at EOF. An unterminated function
// means the rest of the file was read in the wrong context, which is a coverage
// problem, not a style problem.
func (lx *lexer) closeFrames() {
	for _, fr := range lx.frames {
		if fr.isFunc {
			lx.note(NoteUnterminatedFunction, fr.line,
				fmt.Sprintf("function %s() is never closed; its body was read to end of file", fr.fn))
		}
	}
}

func isBlank(c byte) bool { return c == ' ' || c == '\t' || c == '\r' }

// skipSeparators consumes whitespace, newlines, comments and command
// separators between commands, consuming heredoc bodies at each newline.
func (lx *lexer) skipSeparators() {
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch {
		case isBlank(c):
			lx.i++
		case c == '\n':
			lx.i++
			lx.line++
			lx.consumeHeredocs()
		case c == '#':
			lx.skipComment()
		case c == ';' || c == '&' || c == '|':
			lx.i++
			if lx.i < len(lx.src) && lx.src[lx.i] == c {
				lx.i++
			}
		default:
			return
		}
	}
}

func (lx *lexer) skipComment() {
	for lx.i < len(lx.src) && lx.src[lx.i] != '\n' {
		lx.i++
	}
}

// command reads one simple command: leading VAR=value assignments, then words,
// stopping at a separator. Redirections are consumed as operators so a
// redirection target is never mistaken for a command or an argument.
func (lx *lexer) command() {
	if lx.budget.commands >= maxCommands {
		if !lx.budget.stopped {
			lx.note(NoteLimit, lx.line, fmt.Sprintf("more than %d commands; the rest of the file was not read", maxCommands))
			lx.budget.stopped = true
		}
		lx.i = len(lx.src)
		return
	}
	lx.budget.commands++

	startLine := lx.line
	var (
		words   []Word
		assigns []Assignment
		sep     string
	)

	// Leading assignments. In command position only: `make CC=gcc` passes an
	// argument, `CC=gcc make` sets a variable.
	for len(words) == 0 {
		lx.skipInline()
		a, ok := lx.tryAssignment()
		if !ok {
			break
		}
		assigns = append(assigns, a)
	}

loop:
	for lx.i < len(lx.src) {
		lx.skipInline()
		if lx.i >= len(lx.src) {
			break
		}
		c := lx.src[lx.i]
		switch {
		case c == '\n':
			lx.i++
			lx.line++
			lx.consumeHeredocs()
			sep = "\n"
			break loop
		case c == '#':
			lx.skipComment()
			continue
		case c == ';':
			lx.i++
			if lx.i < len(lx.src) && lx.src[lx.i] == ';' { // case terminator
				lx.i++
			}
			sep = ";"
			break loop
		case c == '|' || c == '&':
			lx.i++
			sep = string(c)
			if lx.i < len(lx.src) && lx.src[lx.i] == c {
				lx.i++
				sep += string(c)
			}
			break loop
		case c == '<' || c == '>':
			lx.redirection()
			continue
		case (c == '{' || c == '}') && len(words) == 0 && len(assigns) == 0:
			lx.brace(c)
			return
		case c == '(' && len(words) == 0 && len(assigns) == 0:
			// A bare subshell. Its contents are ordinary commands.
			lx.i++
			continue
		case c == ')':
			// Closing a subshell, or the ) of a `case` pattern. Neither is a
			// word.
			lx.i++
			continue
		}

		if len(words) >= maxWords {
			lx.note(NoteLimit, lx.line, fmt.Sprintf("command has more than %d words", maxWords))
			lx.skipToLineEnd()
			break loop
		}
		w := lx.word()
		if w.Raw == "" {
			// No progress possible on this byte; consume it rather than spin.
			if lx.i < len(lx.src) {
				lx.i++
			}
			continue
		}
		// `name()` opens a function definition.
		if len(words) == 0 && lx.functionHeader(w) {
			return
		}
		words = append(words, w)
	}

	if len(words) == 0 {
		// A pure assignment line, or an empty one.
		lx.f.Assignments = append(lx.f.Assignments, assigns...)
		return
	}
	cmd := Command{Words: words, Line: startLine, Func: lx.fn(), Sep: sep, SubstDepth: lx.depth, Assigns: assigns}
	lx.f.Commands = append(lx.f.Commands, cmd)
	lx.f.Assignments = append(lx.f.Assignments, assigns...)
	lx.classify(cmd)
}

// classify records the notes a command's identity implies. It rates nothing:
// eval is in 9% of an honest corpus and `source` of another file is in 2 of 34.
func (lx *lexer) classify(c Command) {
	switch c.Name() {
	case "eval":
		lx.note(NoteEval, c.Line,
			"eval builds and runs code at build time; whatever it generates is not in the recipe text and was not analysed")
	case "source", ".":
		// The bash builtin, not the source=() array: this pulls in a file that
		// is not in front of us.
		var what string
		if args := c.Args(); len(args) > 0 {
			what = args[0].Raw
		}
		lx.note(NoteExternalSource, c.Line,
			fmt.Sprintf("the recipe sources an external file (%s); its contents were not analysed", what))
	}
}

// skipInline consumes blanks and line continuations within one logical line.
func (lx *lexer) skipInline() {
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		if isBlank(c) {
			lx.i++
			continue
		}
		if c == '\\' && lx.i+1 < len(lx.src) && lx.src[lx.i+1] == '\n' {
			lx.i += 2
			lx.line++
			continue
		}
		return
	}
}

func (lx *lexer) skipToLineEnd() {
	for lx.i < len(lx.src) && lx.src[lx.i] != '\n' {
		lx.i++
	}
}

// brace handles a { or } in command position: the body of a function, or a
// grouping block.
func (lx *lexer) brace(c byte) {
	lx.i++
	if c == '{' {
		if len(lx.frames) >= maxFrameDepth {
			lx.note(NoteLimit, lx.line, fmt.Sprintf("blocks nested deeper than %d", maxFrameDepth))
			return
		}
		lx.frames = append(lx.frames, frame{line: lx.line, bodyStart: lx.i})
		return
	}
	if len(lx.frames) == 0 {
		return
	}
	fr := lx.frames[len(lx.frames)-1]
	lx.frames = lx.frames[:len(lx.frames)-1]
	if fr.isFunc {
		body := ""
		if fr.bodyStart <= len(lx.src) && fr.bodyStart <= lx.i-1 {
			body = string(lx.src[fr.bodyStart : lx.i-1])
		}
		lx.f.Functions = append(lx.f.Functions, Function{
			Name: fr.fn, Line: fr.line, EndLine: lx.line, Body: body,
		})
	}
}

// functionHeader recognises a `name ( )` definition header at the current
// position, the word `name` having just been read. The `(` terminates a word,
// so the parenthesis pair is never part of the word itself -- which is also how
// a `case` pattern (`x)`) is told apart from a definition: a definition needs
// the OPENING paren.
//
// It returns true when the header was consumed, restoring the position
// untouched when it was not.
func (lx *lexer) functionHeader(w Word) bool {
	name, ok := w.Literal()
	if !ok || !isName(name) || shellKeywords[name] {
		return false
	}
	savedI, savedLine := lx.i, lx.line
	fail := func() bool {
		lx.i, lx.line = savedI, savedLine
		return false
	}
	startLine := lx.line
	for lx.i < len(lx.src) && isBlank(lx.src[lx.i]) {
		lx.i++
	}
	if lx.i >= len(lx.src) || lx.src[lx.i] != '(' {
		return fail()
	}
	lx.i++
	for lx.i < len(lx.src) && isBlank(lx.src[lx.i]) {
		lx.i++
	}
	if lx.i >= len(lx.src) || lx.src[lx.i] != ')' {
		// `name (word...)` is not a definition -- and an array assignment has
		// already been consumed elsewhere, so this is nothing we can name.
		return fail()
	}
	lx.i++
	// The opening brace may be on a later line (nperf-gui-appimage puts it
	// there for every function).
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		if isBlank(c) {
			lx.i++
			continue
		}
		if c == '\n' {
			lx.i++
			lx.line++
			continue
		}
		break
	}
	if lx.i < len(lx.src) && lx.src[lx.i] == '{' {
		lx.i++
		if len(lx.frames) >= maxFrameDepth {
			lx.note(NoteLimit, lx.line, fmt.Sprintf("blocks nested deeper than %d", maxFrameDepth))
			return true
		}
		lx.frames = append(lx.frames, frame{fn: name, bodyStart: lx.i, line: startLine, isFunc: true})
	}
	// A `name() ( subshell )` body opens no brace frame; the definition header
	// is still consumed, because reporting `name` as a command would be wrong.
	return true
}

func isName(s string) bool {
	if s == "" {
		return false
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch {
		case c >= 'a' && c <= 'z', c >= 'A' && c <= 'Z', c == '_':
		case c >= '0' && c <= '9' && i > 0:
		case (c == '-' || c == '.' || c == '+') && i > 0:
			// Not a legal bash NAME, but makepkg's split-package functions are
			// named package_foo-bin, so they must parse.
		default:
			return false
		}
	}
	return true
}

// redirection consumes a redirection operator and its target, registering a
// heredoc when it sees << or <<-. `<<<` is a herestring: its operand is an
// ordinary word, and reading it as a heredoc would consume the rest of the file
// hunting a delimiter that never arrives.
func (lx *lexer) redirection() {
	c := lx.src[lx.i]
	lx.i++
	if c == '<' && lx.i < len(lx.src) && lx.src[lx.i] == '<' {
		lx.i++
		if lx.i < len(lx.src) && lx.src[lx.i] == '<' { // <<< herestring
			lx.i++
			lx.skipInline()
			lx.word()
			return
		}
		strip := false
		if lx.i < len(lx.src) && lx.src[lx.i] == '-' {
			lx.i++
			strip = true
		}
		lx.skipInline()
		line := lx.line
		dw := lx.word()
		delim, quoted := heredocDelim(dw)
		if delim == "" {
			return
		}
		if lx.budget.heredocs >= maxHeredocs {
			lx.note(NoteLimit, line, fmt.Sprintf("more than %d heredocs", maxHeredocs))
			return
		}
		lx.budget.heredocs++
		lx.pending = append(lx.pending, pendingHeredoc{delim: delim, expand: !quoted, strip: strip, line: line})
		return
	}
	// Ordinary redirection: consume the operator's remaining characters and the
	// target word, so `make 2> /dev/null` yields no /dev/null argument.
	for lx.i < len(lx.src) && (lx.src[lx.i] == '>' || lx.src[lx.i] == '&' || lx.src[lx.i] == '<') {
		lx.i++
	}
	lx.skipInline()
	if lx.i < len(lx.src) && lx.src[lx.i] != '\n' && lx.src[lx.i] != ';' {
		lx.word()
	}
}

// heredocDelim extracts the delimiter and whether it was quoted (which
// suppresses expansion in the body).
func heredocDelim(w Word) (string, bool) {
	if len(w.Segs) == 0 {
		return "", false
	}
	quoted := strings.ContainsAny(w.Raw, `"'\`)
	lit, ok := w.Literal()
	if !ok {
		// A computed delimiter. Take the raw text; the body scan will simply
		// fail to find it and report an unterminated heredoc.
		return strings.Trim(w.Raw, `"'`), quoted
	}
	return lit, quoted
}

// consumeHeredocs reads the bodies registered on the logical line that just
// ended. The body is DATA and is never tokenised as commands.
func (lx *lexer) consumeHeredocs() {
	if len(lx.pending) == 0 {
		return
	}
	pend := lx.pending
	lx.pending = nil
	for _, p := range pend {
		var b strings.Builder
		terminated := false
		for lx.i < len(lx.src) {
			// One line of body.
			start := lx.i
			for lx.i < len(lx.src) && lx.src[lx.i] != '\n' {
				lx.i++
			}
			line := string(lx.src[start:lx.i])
			if lx.i < len(lx.src) {
				lx.i++ // the newline
			}
			lx.line++
			probe := line
			if p.strip {
				probe = strings.TrimLeft(probe, "\t")
			}
			if strings.TrimRight(probe, "\r") == p.delim {
				terminated = true
				break
			}
			b.WriteString(line)
			b.WriteByte('\n')
		}
		if !terminated {
			lx.note(NoteUnterminatedHeredoc, p.line,
				fmt.Sprintf("heredoc delimiter %q never appears; the rest of the file was read as its body", p.delim))
		}
		lx.f.Heredocs = append(lx.f.Heredocs, Heredoc{
			Delim: p.delim, Expand: p.expand, Line: p.line,
			Body: b.String(), Terminated: terminated, Func: lx.fn(),
		})
	}
}

// tryAssignment recognises `NAME=`, `NAME+=`, `NAME[i]=` at the current
// position and consumes the whole assignment, array form included.
func (lx *lexer) tryAssignment() (Assignment, bool) {
	j := lx.i
	for j < len(lx.src) {
		c := lx.src[j]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || (j > lx.i && c >= '0' && c <= '9') {
			j++
			continue
		}
		break
	}
	if j == lx.i {
		return Assignment{}, false
	}
	name := string(lx.src[lx.i:j])
	// An explicit array index (`sums[0]=x`) is consumed and ignored: the index
	// itself may be an expansion, and resolve.go works on whole arrays.
	if j < len(lx.src) && lx.src[j] == '[' {
		k := j
		for k < len(lx.src) && lx.src[k] != ']' && lx.src[k] != '\n' {
			k++
		}
		if k >= len(lx.src) || lx.src[k] != ']' {
			return Assignment{}, false
		}
		j = k + 1
	}
	appendOp := false
	if j < len(lx.src) && lx.src[j] == '+' {
		appendOp = true
		j++
	}
	if j >= len(lx.src) || lx.src[j] != '=' {
		return Assignment{}, false
	}
	j++
	line := lx.line
	lx.i = j
	base, arch := splitArch(name)
	a := Assignment{Name: name, Base: base, Arch: arch, Append: appendOp, Line: line, Func: lx.fn()}
	if lx.i < len(lx.src) && lx.src[lx.i] == '(' {
		lx.i++
		a.Array = true
		a.Values = lx.arrayValues()
		return a, true
	}
	if lx.i < len(lx.src) && !isBlank(lx.src[lx.i]) && lx.src[lx.i] != '\n' && lx.src[lx.i] != ';' {
		a.Values = []Word{lx.word()}
	} else {
		a.Values = []Word{{Line: line, Segs: []Segment{{Kind: SegLiteral}}}}
	}
	return a, true
}

// arrayValues reads array elements up to the closing paren, skipping comments
// and newlines inside the array (32 of 34 cached recipes use a multi-line
// source array, several with comments in it).
func (lx *lexer) arrayValues() []Word {
	var out []Word
	for lx.i < len(lx.src) {
		if len(out) >= maxArrayValues {
			lx.note(NoteLimit, lx.line, fmt.Sprintf("array has more than %d elements", maxArrayValues))
			lx.skipToLineEnd()
			return out
		}
		c := lx.src[lx.i]
		switch {
		case isBlank(c):
			lx.i++
			continue
		case c == '\n':
			lx.i++
			lx.line++
			continue
		case c == '\\' && lx.i+1 < len(lx.src) && lx.src[lx.i+1] == '\n':
			lx.i += 2
			lx.line++
			continue
		case c == '#':
			lx.skipComment()
			continue
		case c == ')':
			lx.i++
			return out
		}
		w := lx.word()
		if w.Raw == "" {
			lx.i++
			continue
		}
		out = append(out, w)
	}
	lx.note(NoteLimit, lx.line, "array assignment is never closed; the rest of the file was read as its elements")
	return out
}

// word reads one shell word, preserving its structure as segments. It stops at
// unquoted whitespace, separators, redirections and the ) that closes an array.
func (lx *lexer) word() Word {
	start := lx.i
	line := lx.line
	var (
		segs []Segment
		lit  strings.Builder
	)
	flush := func() {
		if lit.Len() > 0 {
			segs = append(segs, Segment{Kind: SegLiteral, Text: lit.String()})
			lit.Reset()
		}
	}
	add := func(s Segment) {
		flush()
		if len(segs) < maxSegments {
			segs = append(segs, s)
		}
	}

	for lx.i < len(lx.src) {
		if len(segs) >= maxSegments {
			lx.note(NoteLimit, line, fmt.Sprintf("word has more than %d segments", maxSegments))
			lx.skipToLineEnd()
			break
		}
		c := lx.src[lx.i]
		if isBlank(c) || c == '\n' || c == ';' || c == '|' || c == '&' || c == '(' || c == ')' || c == '<' || c == '>' {
			break
		}
		switch c {
		case '\\':
			if lx.i+1 >= len(lx.src) {
				lx.i++
				continue
			}
			if lx.src[lx.i+1] == '\n' {
				lx.i += 2
				lx.line++
				continue
			}
			lit.WriteByte(lx.src[lx.i+1])
			lx.i += 2
		case '\'':
			lx.i++
			s := lx.i
			for lx.i < len(lx.src) && lx.src[lx.i] != '\'' {
				if lx.src[lx.i] == '\n' {
					lx.line++
				}
				lx.i++
			}
			lit.Write(lx.src[s:lx.i])
			if lx.i >= len(lx.src) {
				lx.note(NoteUnterminatedQuote, line, "a single-quoted string is never closed")
			} else {
				lx.i++
			}
		case '"':
			lx.i++
			if !lx.doubleQuoted(&lit, &segs, add, line) {
				lx.note(NoteUnterminatedQuote, line, "a double-quoted string is never closed")
			}
		case '$':
			seg, ok := lx.dollar(line)
			if !ok {
				lit.WriteByte('$')
				lx.i++
				continue
			}
			add(seg)
		case '`':
			add(lx.backtick(line))
		default:
			lit.WriteByte(c)
			lx.i++
		}
	}
	flush()
	return Word{Raw: string(lx.src[start:lx.i]), Line: line, Segs: segs}
}

// doubleQuoted reads the inside of a double-quoted string, where expansions
// still happen but word splitting does not. It returns false if the quote is
// never closed.
func (lx *lexer) doubleQuoted(lit *strings.Builder, segs *[]Segment, add func(Segment), line int) bool {
	for lx.i < len(lx.src) {
		c := lx.src[lx.i]
		switch c {
		case '"':
			lx.i++
			return true
		case '\\':
			if lx.i+1 >= len(lx.src) {
				lx.i++
				return false
			}
			if lx.src[lx.i+1] == '\n' {
				lx.i += 2
				lx.line++
				continue
			}
			lit.WriteByte(lx.src[lx.i+1])
			lx.i += 2
		case '$':
			seg, ok := lx.dollar(line)
			if !ok {
				lit.WriteByte('$')
				lx.i++
				continue
			}
			add(seg)
		case '`':
			add(lx.backtick(line))
		case '\n':
			lx.line++
			lit.WriteByte(c)
			lx.i++
		default:
			if len(*segs) >= maxSegments {
				lx.skipToLineEnd()
				return true
			}
			lit.WriteByte(c)
			lx.i++
		}
	}
	return false
}

// dollar reads one $-construct. It returns ok=false when the $ is a literal
// (end of input, or followed by something that expands to nothing in bash).
func (lx *lexer) dollar(line int) (Segment, bool) {
	if lx.i+1 >= len(lx.src) {
		return Segment{}, false
	}
	switch lx.src[lx.i+1] {
	case '(':
		if lx.i+2 < len(lx.src) && lx.src[lx.i+2] == '(' {
			// $(( arithmetic ))
			inner, ok := lx.balanced(lx.i+3, '(', ')')
			if !ok {
				lx.note(NoteUnterminatedSubstitution, line, "an arithmetic expansion $(( is never closed")
				lx.i = len(lx.src)
				return Segment{Kind: SegArith}, true
			}
			// balanced() left lx.i after the matching ")"; consume the second.
			if lx.i < len(lx.src) && lx.src[lx.i] == ')' {
				lx.i++
			}
			return Segment{Kind: SegArith, Text: inner}, true
		}
		startLine := lx.line
		inner, ok := lx.balanced(lx.i+2, '(', ')')
		if !ok {
			lx.note(NoteUnterminatedSubstitution, line, "a command substitution $( is never closed")
			lx.i = len(lx.src)
			return Segment{Kind: SegCommandSub, Text: inner}, true
		}
		lx.subLex(inner, startLine)
		return Segment{Kind: SegCommandSub, Text: inner}, true
	case '{':
		inner, ok := lx.balanced(lx.i+2, '{', '}')
		if !ok {
			lx.note(NoteUnterminatedSubstitution, line, "a parameter expansion ${ is never closed")
			lx.i = len(lx.src)
			return parseExpansion(inner), true
		}
		return parseExpansion(inner), true
	}
	// $name, $1, $@, $?, $*
	j := lx.i + 1
	c := lx.src[j]
	if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' {
		for j < len(lx.src) {
			c := lx.src[j]
			if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || c >= '0' && c <= '9' {
				j++
				continue
			}
			break
		}
		name := string(lx.src[lx.i+1 : j])
		lx.i = j
		return Segment{Kind: SegVar, Var: name, Text: name}, true
	}
	if strings.IndexByte("0123456789@*?$!#-", c) >= 0 {
		lx.i = j + 1
		return Segment{Kind: SegVar, Var: string(c), Text: string(c)}, true
	}
	return Segment{}, false
}

// backtick reads `...` -- the same thing as $( ) with a worse delimiter.
func (lx *lexer) backtick(line int) Segment {
	startLine := lx.line
	lx.i++ // opening backtick
	s := lx.i
	for lx.i < len(lx.src) && lx.src[lx.i] != '`' {
		if lx.src[lx.i] == '\\' && lx.i+1 < len(lx.src) {
			lx.i++
		}
		if lx.src[lx.i] == '\n' {
			lx.line++
		}
		lx.i++
	}
	inner := string(lx.src[s:min(lx.i, len(lx.src))])
	if lx.i >= len(lx.src) {
		lx.note(NoteUnterminatedSubstitution, line, "a backtick substitution is never closed")
	} else {
		lx.i++
	}
	lx.subLex(inner, startLine)
	return Segment{Kind: SegCommandSub, Text: inner}
}

// balanced scans from `from` for the close matching an already-consumed open,
// honouring quotes and nesting, and leaves lx.i just past the close. It returns
// the inner text and whether the close was found. It does not recurse.
func (lx *lexer) balanced(from int, open, close byte) (string, bool) {
	depth := 1
	i := from
	startLine := lx.line
	line := startLine
	for i < len(lx.src) {
		c := lx.src[i]
		switch c {
		case '\n':
			line++
			i++
		case '\\':
			i += 2
		case '\'':
			i++
			for i < len(lx.src) && lx.src[i] != '\'' {
				if lx.src[i] == '\n' {
					line++
				}
				i++
			}
			i++
		case '"':
			i++
			for i < len(lx.src) && lx.src[i] != '"' {
				if lx.src[i] == '\\' {
					i++
				} else if lx.src[i] == '\n' {
					line++
				}
				i++
			}
			i++
		case open:
			depth++
			i++
		case close:
			depth--
			i++
			if depth == 0 {
				inner := string(lx.src[from : i-1])
				lx.i = i
				lx.line = line
				return inner, true
			}
		default:
			i++
		}
	}
	lx.line = line
	return string(lx.src[from:min(i, len(lx.src))]), false
}

// subLex tokenises the inside of a command substitution as commands, bounded by
// depth. The TEXT is right there, so discarding it would hide
// `$(curl http://x | sh)` from the rules; the VALUE stays unresolvable, because
// producing it would mean running the command.
func (lx *lexer) subLex(inner string, startLine int) {
	if lx.depth >= maxSubstDepth || strings.TrimSpace(inner) == "" {
		return
	}
	sub := &lexer{
		src:    []byte(inner),
		line:   startLine,
		f:      lx.f,
		budget: lx.budget,
		frames: lx.frames,
		depth:  lx.depth + 1,
	}
	sub.run()
}

// parseExpansion turns the inside of ${...} into a SegVar. Anything it cannot
// decompose is still recorded verbatim, so resolve.go can call it unresolvable
// rather than guess.
func parseExpansion(inner string) Segment {
	seg := Segment{Kind: SegVar, Text: inner}
	if inner == "" {
		return seg
	}
	// ${#var} -- a length, which this package does not compute.
	if inner[0] == '#' {
		seg.Op = "#len"
		seg.Var = strings.TrimPrefix(inner, "#")
		return seg
	}
	if inner[0] == '!' {
		// Indirect expansion. Not resolvable without evaluating.
		seg.Op = "!"
		seg.Var = strings.TrimPrefix(inner, "!")
		return seg
	}
	// Name, then optional [index], then an operator.
	i := 0
	for i < len(inner) {
		c := inner[i]
		if c >= 'a' && c <= 'z' || c >= 'A' && c <= 'Z' || c == '_' || (i > 0 && c >= '0' && c <= '9') {
			i++
			continue
		}
		break
	}
	if i == 0 {
		// A positional or special parameter: ${1}, ${@}.
		for i < len(inner) && strings.IndexByte("0123456789@*", inner[i]) >= 0 {
			i++
		}
	}
	seg.Var = inner[:i]
	rest := inner[i:]
	if strings.HasPrefix(rest, "[") {
		if end := strings.IndexByte(rest, ']'); end >= 0 {
			seg.Index = rest[1:end]
			rest = rest[end+1:]
		}
	}
	if rest == "" {
		return seg
	}
	for _, op := range []string{"//", "^^", ",,", "##", "%%", ":-", ":=", ":?", ":+", "/", "#", "%", "^", ",", ":"} {
		if strings.HasPrefix(rest, op) {
			seg.Op = op
			seg.Arg = rest[len(op):]
			return seg
		}
	}
	seg.Op = "?"
	seg.Arg = rest
	return seg
}
