// Package completions holds the shell completion files and the one test that
// keeps them honest.
//
// Completions rot silently. A new subcommand ships, nobody updates the
// completion files, and the omission is invisible because a missing completion
// looks exactly like "no match" -- the shell simply offers nothing and the user
// assumes they typed it wrong. A test is the only thing that notices.
//
// The subcommand list is DERIVED from cmd/aurvet's dispatch switch by parsing
// its AST (go/parser, stdlib -- INV-2's "parse, never execute" applies to our
// own tooling as much as to a PKGBUILD). It is deliberately not a literal list
// in this file: two hand-maintained lists drift together and the test then
// passes forever while certifying staleness.
package completions

import (
	"go/ast"
	"go/parser"
	"go/token"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"testing"
)

// mainGo is the source of truth: the switch in run() is what actually decides
// whether a subcommand exists.
const mainGo = "../cmd/aurvet/main.go"

// dispatchedCommands returns every subcommand cmd/aurvet dispatches, read out
// of the `switch cmd {` statement in run(). Panics-by-t.Fatal if the switch
// cannot be found, because silently returning an empty set would make every
// assertion below vacuous -- the exact failure mode this file exists to
// prevent.
func dispatchedCommands(t *testing.T) []string {
	t.Helper()

	fset := token.NewFileSet()
	file, err := parser.ParseFile(fset, mainGo, nil, parser.SkipObjectResolution)
	if err != nil {
		t.Fatalf("parse %s: %v", mainGo, err)
	}

	var cmds []string
	var found bool
	ast.Inspect(file, func(n ast.Node) bool {
		sw, ok := n.(*ast.SwitchStmt)
		if !ok {
			return true
		}
		id, ok := sw.Tag.(*ast.Ident)
		if !ok || id.Name != "cmd" {
			return true
		}
		found = true
		for _, stmt := range sw.Body.List {
			cc, ok := stmt.(*ast.CaseClause)
			if !ok || cc.List == nil { // nil List == default:
				continue
			}
			for _, e := range cc.List {
				lit, ok := e.(*ast.BasicLit)
				if !ok || lit.Kind != token.STRING {
					t.Fatalf("%s: non-literal case in the command switch: %T", mainGo, e)
				}
				s, err := strconv.Unquote(lit.Value)
				if err != nil {
					t.Fatalf("%s: unquote %s: %v", mainGo, lit.Value, err)
				}
				cmds = append(cmds, s)
			}
		}
		return false
	})

	if !found {
		t.Fatalf("%s: could not find the `switch cmd` dispatch; this test can no longer "+
			"derive the subcommand list and must be updated rather than deleted", mainGo)
	}
	if len(cmds) == 0 {
		t.Fatalf("%s: the command switch has no cases; refusing to certify completions "+
			"against an empty list", mainGo)
	}
	sort.Strings(cmds)
	return cmds
}

func read(t *testing.T, path string) string {
	t.Helper()
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("read %s: %v", path, err)
	}
	return string(b)
}

// between returns the text between the two marker comments, so the extractors
// below read only the block that is meant to list subcommands and cannot be
// satisfied by the word "install" appearing in a description elsewhere in the
// file.
func between(t *testing.T, path, body string) string {
	t.Helper()
	const begin, end = "AURVET_COMMANDS_BEGIN", "AURVET_COMMANDS_END"
	i := strings.Index(body, begin)
	j := strings.Index(body, end)
	if i < 0 || j < 0 || j < i {
		t.Fatalf("%s: missing the %s/%s markers the extractor keys on", path, begin, end)
	}
	return body[i+len(begin) : j]
}

var (
	bashList = regexp.MustCompile(`(?s)_aurvet_commands=\(([^)]*)\)`)
	zshEntry = regexp.MustCompile(`'([a-z][a-z0-9-]*):`)
	fishCmd  = regexp.MustCompile(`__fish_use_subcommand\s+-a\s+([A-Za-z0-9_-]+)`)
)

// offered returns the subcommands each completion file actually offers,
// extracted structurally rather than by grepping the whole file for a word.
func offered(t *testing.T, shell string) []string {
	t.Helper()
	var out []string
	switch shell {
	case "bash":
		const p = "aurvet.bash"
		block := between(t, p, read(t, p))
		m := bashList.FindStringSubmatch(block)
		if m == nil {
			t.Fatalf("%s: could not find the _aurvet_commands=(...) array", p)
		}
		out = strings.Fields(m[1])
	case "zsh":
		const p = "_aurvet"
		block := between(t, p, read(t, p))
		for _, m := range zshEntry.FindAllStringSubmatch(block, -1) {
			out = append(out, m[1])
		}
	case "fish":
		const p = "aurvet.fish"
		for _, m := range fishCmd.FindAllStringSubmatch(read(t, p), -1) {
			out = append(out, m[1])
		}
	default:
		t.Fatalf("unknown shell %q", shell)
	}
	if len(out) == 0 {
		t.Fatalf("%s: extracted zero subcommands; the extractor is broken and every "+
			"assertion below would be vacuous", shell)
	}
	sort.Strings(out)
	return out
}

// TestEverySubcommandIsCompletedInEveryShell is the deliverable: bash, zsh and
// fish must each offer exactly the set cmd/aurvet dispatches. Both directions
// are checked -- a completion for a subcommand that no longer exists is its own
// kind of lie.
func TestEverySubcommandIsCompletedInEveryShell(t *testing.T) {
	want := dispatchedCommands(t)
	for _, shell := range []string{"bash", "zsh", "fish"} {
		t.Run(shell, func(t *testing.T) {
			got := offered(t, shell)
			set := make(map[string]bool, len(got))
			for _, c := range got {
				set[c] = true
			}
			for _, c := range want {
				if !set[c] {
					t.Errorf("%s completion does not offer subcommand %q "+
						"(cmd/aurvet dispatches it; add it to the completion file)", shell, c)
				}
			}
			wantSet := make(map[string]bool, len(want))
			for _, c := range want {
				wantSet[c] = true
			}
			for _, c := range got {
				if !wantSet[c] {
					t.Errorf("%s completion offers subcommand %q, which cmd/aurvet does not "+
						"dispatch; remove it", shell, c)
				}
			}
		})
	}
}

// TestUsageTextListsEverySubcommand catches the other half of the same drift:
// the "commands:" line run() prints on a bad invocation is hand-written, and a
// subcommand missing from it is undiscoverable without reading the source.
func TestUsageTextListsEverySubcommand(t *testing.T) {
	want := dispatchedCommands(t)
	src := read(t, mainGo)
	i := strings.Index(src, "commands: ")
	if i < 0 {
		t.Fatalf("%s: no `commands: ` usage line to check", mainGo)
	}
	line := src[i:]
	if j := strings.IndexByte(line, '\n'); j >= 0 {
		line = line[:j]
	}
	listed := make(map[string]bool)
	for _, f := range strings.Split(strings.TrimPrefix(strings.Trim(line, `"`), "commands: "), ",") {
		listed[strings.Trim(strings.TrimSpace(f), `")`)] = true
	}
	for _, c := range want {
		if !listed[c] {
			t.Errorf("usage line in %s does not list subcommand %q: %s", mainGo, c, line)
		}
	}
}

// TestManPageDocumentsEverySubcommand keeps man/aurvet.1.scd from going stale
// for the same reason. The man page is the only place the exit-code contract is
// written down for a user, so an undocumented subcommand there is a real gap.
func TestManPageDocumentsEverySubcommand(t *testing.T) {
	want := dispatchedCommands(t)
	const p = "../man/aurvet.1.scd"
	body := read(t, p)
	i := strings.Index(body, "# COMMANDS")
	j := strings.Index(body, "# FLAGS")
	if i < 0 || j < 0 || j < i {
		t.Fatalf("%s: no COMMANDS section to check", p)
	}
	section := body[i:j]
	for _, c := range want {
		if !regexp.MustCompile(`(?m)^\*` + regexp.QuoteMeta(c) + `\*`).MatchString(section) {
			t.Errorf("%s: COMMANDS section has no entry for subcommand %q", p, c)
		}
	}
}
