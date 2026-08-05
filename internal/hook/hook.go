// internal/hook/hook.go
//
// Pacman hooks, parsed. Nothing here decides anything: this package reads what
// pacman ships and hands back evidence. What that evidence implies -- which
// files stop being verified, which hook is shadowed by another -- belongs to
// the packages that consume it.
//
// One parser, deliberately. A hook file is an attacker-reachable format (any
// package can ship one), and two parsers of an attacker-reachable format drift
// apart -- the drifted one being, by construction, the one that mis-parses.
//
// INV-2: hook Exec lines are TOKENISED, never executed. The tokeniser is
// deliberately incapable of expansion -- a token carrying a glob, a brace or a
// variable yields no path at all, because a path we cannot pin to one concrete
// file is worse than no path.
package hook

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io/fs"
	"path"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
)

// DefaultHookDirs are pacman's hook directories relative to the scanned root,
// in ascending priority: a hook in the admin directory shadows a system hook of
// the same file name, which is why order is part of the contract and not
// cosmetic. /etc/pacman.d/hooks does not exist on the reference system, and its
// absence is normal rather than a gap.
var DefaultHookDirs = []string{"usr/share/libalpm/hooks", "etc/pacman.d/hooks"}

// maxHookLineBytes bounds one hook line. Hook files are small (the reference
// system's 57 hooks are all under 2 KiB) and are attacker-influenced only
// insofar as a package ships one, but an unbounded scanner buffer on
// attacker-supplied bytes is not a thing this tool gets to have.
const maxHookLineBytes = 64 << 10

// Trigger is one [Trigger] section: what pacman watches.
//
// It is parsed and carried even though the exemption derivation reads only
// Exec, because the Target globs are what makes an exemption auditable -- a
// reader of `explain` output can see which packaged paths caused pacman to run
// the command whose output we stopped verifying.
type Trigger struct {
	Operations []string
	Type       string
	Targets    []string
}

// Hook is one installed pacman hook, as parsed from disk. Nothing here is
// executed; the fields are evidence.
type Hook struct {
	// Name is the hook's file name (not its path), because that is the
	// identity pacman uses when a hook in a higher-priority directory shadows
	// a lower one.
	Name     string
	Dir      string
	Triggers []Trigger
	When     string
	Exec     string
	Desc     string
}

// ParseHook reads one hook file. Hook files are INI-shaped: [Trigger] and
// [Action] sections of `Key = Value` lines, with repeated Operation and Target
// keys inside a Trigger and possibly several Trigger sections.
//
// Unknown keys and bare keys (NeedsTargets, AbortOnFail) are ignored rather
// than refused: pacman accepts more keys than this reads, and refusing a whole
// hook over one we do not model would manufacture a coverage gap.
func ParseHook(name string, data []byte) (Hook, error) {
	h := Hook{Name: name}
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4<<10), maxHookLineBytes)
	section := ""
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSuffix(strings.TrimPrefix(line, "["), "]"))
			if section == "trigger" {
				h.Triggers = append(h.Triggers, Trigger{})
			}
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)
		switch section {
		case "trigger":
			if len(h.Triggers) == 0 {
				continue
			}
			tr := &h.Triggers[len(h.Triggers)-1]
			switch key {
			case "Operation":
				tr.Operations = append(tr.Operations, val)
			case "Type":
				tr.Type = val
			case "Target":
				tr.Targets = append(tr.Targets, val)
			}
		case "action":
			switch key {
			case "When":
				h.When = val
			case "Exec":
				h.Exec = val
			case "Description":
				h.Desc = val
			}
		}
	}
	if err := sc.Err(); err != nil {
		return Hook{}, fmt.Errorf("hook %s: %w", name, err)
	}
	return h, nil
}

// LoadHooks reads every *.hook file under dirs, in the order given, and returns
// the hooks pacman would actually run together with the coverage gaps for the
// ones it could not read.
//
// fsys is the caller's confined view of the scanned root (os.Root.FS() on a
// live system), so this function performs no ambient path resolution of its own
// (INV-4) and an --offline-root is a parameter rather than a second code path.
//
// Shadowing is applied by file name across directories, later winning, because
// that is what pacman does: an admin hook of the same name replaces the system
// one, and an EMPTY replacement (the documented /dev/null symlink) is a hook
// that runs nothing. Such a hook parses to an empty Exec and therefore
// contributes no exemption -- a hook that does not run regenerates nothing, so
// its outputs must stay under verification.
func LoadHooks(fsys fs.FS, dirs []string) ([]Hook, []finding.Gap) {
	var (
		gaps   []finding.Gap
		order  []string
		byName = map[string]Hook{}
	)
	for _, dir := range dirs {
		ents, err := fs.ReadDir(fsys, dir)
		if err != nil {
			// An absent hook directory is the ordinary case for
			// /etc/pacman.d/hooks and says nothing about coverage. Anything
			// else -- EACCES, ENOTDIR -- means the hook set is unknown, and an
			// unknown hook set is an unknown exemption set (INV-9).
			if !isNotExist(err) {
				gaps = append(gaps, finding.Gap{
					RuleID:  "hook-coverage",
					Subject: dir,
					Reason: fmt.Sprintf("hook directory could not be read (%v); the derived exemption set "+
						"is incomplete, so files pacman regenerates may be reported as modified", err),
				})
			}
			continue
		}
		for _, ent := range ents {
			name := ent.Name()
			if !strings.HasSuffix(name, ".hook") {
				continue
			}
			data, err := fs.ReadFile(fsys, path.Join(dir, name))
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  "hook-coverage",
					Subject: path.Join(dir, name),
					Reason: fmt.Sprintf("hook could not be read (%v); whatever it regenerates is "+
						"unknown to the derived exemption set", err),
				})
				continue
			}
			h, err := ParseHook(name, data)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  "hook-coverage",
					Subject: path.Join(dir, name),
					Reason:  fmt.Sprintf("hook could not be parsed (%v)", err),
				})
				continue
			}
			h.Dir = dir
			if _, seen := byName[name]; !seen {
				order = append(order, name)
			}
			byName[name] = h
		}
	}
	hooks := make([]Hook, 0, len(order))
	for _, name := range order {
		hooks = append(hooks, byName[name])
	}
	return hooks, gaps
}

// isNotExist reports the "this directory is simply not here" case without
// swallowing permission errors along with it.
func isNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}

// execMeta are the characters whose presence means a token does not name one
// concrete file: shell globs, brace expansion, variables, command substitution
// and redirection. A token carrying any of them yields no exemption.
const execMeta = "*?[]{}$`<>~!"

// ExecPathLiterals extracts, from a hook's Exec line, the absolute paths that
// command names it operates ON -- never the commands themselves.
//
// The command-position rule is the load-bearing part. `Exec = /usr/bin/rm
// --force /etc/ld.so.cache` must yield /etc/ld.so.cache and must NOT yield
// /usr/bin/rm: exempting the program pacman runs would remove a binary from
// digest coverage, which is precisely the file an attacker would want
// unexamined. Command position is the start of the line, the start of a
// `sh -c` script, and the token after any shell separator.
//
// The tokeniser handles the quoting real hooks use (single quotes around a
// nested script, double quotes around a variable) and nothing more. It performs
// no expansion of any kind: `/usr/share/mime/{globs,magic}` -- the verbatim
// argument of shared-mime-info's remove hook -- yields nothing, because
// guessing at brace expansion would exempt paths that were never named.
func ExecPathLiterals(exec string) []string {
	seen := map[string]bool{}
	var out []string
	for _, p := range execArgPaths(exec, 0) {
		if seen[p] {
			continue
		}
		seen[p] = true
		out = append(out, p)
	}
	return out
}

// execArgPaths walks one command line, recursing at most once into a `-c`
// script argument. depth bounds the recursion so a pathological
// `sh -c 'sh -c '\”sh -c ...'\”'` cannot turn a parse into a stack overflow.
func execArgPaths(s string, depth int) []string {
	toks := shellTokens(s)
	var out []string
	cmdPos := true
	skip := false
	for i, tk := range toks {
		if skip {
			// Either the `-c` script argument, already walked as a command line
			// of its own -- falling through to the path test here would exempt
			// the whole script string, which begins with the nested command's
			// absolute path, i.e. it would exempt /usr/bin/rm -- or a
			// redirection target.
			skip = false
			continue
		}
		if !tk.quoted && isRedirect(tk.text) {
			// `install-info ... 2> /dev/null`: the next token is a redirection
			// target, not a file the command rewrites. Measured on the reference
			// system this rule is what keeps /dev/null out of the derived set.
			skip = true
			continue
		}
		if !tk.quoted && isShellSeparator(tk.text) {
			cmdPos = true
			continue
		}
		if cmdPos {
			// The command itself. Never exempt, whatever it looks like.
			//
			// Command position PROPAGATES through an interpreter prefix, because
			// the real command is what follows it. Measured: Arch's
			// 30-update-mime-database.hook reads `Exec = /usr/bin/env
			// PKGSYSTEM_ENABLE_FSYNC=0 /usr/bin/update-mime-database
			// /usr/share/mime`, and without this the BINARY
			// /usr/bin/update-mime-database landed in the derived exemption set.
			// (Exemptions.Applies would still have refused it for being
			// executable -- that guard exists precisely because this rule can be
			// fooled -- but a derivation that names a binary at all is one
			// mistake away from a blind spot.)
			if !propagatesCommandPosition(tk.text) {
				cmdPos = false
			}
			continue
		}
		if tk.text == "-c" && i+1 < len(toks) && depth < 2 {
			// The next token is a script, not a path: its own first token is a
			// command and must get the same treatment.
			out = append(out, execArgPaths(toks[i+1].text, depth+1)...)
			skip = true
			continue
		}
		if !strings.HasPrefix(tk.text, "/") {
			continue
		}
		if strings.ContainsAny(tk.text, execMeta) {
			continue
		}
		out = append(out, tk.text)
	}
	return out
}

// isShellSeparator reports the tokens after which a new command begins.
func isShellSeparator(s string) bool {
	switch s {
	case ";", "&", "&&", "|", "||", "(", ")", "{", "}":
		return true
	}
	return false
}

// propagatesCommandPosition reports whether a token in command position leaves
// the NEXT token in command position too: an env(1)-style prefix, one of its
// variable assignments, or a flag belonging to it.
func propagatesCommandPosition(s string) bool {
	if strings.Contains(s, "=") || strings.HasPrefix(s, "-") {
		return true
	}
	switch path.Base(s) {
	case "env", "nice", "ionice", "nohup", "setsid", "timeout", "sudo", "doas", "runuser":
		return true
	}
	return false
}

// isRedirect reports a redirection operator, whose following token is a stream
// destination rather than a file the command regenerates. The leading file
// descriptor form ("2>") is included because that is what hooks actually write.
func isRedirect(s string) bool {
	switch strings.TrimLeft(s, "0123456789") {
	case ">", ">>", "<", "<<", "<<<", "&>", ">&":
		return true
	}
	return false
}

type shellToken struct {
	text string
	// quoted records that the token came from a quoted string, so a literal
	// ";" argument is not mistaken for a separator.
	quoted bool
}

// shellTokens splits a command line on unquoted whitespace, honouring single
// quotes, double quotes and backslash escapes, and splitting the shell
// separators off as tokens of their own.
//
// This is a tokeniser and only a tokeniser (INV-2). It cannot expand, dereference
// or run anything.
func shellTokens(s string) []shellToken {
	var (
		out  []shellToken
		cur  strings.Builder
		open bool // a token is being accumulated
		qtd  bool
	)
	flush := func() {
		if open {
			out = append(out, shellToken{text: cur.String(), quoted: qtd})
			cur.Reset()
			open, qtd = false, false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
		case '\'':
			open, qtd = true, true
			for i++; i < len(s) && s[i] != '\''; i++ {
				cur.WriteByte(s[i])
			}
		case '"':
			open, qtd = true, true
			for i++; i < len(s) && s[i] != '"'; i++ {
				if s[i] == '\\' && i+1 < len(s) {
					i++
				}
				cur.WriteByte(s[i])
			}
		case '\\':
			if i+1 < len(s) {
				i++
				open = true
				cur.WriteByte(s[i])
			}
		case ';', '|', '&':
			flush()
			// "&&" and "||" are one separator, not two.
			if i+1 < len(s) && s[i+1] == c {
				out = append(out, shellToken{text: string([]byte{c, c})})
				i++
				continue
			}
			out = append(out, shellToken{text: string(c)})
		default:
			open = true
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}
