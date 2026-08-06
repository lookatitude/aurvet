// internal/surfaces/units.go
//
// systemd units, read from disk. Never from systemctl.
//
// That is the point of this file rather than an optimisation of it. `systemctl
// list-units` asks the running systemd what exists, and a compromised systemd is
// precisely the component that would answer wrong -- it can hide a unit, rewrite
// a name, or report an ExecStart it does not run. A unit file in an offline root
// cannot be interrogated by any running daemon at all, which is what makes INV-4
// hold here: this file is a pure function of (root, dirs) and nothing it does
// depends on the machine it runs on.
//
// INV-2: ExecStart values are TOKENISED, never executed, and nothing here
// resolves a command through a shell. The tokeniser is systemd's shape, not
// sh(1)'s -- systemd performs no globbing, no command substitution and no
// word-splitting of variables -- so reusing internal/hook's shell tokeniser
// would import semantics this format does not have.
//
// # What this parser handles
//
//   - sections, `Key=Value`, `#` and `;` comment lines
//   - repeated Exec* directives, in order. Last-one-wins would drop the earlier
//     command, and the earlier command is where a dropper sits.
//   - the `-`, `@`, `+`, `!`, `!!` and `:` prefixes, which are not part of the path
//   - trailing-backslash line continuation
//   - the empty-value reset (`ExecStart=` clears the list), which is how a
//     drop-in DISABLES what a packaged unit ran
//   - drop-ins: `<unit>.d/*.conf` in every search directory, in ascending
//     directory priority. This is load-bearing rather than completeness: an
//     unowned drop-in extends a packaged unit whose own digest still verifies,
//     so a scan that reads only unit files reads the wrong file.
//   - single and double quoting, and backslash escapes, in a command line
//   - relative commands, resolved against systemd's own search path by
//     UnitFindings (see unitSearchPath). The parser marks them Relative rather
//     than resolving them itself: resolution needs a filesystem, and a parser
//     that reaches for one stops being a function of its bytes.
//   - a relative command that resolves to NOTHING, which is not a coverage gap
//     but one of two determinate answers. With the `-` prefix it is a documented
//     optional dependency that is absent and nothing is reported; without it,
//     the name is unclaimed and whichever search-path directory receives it
//     first decides what systemd runs as root -- RuleUnitExecHijackable.
//

// # What it deliberately does NOT do (INV-6 -- a shape mis-parsed in silence is
// a check that goes quiet)
//
// Each of these is recorded on the value or the unit rather than guessed at, and
// LoadUnits turns the recording into a coverage gap:
//
//   - specifier expansion (%i, %n, %p, %H). A template unit's ExecStart names no
//     concrete file until it is instantiated, and this parser does not
//     instantiate. Reported unresolvable.
//   - variable expansion ($X, ${X}), including anything an EnvironmentFile= would
//     supply -- those files are not read. Reported unresolvable.
//   - a command run through an interpreter. `ExecStart=/usr/bin/sh -c '...'`
//     is attributed to sh, and the script text is NOT tokenised for further
//     paths, so a payload invoked from inside it is invisible here. This is a
//     real blind spot and it is stated rather than mitigated: guessing at shell
//     semantics is how a parser starts executing its input by accident.
//   - `.include`. Recorded as an unparsed shape, never followed.
//   - systemd's C-style escapes inside quotes (\xNN, \NNN, \uXXXX) are not
//     decoded; their presence is noted.
//   - a comment line ending in a backslash, which systemd continues into the
//     following line. Noted, because the following line is then NOT a directive
//     and this parser would read it as one.
//   - generated units. Generators run at boot and write to tmpfs, so an offline
//     root contains none of their output; the generator DIRECTORIES are a
//     surface covered elsewhere (misc.go), and the units they would produce are
//     invisible to any offline scan by construction.
//   - unit aliases (`Alias=`) and shadowing are RECORDED (ShadowedBy) but no
//     finding is derived from them here.
package surfaces

import (
	"bufio"
	"bytes"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"sort"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
	"golang.org/x/sys/unix"
)

// Rule and gap identifiers for the unit surface.
const (
	RuleUnitExecUnowned = "unit-execstart-unowned"

	// RuleUnitExecHijackable is a unit that names a BARE command which resolves
	// to no file in systemd's search path. It is named for what it is rather
	// than for what could not be done: the check ran and got a determinate
	// answer. systemd resolves a bare name at runtime, first match in the search
	// path wins, so a name that resolves to nothing today is a hole -- put a
	// file at that name in the winning directory and systemd runs it as root
	// with the unit's privileges, while the unit file's own digest still
	// verifies because the unit was never touched.
	RuleUnitExecHijackable = "unit-execstart-hijackable"

	RuleUnitCoverage = "unit-coverage"
)

// ErrUnparseable wraps every refusal to parse a unit. A refusal becomes a
// coverage gap (INV-9), never a finding: a unit we could not read is a unit we
// know nothing about, which is not the same as a clean one.
var ErrUnparseable = errors.New("unit could not be parsed")

// DefaultUnitDirs are systemd's system-wide unit directories relative to the
// scanned root, in ASCENDING priority: a unit in /etc/systemd/system shadows a
// same-named unit in /usr/lib/systemd/system. Order is part of the contract, not
// cosmetic.
//
// /run/systemd/system is included and is normally absent in an offline root --
// absence is ordinary and is not a gap. The `user` directories here are the
// SYSTEM-WIDE user-unit directories; per-user paths under a home come from the
// target root's passwd and belong to misc.go, never to the running user's
// environment (INV-4).
var DefaultUnitDirs = []string{
	"usr/lib/systemd/system",
	"usr/local/lib/systemd/system",
	"run/systemd/system",
	"etc/systemd/system",
	"usr/lib/systemd/user",
	"usr/local/lib/systemd/user",
	"etc/systemd/user",
}

// unitSuffixes are the unit types systemd loads from a search directory. A
// `.wants`/`.requires` directory is not in the list and a `.d` drop-in
// directory is not either; both are directories and both are handled by their
// own rules.
var unitSuffixes = []string{
	".service", ".socket", ".timer", ".path", ".mount", ".automount",
	".swap", ".target", ".slice", ".scope", ".device",
}

const (
	// maxUnitFileBytes bounds one unit or drop-in. Real units are under a few
	// KiB; the bound exists because a scanner buffer on attacker-supplied bytes
	// is not something this tool gets to have. Exceeding it is a GAP, never a
	// truncated parse: a truncated parse can miss the last ExecStart, and a unit
	// that lost its last ExecStart is indistinguishable from one that never had
	// one.
	maxUnitFileBytes = 1 << 20

	// maxUnitLineBytes bounds one physical line, including continuations.
	maxUnitLineBytes = 64 << 10
)

// unitLimitCorrelation is the honest ceiling on everything in this file and in
// wants.go, and it is carried in the FINDING rather than only in documentation
// (INV-6). A tool that overstates what an unowned path proves teaches its user
// to trust a clean result that was never earned.
const unitLimitCorrelation = "This is weak evidence on its own and is rated accordingly. An unowned path " +
	"proves only that no installed package records it: a hand-written administrator unit is " +
	"indistinguishable from a planted one, and this check cannot tell them apart. It is also blind to " +
	"the competent case -- a payload built into its own $pkgdir and shipped in the package's own file " +
	"list yields an ExecStart resolving to a package-owned binary, a self-consistent mtree and no " +
	"unowned file at all, and every check in this phase then goes silent. Correlation is what can earn " +
	"a critical rating; an unowned path alone cannot, and a clean result here is not evidence of absence."

// Exec is one Exec* value, decomposed. Nothing in it is ever executed.
type Exec struct {
	// Directive is the key as written: ExecStart, ExecStartPre, ExecStopPost...
	Directive string

	// Section is the section the value appeared in, so `[Socket] ExecStartPre`
	// is not silently reported as a service command.
	Section string

	// Origin is the file the value came from -- the unit itself or one of its
	// drop-ins. A command added by a drop-in must be attributable to the
	// drop-in, since that is the file an attacker adds and the unit's own digest
	// still verifies.
	Origin string

	// Raw is the value with its prefix characters stripped and continuations
	// joined, exactly as it will be tokenised.
	Raw string

	// Prefixes are the leading `-@+!:` characters, kept as evidence and removed
	// from Bin -- they are systemd syntax, not part of the path.
	Prefixes string

	// Bin is the first token: the program systemd would run.
	Bin string

	// Args are all tokens including Bin.
	Args []string

	// Resolvable reports that Bin names one concrete absolute path, so ownership
	// may be asked about it. When false, Unresolvable says why and the caller
	// must produce a coverage gap instead of a verdict.
	Resolvable   bool
	Unresolvable string

	// Relative marks the one unresolvable shape that is recoverable with a
	// filesystem behind it: a bare command name, which systemd looks up in its
	// own search path. Measured on the reference system, 669 units yield ~80 of
	// these -- systemd's own ldconfig.service really does say `ExecStart=ldconfig
	// -X` -- so treating them as permanent coverage gaps would report the live
	// system as incomplete on every run and drown the gaps that mean something.
	// UnitFindings resolves them against unitSearchPath.
	Relative bool
}

// Unit is one unit file as read from disk, plus the drop-ins merged into it.
type Unit struct {
	// Path is the unit file's path relative to the scanned root.
	Path string
	Dir  string
	Name string

	Description string
	Type        string
	WantedBy    []string
	RequiredBy  []string

	// Exec carries every Exec* value in file order, drop-ins last.
	Exec []Exec

	// DropIns are the paths of the drop-in files merged into this unit, in
	// merge order.
	DropIns []string

	// ShadowedBy is the path of a same-named unit in a higher-priority
	// directory, which is the file systemd actually loads. Recorded as evidence;
	// no finding is derived from it here.
	ShadowedBy string

	// Notes record modelled observations worth carrying as evidence -- an
	// applied reset, for instance. They are NOT coverage gaps: the parser
	// understood them.
	Notes []string

	// Unparsed records shapes this parser met and did NOT model. LoadUnits turns
	// each into a coverage gap, because a directive whose effect is unknown is
	// not a directive that can be called clean (INV-9).
	Unparsed []string
}

// ParseUnit parses one unit file's bytes. name is the unit's file name, used in
// messages; nothing is read from the filesystem.
func ParseUnit(name string, data []byte) (Unit, error) {
	u := Unit{Name: name}
	if err := u.Merge(name, data); err != nil {
		return Unit{}, err
	}
	return u, nil
}

// Merge applies a further file's directives to u, which is how drop-ins work:
// values append, and an empty value resets the directive's list.
func (u *Unit) Merge(origin string, data []byte) error {
	if bytes.IndexByte(data, 0) >= 0 {
		// A NUL makes the file mean two different things to two different
		// readers, so it is refused rather than interpreted.
		return fmt.Errorf("%w: %s contains a NUL byte", ErrUnparseable, origin)
	}
	lines, unparsed, err := logicalLines(origin, data)
	if err != nil {
		return err
	}
	u.Unparsed = append(u.Unparsed, unparsed...)

	section := ""
	for _, line := range lines {
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		if strings.HasPrefix(line, ".include") {
			u.Unparsed = append(u.Unparsed, fmt.Sprintf("%s uses .include, which this parser records and does "+
				"not follow; the included file's directives were not read", origin))
			continue
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key, val = strings.TrimSpace(key), strings.TrimSpace(val)

		if isExecDirective(key) {
			if val == "" {
				// systemd's reset semantics. This is the SUPPRESSION direction:
				// a drop-in that empties ExecStart disables what the packaged
				// unit ran, and a parser that appends here reports a command
				// that no longer executes.
				u.Exec = dropDirective(u.Exec, key)
				u.Notes = append(u.Notes, fmt.Sprintf("%s resets %s with an empty value: every earlier "+
					"%s was discarded, so the packaged command no longer runs", origin, key, key))
				continue
			}
			u.Exec = append(u.Exec, parseExec(key, section, origin, val))
			continue
		}

		switch {
		case strings.EqualFold(key, "Description"):
			u.Description = val
		case strings.EqualFold(key, "Type"):
			u.Type = val
		case strings.EqualFold(key, "WantedBy"):
			u.WantedBy = append(u.WantedBy, strings.Fields(val)...)
		case strings.EqualFold(key, "RequiredBy"):
			u.RequiredBy = append(u.RequiredBy, strings.Fields(val)...)
		}
	}
	return nil
}

// isExecDirective reports the keys whose value is a command line. The test is by
// PREFIX rather than against a fixed list: systemd has added Exec* keys over
// time (ExecCondition arrived in v243), and a key this tool does not know is
// still a key whose value gets executed.
func isExecDirective(key string) bool {
	return len(key) > len("Exec") && strings.HasPrefix(key, "Exec")
}

func dropDirective(execs []Exec, key string) []Exec {
	out := make([]Exec, 0, len(execs))
	for _, e := range execs {
		if !strings.EqualFold(e.Directive, key) {
			out = append(out, e)
		}
	}
	return out
}

// execPrefixChars are systemd's Exec value prefixes. They change how a command
// is run, never which file runs, so they are stripped from Bin and kept as
// evidence.
const execPrefixChars = "-@+!:"

func parseExec(directive, section, origin, val string) Exec {
	e := Exec{Directive: directive, Section: section, Origin: origin}
	i := 0
	for i < len(val) && strings.IndexByte(execPrefixChars, val[i]) >= 0 {
		i++
	}
	e.Prefixes, e.Raw = val[:i], strings.TrimSpace(val[i:])
	e.Args = systemdTokens(e.Raw)
	if len(e.Args) > 0 {
		e.Bin = e.Args[0]
	}

	switch {
	case e.Bin == "":
		e.Unresolvable = "the value carries no command"
	case strings.Contains(e.Bin, "%"):
		e.Unresolvable = "the command contains a systemd specifier, which this parser does not expand " +
			"(a template unit names no concrete file until it is instantiated)"
	case strings.Contains(e.Bin, "$"):
		e.Unresolvable = "the command contains a variable, which this parser does not expand " +
			"(EnvironmentFile= contents are not read)"
	case !strings.HasPrefix(e.Bin, "/"):
		e.Relative = true
		e.Unresolvable = "the command is not absolute; systemd resolves a bare name against its own " +
			"search path, so the file that runs is decided by which directory holds it first"
	default:
		e.Resolvable = true
	}
	return e
}

// logicalLines strips comments and joins backslash continuations, returning the
// directive lines plus the unmodelled shapes it met.
func logicalLines(origin string, data []byte) (lines, unparsed []string, err error) {
	var (
		out  []string
		cur  strings.Builder
		open bool
	)
	sc := bufio.NewScanner(bytes.NewReader(data))
	sc.Buffer(make([]byte, 0, 4<<10), maxUnitLineBytes)
	for sc.Scan() {
		raw := sc.Text()
		trimmed := strings.TrimSpace(raw)
		if !open {
			if trimmed == "" {
				continue
			}
			if strings.HasPrefix(trimmed, "#") || strings.HasPrefix(trimmed, ";") {
				if strings.HasSuffix(trimmed, `\`) {
					// systemd continues a comment across the backslash, so the
					// NEXT line is part of the comment and is not a directive.
					// This parser reads it as one, which is a mis-parse in the
					// direction of seeing a directive that does not apply.
					unparsed = append(unparsed, fmt.Sprintf("%s has a comment line ending in a backslash; "+
						"systemd continues the comment into the following line and this parser does "+
						"not, so the following line may have been read as a directive", origin))
				}
				continue
			}
		}
		if strings.HasSuffix(trimmed, `\`) {
			cur.WriteString(strings.TrimSuffix(trimmed, `\`))
			if !strings.HasSuffix(trimmed, ` \`) {
				cur.WriteString(" ")
			}
			open = true
			if cur.Len() > maxUnitLineBytes {
				return nil, nil, fmt.Errorf("%w: %s has a continued line over %d bytes",
					ErrUnparseable, origin, maxUnitLineBytes)
			}
			continue
		}
		cur.WriteString(trimmed)
		out = append(out, strings.TrimSpace(cur.String()))
		cur.Reset()
		open = false
	}
	if err := sc.Err(); err != nil {
		return nil, nil, fmt.Errorf("%w: %s: %v", ErrUnparseable, origin, err)
	}
	if open {
		// A file ending mid-continuation: keep what we have and say so.
		out = append(out, strings.TrimSpace(cur.String()))
		unparsed = append(unparsed, fmt.Sprintf("%s ends in an unterminated line continuation", origin))
	}
	return out, unparsed, nil
}

// systemdTokens splits one command line the way systemd does: on unquoted
// whitespace, honouring single quotes, double quotes and backslash escapes.
//
// It is a tokeniser and only a tokeniser (INV-2). systemd performs no globbing,
// no command substitution and no word splitting of variable values, so this must
// not either -- and that is why internal/hook's SHELL tokeniser is not reused
// here. Two formats that look alike are not the same format, and sharing a
// tokeniser between them would import sh(1) semantics into a file that has none.
//
// C-style escapes (\xNN, \NNN, \uXXXX) are NOT decoded; the caller notes their
// presence rather than half-decoding a path.
func systemdTokens(s string) []string {
	var (
		out  []string
		cur  strings.Builder
		open bool
	)
	flush := func() {
		if open {
			out = append(out, cur.String())
			cur.Reset()
			open = false
		}
	}
	for i := 0; i < len(s); i++ {
		c := s[i]
		switch c {
		case ' ', '\t', '\n', '\r':
			flush()
		case '\'':
			open = true
			for i++; i < len(s) && s[i] != '\''; i++ {
				cur.WriteByte(s[i])
			}
		case '"':
			open = true
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
		default:
			open = true
			cur.WriteByte(c)
		}
	}
	flush()
	return out
}

// LoadUnits reads every unit in dirs, merges each unit's drop-ins, and returns
// the units together with the coverage gaps for what it could not read.
//
// dirs are in ascending priority, so a later directory shadows an earlier one by
// unit name. Shadowed units are RETURNED rather than dropped -- the file is
// still on disk and its ownership is still a fact -- with ShadowedBy set.
//
// An ABSENT directory is not a gap: /run/systemd/system does not exist in an
// offline root and /usr/local/lib/systemd/system exists on almost no system.
// Anything else (EACCES, ENOTDIR) means the unit set is unknown, and an unknown
// unit set must not read as a clean one (INV-9).
func LoadUnits(root *os.Root, dirs []string) ([]Unit, []finding.Gap) {
	var (
		units []Unit
		gaps  []finding.Gap
	)
	if root == nil {
		return nil, []finding.Gap{{
			RuleID:  RuleUnitCoverage,
			Subject: "systemd unit directories",
			Reason:  "no scanned root was supplied, so no unit could be read",
		}}
	}

	// dropInDirs[dir] is the set of "<unit>.d" directories present in dir, so a
	// drop-in lookup costs no syscall for the overwhelming majority of units
	// that have none.
	dropInDirs := make(map[string]map[string]bool, len(dirs))
	// linked records unit-named symlinks in a search directory: they are not
	// parsed where they are found (the file lives elsewhere), and if the
	// elsewhere is outside the search path its ExecStart never gets read.
	type linkedUnit struct{ path, target string }
	var linked []linkedUnit

	for _, dir := range dirs {
		ents, err := readDirSorted(root, dir)
		if err != nil {
			if !errors.Is(err, fs.ErrNotExist) {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleUnitCoverage,
					Subject: dir,
					Reason: fmt.Sprintf("unit directory could not be listed (%v); the units it holds, "+
						"and every ExecStart in them, were not examined", err),
				})
			}
			continue
		}
		for _, ent := range ents {
			name := ent.Name()
			rel := path.Join(dir, name)
			if ent.IsDir() {
				if strings.HasSuffix(name, ".d") {
					if dropInDirs[dir] == nil {
						dropInDirs[dir] = map[string]bool{}
					}
					dropInDirs[dir][name] = true
				}
				continue
			}
			if !hasUnitSuffix(name) {
				continue
			}
			if ent.Type()&fs.ModeSymlink != 0 {
				target, lerr := fsx.ReadLinkConfined(root, rel)
				if lerr != nil {
					gaps = append(gaps, finding.Gap{
						RuleID:  RuleUnitCoverage,
						Subject: rel,
						Reason: fmt.Sprintf("unit is a symlink whose target could not be read (%v); its "+
							"ExecStart was not examined", lerr),
					})
					continue
				}
				linked = append(linked, linkedUnit{path: rel, target: resolveLinkPath(dir, target)})
				continue
			}
			data, err := readUnitFile(root, rel)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleUnitCoverage,
					Subject: rel,
					Reason:  fmt.Sprintf("unit could not be read (%v); its ExecStart was not examined", err),
				})
				continue
			}
			u, err := ParseUnit(name, data)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleUnitCoverage,
					Subject: rel,
					Reason:  fmt.Sprintf("unit could not be parsed (%v)", err),
				})
				continue
			}
			u.Path, u.Dir = rel, dir
			units = append(units, u)
		}
	}

	// Drop-ins, after every directory is known: systemd searches for
	// <unit>.d/*.conf in EVERY unit directory, not only the one holding the
	// unit, and an unowned drop-in under /etc extending a packaged unit is the
	// shape that leaves the packaged file's own digest intact.
	for i := range units {
		for _, dir := range dirs {
			dname := units[i].Name + ".d"
			if !dropInDirs[dir][dname] {
				continue
			}
			ddir := path.Join(dir, dname)
			ents, err := readDirSorted(root, ddir)
			if err != nil {
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleUnitCoverage,
					Subject: ddir,
					Reason: fmt.Sprintf("drop-in directory could not be listed (%v); directives it adds "+
						"to %s were not examined", err, units[i].Path),
				})
				continue
			}
			for _, ent := range ents {
				if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".conf") {
					continue
				}
				drel := path.Join(ddir, ent.Name())
				data, err := readUnitFile(root, drel)
				if err != nil {
					gaps = append(gaps, finding.Gap{
						RuleID:  RuleUnitCoverage,
						Subject: drel,
						Reason: fmt.Sprintf("drop-in could not be read (%v); the directives it adds to %s "+
							"were not examined", err, units[i].Path),
					})
					continue
				}
				if err := units[i].Merge(drel, data); err != nil {
					gaps = append(gaps, finding.Gap{
						RuleID:  RuleUnitCoverage,
						Subject: drel,
						Reason:  fmt.Sprintf("drop-in could not be parsed (%v)", err),
					})
					continue
				}
				units[i].DropIns = append(units[i].DropIns, drel)
			}
		}
	}

	// Shadowing, by name, later directory winning -- systemd's own rule.
	byName := map[string]int{}
	for i, u := range units {
		if prev, seen := byName[u.Name]; seen {
			units[prev].ShadowedBy = u.Path
		}
		byName[u.Name] = i
	}

	// A unit reachable only through a symlink into a directory this scan never
	// reads is a unit whose ExecStart nobody looked at. Silence there is exactly
	// what INV-9 forbids.
	loaded := map[string]bool{}
	for _, u := range units {
		loaded[u.Path] = true
	}
	for _, l := range linked {
		if l.target != "" && loaded[l.target] {
			continue
		}
		gaps = append(gaps, finding.Gap{
			RuleID:  RuleUnitCoverage,
			Subject: l.path,
			Reason: fmt.Sprintf("unit is a symlink to %q, which is not one of the unit files this scan "+
				"read; its ExecStart was not examined", l.target),
		})
	}

	// A shape met and not modelled is a directive whose effect is unknown, which
	// is a coverage gap rather than a silence.
	for _, u := range units {
		for _, n := range u.Unparsed {
			gaps = append(gaps, finding.Gap{RuleID: RuleUnitCoverage, Subject: u.Path, Reason: n})
		}
	}
	return units, gaps
}

func hasUnitSuffix(name string) bool {
	for _, s := range unitSuffixes {
		if strings.HasSuffix(name, s) {
			return true
		}
	}
	return false
}

// resolveLinkPath turns a symlink's target into a path relative to the SCANNED
// root. An absolute target is re-rooted at the scanned root rather than at the
// running filesystem's "/" -- that is the chroot reading, and the only one
// compatible with --offline-root, where /usr/lib/... means that tree's copy and
// not this machine's. A target escaping the root resolves to nothing.
func resolveLinkPath(dir, target string) string {
	var p string
	if strings.HasPrefix(target, "/") {
		p = path.Clean(strings.TrimPrefix(target, "/"))
	} else {
		p = path.Clean(path.Join(dir, target))
	}
	if p == ".." || strings.HasPrefix(p, "../") || p == "." || p == "/" {
		return ""
	}
	return p
}

// readUnitFile reads one unit or drop-in through the confined API, bounded.
// fsx.OpenConfined refuses a symlink leaf and anything that is not a regular
// file, so a unit replaced by a fifo is a gap rather than a hang.
func readUnitFile(root *os.Root, rel string) ([]byte, error) {
	f, _, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	data, err := io.ReadAll(io.LimitReader(f, maxUnitFileBytes+1))
	if err != nil {
		return nil, err
	}
	if len(data) > maxUnitFileBytes {
		return nil, fmt.Errorf("file is larger than the %d-byte limit and was refused rather than "+
			"truncated (a truncated parse can lose the last ExecStart)", maxUnitFileBytes)
	}
	return data, nil
}

// readDirSorted lists dir through the root, sorted by name.
//
// The sort is not cosmetic: os.File.ReadDir returns entries in directory order,
// which varies between two filesystems holding identical trees, and INV-4's
// purity claim covers the ORDER of the evidence as well as its content.
//
// Entry types come from the directory read itself, so a symlink is reported as a
// symlink and is not followed to decide whether it is a directory. That is what
// makes the "*.wants excludes directories" rule mean what it says.
func readDirSorted(root *os.Root, dir string) ([]os.DirEntry, error) {
	f, err := root.Open(dir)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	ents, err := f.ReadDir(-1)
	if err != nil {
		return nil, err
	}
	sort.Slice(ents, func(i, j int) bool { return ents[i].Name() < ents[j].Name() })
	return ents, nil
}

// unitSearchPath is systemd's compiled-in search path for a relative Exec
// command, in the order systemd searches it (Arch's build). A bare `ldconfig`
// runs the FIRST of these that exists, which is why the order is part of the
// evidence and not a detail: a file planted in an earlier directory shadows the
// packaged one, and that is a real attack rather than a hypothetical.
var unitSearchPath = []string{"usr/local/sbin", "usr/local/bin", "usr/sbin", "usr/bin"}

// presence is what a confined probe can honestly say about a path. The third
// value is not padding: an unreadable parent directory means "I do not know",
// and the severity of an unowned command depends on whether it is actually there.
type presence int

const (
	presenceUnknown presence = iota
	presencePresent
	presenceAbsent
)

// probePresence answers only "is something at this path", using the confined
// opener and nothing else. It never reads the file and never executes it (INV-2).
//
// A symlink or a non-regular file counts as PRESENT: fsx.OpenConfined refuses
// both, and it refuses them precisely because it got far enough to know they are
// there. Treating that refusal as absence would be reading an error message as a
// fact about the filesystem.
func probePresence(root *os.Root, rel string) presence {
	if root == nil {
		return presenceUnknown
	}
	f, _, err := fsx.OpenConfined(root, strings.TrimPrefix(rel, "/"))
	if err == nil {
		f.Close()
		return presencePresent
	}
	switch {
	case errors.Is(err, fsx.ErrSymlink), errors.Is(err, fsx.ErrNotRegular):
		return presencePresent
	case errors.Is(err, fs.ErrNotExist), errors.Is(err, unix.ENOTDIR):
		return presenceAbsent
	default:
		// EACCES, ELOOP, an escape, an unsafe path: an inability, not an answer.
		return presenceUnknown
	}
}

// UnitFindings asks the ownership oracle about every command a unit would run.
//
// Three answers, three different outputs, and the difference is the whole point
// (INV-9): Owned is silence, Unowned is a finding, and Unresolved is a coverage
// gap. A value this parser could not pin to one file is a gap too -- otherwise a
// unit whose ExecStart is "${DIR}/agent" reads as clean.
//
// A value that resolves to nothing is NOT in that last category, and separating
// it out is what took this surface from 8 blocking coverage gaps on a stock Arch
// host to 0 (the eight decomposed into six `-plymouth` optional dependencies and
// two bare `swtpm_ioctl` holes). "Could not be examined" must keep meaning an
// unreadable directory, an unparseable unit, or a specifier this parser cannot
// expand; a determinate answer filed under it is a false statement that also
// blocks `baseline init` under INV-3.
//
// Severity splits on PRESENCE, and the split is the difference between a rule
// that is usable on a real system and one that is not. Measured on the reference
// system: 3 of 4 unowned commands are absent files named by PACKAGED units
// (systemd's own quotaon-root.service names /usr/bin/quotaon, and quota-tools is
// not installed; mdmonitor-oneshot.service names an mdadm_env.sh that mdadm no
// longer ships). Nothing can be executed from a path that holds no file, so
// those are reported at info -- visible, not alarming -- while a file that is
// really there and belongs to no package stays suspicious.
//
// root may be nil: the checks then degrade to "presence unknown", which is the
// higher severity, never a silence.
func UnitFindings(root *os.Root, units []Unit, owners *own.Owners) ([]finding.Finding, []finding.Gap) {
	var (
		findings []finding.Finding
		gaps     []finding.Gap
	)
	if owners == nil {
		return nil, []finding.Gap{{
			RuleID:  RuleUnitCoverage,
			Subject: "systemd units",
			Reason:  "no ownership index was supplied, so no ExecStart could be attributed to a package",
		}}
	}
	// The search-path winner is a property of the ROOT, not of any one unit, so
	// it is probed once. It is also the same fact for every hijackable finding,
	// which is why they can be compared against each other.
	winner := findSearchPathWinner(root)

	for _, u := range units {
		seen := map[string]bool{}
		for _, e := range u.Exec {
			out, bin, via, gap := unitExecTarget(root, u, e)
			switch out {
			case execGap:
				gaps = append(gaps, *gap)
				continue
			case execOptionalAbsent:
				// The unit author declared the command optional and it is not
				// here. Determinate, and nothing to say about it.
				continue
			case execHijackable:
				if seen["bare:"+e.Bin] {
					continue
				}
				seen["bare:"+e.Bin] = true
				findings = append(findings, unitHijackableFinding(u, e, winner))
				continue
			}
			if seen[bin] {
				continue
			}
			seen[bin] = true

			_, st, err := owners.Resolve(bin)
			switch st {
			case own.Owned:
				// The ordinary case, and the reason this rule is quiet on a
				// stock root: the link may be unowned, the binary is not.
				continue
			case own.Unresolved:
				gaps = append(gaps, finding.Gap{
					RuleID:  RuleUnitCoverage,
					Subject: u.Path,
					Reason: fmt.Sprintf("%s = %s (in %s): ownership of %s could not be determined (%v), "+
						"so it is reported as unknown rather than as unowned",
						e.Directive, e.Raw, e.Origin, bin, err),
				})
				continue
			}

			sev, presenceNote := finding.SevSuspicious, "the file is present and belongs to no installed package"
			switch probePresence(root, bin) {
			case presenceAbsent:
				sev = finding.SevInfo
				presenceNote = "no file exists at this path, so the unit cannot currently start it; " +
					"this becomes suspicious the moment the file appears"
			case presenceUnknown:
				presenceNote = "whether a file exists at this path could not be determined, so the " +
					"higher severity was kept"
			}

			evidence := []string{
				fmt.Sprintf("%s = %s%s (from %s)", e.Directive, e.Prefixes, e.Raw, e.Origin),
				fmt.Sprintf("%s is owned by no installed package", bin),
				presenceNote,
				fmt.Sprintf("unit file %s: %s", u.Path, unitOwnerText(owners, u.Path)),
			}
			if via != "" {
				evidence = append(evidence, via)
			}
			findings = append(findings, finding.Finding{
				RuleID:      RuleUnitExecUnowned,
				SubjectKind: "systemd-unit",
				Subject:     u.Path,
				Severity:    sev,
				Summary: fmt.Sprintf("unit %s runs %s, which no installed package owns",
					u.Name, bin),
				Evidence: append(evidence, unitExtraEvidence(u)...),
				Limits:   unitLimitCorrelation,
			})
		}
	}
	return findings, gaps
}

// execOutcome is what asking "which file would this Exec value run" can produce.
// Four answers rather than two, because collapsing them is exactly what put six
// documented optional dependencies and two real hijack surfaces into one
// undifferentiated gap list.
type execOutcome int

const (
	// execResolved: one concrete path, subject to the ownership verdict.
	execResolved execOutcome = iota

	// execGap: this parser could not pin the value to a file at all (a
	// specifier, a variable, an empty value, or no root to resolve against).
	// INV-9 -- an inability, not an answer.
	execGap

	// execOptionalAbsent: a BARE command carrying systemd's `-` prefix that
	// resolves to nothing. The unit's own author declared the command optional
	// and systemd ignores its failure; the command is not here. That is a
	// determinate answer, and reporting it as "could not be examined" would be
	// false. Neither a gap nor a finding.
	execOptionalAbsent

	// execHijackable: a bare command, NOT marked optional, that resolves to
	// nothing. A finding -- see RuleUnitExecHijackable.
	execHijackable
)

// unitExecTarget decides which file an Exec value names.
//
// The relative case is resolved against systemd's own search path rather than
// guessed at or written off: the FIRST directory holding the name is the file
// that runs, which is also why the walk stops at the first PRESENT candidate
// rather than the first OWNED one. Stopping at the first owned candidate would
// silently absolve a name planted in /usr/local/bin ahead of the packaged
// /usr/bin copy -- reporting the packaged file and missing the shadow.
//
// The `-` prefix suppresses only the UNRESOLVED bare case, and the conjunction
// is deliberate: `-` says "failure is ignored", not "this command is
// uninteresting". `ExecStartPre=-/usr/local/bin/evil` resolves, and it gets the
// ordinary ownership verdict like any other value -- otherwise an attacker buys
// an exemption for the price of one character.
func unitExecTarget(root *os.Root, u Unit, e Exec) (out execOutcome, bin, via string, gap *finding.Gap) {
	if e.Resolvable {
		return execResolved, e.Bin, "", nil
	}
	if !e.Relative || root == nil {
		return execGap, "", "", &finding.Gap{
			RuleID:  RuleUnitCoverage,
			Subject: u.Path,
			Reason: fmt.Sprintf("%s = %s (in %s) was not attributed to a package: %s",
				e.Directive, e.Raw, e.Origin, e.Unresolvable),
		}
	}
	for _, dir := range unitSearchPath {
		cand := path.Join(dir, e.Bin)
		if probePresence(root, cand) == presencePresent {
			return execResolved, "/" + cand, fmt.Sprintf("%q is a bare command name; it was resolved to /%s, "+
				"the first entry in systemd's search path (%s) that holds a file of that name",
				e.Bin, cand, strings.Join(unitSearchPath, ", ")), nil
		}
	}
	if strings.Contains(e.Prefixes, "-") {
		return execOptionalAbsent, "", "", nil
	}
	return execHijackable, "", "", nil
}

// searchPathWinner is which search-path directory would capture a bare name, and
// what is known about who can write to it.
//
// Winner is the first entry in unitSearchPath that EXISTS in the scanned root.
// Naming the first entry unconditionally would send an operator to inspect a
// directory that is not there; a directory that does not exist cannot receive a
// file without also being created, which is a larger and separately visible
// change. Skipped records the entries passed over, so the reasoning is in the
// evidence rather than in this comment.
type searchPathWinner struct {
	Dir     string   // relative path; "" when no search-path directory exists
	Skipped []string // earlier entries absent from the root
	Mode    fs.FileMode
	Known   bool // whether Mode could be read at all (INV-9)
}

// writableByNonOwner reports the fact severity turns on: a group- or
// world-writable directory can receive the planted name from someone who is not
// root, which is a privilege boundary this hole crosses. An attacker who already
// has root does not need the hole at all.
func (w searchPathWinner) writableByNonOwner() bool {
	return w.Known && w.Mode.Perm()&0o022 != 0
}

// findSearchPathWinner probes the search path through the confined root. It
// opens directories only to stat them; nothing is read and nothing is executed.
func findSearchPathWinner(root *os.Root) searchPathWinner {
	w := searchPathWinner{}
	if root == nil {
		return w
	}
	for _, dir := range unitSearchPath {
		f, err := root.Open(dir)
		if err != nil {
			if errors.Is(err, fs.ErrNotExist) || errors.Is(err, unix.ENOTDIR) {
				w.Skipped = append(w.Skipped, dir)
				continue
			}
			// EACCES on a search-path directory: it is there, and what its mode
			// is cannot be said. That is the higher severity, never a silence.
			w.Dir = dir
			return w
		}
		st, serr := f.Stat()
		f.Close()
		if serr != nil || !st.IsDir() {
			w.Skipped = append(w.Skipped, dir)
			continue
		}
		w.Dir, w.Mode, w.Known = dir, st.Mode(), true
		return w
	}
	return w
}

// unitLimitHijackable is the INV-6 text for RuleUnitExecHijackable, and its
// first job is to say that this is a statement about the search path AS IT IS
// NOW. systemd performs the lookup at runtime, so nothing here predicts what
// will run -- it reports that nothing currently would, and which directory
// decides that.
const unitLimitHijackable = "systemd resolves a bare command name at RUNTIME, so this is a statement about " +
	"the search path as it stands in the scanned root at this moment and not a prediction about what will " +
	"run. Nothing is currently executed from this name; the finding is that the name is unclaimed and the " +
	"first search-path directory to receive it decides what runs, while the unit file's own digest continues " +
	"to verify because the unit is never modified. This is weak evidence on its own and is rated accordingly: " +
	"a packaged unit naming a command from an uninstalled optional dependency looks exactly like this, and " +
	"the check cannot tell the two apart. It is also blind to the competent case -- a payload built into its " +
	"own $pkgdir and shipped in the package's file list yields an ExecStart resolving to a package-owned " +
	"binary and every check in this phase goes silent."

// unitHijackableFinding builds the finding for a bare command that resolves to
// nothing. The evidence names the unit, the directive, the bare name, the search
// path consulted IN ORDER, and which directory would win -- an operator who
// cannot see the winning directory cannot check the claim or fix the hole.
func unitHijackableFinding(u Unit, e Exec, w searchPathWinner) finding.Finding {
	sev := finding.SevInfo
	var winnerNote string
	switch {
	case w.Dir == "":
		winnerNote = fmt.Sprintf("none of the search-path directories (%s) exists in this root, so the "+
			"name could only be captured by creating one of them first",
			strings.Join(unitSearchPath, ", "))
	case !w.Known:
		sev = finding.SevSuspicious
		winnerNote = fmt.Sprintf("a file placed at /%s/%s would be found first; who may write to that "+
			"directory could not be determined, so the higher severity was kept", w.Dir, e.Bin)
	case w.writableByNonOwner():
		sev = finding.SevSuspicious
		winnerNote = fmt.Sprintf("a file placed at /%s/%s would be found first, and that directory is "+
			"mode %#o -- group- or world-writable, so a non-root user can plant the name",
			w.Dir, e.Bin, w.Mode.Perm())
	default:
		winnerNote = fmt.Sprintf("a file placed at /%s/%s would be found first; that directory is mode "+
			"%#o, so planting the name needs its owner's privileges already",
			w.Dir, e.Bin, w.Mode.Perm())
	}

	evidence := []string{
		fmt.Sprintf("%s = %s%s (from %s)", e.Directive, e.Prefixes, e.Raw, e.Origin),
		fmt.Sprintf("the command %q is a bare name: it is not a path, so systemd looks it up in its own "+
			"search path", e.Bin),
		fmt.Sprintf("search path consulted, in order: %s", strings.Join(unitSearchPath, ", ")),
		"no directory in that search path currently holds a file of that name",
		winnerNote,
	}
	if len(w.Skipped) > 0 {
		evidence = append(evidence, fmt.Sprintf("earlier search-path entries absent from this root and "+
			"therefore passed over: %s", strings.Join(w.Skipped, ", ")))
	}
	return finding.Finding{
		RuleID:      RuleUnitExecHijackable,
		SubjectKind: "systemd-unit",
		Subject:     u.Path,
		Severity:    sev,
		Summary: fmt.Sprintf("unit %s runs the bare command %q, which resolves to no file in systemd's "+
			"search path", u.Name, e.Bin),
		Evidence: append(evidence, unitExtraEvidence(u)...),
		Limits:   unitLimitHijackable,
	}
}

// unitExtraEvidence adds the facts that change how the finding should be read: a
// command contributed by a drop-in, and a unit that is shadowed and therefore
// not the file systemd loads.
func unitExtraEvidence(u Unit) []string {
	var out []string
	if len(u.DropIns) > 0 {
		out = append(out, fmt.Sprintf("drop-ins merged into this unit: %s", strings.Join(u.DropIns, ", ")))
	}
	if u.ShadowedBy != "" {
		out = append(out, fmt.Sprintf("this unit is shadowed by %s, which is the file systemd loads", u.ShadowedBy))
	}
	return out
}

// unitOwnerText renders the ownership of a path for evidence, keeping the third
// state visible: "could not be determined" is not "unowned".
func unitOwnerText(owners *own.Owners, rel string) string {
	pkg, st, err := owners.Resolve(rel)
	switch st {
	case own.Owned:
		return fmt.Sprintf("owned by %s", pkg)
	case own.Unowned:
		return "owned by no installed package"
	default:
		return fmt.Sprintf("ownership could not be determined (%v)", err)
	}
}
