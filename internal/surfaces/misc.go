// internal/surfaces/misc.go
//
// The persistence surfaces that are not units and not pacman hooks:
// /etc/ld.so.preload, the systemd generator directories, /etc/profile.d, XDG
// autostart, and the per-user versions of the last two -- enumerated from the
// SCANNED ROOT's /etc/passwd, never from os/user or $HOME.
//
// Three rules govern everything below, and every one of them exists because the
// naive version of this check produces false positives at volume:
//
//   - Ownership is asked of internal/own, which resolves symlinks. An
//     enablement link, a /usr/bin shim, a desktop entry symlinked into a home:
//     all of them are unowned paths whose TARGET is packaged, and a check that
//     stops at the link reports every one of them.
//   - Directories are never subjects. No package owns a directory it did not
//     ship, and admin tooling creates them freely.
//   - "Could not tell" is never "found something". An unreadable home, an
//     unparseable entry, an own.Unresolved path: each is a finding.Gap
//     attributed to the path that produced it (INV-9), which is exit 3, not a
//     finding and never silence.
//
// INV-2: Exec= lines and preloaded object paths are parsed and resolved as
// strings. Nothing here runs, dlopens or stats-then-executes anything.
// INV-4: a pure function of (root, owners, cfg). No process CWD, no $HOME, no
// os/user (which consults the HOST's NSS and would answer for the wrong machine
// entirely under --offline-root), no writes.
//
// Severity ceiling, deliberately low: nothing in this file reaches
// SevCritical on its own. Each of these facts is individually weak -- an
// unowned object in ld.so.preload is the strongest of them and is still
// suspicious -- and the only thing that earns critical is correlation, which
// lives in internal/correlate. See the Limits text on every finding: an
// attacker who builds the payload into its own $pkgdir produces no unowned
// path at all and every check here goes silent.
package surfaces

import (
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"path"
	"strings"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/own"
)

// Rule identifiers. One per surface family, so a suppression or an adjudication
// can be scoped to a family without silencing the others.
const (
	RulePreload      = "surface-preload-unowned"
	RuleGenerator    = "surface-generator-unowned"
	RuleProfileD     = "surface-profiled-unowned"
	RuleAutostart    = "surface-autostart-unowned-exec"
	RuleMiscCoverage = "surface-misc-coverage"
)

// miscMaxFileBytes bounds one file read. /etc/ld.so.preload and a .desktop
// entry are both a few hundred bytes in practice; the cap exists because these
// are attacker-writable paths and an unbounded read of one is a denial of tool.
const miscMaxFileBytes = 1 << 20

// MiscConfig names the paths this check covers. Every field is relative to the
// scanned root with no leading slash, because that is the form os.Root's FS
// accepts and the form internal/own keys on.
//
// The zero value is usable: Misc fills in the defaults below. The fields exist
// so a distribution with different paths, or a test, can state them rather than
// patch them.
type MiscConfig struct {
	// PreloadPath is the dynamic-loader preload list.
	PreloadPath string

	// GeneratorDirs are systemd's generator directories. Generators run as
	// root at every daemon-reload, which is why they are here.
	GeneratorDirs []string

	// ProfileDirs are the shell-startup drop-in directories.
	ProfileDirs []string

	// SystemAutostartDirs are the system-wide XDG autostart directories.
	SystemAutostartDirs []string

	// UserAutostartDirs and UserGeneratorDirs are relative to each home
	// directory found in PasswdPath.
	UserAutostartDirs []string
	UserGeneratorDirs []string

	// PasswdPath is the ONLY source of per-user paths.
	PasswdPath string

	// CommandDirs are searched when a desktop entry's Exec names a bare
	// command rather than an absolute path (`Exec=nm-applet`, which 5 of the
	// reference system's 15 system autostart entries do). This is a minimal,
	// stated model of PATH: if the command is found and owned here the entry
	// is silent, and if it is not found the answer is a coverage gap, never
	// "unowned".
	CommandDirs []string

	// MaxFileBytes bounds one file read; 0 means miscMaxFileBytes.
	MaxFileBytes int64
}

// DefaultMiscConfig is the Arch layout.
//
// /run/systemd/*-generators is deliberately absent. It is a tmpfs that does not
// survive a boot, so it cannot carry persistence, and under --offline-root it
// is empty by construction -- scanning it would add noise on live systems in
// exchange for nothing.
func DefaultMiscConfig() MiscConfig {
	return MiscConfig{
		PreloadPath: "etc/ld.so.preload",
		GeneratorDirs: []string{
			"etc/systemd/system-generators",
			"etc/systemd/user-generators",
			"etc/systemd/system-environment-generators",
			"etc/systemd/user-environment-generators",
			"usr/lib/systemd/system-generators",
			"usr/lib/systemd/user-generators",
			"usr/lib/systemd/system-environment-generators",
			"usr/lib/systemd/user-environment-generators",
			"usr/local/lib/systemd/system-generators",
			"usr/local/lib/systemd/user-generators",
		},
		ProfileDirs:         []string{"etc/profile.d"},
		SystemAutostartDirs: []string{"etc/xdg/autostart"},
		UserAutostartDirs:   []string{".config/autostart"},
		UserGeneratorDirs: []string{
			".config/systemd/user-generators",
			".config/systemd/user-environment-generators",
			".local/share/systemd/user-generators",
		},
		PasswdPath:   "etc/passwd",
		CommandDirs:  []string{"usr/bin", "usr/local/bin"},
		MaxFileBytes: miscMaxFileBytes,
	}
}

func (c MiscConfig) withDefaults() MiscConfig {
	d := DefaultMiscConfig()
	if c.PreloadPath == "" {
		c.PreloadPath = d.PreloadPath
	}
	if c.GeneratorDirs == nil {
		c.GeneratorDirs = d.GeneratorDirs
	}
	if c.ProfileDirs == nil {
		c.ProfileDirs = d.ProfileDirs
	}
	if c.SystemAutostartDirs == nil {
		c.SystemAutostartDirs = d.SystemAutostartDirs
	}
	if c.UserAutostartDirs == nil {
		c.UserAutostartDirs = d.UserAutostartDirs
	}
	if c.UserGeneratorDirs == nil {
		c.UserGeneratorDirs = d.UserGeneratorDirs
	}
	if c.PasswdPath == "" {
		c.PasswdPath = d.PasswdPath
	}
	if c.CommandDirs == nil {
		c.CommandDirs = d.CommandDirs
	}
	if c.MaxFileBytes <= 0 {
		c.MaxFileBytes = d.MaxFileBytes
	}
	return c
}

// The Limits sentences. INV-6 is satisfied in the finding, not in the
// documentation: a user reading one line of output has to be told what it does
// not prove, and the thing it does not prove is large.
const (
	miscLimitCorrelation = "On its own this is weak evidence and it is rated accordingly. This phase catches " +
		"SLOPPY malware only: a payload built into its own $pkgdir and shipped inside the package's own file " +
		"list produces no unowned path at all, a self-consistent mtree, and an entry point that resolves to a " +
		"package-owned binary -- and then this check finds nothing. A clean result here is not evidence of a " +
		"clean system."
	miscLimitPreload = "An unowned preloaded object is not proof of injection: locally built libraries and " +
		"vendor-installed shims are legitimately preloaded. The object was never read, loaded or executed " +
		"(INV-2) -- only the path's ownership was resolved -- so this says nothing about what it contains. " +
		miscLimitCorrelation
	miscLimitGenerator = "A generator directory legitimately receives locally built and vendor-installed " +
		"generators, and this check reads only ownership: the file's contents were not analysed and nothing " +
		"was executed. " + miscLimitCorrelation
	miscLimitProfileD = "A hand-written shell-startup snippet is ordinary administration, so this is a report " +
		"of an unowned file on a high-signal path and nothing more. Only the drop-in directory is examined: " +
		"/etc/profile itself, /etc/bash.bashrc and per-shell rc files are not, so an equivalent line in one of " +
		"those would not appear here. " + miscLimitCorrelation
	miscLimitAutostart = "Ownership of the autostart entry itself is deliberately NOT the trigger: no package " +
		"owns anything in a home directory, so every per-user entry would qualify. Only the Exec= program is " +
		"resolved, and only its first token -- TryExec, D-Bus activation, an entry that launches an " +
		"interpreter, and a program that re-execs something else are not followed, so an unowned program " +
		"reached indirectly does not appear here. " + miscLimitCorrelation
)

// Misc reports the non-unit, non-hook persistence surfaces.
//
// root is the scanned tree ("/" for a live scan, the offline tree otherwise) and
// is only ever read. owners is the ownership oracle built over the same root --
// own.IndexIn, so that symlinks resolve; an oracle built by own.Index without a
// root would answer Unowned for every path reached through /bin or /lib and
// this function would report the lot.
//
// Findings are emitted in a fixed order: preload, generators, profile.d, system
// autostart, then per-user surfaces in /etc/passwd order. fs.ReadDir sorts, so
// two runs over an unchanged tree produce byte-identical output.
func Misc(root *os.Root, owners *own.Owners, cfg MiscConfig) finding.Result {
	cfg = cfg.withDefaults()
	var res finding.Result

	if root == nil {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: RuleMiscCoverage, Subject: "/",
			Reason: "no scan root was opened, so no persistence surface was examined",
		})
		return res
	}
	if owners == nil {
		// Without the oracle every rule here degenerates to "this path
		// exists", which is not a finding about anything. Saying so is the
		// only honest option; guessing is how a gap becomes an accusation.
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: RuleMiscCoverage, Subject: cfg.PreloadPath,
			Reason: "no ownership index was supplied, so no surface could be attributed to a package " +
				"or shown to be unowned",
		})
		return res
	}

	fsys := root.FS()

	miscAppend(&res, miscPreload(root, owners, cfg))
	for _, dir := range cfg.GeneratorDirs {
		miscAppend(&res, miscUnownedInDir(fsys, owners, dir, RuleGenerator,
			"file in a systemd generator directory is owned by no installed package",
			"systemd runs every generator in this directory as root at each daemon-reload, before any unit starts",
			miscLimitGenerator))
	}
	for _, dir := range cfg.ProfileDirs {
		miscAppend(&res, miscUnownedInDir(fsys, owners, dir, RuleProfileD,
			"file in a shell-startup drop-in directory is owned by no installed package",
			"every interactive login shell sources this directory",
			miscLimitProfileD))
	}
	for _, dir := range cfg.SystemAutostartDirs {
		miscAppend(&res, miscAutostartDir(root, fsys, owners, cfg, dir, ""))
	}

	users, gaps := PasswdUsers(fsys, cfg.PasswdPath)
	res.Gaps = append(res.Gaps, gaps...)
	for _, u := range users {
		miscAppend(&res, miscUserSurfaces(root, fsys, owners, cfg, u))
	}
	return res
}

func miscAppend(dst *finding.Result, src finding.Result) {
	dst.Findings = append(dst.Findings, src.Findings...)
	dst.Gaps = append(dst.Gaps, src.Gaps...)
}

// miscPreload reads the loader's preload list and reports the objects in it
// that no package owns.
//
// A single unowned path here injects into every dynamically linked process on
// the system, which makes it the highest-value surface in this file. It is also
// the one where "the file exists" must not be the trigger: an EMPTY
// /etc/ld.so.preload is common and benign, and a rule that fires on existence
// fires on it.
//
// Absence is not a finding and not a gap -- the reference system has no such
// file at all. Being unable to READ one that is there is a gap: every process
// on the machine is then loading something this scan cannot name.
func miscPreload(root *os.Root, owners *own.Owners, cfg MiscConfig) finding.Result {
	var res finding.Result

	data, err := miscReadFile(root, cfg.PreloadPath, cfg.MaxFileBytes)
	if err != nil {
		if miscIsNotExist(err) {
			return res
		}
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: RulePreload, Subject: cfg.PreloadPath,
			Reason: fmt.Sprintf("the loader preload list could not be read (%v); every dynamically linked "+
				"process on this system loads what it names, and this scan cannot say what that is", err),
		})
		return res
	}

	for _, tok := range miscPreloadTokens(string(data)) {
		if !strings.HasPrefix(tok, "/") {
			// glibc resolves a bare name through the loader search path
			// (DT_RUNPATH, /etc/ld.so.conf, the cache), none of which this
			// scan models. It is also the shape a comment line takes, since
			// the file has no comment syntax. Either way the object cannot be
			// pinned to one file, so it cannot be pinned to a package.
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: RulePreload, Subject: cfg.PreloadPath,
				Reason: fmt.Sprintf("preload entry %q is not an absolute path; glibc resolves it through the "+
					"loader search path, which this scan does not model, so its ownership is unknown", tok),
			})
			continue
		}
		pkg, st, err := owners.Resolve(tok)
		switch st {
		case own.Owned:
			_ = pkg
		case own.Unresolved:
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: RulePreload, Subject: strings.TrimPrefix(tok, "/"),
				Reason: fmt.Sprintf("preload entry named in %s could not be resolved (%v), so it could "+
					"neither be attributed to a package nor shown to be unowned", cfg.PreloadPath, err),
			})
		default:
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: RulePreload, SubjectKind: "file", Subject: strings.TrimPrefix(tok, "/"),
				Severity: finding.SevSuspicious,
				Summary:  "object preloaded into every process is owned by no installed package",
				Evidence: []string{
					fmt.Sprintf("named in %s as %q", cfg.PreloadPath, tok),
					"no installed package records this path, resolving symlinks",
					"the loader preloads it into every dynamically linked process started on this system",
				},
				Limits: miscLimitPreload,
			})
		}
	}
	return res
}

// miscPreloadTokens splits the preload list the way glibc does: on colons,
// spaces, tabs and newlines. There is no comment syntax, so nothing is treated
// as one -- a '#' line becomes a token and is reported as unresolvable rather
// than quietly dropped, because dropping it would also drop any real path an
// attacker put on the same line.
func miscPreloadTokens(s string) []string {
	var out []string
	for _, f := range strings.FieldsFunc(s, func(r rune) bool {
		return r == ':' || r == ' ' || r == '\t' || r == '\n' || r == '\r' || r == 0
	}) {
		if f != "" {
			out = append(out, f)
		}
	}
	return out
}

// miscUnownedInDir is the shared body of the generator and profile.d rules:
// every non-directory entry whose resolved path no package owns.
//
// Directories are excluded rather than reported. This is the same rule the
// *.wants triage needs and for the same reason: admin tooling and locally built
// software create directories under packaged trees, no package owns a directory
// it did not ship, and a check that reports them buries its own signal.
func miscUnownedInDir(fsys fs.FS, owners *own.Owners, dir, ruleID, summary, why, limits string) finding.Result {
	var res finding.Result

	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		if miscIsNotExist(err) {
			// The directory is simply not there. Nothing is hidden by a
			// surface that does not exist.
			return res
		}
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: ruleID, Subject: dir,
			Reason: fmt.Sprintf("directory could not be read (%v); anything planted in it is invisible "+
				"to this scan", err),
		})
		return res
	}

	for _, ent := range ents {
		if ent.IsDir() {
			continue
		}
		p := path.Join(dir, ent.Name())
		_, st, err := owners.Resolve(p)
		switch st {
		case own.Owned:
			continue
		case own.Unresolved:
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: ruleID, Subject: p,
				Reason: fmt.Sprintf("path could not be resolved (%v), so it could neither be attributed "+
					"to a package nor shown to be unowned", err),
			})
		default:
			ev := []string{"no installed package records this path, resolving symlinks"}
			if why != "" {
				ev = append(ev, why)
			}
			if ent.Type()&fs.ModeSymlink != 0 {
				ev = append(ev, "the path is a symlink, and its target is unowned too")
			}
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: ruleID, SubjectKind: "file", Subject: p,
				Severity: finding.SevSuspicious,
				Summary:  summary,
				Evidence: ev,
				Limits:   limits,
			})
		}
	}
	return res
}

// miscAutostartDir reports XDG autostart entries whose Exec program is unowned.
//
// The discriminator is the Exec target, NOT the entry file. In a home directory
// nothing is package-owned, so entry ownership would flag every autostart entry
// on every desktop; on the reference system the one user entry is a symlink to
// a packaged .desktop file, which a rule keyed on the link would also flag.
//
// scope labels the subject for a per-user directory (the user name) and is
// empty for a system one.
func miscAutostartDir(root *os.Root, fsys fs.FS, owners *own.Owners, cfg MiscConfig, dir, scope string) finding.Result {
	var res finding.Result

	ents, err := fs.ReadDir(fsys, dir)
	if err != nil {
		if miscIsNotExist(err) {
			return res
		}
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: RuleAutostart, Subject: dir,
			Reason: fmt.Sprintf("autostart directory could not be read (%v); entries in it start at "+
				"every session login and are invisible to this scan%s", err, miscScopeSuffix(scope)),
		})
		return res
	}

	for _, ent := range ents {
		if ent.IsDir() || !strings.HasSuffix(ent.Name(), ".desktop") {
			continue
		}
		entry := path.Join(dir, ent.Name())

		// A package-owned entry (directly, or through a symlink to one) is
		// ordinary: its Exec is whatever the package ships, and it is covered
		// by the integrity tier rather than by this rule.
		if _, st, _ := owners.Resolve(entry); st == own.Owned {
			continue
		}

		data, err := miscReadFile(root, entry, cfg.MaxFileBytes)
		if err != nil {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: RuleAutostart, Subject: entry,
				Reason: fmt.Sprintf("autostart entry could not be read (%v), so the program it starts at "+
					"login is unknown%s", err, miscScopeSuffix(scope)),
			})
			continue
		}
		exec, hidden, ok := miscDesktopExec(string(data))
		if hidden {
			// Hidden=true means the entry is ignored by every autostart
			// implementation. It starts nothing, so it is not a surface.
			continue
		}
		if !ok {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: RuleAutostart, Subject: entry,
				Reason: fmt.Sprintf("autostart entry names no usable Exec program (a variable, a glob, or "+
					"no Exec key at all), so what it starts at login could not be determined%s",
					miscScopeSuffix(scope)),
			})
			continue
		}

		target, st, rerr := miscResolveProgram(owners, cfg, exec)
		switch st {
		case own.Owned:
			continue
		case own.Unresolved:
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: RuleAutostart, Subject: entry,
				Reason: fmt.Sprintf("the program %q started by this autostart entry could not be resolved "+
					"(%v), so it could neither be attributed to a package nor shown to be unowned%s",
					exec, rerr, miscScopeSuffix(scope)),
			})
		default:
			ev := []string{
				fmt.Sprintf("entry %s runs %q at session start", entry, exec),
				fmt.Sprintf("no installed package records %s, resolving symlinks", target),
			}
			if scope != "" {
				ev = append(ev, fmt.Sprintf("per-user surface for %q, enumerated from %s", scope, cfg.PasswdPath))
			}
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: RuleAutostart, SubjectKind: "file", Subject: entry,
				Severity: finding.SevSuspicious,
				Summary:  "autostart entry starts a program owned by no installed package",
				Evidence: ev,
				Limits:   miscLimitAutostart,
			})
		}
	}
	return res
}

func miscScopeSuffix(scope string) string {
	if scope == "" {
		return ""
	}
	return fmt.Sprintf(" (user %q)", scope)
}

// miscDesktopExec pulls the Exec program out of a .desktop file's [Desktop
// Entry] group. It returns the program, whether the entry is disabled, and
// whether a usable program was found at all.
//
// It reads the FIRST token of Exec and strips the trailing %f/%U field codes.
// A token carrying a shell metacharacter or a variable yields nothing: a path
// this parser cannot pin to one concrete file must not be reported as unowned,
// because "unowned" would then be a statement about a string rather than about
// a file. INV-2 -- the value is never expanded and never run.
func miscDesktopExec(s string) (exec string, hidden, ok bool) {
	group := ""
	for _, line := range strings.Split(s, "\n") {
		line = strings.TrimSpace(strings.TrimSuffix(line, "\r"))
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			group = strings.TrimSuffix(strings.TrimPrefix(line, "["), "]")
			continue
		}
		if group != "Desktop Entry" {
			continue
		}
		key, val, cut := strings.Cut(line, "=")
		if !cut {
			continue
		}
		switch strings.TrimSpace(key) {
		case "Hidden":
			if strings.EqualFold(strings.TrimSpace(val), "true") {
				hidden = true
			}
		case "Exec":
			if exec != "" {
				// A repeated key: the first wins, as in the spec.
				continue
			}
			exec = miscFirstWord(strings.TrimSpace(val))
		}
	}
	if hidden {
		return "", true, false
	}
	if exec == "" || strings.ContainsAny(exec, "$*?[]{}`\"'") {
		return "", false, false
	}
	return exec, false, true
}

// miscFirstWord returns the first whitespace-separated word, honouring the
// desktop-entry escape for an embedded space ("\\ ").
func miscFirstWord(s string) string {
	var b strings.Builder
	for i := 0; i < len(s); i++ {
		switch s[i] {
		case '\\':
			if i+1 < len(s) {
				i++
				b.WriteByte(s[i])
			}
		case ' ', '\t':
			return b.String()
		default:
			b.WriteByte(s[i])
		}
	}
	return b.String()
}

// miscResolveProgram answers ownership for a program named by a desktop entry.
//
// An absolute path is resolved directly. A bare command name is looked for in
// cfg.CommandDirs -- a deliberately minimal, stated model of PATH, because 5 of
// the reference system's 15 system autostart entries name one (`Exec=nm-applet`)
// and every one of them is a packaged binary in /usr/bin. If no candidate is
// owned, the answer is Unresolved and not Unowned: this function does not know
// where the shell would have found it, and inventing a finding out of an
// unmodelled PATH is exactly the false accusation INV-9 exists to prevent.
func miscResolveProgram(owners *own.Owners, cfg MiscConfig, exec string) (target string, st own.State, err error) {
	if strings.HasPrefix(exec, "/") {
		_, st, err := owners.Resolve(exec)
		return strings.TrimPrefix(exec, "/"), st, err
	}
	if strings.Contains(exec, "/") {
		// A path relative to the launching directory, which no autostart
		// implementation defines usefully and this scan cannot reconstruct.
		return exec, own.Unresolved, fmt.Errorf("%w: %q is neither absolute nor a bare command name",
			own.ErrUnresolved, exec)
	}
	for _, dir := range cfg.CommandDirs {
		cand := path.Join(dir, exec)
		if _, st, _ := owners.Resolve(cand); st == own.Owned {
			return cand, own.Owned, nil
		}
	}
	return exec, own.Unresolved, fmt.Errorf("%w: bare command %q was not found in %s; this scan does not "+
		"model the loader or shell search path", own.ErrUnresolved, exec, strings.Join(cfg.CommandDirs, ", "))
}

// PasswdUser is one account from the scanned root's passwd file.
type PasswdUser struct {
	Name string
	// Home is the home directory as a path relative to the scanned root, with
	// no leading slash. Accounts whose home is the root itself, or is not
	// absolute, are not returned: they are system accounts, and walking "/" as
	// if it were a home invents surfaces that do not exist.
	Home string
}

// PasswdUsers enumerates accounts from the SCANNED ROOT's passwd file.
//
// This exists so that per-user surfaces come from the tree being scanned. Two
// things it deliberately is not: os/user (which consults the running host's
// NSS, so under --offline-root it answers for the wrong machine) and $HOME
// (which answers for whoever launched the scan). INV-4 -- the offline root is a
// parameter, not a second code path.
//
// A passwd file that cannot be read is a coverage gap covering every per-user
// surface at once: with no account list, no home directory is examined and the
// scan must say so rather than report per-user surfaces as clean.
//
// The shell field is not used as a filter. A nologin account's home is usually
// absent, which costs nothing to skip, and an account's shell is editable by
// anyone who can edit the file that lists it -- filtering on it would let the
// same write that plants an autostart entry also hide it.
func PasswdUsers(fsys fs.FS, passwdPath string) ([]PasswdUser, []finding.Gap) {
	data, err := fs.ReadFile(fsys, passwdPath)
	if err != nil {
		return nil, []finding.Gap{{
			RuleID: RuleMiscCoverage, Subject: passwdPath,
			Reason: fmt.Sprintf("the account list could not be read (%v), so no per-user persistence "+
				"surface (XDG autostart, per-user generators) was examined for any account", err),
		}}
	}

	var (
		users []PasswdUser
		gaps  []finding.Gap
		seen  = map[string]bool{}
	)
	for n, line := range strings.Split(string(data), "\n") {
		line = strings.TrimSuffix(line, "\r")
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		f := strings.Split(line, ":")
		if len(f) < 6 {
			gaps = append(gaps, finding.Gap{
				RuleID: RuleMiscCoverage, Subject: fmt.Sprintf("%s:%d", passwdPath, n+1),
				Reason: "passwd line has fewer than six fields, so no home directory could be read from " +
					"it and that account's per-user surfaces were not examined",
			})
			continue
		}
		name, home := f[0], f[5]
		if !strings.HasPrefix(home, "/") {
			if home != "" {
				gaps = append(gaps, finding.Gap{
					RuleID: RuleMiscCoverage, Subject: fmt.Sprintf("%s:%d", passwdPath, n+1),
					Reason: fmt.Sprintf("account %q has a non-absolute home directory %q, which this scan "+
						"cannot locate, so its per-user surfaces were not examined", name, home),
				})
			}
			continue
		}
		rel := strings.Trim(home, "/")
		if rel == "" || seen[rel] {
			// "/" is the conventional placeholder for an account with no home
			// (bin, nobody). It is not a home, and the surfaces beneath it are
			// already covered as system paths.
			continue
		}
		if miscHasDotDot(rel) {
			gaps = append(gaps, finding.Gap{
				RuleID: RuleMiscCoverage, Subject: fmt.Sprintf("%s:%d", passwdPath, n+1),
				Reason: fmt.Sprintf("account %q has a home directory %q containing a %q component, which "+
					"this scan refuses to interpret, so its per-user surfaces were not examined",
					name, home, ".."),
			})
			continue
		}
		seen[rel] = true
		users = append(users, PasswdUser{Name: name, Home: rel})
	}
	return users, gaps
}

func miscHasDotDot(rel string) bool {
	for _, c := range strings.Split(rel, "/") {
		if c == ".." || c == "." {
			return true
		}
	}
	return false
}

// miscUserSurfaces examines one account's per-user surfaces.
//
// The INV-9 distinction this function exists for:
//
//   - the home directory is ABSENT: not a finding and not a gap. An account
//     with no home is ordinary (nobody, ftp, a service account), there is
//     nothing to read and nothing was hidden.
//   - the home directory is PRESENT but unreadable: a coverage gap. An
//     unprivileged scan cannot see into another user's home, and reporting
//     "no autostart entries found" there would be a lie told with confidence.
//
// The two are told apart by the error from the read of the home directory
// itself, before any surface beneath it is touched: ENOENT is the first case,
// anything else -- EACCES above all -- is the second.
func miscUserSurfaces(root *os.Root, fsys fs.FS, owners *own.Owners, cfg MiscConfig, u PasswdUser) finding.Result {
	var res finding.Result

	if _, err := fs.ReadDir(fsys, u.Home); err != nil {
		if miscIsNotExist(err) {
			return res
		}
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: RuleMiscCoverage, Subject: u.Home,
			Reason: fmt.Sprintf("the home directory of %q exists but could not be read (%v); its per-user "+
				"persistence surfaces (XDG autostart, per-user generators) were not examined, and this "+
				"scan cannot say they are clean", u.Name, err),
		})
		return res
	}

	for _, sub := range cfg.UserAutostartDirs {
		miscAppend(&res, miscAutostartDir(root, fsys, owners, cfg, path.Join(u.Home, sub), u.Name))
	}
	for _, sub := range cfg.UserGeneratorDirs {
		miscAppend(&res, miscUnownedInDir(fsys, owners, path.Join(u.Home, sub), RuleGenerator,
			"file in a per-user systemd generator directory is owned by no installed package",
			fmt.Sprintf("systemd --user runs every generator in this directory at each daemon-reload "+
				"for %q", u.Name),
			miscLimitGenerator))
	}
	return res
}

// miscReadFile reads one file through the confined opener: resolved once,
// O_NOFOLLOW on the leaf, S_ISREG enforced on the descriptor that open
// returned. A symlink standing where a regular file is expected is refused
// rather than followed, which surfaces as a gap in the caller -- the honest
// answer, since the target was never looked at.
func miscReadFile(root *os.Root, rel string, max int64) ([]byte, error) {
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	if st.Size > max {
		return nil, fmt.Errorf("%s: %d bytes exceeds the %d-byte read cap", rel, st.Size, max)
	}
	return io.ReadAll(io.LimitReader(f, max))
}

// miscIsNotExist reports the "not here" case without swallowing a permission
// error along with it. That distinction is the whole of INV-9 on this surface:
// absent is silence, unreadable is a gap.
func miscIsNotExist(err error) bool {
	return errors.Is(err, fs.ErrNotExist)
}
