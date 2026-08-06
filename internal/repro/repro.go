// internal/repro/repro.go

// Package repro builds the redacted, self-contained fixture root that
// `aurvet bundle <fingerprint>` emits: spec §12's "redacted reproducer = fixture
// root", which "costs almost nothing because offline-root already exists, and
// makes every false-positive report a test case".
//
// The name is `repro` and not `bundle` because internal/bundle is the INDICATOR
// bundle -- signed detection data fetched from a publisher. Two things called
// "bundle" in one security tool is one confusion too many.
//
// # What a bundle is for, and who is about to read it
//
// The operator is about to attach the output to a public issue. Everything here
// is built around that single fact. A tool that says "redacted" when it means
// "mostly redacted" has done real harm, so this package states, in the emitted
// README and in the MANIFEST, exactly what each file is: its own bytes, a
// filtered subset of its own bytes, a placeholder, or something synthesised.
//
// # The redaction rule, in one sentence
//
// A FILE'S OWN BYTES ARE NEVER COPIED. Every emitted regular file is either a
// zero-byte placeholder or a file RECONSTRUCTED from the handful of directives
// the compiled checks actually parse.
//
// The inversion matters: an allowlist of directives means a new key in a unit
// file is withheld by default. A denylist ("drop Environment=") would leak
// every directive nobody thought of, which is the set that grows.
//
// # Command lines are reduced to their program
//
// The allowlist alone is not enough, and the gap it left was live: a kept
// `ExecStart=` was emitted whole, arguments included, so
// `ExecStart=/usr/local/bin/backup --token hunter2` published the token. The
// directive was on the allowlist for a good reason and the secret rode along
// inside it.
//
// So an Exec-family value is reduced to its PROGRAM -- systemd's prefix
// characters plus the first token -- and every remaining argument is withheld and
// counted. This costs no fidelity, which is what makes it the right fix rather
// than a trade: internal/surfaces resolves ownership, resolvability and
// hijackability from Exec.Bin, the first token, and nothing in any rule reads
// Exec.Args beyond it. The fingerprint is over rule, subject kind, subject and
// scope class, so it does not move either -- the round-trip test proves that
// rather than assuming it.
//
// An argument is uninspected free text on the reporter's machine. That is the
// same reason Environment= is dropped, applied one level deeper, and the
// tokeniser is shared with internal/surfaces so the program kept here is the
// program the check resolves there.
//
// # Home paths
//
// Occurrences of /home/<user>/... inside emitted CONTENT are rewritten to
// /home/redacted/redacted -- a systemd unit on the reference machine points at
// /home/<user>/Projects/<employer>/..., which is a directory layout no one
// should have to publish to file a false-positive report.
//
// The one exception is stated loudly rather than hidden: a home path that is
// ITSELF part of the reproduction -- an emitted file, or the program an emitted
// entry point resolves to -- keeps its own spelling, because without it the
// finding does not reproduce and the bundle would be decoration. Every such path
// is listed in Report.HomePaths, printed on stdout, and named in the README, so
// the operator sees exactly which ones they are about to publish before they do.
//
// # What cannot be reproduced, named rather than faked
//
// A bundle that quietly fails to reproduce its finding is worse than no bundle:
// the maintainer runs it, sees nothing, and closes the report. Classify() is an
// explicit table and its DEFAULT IS "not guaranteed", so a rule added later
// fails closed into an honest label instead of inheriting a promise.
//
// Nothing here executes anything (INV-2) and nothing is written under the
// examined tree (INV-5, enforced by the caller).
package repro

import (
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/surfaces"
)

// Schema versions MANIFEST.json.
const Schema = 1

// maxContentBytes caps a reconstructed file. A unit file is a few hundred bytes;
// anything near this is not a unit file, and a reproducer is not a place to find
// out what it is instead.
const maxContentBytes = 256 << 10

// maxPaths caps how many paths one bundle describes. A finding names a handful;
// the cap exists so a crafted evidence list cannot turn `bundle` into a
// filesystem copier.
const maxPaths = 512

// maxLinkDepth bounds symlink chasing.
const maxLinkDepth = 8

// Disposition is what happened to one emitted path. It is the honesty of the
// bundle expressed as data: MANIFEST.json carries one of these per file, so a
// maintainer reading the fixture never has to guess whether an empty file was
// empty on the reporter's machine.
type Disposition string

const (
	// DispFiltered is a file RECONSTRUCTED from the directives the checks parse.
	// Everything else in the original file is gone.
	DispFiltered Disposition = "filtered"

	// DispPlaceholder is a zero-byte stand-in. The path, the mode and the mtime
	// are real; the contents were never read.
	DispPlaceholder Disposition = "placeholder"

	// DispSymlink is a symlink, reproduced by its target TEXT (never followed).
	DispSymlink Disposition = "symlink"

	// DispDirectory is a directory.
	DispDirectory Disposition = "directory"

	// DispSynthesised is a file this package invented -- a package database
	// entry rebuilt from parsed fields, a minimal pacman.conf, a passwd holding
	// only the users the bundle already reveals. Nothing in one of these came
	// off the reporter's disk verbatim.
	DispSynthesised Disposition = "synthesised"
)

// Entry is one path in the bundle.
type Entry struct {
	Path        string      `json:"path"`
	Disposition Disposition `json:"disposition"`
	Mode        string      `json:"mode,omitempty"`
	Bytes       int         `json:"bytes"`
	Target      string      `json:"target,omitempty"`
	Note        string      `json:"note,omitempty"`
}

// Reproduction says whether running the tool against this bundle will produce
// the finding again, and when it will not, why not.
type Reproduction struct {
	// Reproduces is true only when the compiled classification says this rule
	// needs nothing the bundle withholds.
	Reproduces bool `json:"reproduces"`

	// Why is populated whenever Reproduces is false. It names the class, not the
	// individual finding: "this kind of finding cannot be reproduced from a
	// bundle, and here is what it would need".
	Why string `json:"why,omitempty"`

	// Command is the invocation that reproduces it.
	Command string `json:"command"`
}

// Report is what Build produced.
type Report struct {
	Dir          string       `json:"dir"`
	Schema       int          `json:"schema_version"`
	RuleID       string       `json:"rule_id"`
	SubjectKind  string       `json:"subject_kind"`
	Subject      string       `json:"subject"`
	Severity     string       `json:"severity"`
	FindingID    string       `json:"finding_id"`
	Summary      string       `json:"summary"`
	Reproduction Reproduction `json:"reproduction"`

	// Files is every path in the bundle with what was done to it.
	Files []Entry `json:"files"`

	// Packages names the local-database entries that were rebuilt.
	Packages []string `json:"packages"`

	// HomePaths are the emitted paths that lie under /home. They are published
	// as-is because the finding is about them; they are listed here so that
	// "published as-is" is a thing the operator SEES rather than discovers.
	HomePaths []string `json:"home_paths"`

	// RedactedEntryPoint names the Exec program under /home that was redacted,
	// when there was one. It is `json:"-"` and absent from the README ON PURPOSE:
	// the operator publishes those two files, and a field that spelled out the
	// very path the redaction removed would put it back. The CLI prints it to the
	// operator's terminal, which is the one place it belongs.
	RedactedEntryPoint string `json:"-"`

	// Gaps records what the builder itself could not do (INV-9): a path it could
	// not read, a link it could not follow. A bundle missing a file it meant to
	// include must say so, or the maintainer debugs the wrong absence.
	Gaps []finding.Gap `json:"-"`
}

// Input is one bundle's whole input.
type Input struct {
	// Root is the scanned root, as the scan resolved it.
	Root string

	// Finding is the finding to reproduce, and FindingID the id the operator
	// typed.
	Finding   finding.Finding
	FindingID string

	// Packages is the parsed local package set, used both to decide which
	// database entries the bundle needs and to keep every ownership verdict
	// inside it identical to the one on the reporter's machine.
	Packages []alpm.Package

	// Version is the build identity, recorded in the README so a maintainer
	// knows which binary produced the finding.
	Version string

	// Now is the build time (INV-4: passed in, never read from the clock).
	Now time.Time
}

// Build writes the fixture root at dir and returns what it contains.
//
// dir must not exist, or must be empty. Refusing a populated directory is not
// tidiness: the bundle's whole claim is that it is self-contained, and a bundle
// mixed with whatever was already there reproduces something nobody can
// characterise.
func Build(dir string, in Input) (Report, error) {
	if err := prepareDir(dir); err != nil {
		return Report{}, err
	}
	rep := Report{
		Dir: dir, Schema: Schema,
		RuleID: in.Finding.RuleID, SubjectKind: in.Finding.SubjectKind,
		Subject: in.Finding.Subject, Severity: in.Finding.Severity.String(),
		FindingID: in.FindingID, Summary: in.Finding.Summary,
	}
	rep.Reproduction = Classify(in.Finding.RuleID)

	root, err := os.OpenRoot(in.Root)
	if err != nil {
		return Report{}, fmt.Errorf("the scanned root %s could not be opened: %w", in.Root, err)
	}
	defer root.Close()

	b := &builder{in: in, root: root, dir: dir,
		wanted: map[string]bool{}, required: map[string]bool{}}
	b.collectPaths()
	b.emitPaths(&rep)
	b.emitPackages(&rep)
	b.emitSynthesised(&rep)
	rep.Gaps = b.gaps
	if b.entryPointRedacted != "" {
		rep.RedactedEntryPoint = b.entryPointRedacted
		if rep.Reproduction.Reproduces {
			rep.Reproduction.Reproduces = false
			rep.Reproduction.Why = "the program this finding names lies under a home directory. " +
				"Publishing its path would publish one operator's directory layout in a " +
				"false-positive report, so it was replaced. The finding may well reappear with " +
				"the same id -- an unowned program is unowned under any name -- but its EVIDENCE " +
				"now points somewhere that never existed, so what a maintainer would debug is " +
				"not what happened. Treated as not faithfully reproducing for that reason. The " +
				"real path was printed to the terminal that built this bundle and is deliberately " +
				"absent from the bundle itself"
		}
	}

	sort.Slice(rep.Files, func(i, j int) bool { return rep.Files[i].Path < rep.Files[j].Path })
	sort.Strings(rep.Packages)
	sort.Strings(rep.HomePaths)

	if err := writeManifest(dir, rep); err != nil {
		return Report{}, err
	}
	if err := writeReadme(dir, in, rep); err != nil {
		return Report{}, err
	}
	return rep, nil
}

func prepareDir(dir string) error {
	entries, err := os.ReadDir(dir)
	switch {
	case errors.Is(err, os.ErrNotExist):
		return os.MkdirAll(dir, 0o755)
	case err != nil:
		return err
	case len(entries) > 0:
		return fmt.Errorf("%s is not empty; a bundle must be self-contained, and one mixed with "+
			"whatever was already in the directory reproduces something nobody can characterise", dir)
	}
	return nil
}

// builder carries one build's mutable state.
type builder struct {
	in     Input
	root   *os.Root
	dir    string
	wanted map[string]bool // root-relative paths, no leading slash
	order  []string

	// required marks the paths the bundle MUST carry: the subject, and whatever
	// is reachable from it by symlink. A path that only appeared inside an
	// evidence line is OPPORTUNISTIC -- evidence quotes command lines, glob
	// triggers and prose, so a token that is not there is usually not a path at
	// all. Only a missing REQUIRED path is a coverage gap; treating every
	// unresolvable evidence token as one would fill a healthy bundle with gaps
	// and train the reader to ignore them.
	required map[string]bool
	gaps     []finding.Gap

	// entryPointRedacted names an Exec program that lies under /home and was
	// therefore redacted out of the bundle. It downgrades the reproduction
	// verdict: the finding is ABOUT that program, so with it redacted the bundle
	// no longer reproduces the finding, and saying otherwise would be the lie
	// this whole package is arranged to avoid.
	entryPointRedacted string
}

func (b *builder) gap(subject, reason string) {
	b.gaps = append(b.gaps, finding.Gap{RuleID: "bundle-coverage", Subject: subject, Reason: reason})
}

// -- deciding which paths the bundle needs ------------------------------------

// pathish matches the absolute-looking and root-relative paths a finding's
// subject and evidence carry. It is deliberately anchored on the top-level
// directories a packaged system uses: a looser pattern would drag arbitrary
// words out of prose and turn a reproducer into a scattergun.
var pathish = regexp.MustCompile(
	`(?:^|[\s"'=(\[,;])(/?(?:etc|usr|opt|srv|boot|var|run|home)/[A-Za-z0-9._@+~-]+(?:/[A-Za-z0-9._@+~-]+)*)`)

// collectPaths decides which paths the bundle carries.
//
// The SUBJECT may lie anywhere, including under /home: the subject is the
// finding, and a bundle that omitted it would reproduce nothing.
//
// A path scraped out of EVIDENCE may not lie under /home. Evidence routinely
// names arguments rather than subjects -- on the reference system a unit's
// ExecStart reads `... --backup /home/<user>` -- and one operator's home
// directory layout is not something a false-positive report should publish
// because a rule quoted a command line. Those occurrences are redacted out of
// the emitted content instead; see redactHome.
func (b *builder) collectPaths() {
	if b.want(b.in.Finding.Subject) {
		b.required[normalise(b.in.Finding.Subject)] = true
	}
	for _, ev := range b.in.Finding.Evidence {
		for _, m := range pathish.FindAllStringSubmatch(ev, -1) {
			if strings.HasPrefix(normalise(m[1]), "home/") {
				continue
			}
			b.want(m[1])
		}
	}
	// Symlink targets, chased breadth-first and bounded. The link is what the
	// finding names; the target is what makes the ownership verdict come out the
	// same, so a bundle without it reproduces a DIFFERENT finding.
	for depth := 0; depth < maxLinkDepth; depth++ {
		added := false
		for _, p := range append([]string(nil), b.order...) {
			target, err := fsx.ReadLinkConfined(b.root, p)
			if err != nil {
				continue
			}
			next := resolveLink(p, target)
			if b.want(next) {
				added = true
			}
			// A link the bundle carries is useless without its target, whatever
			// brought the link in -- the ownership verdict is the target's.
			if b.required[p] && next != "" {
				b.required[next] = true
			}
		}
		if !added {
			break
		}
	}
}

// want normalises a path and records it. It returns true when the path is new.
func (b *builder) want(p string) bool {
	rel := normalise(p)
	if rel == "" || b.wanted[rel] || len(b.order) >= maxPaths {
		return false
	}
	b.wanted[rel] = true
	b.order = append(b.order, rel)
	return true
}

// normalise turns a subject or an evidence token into a root-relative path, or
// "" if it is not usable as one. A ".." component is refused rather than
// cleaned: it means the string was not a path the scan produced, and a
// reproducer must not invent one.
func normalise(p string) string {
	s := strings.TrimSpace(p)
	s = strings.Trim(s, `"'`)
	s = strings.TrimPrefix(s, "./")
	s = strings.TrimPrefix(s, "/")
	s = strings.TrimSuffix(s, "/")
	if s == "" || s == "." {
		return ""
	}
	for _, seg := range strings.Split(s, "/") {
		if seg == "" || seg == "." || seg == ".." {
			return ""
		}
	}
	return s
}

// resolveLink resolves a symlink target against the link's own directory, the
// way the scanned root would. An absolute target is root-relative here, because
// under --offline-root that is what an absolute target means.
func resolveLink(link, target string) string {
	if strings.HasPrefix(target, "/") {
		return normalise(target)
	}
	joined := path.Join(path.Dir(link), target)
	if strings.HasPrefix(joined, "..") {
		return ""
	}
	return normalise(joined)
}

// -- emitting -----------------------------------------------------------------

func (b *builder) emitPaths(rep *Report) {
	for _, rel := range b.order {
		if target, err := fsx.ReadLinkConfined(b.root, rel); err == nil {
			b.emitSymlink(rep, rel, target)
			continue
		}
		f, st, err := fsx.OpenConfined(b.root, rel)
		if err != nil {
			// A directory, an absent path or an unreadable one. A directory is
			// emitted so the shape survives; the rest is a gap, not silence.
			if info, serr := b.root.Stat(rel); serr == nil && info.IsDir() {
				b.emitDir(rep, rel, info.Mode().Perm())
				continue
			}
			if b.required[rel] {
				b.gap(rel, fmt.Sprintf("the path could not be opened (%v), so the bundle does not "+
					"carry it and may not reproduce the finding", err))
			}
			continue
		}
		content, disp, note := b.contentFor(rel, f)
		f.Close()
		mode := os.FileMode(st.Mode & 0o7777)
		mtime := time.Unix(st.Mtim.Sec, st.Mtim.Nsec)
		if err := b.writeFile(rel, content, mode, mtime); err != nil {
			b.gap(rel, fmt.Sprintf("the bundle could not be written: %v", err))
			continue
		}
		b.record(rep, Entry{
			Path: rel, Disposition: disp, Mode: fmt.Sprintf("%04o", mode),
			Bytes: len(content), Note: note,
		})
	}
}

func (b *builder) emitSymlink(rep *Report, rel, target string) {
	redacted, _ := b.redactHome(target)
	dst := filepath.Join(b.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		b.gap(rel, err.Error())
		return
	}
	if err := os.Symlink(redacted, dst); err != nil {
		b.gap(rel, err.Error())
		return
	}
	note := ""
	if redacted != target {
		note = "the link target contained a home path and was redacted"
	}
	b.record(rep, Entry{Path: rel, Disposition: DispSymlink, Target: redacted, Note: note})
}

func (b *builder) emitDir(rep *Report, rel string, mode os.FileMode) {
	dst := filepath.Join(b.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(dst, 0o755); err != nil {
		b.gap(rel, err.Error())
		return
	}
	// The mode is preserved because a group- or world-writable directory is what
	// unit-execstart-hijackable rates on.
	if err := os.Chmod(dst, mode); err != nil {
		b.gap(rel, err.Error())
	}
	b.record(rep, Entry{Path: rel, Disposition: DispDirectory, Mode: fmt.Sprintf("%04o", mode)})
}

func (b *builder) record(rep *Report, e Entry) {
	rep.Files = append(rep.Files, e)
	if strings.HasPrefix(e.Path, "home/") {
		rep.HomePaths = append(rep.HomePaths, e.Path)
	}
}

func (b *builder) writeFile(rel string, content []byte, mode os.FileMode, mtime time.Time) error {
	dst := filepath.Join(b.dir, filepath.FromSlash(rel))
	if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(dst, content, 0o600); err != nil {
		return err
	}
	// The mode is preserved, setuid bits included: integrity-unowned-setuid rates
	// on exactly those bits, and a reproducer that dropped them would silence the
	// finding it exists to show.
	if err := os.Chmod(dst, mode); err != nil {
		return err
	}
	if !mtime.IsZero() {
		if err := os.Chtimes(dst, mtime, mtime); err != nil {
			return err
		}
	}
	return nil
}

// -- the content policy -------------------------------------------------------

// contentFor decides what, if anything, of a file's bytes is emitted.
//
// The default is a zero-byte placeholder. Only a file whose FORMAT a compiled
// check parses gets a reconstruction, and that reconstruction carries only the
// directives the check reads.
func (b *builder) contentFor(rel string, f io.Reader) ([]byte, Disposition, string) {
	keep, kind := directiveFilter(rel)
	if keep == nil {
		return nil, DispPlaceholder, "contents withheld: nothing in this file's format is parsed " +
			"by a check, so a reproducer does not need them"
	}
	raw, err := io.ReadAll(io.LimitReader(f, maxContentBytes+1))
	if err != nil {
		b.gap(rel, fmt.Sprintf("the file could not be read (%v); an empty placeholder was emitted "+
			"instead and the finding may not reproduce", err))
		return nil, DispPlaceholder, "contents unreadable; see the coverage gaps"
	}
	if len(raw) > maxContentBytes {
		b.gap(rel, fmt.Sprintf("the file is larger than %d bytes, which no %s is; an empty "+
			"placeholder was emitted instead", maxContentBytes, kind))
		return nil, DispPlaceholder, "over the size cap; contents withheld"
	}
	out, dropped, argsHeld := filterLines(string(raw), keep)
	b.noteRedactedEntryPoint(out)
	redacted, homes := b.redactHome(out)
	note := fmt.Sprintf("rebuilt as a %s from the %d directive(s) a check reads; %d line(s) of the "+
		"original were dropped unread", kind, countLines(redacted), dropped)
	if argsHeld > 0 {
		note += fmt.Sprintf("; %d command argument(s) withheld, only the program each command runs "+
			"was kept", argsHeld)
	}
	if homes > 0 {
		note += fmt.Sprintf("; %d home path(s) redacted", homes)
	}
	return []byte(redacted), DispFiltered, note
}

// directiveFilter returns the set of keys emitted for this path's format, and a
// word for what that format is. A nil set means "no format we parse".
//
// The classification is by NAME AND LOCATION rather than by sniffing content,
// because sniffing means reading, and the decision about whether to read a file
// must not require reading it.
func directiveFilter(rel string) (map[string]bool, string) {
	base := path.Base(rel)
	switch {
	case rel == "etc/ld.so.preload":
		// The whole content IS the finding: a list of shared objects. There are
		// no keys, so the filter keeps every non-comment line, and every one of
		// them is a path the finding already names.
		return preloadKeys, "ld.so.preload list"
	case strings.HasSuffix(base, ".hook"):
		return hookKeys, "pacman hook"
	case strings.HasSuffix(base, ".desktop"):
		return desktopKeys, "XDG desktop entry"
	case unitSuffix(base):
		return unitKeys, "systemd unit"
	}
	return nil, ""
}

func unitSuffix(base string) bool {
	for _, s := range []string{".service", ".socket", ".timer", ".mount", ".automount",
		".path", ".target", ".slice", ".scope", ".swap", ".device"} {
		if strings.HasSuffix(base, s) {
			return true
		}
	}
	return false
}

// The three directive allowlists. Everything absent from them is withheld, which
// is the direction that stays safe as unit files grow keys: Environment,
// EnvironmentFile, User, Group, PassEnvironment and every future key are dropped
// without anyone having to remember them.
var (
	unitKeys = keySet("Exec", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
		"ExecStopPost", "ExecReload", "ExecCondition", "Type", "WantedBy", "RequiredBy",
		"Alias", "Also", "DefaultInstance")

	hookKeys = keySet("Exec", "When", "Type", "Operation", "Target", "AbortOnFail", "NeedsTargets")

	desktopKeys = keySet("Exec", "TryExec", "Hidden", "Type", "NoDisplay")

	// preloadKeys is empty and non-nil: the format has no keys, and filterLines
	// treats an empty set as "keep every non-comment, non-key line".
	preloadKeys = map[string]bool{}

	// commandKeys are the allowlisted keys whose value is a COMMAND LINE, and so
	// the keys whose arguments are withheld (see the package comment). Membership
	// is by key name across all three formats because the shape is the same in
	// each: `Exec=` in a pacman hook and `ExecStart=` in a unit are both a program
	// followed by uninspected free text.
	//
	// Note what is NOT here: Type, WantedBy, RequiredBy, Alias, Also, When,
	// Operation, Target, Hidden, NoDisplay. Those hold enumerated values or unit
	// names, not command lines, and reducing them to a first token would corrupt
	// them.
	commandKeys = keySet("Exec", "ExecStart", "ExecStartPre", "ExecStartPost", "ExecStop",
		"ExecStopPost", "ExecReload", "ExecCondition", "TryExec")
)

func keySet(keys ...string) map[string]bool {
	m := make(map[string]bool, len(keys))
	for _, k := range keys {
		m[strings.ToLower(k)] = true
	}
	return m
}

// filterLines rebuilds a keyed config file from the allowed directives, keeping
// section headers so the result still parses. It returns the rebuilt text, how
// many lines were dropped unread, and how many command arguments were withheld
// from the lines it kept.
func filterLines(raw string, keep map[string]bool) (text string, dropped, argsHeld int) {
	var out []string
	for _, line := range strings.Split(raw, "\n") {
		t := strings.TrimSpace(line)
		switch {
		case t == "":
			continue
		case strings.HasPrefix(t, "#") || strings.HasPrefix(t, ";"):
			// Comments are prose written by a human on the reporter's machine.
			dropped++
			continue
		case strings.HasPrefix(t, "[") && strings.HasSuffix(t, "]"):
			out = append(out, t)
			continue
		}
		key, value, isPair := strings.Cut(t, "=")
		if len(keep) == 0 {
			// Keyless format (ld.so.preload): the line is the datum.
			if isPair {
				dropped++
				continue
			}
			out = append(out, t)
			continue
		}
		name := strings.ToLower(strings.TrimSpace(key))
		if !isPair || !keep[name] {
			dropped++
			continue
		}
		if commandKeys[name] {
			reduced, held := programOnly(value)
			argsHeld += held
			out = append(out, strings.TrimSpace(key)+"="+reduced)
			continue
		}
		out = append(out, t)
	}
	if len(out) == 0 {
		return "", dropped, argsHeld
	}
	return strings.Join(out, "\n") + "\n", dropped, argsHeld
}

// programOnly reduces one Exec value to systemd's prefix characters plus the
// program, and reports how many arguments it withheld.
//
// The empty value is preserved as empty: `ExecStart=` with no value is systemd's
// RESET, which is how a drop-in disables what a packaged unit ran, and turning it
// into anything else would change the unit's meaning.
func programOnly(value string) (string, int) {
	v := strings.TrimSpace(value)
	i := 0
	for i < len(v) && strings.IndexByte(surfaces.ExecPrefixChars, v[i]) >= 0 {
		i++
	}
	prefixes, rest := v[:i], strings.TrimSpace(v[i:])
	if rest == "" {
		return v, 0
	}
	toks := surfaces.SystemdTokens(rest)
	if len(toks) == 0 {
		return v, 0
	}
	return prefixes + requote(toks[0]), len(toks) - 1
}

// requote puts back the quoting a path needs to survive re-tokenisation. A
// program path containing whitespace or a quote character was quoted in the
// original, and emitting the bare token would split into several tokens on the
// way back in -- so the bundle would name a different program than the machine
// did.
func requote(tok string) string {
	if !strings.ContainsAny(tok, " \t\n\r'\"\\") {
		return tok
	}
	var b strings.Builder
	b.WriteByte('"')
	for i := 0; i < len(tok); i++ {
		if tok[i] == '"' || tok[i] == '\\' {
			b.WriteByte('\\')
		}
		b.WriteByte(tok[i])
	}
	b.WriteByte('"')
	return b.String()
}

func countLines(s string) int {
	if s == "" {
		return 0
	}
	return strings.Count(strings.TrimSuffix(s, "\n"), "\n") + 1
}

// noteRedactedEntryPoint records when the PROGRAM a kept directive names lies
// under /home and is not itself part of the bundle.
//
// The distinction from an argument is the whole point. `ExecStart=/usr/bin/foo
// --backup /home/u` reproduces perfectly with the argument redacted, because the
// checks resolve the first token. `ExecStart=/home/u/bin/foo` does not: the
// program IS what the finding is about, and redacting it changes the finding.
func (b *builder) noteRedactedEntryPoint(text string) {
	for _, line := range strings.Split(text, "\n") {
		_, value, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		fields := strings.Fields(value)
		if len(fields) == 0 {
			continue
		}
		prog := strings.TrimPrefix(fields[0], "-") // systemd's ignore-failure prefix
		if !strings.HasPrefix(prog, "/home/") || b.wanted[normalise(prog)] {
			continue
		}
		if b.entryPointRedacted == "" {
			b.entryPointRedacted = prog
		}
	}
}

// homePath matches an absolute path under /home.
var homePath = regexp.MustCompile(`/home/[A-Za-z0-9._@+-]+(?:/[A-Za-z0-9._@+~-]+)*`)

// redactHome rewrites home paths in emitted content, EXCEPT those the bundle is
// already reproducing. See the package comment for why the exception exists and
// how it is surfaced.
func (b *builder) redactHome(s string) (string, int) {
	n := 0
	out := homePath.ReplaceAllStringFunc(s, func(m string) string {
		if b.wanted[normalise(m)] {
			return m
		}
		n++
		return "/home/redacted/redacted"
	})
	return out, n
}

// -- the package database -----------------------------------------------------

// emitPackages rebuilds the local-database entries the bundle needs.
//
// Two decisions, both narrowing:
//
//   - only packages that OWN a path in the bundle are included. Emitting the
//     whole database would publish the reporter's complete installed-software
//     inventory to reproduce a finding about one unit file.
//   - each entry's %FILES% is narrowed to the paths the bundle carries. Ownership
//     verdicts inside the bundle are therefore identical to the ones on the
//     reporter's machine, and the paths that are not in the bundle do not exist
//     in it, so nothing is lost by omitting them.
//
// The entries are SYNTHESISED from parsed fields rather than copied, which is
// what guarantees %PACKAGER% -- the operator's own name and address on a
// locally-built package -- never travels.
func (b *builder) emitPackages(rep *Report) {
	// The local-database directory exists even when no package qualifies, and it
	// has to: a root with no `var/lib/pacman/local` at all is a root the scan
	// refuses to start on ("the package database was not read"), so a bundle
	// whose finding is about a file nobody owns would be unscannable -- which is
	// most of them, since "owned by no installed package" is what half these
	// rules report.
	const localDB = "var/lib/pacman/local"
	if err := os.MkdirAll(filepath.Join(b.dir, filepath.FromSlash(localDB)), 0o755); err != nil {
		b.gap(localDB, err.Error())
		return
	}
	b.record(rep, Entry{Path: localDB, Disposition: DispDirectory, Mode: "0755",
		Note: "present even when empty: a root with no local database is one the scan " +
			"refuses to start on"})

	for _, p := range b.in.Packages {
		owned := b.ownedInBundle(p)
		isSubject := b.in.Finding.SubjectKind == "package" && p.Name == b.in.Finding.Subject
		if len(owned) == 0 && !isSubject {
			continue
		}
		dir := path.Join(localDB, p.Name+"-"+p.Version)
		desc := synthDesc(p)
		files := synthFiles(p, owned)
		for name, body := range map[string]string{"desc": desc, "files": files} {
			if err := b.writeFile(path.Join(dir, name), []byte(body), 0o644, time.Time{}); err != nil {
				b.gap(dir+"/"+name, err.Error())
				continue
			}
			b.record(rep, Entry{
				Path: path.Join(dir, name), Disposition: DispSynthesised, Mode: "0644",
				Bytes: len(body),
				Note: "rebuilt from parsed fields; %PACKAGER% and every unparsed field were " +
					"never written, and %FILES% is narrowed to the paths this bundle carries",
			})
		}
		rep.Packages = append(rep.Packages, p.Name)
	}
}

// ownedInBundle returns the package's file-list entries that name a path the
// bundle carries.
//
// A package QUALIFIES only by owning a FILE in the bundle. Directory entries
// (trailing "/") are then included as well, because the ownership oracle reads
// them -- but they never make a package qualify on their own, and that is the
// difference between a bundle naming three packages and a bundle naming a
// hundred and forty-seven. Nearly every package on a system owns `usr/` and
// `etc/`, so qualifying on a directory publishes the operator's whole installed
// inventory to reproduce a finding about one unit file.
func (b *builder) ownedInBundle(p alpm.Package) []string {
	var files, dirs []string
	for _, f := range p.Files {
		rel := normalise(f)
		if rel == "" {
			continue
		}
		if strings.HasSuffix(f, "/") {
			for _, w := range b.order {
				if strings.HasPrefix(w, rel+"/") {
					dirs = append(dirs, f)
					break
				}
			}
			continue
		}
		if b.wanted[rel] {
			files = append(files, f)
		}
	}
	if len(files) == 0 {
		return nil
	}
	return append(dirs, files...)
}

// synthDesc writes the five fields anything in this tree reads, and nothing
// else. %PACKAGER%, %URL%, %DESC%, %LICENSE% and the dependency lists are all
// absent by construction rather than by filtering.
func synthDesc(p alpm.Package) string {
	var b strings.Builder
	fmt.Fprintf(&b, "%%NAME%%\n%s\n\n", p.Name)
	fmt.Fprintf(&b, "%%VERSION%%\n%s\n\n", p.Version)
	if p.Base != "" {
		fmt.Fprintf(&b, "%%BASE%%\n%s\n\n", p.Base)
	}
	if p.Validation != "" {
		fmt.Fprintf(&b, "%%VALIDATION%%\n%s\n\n", p.Validation)
	}
	if !p.InstallDate.IsZero() {
		fmt.Fprintf(&b, "%%INSTALLDATE%%\n%s\n\n", strconv.FormatInt(p.InstallDate.Unix(), 10))
	}
	return b.String()
}

func synthFiles(p alpm.Package, owned []string) string {
	var b strings.Builder
	b.WriteString("%FILES%\n")
	for _, f := range owned {
		b.WriteString(f + "\n")
	}
	var backups []string
	for pathName, digest := range p.Backup {
		if slicesContains(owned, pathName) {
			backups = append(backups, pathName+"\t"+digest)
		}
	}
	if len(backups) > 0 {
		sort.Strings(backups)
		b.WriteString("\n%BACKUP%\n")
		for _, line := range backups {
			b.WriteString(line + "\n")
		}
	}
	return b.String()
}

func slicesContains(hay []string, needle string) bool {
	for _, h := range hay {
		if h == needle {
			return true
		}
	}
	return false
}

// -- synthesised configuration ------------------------------------------------

// emitSynthesised writes the two configuration files a fixture root needs to be
// interpreted the way the reporter's machine interpreted it. Both are built from
// the bundle's own contents, so neither can leak anything the bundle does not
// already carry.
func (b *builder) emitSynthesised(rep *Report) {
	b.emitPasswd(rep)
	b.emitPacmanConf(rep)
}

// emitPasswd names only the users whose home directories the bundle already
// contains. Copying the real passwd would publish every local account; omitting
// it entirely would make a per-user surface finding unreproducible, because the
// per-user directories are enumerated from passwd.
func (b *builder) emitPasswd(rep *Report) {
	seen := map[string]bool{}
	var users []string
	for _, p := range b.order {
		rest, ok := strings.CutPrefix(p, "home/")
		if !ok {
			continue
		}
		user, _, _ := strings.Cut(rest, "/")
		if user == "" || seen[user] {
			continue
		}
		seen[user] = true
		users = append(users, user)
	}
	if len(users) == 0 {
		return
	}
	sort.Strings(users)
	var body strings.Builder
	body.WriteString("root:x:0:0::/root:/usr/bin/bash\n")
	for i, u := range users {
		fmt.Fprintf(&body, "%s:x:%d:%d::/home/%s:/usr/bin/bash\n", u, 1000+i, 1000+i, u)
	}
	if err := b.writeFile("etc/passwd", []byte(body.String()), 0o644, time.Time{}); err != nil {
		b.gap("etc/passwd", err.Error())
		return
	}
	b.record(rep, Entry{
		Path: "etc/passwd", Disposition: DispSynthesised, Mode: "0644", Bytes: body.Len(),
		Note: fmt.Sprintf("invented: %d user(s) whose home directory this bundle already carries, "+
			"plus root. No other local account is named, and no shell, uid or gid here is real",
			len(users)),
	})
}

// emitPacmanConf writes a minimal pacman.conf naming the hook directories the
// bundle's own hook files live in. Without it a hook in a non-default HookDir is
// not read at all and the finding does not reproduce; with it, nothing of the
// reporter's repository configuration, mirrors or SigLevel travels.
func (b *builder) emitPacmanConf(rep *Report) {
	seen := map[string]bool{}
	var dirs []string
	for _, e := range rep.Files {
		if !strings.HasSuffix(e.Path, ".hook") {
			continue
		}
		d := path.Dir(e.Path)
		if d == "usr/share/libalpm/hooks" || seen[d] {
			continue
		}
		seen[d] = true
		dirs = append(dirs, d)
	}
	if len(dirs) == 0 {
		return
	}
	sort.Strings(dirs)
	var body strings.Builder
	body.WriteString("# Synthesised by `aurvet bundle`. It names the hook directories this\n")
	body.WriteString("# bundle's hook files live in, and nothing else: no repositories, no\n")
	body.WriteString("# mirrors, no SigLevel from the reporting machine.\n")
	body.WriteString("[options]\n")
	for _, d := range dirs {
		fmt.Fprintf(&body, "HookDir = /%s/\n", d)
	}
	if err := b.writeFile("etc/pacman.conf", []byte(body.String()), 0o644, time.Time{}); err != nil {
		b.gap("etc/pacman.conf", err.Error())
		return
	}
	b.record(rep, Entry{
		Path: "etc/pacman.conf", Disposition: DispSynthesised, Mode: "0644", Bytes: body.Len(),
		Note: "invented: the HookDir lines this bundle's hooks need, and nothing else",
	})
}

// -- what reproduces, and what does not ---------------------------------------

// notReproducible maps a rule id to the reason a bundle cannot reproduce it.
//
// The table is explicit and Classify's DEFAULT IS "not guaranteed", so a rule
// added later inherits an honest label rather than a promise. Getting this
// backwards would be the failure that matters: a maintainer runs a bundle, sees
// nothing, and closes a real report.
var notReproducible = map[string]string{
	"integrity-digest-mismatch": "an integrity finding is a statement about a file's CONTENTS " +
		"against the digest its package recorded. A bundle carries neither -- no file's bytes and " +
		"no package mtree -- because publishing either is publishing the file",
	"integrity-missing":        "reproducing it needs the package's mtree, which a bundle does not carry",
	"integrity-link-target":    "reproducing it needs the package's mtree, which a bundle does not carry",
	"integrity-unowned-setuid": "the setuid sweep runs only at tier paranoid and enumerates whole trees; a bundle carries the named paths and no tree",
	"integrity-coverage":       "a coverage gap is a statement about what a run could not read, which is a property of the machine and not of a fixture",
	"integrity-mtree":          "reproducing it needs the package's mtree, which a bundle does not carry",
	"aur-absent":               "AUR provenance is answered by the AUR RPC at run time; a bundle carries no recorded network response, so an offline run reports a coverage gap instead",
	"aur-orphaned":             "AUR provenance is answered by the AUR RPC at run time; a bundle carries no recorded network response",
	"aur-submitter-mismatch":   "AUR provenance is answered by the AUR RPC at run time; a bundle carries no recorded network response",
	"aur-tombstone":            "AUR provenance is answered by the AUR RPC at run time; a bundle carries no recorded network response",
	"aur-provenance":           "it rests on the provenance snapshot store in the state directory, which is not part of a fixture root",
	"correlated-cluster":       "correlation's temporal key compares file mtimes and %INSTALLDATE% against the age of the run. The bundle preserves both, but the cluster it earns depends on when the bundle is opened, so reproduction is likely rather than guaranteed",
	"correlate-coverage":       "it reports what correlation could not attribute on the reporting machine",
	"baseline-drift":           "drift is measured against a SIGNED baseline manifest in the state directory, which a fixture root does not and must not carry",
	"sync-coverage":            "it is about the freshness of the sync databases on the reporting machine, which a bundle does not carry",
	"local-db":                 "it reports what could not be read from the reporting machine's package database",
	"surface-misc-coverage":    "a coverage gap is a statement about what a run could not read on the reporting machine",
	"unit-coverage":            "a coverage gap is a statement about what a run could not parse on the reporting machine",
	"wants-coverage":           "a coverage gap is a statement about what a run could not read on the reporting machine",
	"hook-coverage":            "a coverage gap is a statement about what a run could not parse on the reporting machine",
	"privilege-coverage":       "it is a statement about the privileges the reporting run held",
	"adjudicate-store":         "it is a statement about the reporting machine's signed adjudication store",
	"triage-store":             "it is a statement about the reporting machine's local triage store",
}

// reproducible is the compiled set of rules a bundle DOES reproduce. It is an
// allowlist for the same reason the directive filters are: a rule nobody has
// classified must not inherit a promise.
var reproducible = map[string]bool{
	"unit-execstart-unowned":         true,
	"unit-execstart-hijackable":      true,
	"wants-link-unowned-target":      true,
	"hook-unowned":                   true,
	"hook-suppressed":                true,
	"hook-dirs":                      true,
	"surface-preload-unowned":        true,
	"surface-generator-unowned":      true,
	"surface-profiled-unowned":       true,
	"surface-autostart-unowned-exec": true,
}

// Classify says whether a bundle reproduces this rule's findings.
func Classify(ruleID string) Reproduction {
	const cmd = "aurvet scan --offline-root <bundle> --no-network --min-severity info"
	if reproducible[ruleID] {
		return Reproduction{Reproduces: true, Command: cmd}
	}
	why, known := notReproducible[ruleID]
	if !known {
		why = fmt.Sprintf("rule %q is not in this build's reproduction table. That is reported as "+
			"NOT reproducible rather than assumed to work: a bundle that quietly fails to reproduce "+
			"its finding is worse than no bundle", ruleID)
	}
	return Reproduction{Reproduces: false, Why: why, Command: cmd}
}

// -- the two documents ---------------------------------------------------------

func writeManifest(dir string, rep Report) error {
	blob, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "MANIFEST.json"), append(blob, '\n'), 0o644)
}

// writeReadme states what the bundle contains in the words the operator needs,
// because the operator is about to attach it to a public issue.
func writeReadme(dir string, in Input, rep Report) error {
	var b strings.Builder
	fmt.Fprintf(&b, "# aurvet reproducer for `%s`\n\n", rep.RuleID)
	fmt.Fprintf(&b, "Finding id `%s` on `%s:%s`, severity %s, produced by aurvet %s at %s.\n\n",
		rep.FindingID, rep.SubjectKind, rep.Subject, rep.Severity, in.Version,
		in.Now.Format(time.RFC3339))
	fmt.Fprintf(&b, "> %s\n\n", rep.Summary)

	b.WriteString("## Reproduce\n\n```\n")
	fmt.Fprintf(&b, "%s\n```\n\n", strings.Replace(rep.Reproduction.Command, "<bundle>", ".", 1))
	if rep.Reproduction.Reproduces {
		fmt.Fprintf(&b, "The finding should reappear with the same id, `%s`.\n\n", rep.FindingID)
	} else {
		fmt.Fprintf(&b, "**This finding does NOT reproduce from this bundle.** %s\n\n"+
			"The bundle is still worth attaching: it carries the shape of the paths involved. "+
			"It is labelled here rather than left to be discovered.\n\n", rep.Reproduction.Why)
	}

	b.WriteString("## What is in here, exactly\n\n")
	b.WriteString("**No file's own bytes were copied.** Every regular file below is either a\n")
	b.WriteString("zero-byte placeholder or a file *rebuilt* from the handful of directives\n")
	b.WriteString("aurvet's compiled checks parse (`ExecStart=`, `Exec=`, `TryExec=`, `When=`,\n")
	b.WriteString("`Type=`, the enablement keys, and the path list of `ld.so.preload`).\n")
	b.WriteString("Comments, `Environment=`, `EnvironmentFile=`, `User=`, `Description=` and\n")
	b.WriteString("every other directive were dropped unread.\n\n")
	b.WriteString("Within a kept command, only the PROGRAM was written: the arguments were\n")
	b.WriteString("withheld. `ExecStart=/usr/local/bin/backup --token <secret>` is emitted as\n")
	b.WriteString("`ExecStart=/usr/local/bin/backup`. aurvet resolves ownership from the first\n")
	b.WriteString("token and reads nothing past it, so the finding still reproduces; an\n")
	b.WriteString("argument is free text from the reporting machine and is treated as such.\n")
	b.WriteString("The per-file table below counts what each command withheld.\n\n")
	b.WriteString("Package database entries are **synthesised** from parsed fields: `%NAME%`,\n")
	b.WriteString("`%VERSION%`, `%BASE%`, `%VALIDATION%`, `%INSTALLDATE%`, and a `%FILES%` list\n")
	b.WriteString("narrowed to the paths this bundle carries. `%PACKAGER%` -- your name and\n")
	b.WriteString("address on anything you built locally -- is never written.\n\n")
	b.WriteString("`etc/passwd` and `etc/pacman.conf`, where present, were invented from the\n")
	b.WriteString("bundle's own contents. Neither is a copy of yours.\n\n")
	b.WriteString("Absolute paths under `/home` inside file contents were rewritten to\n")
	b.WriteString("`/home/redacted/redacted`.\n\n")

	if len(rep.HomePaths) > 0 {
		b.WriteString("### Read this before you publish\n\n")
		b.WriteString("These paths lie under `/home` and are published **as they are**, because\n")
		b.WriteString("the finding is about them and redacting them would mean the bundle does not\n")
		b.WriteString("reproduce anything:\n\n")
		for _, p := range rep.HomePaths {
			fmt.Fprintf(&b, "- `/%s`\n", p)
		}
		b.WriteString("\nDelete the bundle rather than publishing it if that is not acceptable.\n\n")
	}

	b.WriteString("### Every file, and what was done to it\n\n")
	b.WriteString("| path | disposition | bytes | note |\n| --- | --- | --- | --- |\n")
	for _, e := range rep.Files {
		note := e.Note
		if e.Disposition == DispSymlink {
			note = "symlink to `" + e.Target + "`, read verbatim and never followed"
		}
		fmt.Fprintf(&b, "| `%s` | %s | %d | %s |\n", e.Path, e.Disposition, e.Bytes, note)
	}
	if len(rep.Gaps) > 0 {
		b.WriteString("\n### What this bundle could not include\n\n")
		for _, g := range rep.Gaps {
			fmt.Fprintf(&b, "- `%s`: %s\n", g.Subject, g.Reason)
		}
	}
	b.WriteString("\n`MANIFEST.json` carries the same information for a machine.\n")
	return os.WriteFile(filepath.Join(dir, "README.md"), []byte(b.String()), 0o644)
}
