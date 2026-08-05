// internal/pacmanlog/pacmanlog.go
//
// Package pacmanlog reads /var/log/pacman.log and its rotated siblings into
// transaction facts. It is the third clock in correlation: internal/correlate
// takes transaction times as an INPUT (Config.Transactions) and deliberately
// does not parse them, and this package fills that hole.
//
// Four properties of the real file drive the whole design, and every one of
// them was measured on the reference log (16,840 lines, 1.4 MB):
//
//  1. One file mixes UTC offsets. The reference log carries exactly two --
//     +0000 on 10,498 lines and +0100 on 6,342 -- because a DST boundary falls
//     inside its span. A reader that drops the offset, or that reads the stamp
//     as local time, orders two transactions across that boundary WRONGLY, and
//     correlate's temporal key then draws a conclusion from a reversed
//     sequence. Every timestamp here is parsed with its explicit offset;
//     time.Local is never consulted and a stamp without an offset is a gap
//     rather than a guess (INV-9).
//
//  2. [ALPM] and [PACMAN] are different things. The reference log has 11,298
//     [ALPM] lines and 1,683 [PACMAN] lines; [PACMAN] records an invocation,
//     not a package transaction, and [ALPM-SCRIPTLET] (3,859 lines there)
//     records output from a scriptlet this project never runs (INV-2). Only
//     [ALPM] lines become transactions. [PACMAN] lines are still read, because
//     they carry the root -- see 3 -- and because the manifest's earliest
//     timestamp must span every category: on the reference log the very first
//     line is [PACMAN].
//
//  3. Entries may describe another filesystem. The reference log contains 15
//     invocations naming another root (`-r /mnt`, from the installer), and the
//     transactions that follow such an invocation happened THERE. Attributing
//     them to this root is not a false positive, it is a false statement about
//     what happened on this machine, so they are separated out and reported as
//     a coverage gap for this root.
//
//  4. History ends silently. Rotation is where a log stops covering the
//     baseline window, and the reference machine has NO rotated siblings at all
//     -- so the rotation path cannot be exercised against it and is covered by
//     fixtures instead.
//
// The distinction this package exists to make is between two things that look
// identical in the output of a naive reader:
//
//   - Short coverage: the log never reached back to the baseline. Ordinary,
//     usually rotation, and a COVERAGE GAP (INV-9) -- not a wall of criticals,
//     one per package installed before the log begins. A tool that emits
//     thousands of criticals for a log rotation teaches its user to ignore it.
//   - Truncation: the log DID reach back that far, because a signed manifest
//     recorded its earliest timestamp, and now it does not. Lines were removed,
//     which is what covering tracks looks like, so that is a finding.
//
// The second is only detectable because the manifest stores the earliest
// timestamp (P4 task 4). Result.Earliest / EarliestString is what it stores.
package pacmanlog

import (
	"fmt"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
)

// Gap and finding rule identifiers.
const (
	// RuleUnparsed is a line whose grammar this package does not recognise:
	// no timestamp, a timestamp without an explicit UTC offset, or an [ALPM]
	// message with a verb it has no parse for. Reported per file and per kind
	// with a count, never per line -- a corrupt log would otherwise produce one
	// gap per line, which is the same wall of noise this package exists to
	// avoid.
	RuleUnparsed = "pacmanlog-unparsed-line"

	// RuleSibling is a rotated sibling that exists but could not be read: an
	// unsupported compression format (zstd, xz, bzip2 -- none in the standard
	// library, and no module may be added), an unreadable file, or something
	// that is not a regular file. Unreadable history is missing history.
	RuleSibling = "pacmanlog-rotated-sibling"

	// RuleBound is input that hit a limit rather than input that was wrong: an
	// overlong line, too many lines, too many bytes after decompression (a gzip
	// bomb is trivial to write), too many siblings. Under --offline-root the log
	// is attacker-supplied, so everything an attacker sizes is bounded, and
	// hitting a bound is a coverage gap for the part not read.
	RuleBound = "pacmanlog-bound"

	// RuleAbsent is a missing primary log. Absence is a gap, not an error: a
	// container image or a fresh --offline-root may legitimately have none, and
	// refusing the whole scan over it would be the wrong trade.
	RuleAbsent = "pacmanlog-absent"

	// RuleForeignRoot is transactions attributed to another root. They are
	// facts about a different filesystem and are excluded from Entries; the gap
	// says how many, because packages installed there have no transaction
	// record here and the temporal key cannot reach them.
	RuleForeignRoot = "pacmanlog-other-root"

	// RuleWindowNotCovered is short coverage: the log begins after the
	// baseline window starts. Exactly one gap, whatever the number of packages
	// it leaves unexplained.
	RuleWindowNotCovered = "pacmanlog-window-not-covered"

	// RuleTruncated is the finding -- not a gap. The manifest recorded an
	// earlier timestamp than the log now carries, so lines that existed when
	// the baseline was signed are gone.
	RuleTruncated = "pacmanlog-truncated"
)

// SubjectLog is the subject kind for everything this package reports.
const SubjectLog = "pacman-log"

// Line categories, as written in the log between the second pair of brackets.
const (
	CategoryALPM      = "ALPM"
	CategoryPacman    = "PACMAN"
	CategoryScriptlet = "ALPM-SCRIPTLET"
)

// Transaction operations, as pacman writes them.
const (
	OpInstalled   = "installed"
	OpRemoved     = "removed"
	OpUpgraded    = "upgraded"
	OpDowngraded  = "downgraded"
	OpReinstalled = "reinstalled"
)

// DefaultPath is the log's location relative to a root.
const DefaultPath = "var/log/pacman.log"

// TimeLayout is the only layout that produces an orderable instant: an
// explicit numeric UTC offset. RFC3339's colon form and Z are accepted too
// (see parseStamp); a stamp with no offset at all is a gap.
const TimeLayout = "2006-01-02T15:04:05-0700"

// MinPlausibleYear and MaxPlausibleYear bound the timestamps this reader will
// accept as transactions. pacman predates none of this by much and the log
// format with offsets arrived in 5.1 (2018), so a stamp outside this range is a
// corrupt or forged line rather than history. The bound is not cosmetic: a
// single line dated year 1 would otherwise become Result.Earliest -- and an
// instant that IsZero() reports as unset, which is this package's sentinel for
// "no timestamp at all".
const (
	MinPlausibleYear = 2000
	MaxPlausibleYear = 2200
)

// Limits bounds everything an attacker sizes. The zero value is not usable;
// Read substitutes DefaultLimits for any zero field.
type Limits struct {
	// MaxFiles bounds the primary log plus its siblings. When more exist the
	// NEWEST MaxFiles are read: dropping recent history to make room for old
	// history would be the wrong end to cut.
	MaxFiles int

	// MaxLines bounds lines per file.
	MaxLines int

	// MaxLineBytes bounds one line. A longer line is dropped, gapped, and
	// reading continues at the next newline -- one absurd line must not cost
	// the rest of the file.
	MaxLineBytes int

	// MaxFileBytes bounds bytes read per file AFTER decompression, which is
	// where a gzip bomb lands.
	MaxFileBytes int64

	// MaxSamples bounds how many line numbers and quoted samples an unparsed
	// gap names.
	MaxSamples int
}

// DefaultLimits are sized against the reference log: 16,840 lines and 1.4 MB
// for roughly seven months of history on a busy desktop, so MaxLines allows
// well over a century of it and MaxFileBytes leaves two orders of magnitude of
// headroom before a bomb is even plausible.
func DefaultLimits() Limits {
	return Limits{
		MaxFiles:     32,
		MaxLines:     4_000_000,
		MaxLineBytes: 64 << 10,
		MaxFileBytes: 256 << 20,
		MaxSamples:   5,
	}
}

func (l Limits) withDefaults() Limits {
	d := DefaultLimits()
	if l.MaxFiles <= 0 {
		l.MaxFiles = d.MaxFiles
	}
	if l.MaxLines <= 0 {
		l.MaxLines = d.MaxLines
	}
	if l.MaxLineBytes <= 0 {
		l.MaxLineBytes = d.MaxLineBytes
	}
	if l.MaxFileBytes <= 0 {
		l.MaxFileBytes = d.MaxFileBytes
	}
	if l.MaxSamples <= 0 {
		l.MaxSamples = d.MaxSamples
	}
	return l
}

// Config is Read's whole input. Read is pure (root, cfg) -> evidence per INV-4:
// no clock is consulted, no zone database is consulted, nothing is written
// (INV-5).
type Config struct {
	// Path is the primary log. Empty means filepath.Join(Root, DefaultPath),
	// so an --offline-root scan reads the offline log and never the live one.
	Path string

	// Root is the filesystem root whose transactions are wanted. Empty means
	// "/". Entries from an invocation naming a different root land in Foreign.
	//
	// Note the honest limit: on the reference machine the installer's `-r /mnt`
	// transactions describe the filesystem that LATER became this one. The
	// entries are kept in Foreign rather than dropped precisely so a caller can
	// look, but this package will not guess that /mnt and / are the same
	// filesystem, because in a chroot build they are not.
	Root string

	// BaselineStart is the start of the window the caller needs covered; zero
	// means unknown, and then short coverage cannot be judged.
	BaselineStart time.Time

	// RecordedEarliest is the earliest timestamp a signed manifest recorded for
	// this log. Zero means there is none, and then truncation cannot be
	// detected at all -- said out loud in Notes rather than left to look clean
	// (INV-3).
	RecordedEarliest time.Time

	Limits Limits
}

// Entry is one [ALPM] package transaction.
type Entry struct {
	// Time carries the offset the line was written with, never the reader's
	// zone.
	Time time.Time

	// Offset is that offset as written, normalised to +hhmm, so a caller can
	// show a mixed-offset log without re-deriving it.
	Offset string

	Category string
	Op       string
	Pkg      string

	// Version is the version after the operation; PrevVersion is the version
	// before it, set only for upgraded/downgraded.
	Version     string
	PrevVersion string

	// Root is the root the governing invocation named, cleaned. "/" when no
	// invocation line preceded this entry in the file.
	Root string

	// RootInferred records that no invocation line preceded this entry, so Root
	// is the caller's target root by assumption rather than by evidence -- the
	// normal shape of a rotated file that begins mid-transaction.
	RootInferred bool

	File string
	Line int
}

// Transaction is the projection internal/correlate consumes. Its fields match
// correlate.Transaction exactly; the conversion is a three-line loop in the
// caller, which keeps this package free of a dependency on the engine that
// happens to read it.
type Transaction struct {
	Time time.Time
	Op   string
	Pkg  string
}

// FileStat is one file this package actually read.
type FileStat struct {
	Path string

	// Bytes and Lines are what was READ, which is not the file's size when a
	// bound was hit.
	Bytes int64
	Lines int

	// Bounded records that reading stopped at a limit, so this file's history
	// is incomplete above the last line read.
	Bounded bool

	Compression string
}

// Result is the evidence Read produces.
type Result struct {
	// Entries are transactions attributed to Config.Root, sorted by time then
	// file then line.
	Entries []Entry

	// Foreign are transactions attributed to a different root, kept so a caller
	// can inspect rather than wonder where they went.
	Foreign      []Entry
	ForeignRoots map[string]int

	// Files are the files read, oldest first.
	Files []FileStat

	LinesRead      int
	ALPMLines      int
	PacmanLines    int
	ScriptletLines int

	// Unparsed counts lines whose grammar was not recognised. Each is
	// accounted for in a Gap; none is silently skipped.
	Unparsed int

	// Offsets are the distinct UTC offsets seen, sorted. Two is normal.
	Offsets []string

	// Earliest and Latest span EVERY timestamped line in every file read, in
	// every category and for every root. Earliest is what the manifest stores
	// so that later truncation is detectable; anchoring it on [ALPM] alone
	// would move it later and blunt that detector.
	Earliest time.Time
	Latest   time.Time

	Findings []finding.Finding
	Gaps     []finding.Gap

	// Notes are statements about what this read could not determine and did not
	// turn into a gap -- chiefly "truncation could not be checked".
	Notes []string

	// Limits is what this evidence cannot prove, rendered with any finding
	// derived from it (INV-6).
	Limits string
}

// Transactions projects Entries for internal/correlate. Only entries for the
// target root are returned: correlate's temporal key would otherwise corroborate
// a file on this filesystem with a transaction on another one.
func (r Result) Transactions() []Transaction {
	out := make([]Transaction, 0, len(r.Entries))
	for _, e := range r.Entries {
		out = append(out, Transaction{Time: e.Time, Op: e.Op, Pkg: e.Pkg})
	}
	return out
}

// MixedOffsets reports whether more than one UTC offset appeared. True on the
// reference log.
func (r Result) MixedOffsets() bool { return len(r.Offsets) > 1 }

// EarliestString renders Earliest in the log's own layout, preserving the
// offset as written. This is the manifest field's canonical form: storing it
// as a local-time string, or as an integer with the offset discarded, would
// make the truncation comparison depend on the reader.
func (r Result) EarliestString() string {
	if r.Earliest.IsZero() {
		return ""
	}
	return r.Earliest.Format(TimeLayout)
}

// Covers reports whether an instant falls inside the span the log actually
// covers. This is the query the "wall of criticals" prevention needs: a caller
// holding a package whose install date is NOT covered must bucket it as a
// coverage gap, never rate it on the log's silence (INV-3).
func (r Result) Covers(t time.Time) bool {
	if r.Earliest.IsZero() || r.Latest.IsZero() || t.IsZero() {
		return false
	}
	return !t.Before(r.Earliest) && !t.After(r.Latest)
}

// CoversWindow reports whether the log reaches back to start.
func (r Result) CoversWindow(start time.Time) bool {
	if r.Earliest.IsZero() || start.IsZero() {
		return false
	}
	return !r.Earliest.After(start)
}

// MaxSeverityIsCritical is a convenience for tests and callers asserting that
// a shortfall did not become an accusation.
func (r Result) MaxSeverityIsCritical() bool {
	for _, f := range r.Findings {
		if f.Severity == finding.SevCritical {
			return true
		}
	}
	return false
}

// LimitsText is what a pacman.log cannot tell you, whatever it says.
const LimitsText = "pacman.log records what pacman did, not what a build did: a package's " +
	"build ran arbitrary code before pacman ever saw a file, and the log holds no trace of it. " +
	"Timestamps are what the writing process recorded, and root can rewrite them. The log covers " +
	"only the span between the earliest and latest lines actually read, so a package installed " +
	"before that span has no transaction record and its absence from the log means nothing."

// Read parses the log and its rotated siblings. It returns an error only when
// the configuration itself is unusable; a missing, unreadable, corrupt or
// truncated log is evidence, reported as gaps.
func Read(cfg Config) (Result, error) {
	lim := cfg.Limits.withDefaults()
	root := cleanRoot(cfg.Root)
	path := cfg.Path
	if path == "" {
		path = filepath.Join(root, DefaultPath)
	}
	if !filepath.IsAbs(path) && cfg.Path == "" {
		return Result{}, fmt.Errorf("pacmanlog: root %q does not yield an absolute log path", cfg.Root)
	}

	r := Result{ForeignRoots: map[string]int{}, Limits: LimitsText}

	files, fileGaps := discover(path, lim)
	r.Gaps = append(r.Gaps, fileGaps...)
	if len(files) == 0 {
		r.Gaps = append(r.Gaps, finding.Gap{
			RuleID:  RuleAbsent,
			Subject: path,
			Reason: fmt.Sprintf("%s does not exist or could not be opened, so no pacman transaction "+
				"times participate in this scan at all: the temporal key runs on %%INSTALLDATE%% and "+
				"file mtimes alone", path),
		})
		r.finish(cfg, lim)
		return r, nil
	}

	offsets := map[string]bool{}
	for _, f := range files {
		st, entries, tally := readFile(f, root, lim, &r)
		r.Files = append(r.Files, st)
		r.LinesRead += st.Lines
		r.ALPMLines += tally.alpm
		r.PacmanLines += tally.pacman
		r.ScriptletLines += tally.scriptlet
		r.Unparsed += tally.unparsed
		for off := range tally.offsets {
			offsets[off] = true
		}
		if !tally.earliest.IsZero() && (r.Earliest.IsZero() || tally.earliest.Before(r.Earliest)) {
			r.Earliest = tally.earliest
		}
		if !tally.latest.IsZero() && (r.Latest.IsZero() || tally.latest.After(r.Latest)) {
			r.Latest = tally.latest
		}
		for _, e := range entries {
			if e.Root == root {
				r.Entries = append(r.Entries, e)
			} else {
				r.Foreign = append(r.Foreign, e)
				r.ForeignRoots[e.Root]++
			}
		}
	}
	for off := range offsets {
		r.Offsets = append(r.Offsets, off)
	}
	sort.Strings(r.Offsets)
	sortEntries(r.Entries)
	sortEntries(r.Foreign)

	r.finish(cfg, lim)
	return r, nil
}

func sortEntries(es []Entry) {
	sort.SliceStable(es, func(i, j int) bool {
		a, b := es[i], es[j]
		if !a.Time.Equal(b.Time) {
			return a.Time.Before(b.Time)
		}
		if a.File != b.File {
			return a.File < b.File
		}
		return a.Line < b.Line
	})
}

// finish derives the coverage judgements. It is the whole point of the package
// and is deliberately the only place a severity is assigned.
func (r *Result) finish(cfg Config, lim Limits) {
	if r.ForeignRoots == nil {
		r.ForeignRoots = map[string]int{}
	}
	target := cleanRoot(cfg.Root)

	if len(r.Foreign) > 0 {
		roots := make([]string, 0, len(r.ForeignRoots))
		for k := range r.ForeignRoots {
			roots = append(roots, k)
		}
		sort.Strings(roots)
		var parts []string
		for _, k := range roots {
			parts = append(parts, fmt.Sprintf("%s (%d)", k, r.ForeignRoots[k]))
		}
		r.Gaps = append(r.Gaps, finding.Gap{
			RuleID:  RuleForeignRoot,
			Subject: target,
			Reason: fmt.Sprintf("%d [ALPM] transactions follow an invocation naming another root and "+
				"describe a different filesystem, so they are not attributed to %s: %s. Packages "+
				"installed there have no transaction record for this root and the temporal key "+
				"cannot reach them",
				len(r.Foreign), target, strings.Join(parts, ", ")),
		})
	}

	// Short coverage. One gap, never one per package: this is the case that
	// would otherwise be a wall of criticals.
	switch {
	case cfg.BaselineStart.IsZero():
		r.Notes = append(r.Notes, "no baseline window was supplied, so whether the log covers it "+
			"was not judged")
	case r.Earliest.IsZero():
		r.Gaps = append(r.Gaps, finding.Gap{
			RuleID:  RuleWindowNotCovered,
			Subject: SubjectLog,
			Reason: fmt.Sprintf("no timestamped line was read, so the log covers none of the baseline "+
				"window beginning %s: every package's install is unexplained by the log, which is a "+
				"coverage gap and not evidence against any of them",
				cfg.BaselineStart.Format(TimeLayout)),
		})
	case !r.CoversWindow(cfg.BaselineStart):
		r.Gaps = append(r.Gaps, finding.Gap{
			RuleID:  RuleWindowNotCovered,
			Subject: SubjectLog,
			Reason: fmt.Sprintf("log coverage begins %s but the baseline window begins %s, so %s of it "+
				"is not covered: any package whose install predates the log has no transaction record, "+
				"which is a coverage gap for those packages and not a finding against them. Ordinary "+
				"log rotation produces exactly this",
				r.EarliestString(), cfg.BaselineStart.Format(TimeLayout),
				r.Earliest.Sub(cfg.BaselineStart).Round(time.Second)),
		})
	}

	// Truncation. Only detectable against a recorded earliest timestamp, which
	// is why the manifest stores one.
	switch {
	case cfg.RecordedEarliest.IsZero():
		r.Notes = append(r.Notes, "no recorded earliest timestamp was supplied, so truncation could not "+
			"be checked: without a signed record of how far the log once reached, a log that begins "+
			"late is indistinguishable from a log that never began earlier")
	case !r.Earliest.IsZero() && r.Earliest.After(cfg.RecordedEarliest):
		r.Findings = append(r.Findings, finding.Finding{
			RuleID:      RuleTruncated,
			SubjectKind: SubjectLog,
			Subject:     firstPath(r.Files),
			Severity:    finding.SevSuspicious,
			Summary: fmt.Sprintf("pacman.log no longer reaches back as far as the baseline recorded: "+
				"it now begins %s, %s later than the recorded %s",
				r.EarliestString(), r.Earliest.Sub(cfg.RecordedEarliest).Round(time.Second),
				cfg.RecordedEarliest.Format(TimeLayout)),
			Evidence: []string{
				fmt.Sprintf("recorded earliest timestamp (signed at baseline): %s",
					cfg.RecordedEarliest.Format(time.RFC3339)),
				fmt.Sprintf("earliest timestamp now readable: %s across %d file(s): %s",
					r.EarliestString(), len(r.Files), strings.Join(paths(r.Files), ", ")),
			},
			Limits: "rotation that discards its oldest generation produces identical evidence, and " +
				"the recorded timestamp cannot say which happened; this is why it is rated suspicious " +
				"rather than critical. Corroborate with whether a rotated sibling covering the " +
				"recorded instant exists and with the chain entry that recorded it.",
		})
	}

	if len(r.Files) > 1 {
		r.Notes = append(r.Notes, fmt.Sprintf("%d rotated sibling(s) were read alongside the primary "+
			"log", len(r.Files)-1))
	}
	sort.SliceStable(r.Gaps, func(i, j int) bool {
		a, b := r.Gaps[i], r.Gaps[j]
		if a.RuleID != b.RuleID {
			return a.RuleID < b.RuleID
		}
		if a.Subject != b.Subject {
			return a.Subject < b.Subject
		}
		return a.Reason < b.Reason
	})
	_ = lim
}

func paths(fs []FileStat) []string {
	out := make([]string, 0, len(fs))
	for _, f := range fs {
		out = append(out, f.Path)
	}
	return out
}

func firstPath(fs []FileStat) string {
	if len(fs) == 0 {
		return SubjectLog
	}
	return fs[len(fs)-1].Path
}

func cleanRoot(root string) string {
	if root == "" {
		return "/"
	}
	c := filepath.Clean(root)
	if c == "." {
		return "/"
	}
	return c
}
