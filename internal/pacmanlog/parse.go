// internal/pacmanlog/parse.go
//
// The line grammar, hand-written rather than regexp-driven so the bounds are
// visible: every function here takes a bounded string and returns a decision,
// and none of them can loop on adversarial input.
package pacmanlog

import (
	"strings"
	"time"
)

// parseKind classifies why a line was not understood. Kinds are aggregated into
// one gap each, per file.
type parseKind int

const (
	kindOK parseKind = iota

	// kindNoStructure: the line does not open with "[stamp] [CATEGORY] ".
	// Continuation output from a scriptlet that wrote a bare newline looks like
	// this, and so does a deliberately malformed offline log.
	kindNoStructure

	// kindNoOffset: the timestamp has no UTC offset. pacman wrote this format
	// before 5.1 ("[2015-06-01 12:00]"). Reading it as local time would order
	// it by the READER's zone, which is a fact about the reader and not about
	// the machine, so it is refused.
	kindNoOffset

	// kindBadStamp: the timestamp is not a timestamp.
	kindBadStamp

	// kindUnknownMessage: an [ALPM] line whose verb has no parse here. Counted
	// so that a pacman that grows a new transaction verb shows up as a gap
	// instead of as silence.
	kindUnknownMessage
)

func (k parseKind) reason() string {
	switch k {
	case kindNoStructure:
		return "line does not match the \"[timestamp] [CATEGORY] message\" grammar"
	case kindNoOffset:
		return "timestamp carries no explicit UTC offset (the pre-5.1 pacman format), and reading it " +
			"as local time would order it by the reader's zone rather than by when it happened"
	case kindBadStamp:
		return "timestamp is not parseable with an explicit UTC offset"
	case kindUnknownMessage:
		return "unrecognised [ALPM] message: this reader has no parse for its verb, so any transaction " +
			"it describes is not counted"
	default:
		return "unclassified"
	}
}

// line is one structurally valid log line.
type line struct {
	when     time.Time
	offset   string
	category string
	message  string
}

// parseLine splits a line into its three fields and parses the timestamp with
// its explicit offset. It never consults time.Local.
func parseLine(s string) (line, parseKind) {
	var l line
	if len(s) == 0 || s[0] != '[' {
		return l, kindNoStructure
	}
	end := strings.IndexByte(s, ']')
	if end < 0 {
		return l, kindNoStructure
	}
	stamp := s[1:end]
	rest := s[end+1:]
	rest = strings.TrimPrefix(rest, " ")
	if len(rest) == 0 || rest[0] != '[' {
		return l, kindNoStructure
	}
	cend := strings.IndexByte(rest, ']')
	if cend < 0 {
		return l, kindNoStructure
	}
	l.category = rest[1:cend]
	l.message = strings.TrimPrefix(rest[cend+1:], " ")
	if l.category == "" {
		return l, kindNoStructure
	}

	when, off, kind := parseStamp(stamp)
	if kind != kindOK {
		return l, kind
	}
	l.when, l.offset = when, off
	return l, kindOK
}

// parseStamp accepts only stamps carrying an explicit offset: pacman's own
// "-0700" form, RFC3339's "-07:00", and "Z". The offset is returned normalised
// to +hhmm so a caller can count the distinct offsets in a file -- the reference
// log has exactly two, which is the DST boundary and the reason none of this can
// be shortcut.
func parseStamp(stamp string) (time.Time, string, parseKind) {
	if len(stamp) < 19 || len(stamp) > 40 {
		return time.Time{}, "", kindBadStamp
	}
	for _, layout := range []string{TimeLayout, time.RFC3339, "2006-01-02T15:04:05Z0700"} {
		t, err := time.Parse(layout, stamp)
		if err != nil {
			continue
		}
		// time.Parse is lenient -- it accepts a single-digit hour, for instance --
		// so the parse is only accepted when it round-trips to exactly the bytes
		// on the line. A stamp this reader would render differently is a stamp it
		// does not really understand, and the fuzzer found one:
		// "[0001-01-01T0:00:00+0000]" parsed to an instant that IsZero() reports
		// as unset, which is the sentinel this package uses for "no timestamp".
		if t.Format(layout) != stamp {
			continue
		}
		if y := t.Year(); y < MinPlausibleYear || y > MaxPlausibleYear {
			// An implausible year is a corrupt or forged line, not a transaction.
			// Accepting it would let one line move Earliest to year 1 and make the
			// truncation comparison meaningless.
			return time.Time{}, "", kindBadStamp
		}
		_, secs := t.Zone()
		return t, formatOffset(secs), kindOK
	}
	// Distinguish "no offset" from "not a timestamp": the first is a known
	// legacy format and deserves its own gap, because the same log may hold
	// both and the user needs to know which half is unusable.
	for _, layout := range []string{"2006-01-02 15:04", "2006-01-02 15:04:05", "2006-01-02T15:04:05"} {
		if _, err := time.Parse(layout, stamp); err == nil {
			return time.Time{}, "", kindNoOffset
		}
	}
	return time.Time{}, "", kindBadStamp
}

func formatOffset(secs int) string {
	sign := "+"
	if secs < 0 {
		sign = "-"
		secs = -secs
	}
	h, m := secs/3600, (secs%3600)/60
	return sign + twoDigit(h) + twoDigit(m)
}

func twoDigit(n int) string {
	if n < 0 {
		n = -n
	}
	if n > 99 {
		n = 99
	}
	return string([]byte{byte('0' + n/10), byte('0' + n%10)})
}

// parseALPM turns an [ALPM] message into a transaction, reporting whether it
// was one. Recognised non-transaction messages ("transaction started",
// "running '...'", "warning:", "error:") return ok=false with known=true: they
// are understood and carry no package, so they are neither entries nor gaps.
func parseALPM(msg string) (op, pkg, version, prev string, isTx, known bool) {
	verb, rest := cut(msg)
	switch verb {
	case OpInstalled, OpRemoved, OpUpgraded, OpDowngraded, OpReinstalled:
	case "transaction", "running", "warning:", "error:", "note:":
		return "", "", "", "", false, true
	default:
		return "", "", "", "", false, false
	}
	name, paren := cut(rest)
	if name == "" || len(paren) < 3 || paren[0] != '(' || !strings.HasSuffix(paren, ")") {
		// A transaction verb whose operand does not parse is NOT a recognised
		// line: a package name recorded without a version, or a truncated line,
		// must surface as a gap rather than as a versionless entry.
		return "", "", "", "", false, false
	}
	inner := paren[1 : len(paren)-1]
	if before, after, found := cut3(inner, " -> "); found {
		prev, version = before, after
	} else {
		version = inner
	}
	if version == "" || strings.ContainsAny(name, " \t") {
		return "", "", "", "", false, false
	}
	switch verb {
	case OpUpgraded, OpDowngraded:
		if prev == "" {
			return "", "", "", "", false, false
		}
	}
	return verb, name, version, prev, true, true
}

func cut(s string) (head, rest string) {
	i := strings.IndexByte(s, ' ')
	if i < 0 {
		return s, ""
	}
	return s[:i], strings.TrimLeft(s[i+1:], " ")
}

func cut3(s, sep string) (before, after string, found bool) {
	i := strings.Index(s, sep)
	if i < 0 {
		return s, "", false
	}
	return s[:i], s[i+len(sep):], true
}

// invocationRoot extracts the root a [PACMAN] invocation named. It returns
// ok=false for [PACMAN] lines that are not invocations ("synchronizing package
// lists", "starting full system upgrade"), which leave the current root
// context alone.
//
// This is the only place the log says which filesystem the transactions that
// FOLLOW belong to, so getting the flag shapes right is load-bearing: `-r /mnt`,
// `--root /mnt`, `--root=/mnt`, and the clustered `-Sr/mnt` all appear in the
// wild, and missing one silently attributes another root's install to this one.
// Note what is deliberately NOT treated as a root: `-b` sets the database path,
// and a chroot build passes both.
func invocationRoot(msg string) (string, bool) {
	const pfx = "Running '"
	if !strings.HasPrefix(msg, pfx) {
		return "", false
	}
	cmd := msg[len(pfx):]
	if i := strings.LastIndexByte(cmd, '\''); i >= 0 {
		cmd = cmd[:i]
	}
	args := strings.Fields(cmd)
	for i := 0; i < len(args); i++ {
		a := args[i]
		switch {
		case a == "--root" || a == "-r":
			if i+1 < len(args) {
				return cleanRoot(args[i+1]), true
			}
			// A trailing --root with no value names no root; the invocation is
			// still an invocation, so the context resets to the default rather
			// than inheriting the previous one.
			return "/", true
		case strings.HasPrefix(a, "--root="):
			return cleanRoot(strings.TrimPrefix(a, "--root=")), true
		case strings.HasPrefix(a, "--"):
			// Long options that are not --root; --config=X etc. carry values
			// inline or in the next argument, and neither can be mistaken for a
			// root because only --root is matched.
		case strings.HasPrefix(a, "-") && len(a) > 1:
			// Short cluster. Only a trailing r takes the rest of the token, or
			// the next argument, as its value.
			if j := strings.IndexByte(a, 'r'); j > 0 {
				if j == len(a)-1 {
					if i+1 < len(args) {
						return cleanRoot(args[i+1]), true
					}
					return "/", true
				}
				return cleanRoot(a[j+1:]), true
			}
		}
	}
	return "/", true
}
