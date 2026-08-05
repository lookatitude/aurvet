// internal/pacmanlog/read.go
//
// File discovery and bounded reading. Under --offline-root the log and its
// siblings are attacker-supplied files, so every dimension an attacker controls
// is bounded here: the number of siblings, the number of lines, the length of a
// line, and the number of bytes a compressed sibling expands to.
package pacmanlog

import (
	"bufio"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
)

// logFile is one discovered file, with the age rank that orders reading.
type logFile struct {
	path string

	// age orders files oldest-last: 0 is the live log, higher is older. It is
	// the rotation number for numeric rotation and a derived value for
	// date-suffixed rotation.
	age int64

	// compression is "" (plain) or "gzip". Anything else is never a logFile --
	// it is a gap, because zstd, xz and bzip2 are not in the standard library
	// and this project adds no modules to get them.
	compression string
}

// knownUnsupported maps a rotation suffix to the reason it cannot be read. Being
// explicit beats a generic "unknown extension": a user whose logrotate is
// configured for zstd needs to be told that specifically, since the alternative
// reading -- "there is no older history" -- is false.
var knownUnsupported = map[string]string{
	".zst":  "zstd, which is not in the Go standard library and this project adds no modules",
	".zstd": "zstd, which is not in the Go standard library and this project adds no modules",
	".xz":   "xz, which is not in the Go standard library",
	".lzma": "lzma, which is not in the Go standard library",
	".bz2":  "bzip2, which is not in the Go standard library",
	".lz4":  "lz4, which is not in the Go standard library",
	".Z":    "compress(1), which is not in the Go standard library",
	".zip":  "zip, which is not a log rotation format this reader accepts",
}

// discover finds the primary log and its rotated siblings.
//
// Rotation is where history silently ends: a reader that opens only pacman.log
// reports a short window as if it were the whole history, and then a package
// installed six months ago looks unexplained. The reference machine has NO
// rotated siblings, so this path is exercised by fixtures rather than by
// measurement -- stated plainly because "it works here" would be worthless
// evidence for it.
func discover(path string, lim Limits) ([]logFile, []finding.Gap) {
	var gaps []finding.Gap
	dir := filepath.Dir(path)
	base := filepath.Base(path)

	var files []logFile
	if f, gap, ok := classifyPrimary(path); ok {
		files = append(files, f)
	} else if gap != nil {
		gaps = append(gaps, *gap)
	}

	ents, err := os.ReadDir(dir)
	if err != nil {
		// The directory is unreadable, so rotation cannot be ruled out. Saying
		// "no siblings" here would be a claim this read cannot support.
		gaps = append(gaps, finding.Gap{
			RuleID:  RuleSibling,
			Subject: dir,
			Reason: fmt.Sprintf("%s could not be listed (%v), so whether rotated siblings exist is "+
				"unknown and any history they hold is not covered", dir, err),
		})
		return files, gaps
	}
	for _, ent := range ents {
		name := ent.Name()
		if name == base {
			continue
		}
		age, comp, ok := classifySibling(base, name)
		if !ok {
			continue
		}
		full := filepath.Join(dir, name)
		if unsup, bad := knownUnsupported[comp]; bad {
			gaps = append(gaps, finding.Gap{
				RuleID:  RuleSibling,
				Subject: full,
				Reason: fmt.Sprintf("%s is a rotated pacman log compressed with %s, so the transactions "+
					"it records are not read and the coverage this scan reports begins later than the "+
					"history that exists", full, unsup),
			})
			continue
		}
		if !ent.Type().IsRegular() {
			// A symlink or fifo named like a rotation is not history; following
			// it would read whatever it points at, under a name that claims to
			// be a log.
			gaps = append(gaps, finding.Gap{
				RuleID:  RuleSibling,
				Subject: full,
				Reason: fmt.Sprintf("%s is named like a rotated pacman log but is not a regular file "+
					"(%s), so it is not read", full, ent.Type()),
			})
			continue
		}
		files = append(files, logFile{path: full, age: age, compression: comp})
	}

	// Oldest first, so Entries accumulate in roughly chronological order and the
	// earliest timestamp is seen early.
	sort.Slice(files, func(i, j int) bool {
		if files[i].age != files[j].age {
			return files[i].age > files[j].age
		}
		return files[i].path < files[j].path
	})
	if len(files) > lim.MaxFiles {
		// Keep the NEWEST: dropping recent transactions to make room for older
		// ones would discard the part of the log that explains what happened
		// most recently.
		dropped := files[:len(files)-lim.MaxFiles]
		files = files[len(files)-lim.MaxFiles:]
		names := make([]string, 0, len(dropped))
		for _, d := range dropped {
			names = append(names, filepath.Base(d.path))
		}
		gaps = append(gaps, finding.Gap{
			RuleID:  RuleBound,
			Subject: dir,
			Reason: fmt.Sprintf("%d rotated siblings exceed the %d-file bound, so the %d oldest were not "+
				"read and their history is not covered: %s",
				len(dropped)+lim.MaxFiles, lim.MaxFiles, len(dropped), strings.Join(names, ", ")),
		})
	}
	return files, gaps
}

func classifyPrimary(path string) (logFile, *finding.Gap, bool) {
	st, err := os.Lstat(path)
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return logFile{}, nil, false // reported as RuleAbsent by the caller
		}
		g := finding.Gap{
			RuleID:  RuleAbsent,
			Subject: path,
			Reason:  fmt.Sprintf("%s could not be examined (%v), so no transaction times are available", path, err),
		}
		return logFile{}, &g, false
	}
	if !st.Mode().IsRegular() {
		g := finding.Gap{
			RuleID:  RuleAbsent,
			Subject: path,
			Reason: fmt.Sprintf("%s is not a regular file (%s), so it is not read as a log", path,
				st.Mode().Type()),
		}
		return logFile{}, &g, false
	}
	comp := ""
	if strings.HasSuffix(path, ".gz") {
		comp = ".gz"
	}
	return logFile{path: path, age: 0, compression: comp}, nil, true
}

// classifySibling recognises "pacman.log.1", "pacman.log.2.gz" and logrotate's
// dateext form "pacman.log-20260501(.gz)". Anything else with the right prefix
// is ignored rather than guessed at: pacman.log.bak is not rotation.
func classifySibling(base, name string) (age int64, comp string, ok bool) {
	if !strings.HasPrefix(name, base) {
		return 0, "", false
	}
	rest := name[len(base):]
	if rest == "" {
		return 0, "", false
	}
	if ext := filepath.Ext(rest); ext != "" {
		if ext == ".gz" || knownUnsupported[ext] != "" {
			comp = ext
			rest = rest[:len(rest)-len(ext)]
		}
	}
	if len(rest) < 2 {
		return 0, "", false
	}
	sep, digits := rest[0], rest[1:]
	if sep != '.' && sep != '-' {
		return 0, "", false
	}
	n, err := strconv.ParseInt(digits, 10, 64)
	if err != nil || n < 0 {
		return 0, "", false
	}
	switch len(digits) {
	case 8: // dateext: newer date is younger, so invert.
		return 100_000_000 - n, comp, true
	default:
		if n > 1_000_000 {
			return 0, "", false
		}
		return n, comp, true
	}
}

// tally is the per-file census.
type tally struct {
	alpm      int
	pacman    int
	scriptlet int
	unparsed  int
	offsets   map[string]bool
	earliest  time.Time
	latest    time.Time
}

// readFile reads one log file into entries, bounded in every dimension.
func readFile(lf logFile, targetRoot string, lim Limits, res *Result) (FileStat, []Entry, tally) {
	st := FileStat{Path: lf.path, Compression: strings.TrimPrefix(lf.compression, ".")}
	tl := tally{offsets: map[string]bool{}}

	f, err := os.Open(lf.path)
	if err != nil {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID:  RuleSibling,
			Subject: lf.path,
			Reason:  fmt.Sprintf("%s could not be opened (%v), so the history it holds is not covered", lf.path, err),
		})
		return st, nil, tl
	}
	defer f.Close()

	var src io.Reader = f
	if lf.compression == ".gz" {
		// The gzip reader is given a bounded source AND its output is bounded
		// below: a bomb is cheap to write and neither bound alone is enough.
		zr, err := gzip.NewReader(io.LimitReader(f, lim.MaxFileBytes))
		if err != nil {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID:  RuleSibling,
				Subject: lf.path,
				Reason: fmt.Sprintf("%s is not readable as gzip (%v), so the history it holds is not "+
					"covered", lf.path, err),
			})
			return st, nil, tl
		}
		defer zr.Close()
		src = zr
	}

	br := bufio.NewReaderSize(src, 64<<10)
	var entries []Entry
	// Root context. Nothing before the first invocation line says which root a
	// transaction belongs to, so it is attributed to the target root and marked
	// inferred: a rotated file that begins mid-transaction is the normal case.
	curRoot, rootKnown := targetRoot, false
	kinds := map[parseKind][]string{}
	kindCount := map[parseKind]int{}
	overlongCount := 0
	var overlongSamples []string

	for {
		if st.Lines >= lim.MaxLines {
			st.Bounded = true
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID:  RuleBound,
				Subject: lf.path,
				Reason: fmt.Sprintf("%s exceeds the %d-line bound; reading stopped there and any "+
					"transaction after that line is not covered", lf.path, lim.MaxLines),
			})
			break
		}
		text, n, overlong, err := readLine(br, lim.MaxLineBytes)
		if n == 0 && err != nil {
			if !errors.Is(err, io.EOF) {
				res.Gaps = append(res.Gaps, finding.Gap{
					RuleID:  RuleSibling,
					Subject: lf.path,
					Reason: fmt.Sprintf("%s stopped being readable after %d lines (%v), so the rest is "+
						"not covered", lf.path, st.Lines, err),
				})
			}
			break
		}
		if st.Bytes+int64(n) > lim.MaxFileBytes {
			st.Bounded = true
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID:  RuleBound,
				Subject: lf.path,
				Reason: fmt.Sprintf("%s exceeds the %d-byte bound after decompression; reading stopped "+
					"at line %d and the rest is not covered (a compressed log that expands past this "+
					"bound is itself worth a look)",
					lf.path, lim.MaxFileBytes, st.Lines+1),
			})
			break
		}
		st.Bytes += int64(n)
		st.Lines++

		if overlong {
			// A bound, not a grammar failure: the distinction matters because
			// the remedy differs -- an overlong line means this reader refused
			// to buffer what was there, not that what was there was malformed.
			st.Bounded = true
			overlongCount++
			if len(overlongSamples) < lim.MaxSamples {
				overlongSamples = append(overlongSamples,
					fmt.Sprintf("line %d: %d bytes", st.Lines, n))
			}
			continue
		}
		if strings.TrimSpace(text) == "" {
			continue
		}

		l, kind := parseLine(text)
		if kind != kindOK {
			kindCount[kind]++
			if len(kinds[kind]) < lim.MaxSamples {
				kinds[kind] = append(kinds[kind], fmt.Sprintf("line %d: %s", st.Lines, sample(text)))
			}
			continue
		}
		tl.offsets[l.offset] = true
		if tl.earliest.IsZero() || l.when.Before(tl.earliest) {
			tl.earliest = l.when
		}
		if tl.latest.IsZero() || l.when.After(tl.latest) {
			tl.latest = l.when
		}

		switch l.category {
		case CategoryPacman:
			tl.pacman++
			if root, ok := invocationRoot(l.message); ok {
				curRoot, rootKnown = root, true
			}
		case CategoryScriptlet:
			// Scriptlet output is package-controlled text. It is counted and
			// never interpreted (INV-2): it is neither a transaction nor a gap.
			tl.scriptlet++
		case CategoryALPM:
			tl.alpm++
			op, pkg, ver, prev, isTx, known := parseALPM(l.message)
			if !known {
				kindCount[kindUnknownMessage]++
				if len(kinds[kindUnknownMessage]) < lim.MaxSamples {
					kinds[kindUnknownMessage] = append(kinds[kindUnknownMessage],
						fmt.Sprintf("line %d: %s", st.Lines, sample(text)))
				}
				continue
			}
			if !isTx {
				continue
			}
			entries = append(entries, Entry{
				Time:         l.when,
				Offset:       l.offset,
				Category:     l.category,
				Op:           op,
				Pkg:          pkg,
				Version:      ver,
				PrevVersion:  prev,
				Root:         curRoot,
				RootInferred: !rootKnown,
				File:         lf.path,
				Line:         st.Lines,
			})
		default:
			// A category this reader does not know ([PACMAN-something] from a
			// future pacman) is counted as unparsed rather than assumed inert.
			kindCount[kindNoStructure]++
			if len(kinds[kindNoStructure]) < lim.MaxSamples {
				kinds[kindNoStructure] = append(kinds[kindNoStructure],
					fmt.Sprintf("line %d: unknown category [%s]", st.Lines, sample(l.category)))
			}
		}
	}

	if overlongCount > 0 {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID:  RuleBound,
			Subject: lf.path,
			Reason: fmt.Sprintf("%d line(s) in %s exceed the %d-byte line bound and were dropped; "+
				"reading continued at the next newline, so only those lines are uncovered: %s",
				overlongCount, lf.path, lim.MaxLineBytes, strings.Join(overlongSamples, "; ")),
		})
	}

	// One gap per kind per file, with a bounded sample. A corrupt log must not
	// produce one gap per line.
	for _, kind := range []parseKind{kindNoStructure, kindNoOffset, kindBadStamp, kindUnknownMessage} {
		c := kindCount[kind]
		if c == 0 {
			continue
		}
		tl.unparsed += c
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID:  RuleUnparsed,
			Subject: lf.path,
			Reason: fmt.Sprintf("%d line(s) in %s were not understood: %s. Samples: %s",
				c, lf.path, kind.reason(), strings.Join(kinds[kind], "; ")),
		})
	}
	return st, entries, tl
}

// readLine returns one line without its newline, the bytes consumed, and
// whether it exceeded max. An overlong line is discarded to the next newline
// and reading continues: one absurd line must not cost the rest of the file,
// and the bytes consumed are still counted so the byte bound stays honest.
func readLine(br *bufio.Reader, max int) (text string, consumed int, overlong bool, err error) {
	var b strings.Builder
	for {
		chunk, e := br.ReadString('\n')
		consumed += len(chunk)
		if !overlong {
			if b.Len()+len(chunk) > max {
				overlong = true
				b.Reset()
			} else {
				b.WriteString(chunk)
			}
		}
		if e != nil {
			return strings.TrimRight(b.String(), "\n"), consumed, overlong, e
		}
		if strings.HasSuffix(chunk, "\n") {
			return strings.TrimRight(b.String(), "\n"), consumed, overlong, nil
		}
	}
}

// sample renders attacker-controlled text safely for a report: quoted, so
// control characters and escape sequences cannot reach a terminal, and
// truncated, so a 60 KB line cannot become a 60 KB gap.
func sample(s string) string {
	const max = 120
	if len(s) > max {
		return strconv.Quote(s[:max]) + "... (truncated)"
	}
	return strconv.Quote(s)
}
