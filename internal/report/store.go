// internal/report/store.go
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/lookatitude/aurvet/internal/finding"
)

const reportsSubdir = "reports"

// storedReport is the on-disk envelope. schemaVersion is defined in json.go
// and reused here rather than redeclared, so a future format change only
// needs to move that one constant.
type storedReport struct {
	SchemaVersion int               `json:"schema_version"`
	Stamp         string            `json:"stamp"`
	Summary       Summary           `json:"summary"`
	Findings      []finding.Finding `json:"findings"`
	Gaps          []finding.Gap     `json:"gaps"`
}

// Save persists r atomically to <stateDir>/reports/<stamp>.json: a scan
// report names every foreign package on the host, so the directory is
// 0o700 and the file 0o600 — neither is world-readable. The write goes to a
// temp file created in the destination directory (so the final rename never
// crosses a filesystem boundary), Sync'd, then renamed into place; the temp
// file is removed on every error path. Returns the final path.
func Save(stateDir string, r finding.Result, s Summary, stamp string) (string, error) {
	dir := filepath.Join(stateDir, reportsSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	if err := os.Chmod(dir, 0o700); err != nil {
		return "", err
	}

	blob, err := json.MarshalIndent(storedReport{
		SchemaVersion: schemaVersion,
		Stamp:         stamp,
		Summary:       s,
		Findings:      r.Findings,
		Gaps:          r.Gaps,
	}, "", "  ")
	if err != nil {
		return "", err
	}

	tmp, err := os.CreateTemp(dir, ".report-*.tmp")
	if err != nil {
		return "", err
	}
	tmpName := tmp.Name()

	if err := tmp.Chmod(0o600); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		os.Remove(tmpName)
		return "", err
	}
	if err := tmp.Close(); err != nil {
		os.Remove(tmpName)
		return "", err
	}

	final := filepath.Join(dir, stamp+".json")
	if err := os.Rename(tmpName, final); err != nil {
		os.Remove(tmpName)
		return "", err
	}
	return final, nil
}

// LoadLatest returns the newest stored report. Absence — including an empty
// or missing reports directory, and every report present but corrupt or
// written by a schema_version this build does not understand — is reported
// as (zero, false, nil), never an error.
func LoadLatest(stateDir string) (finding.Result, bool, error) {
	return loadNthValid(stateDir, 0)
}

// LoadPrevious returns the second-newest valid stored report — the correct
// --since-last baseline once the current run's own report has already been
// persisted by Save.
func LoadPrevious(stateDir string) (finding.Result, bool, error) {
	return loadNthValid(stateDir, 1)
}

// loadNthValid returns the n-th newest report (0 = newest) among those that
// parse and carry a recognized schema_version, skipping any that don't.
//
// Report stamps are formatted "20060102T150405Z" — lexicographically
// sortable — so sorting file names by string order is sorting by time. That
// assumption is what lets a plain descending string sort double as
// newest-first order below.
//
// A damaged newest report must not hide a healthy older one: this walks
// backwards past every corrupt or unrecognized entry rather than stopping at
// the first failure, so a previous run that was SIGKILLed mid-write degrades
// to "use the next-older report" (or "no baseline") instead of "refuse to
// run" — the safe direction for a security scanner.
func loadNthValid(stateDir string, n int) (finding.Result, bool, error) {
	dir := filepath.Join(stateDir, reportsSubdir)
	entries, err := os.ReadDir(dir)
	if err != nil {
		if os.IsNotExist(err) {
			return finding.Result{}, false, nil
		}
		return finding.Result{}, false, err
	}

	var names []string
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		names = append(names, e.Name())
	}
	sort.Sort(sort.Reverse(sort.StringSlice(names)))

	valid := 0
	for _, name := range names {
		st, ok := readStoredReport(filepath.Join(dir, name))
		if !ok {
			continue
		}
		if valid == n {
			return finding.Result{Findings: st.Findings, Gaps: st.Gaps}, true, nil
		}
		valid++
	}
	return finding.Result{}, false, nil
}

// readStoredReport reads and validates one report file. Any failure — an
// unreadable file, truncated or non-object JSON, or a schema_version this
// build does not recognize — makes the report read as though it were not
// there at all: never an error, never a panic.
func readStoredReport(path string) (storedReport, bool) {
	blob, err := os.ReadFile(path)
	if err != nil {
		return storedReport{}, false
	}
	var st storedReport
	if err := json.Unmarshal(blob, &st); err != nil {
		return storedReport{}, false
	}
	if st.SchemaVersion != schemaVersion {
		return storedReport{}, false
	}
	return st, true
}

// Diff reports findings new in cur and findings resolved since prev. It
// keys on FindingID — the identical (RuleID, SubjectKind, Subject,
// "subject") tuple text.go renders and json.go emits — so a finding never
// drifts out of sync across scan / report / diff. That in turn depends on
// every caller keeping Subject version-independent (finding.Fingerprint's
// doc comment); if a caller ever folds a version into Subject, every
// --since-last suppression breaks on the next package upgrade.
func Diff(prev, cur finding.Result) (added, resolved []finding.Finding) {
	prevSet := make(map[string]finding.Finding, len(prev.Findings))
	for _, f := range prev.Findings {
		prevSet[FindingID(f)] = f
	}
	curSet := make(map[string]finding.Finding, len(cur.Findings))
	for _, f := range cur.Findings {
		curSet[FindingID(f)] = f
	}

	for id, f := range curSet {
		if _, ok := prevSet[id]; !ok {
			added = append(added, f)
		}
	}
	for id, f := range prevSet {
		if _, ok := curSet[id]; !ok {
			resolved = append(resolved, f)
		}
	}

	// Subject alone is not a total order: one package routinely carries
	// several findings (aur-orphaned and aur-submitter-mismatch both fire on
	// the same name), and map iteration would then shuffle them run to run.
	// FindingID breaks the tie because it is unique per finding by
	// construction — the same tuple the two maps above are keyed on.
	byID := func(s []finding.Finding) func(i, j int) bool {
		return func(i, j int) bool {
			if s[i].Subject != s[j].Subject {
				return s[i].Subject < s[j].Subject
			}
			return FindingID(s[i]) < FindingID(s[j])
		}
	}
	sort.Slice(added, byID(added))
	sort.Slice(resolved, byID(resolved))
	return added, resolved
}
