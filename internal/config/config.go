// Package config resolves every filesystem location aurvet touches from a
// single explicit root.
//
// INV-4: no collector may read an ambient path. --offline-root is therefore a
// parameter to this resolution, not a second code path through the scanners.
package config

import (
	"os"
	"path/filepath"
)

// Config is the fully resolved runtime configuration. All path fields are
// absolute and already rooted; consumers never re-join them against Root.
type Config struct {
	// Root is the filesystem tree being examined. "/" for a live system, a
	// mountpoint for --offline-root.
	Root string

	// DBPath is the pacman local database (one directory per installed package).
	DBPath string

	// SyncPath is the pacman sync database directory, the name oracle used to
	// decide foreignness.
	SyncPath string

	// StateDir holds baselines and scan history.
	StateDir string

	// stateDirSource records which of Resolve's state-directory cases fired,
	// so Doctor can report per-key provenance instead of a blanket "derived".
	stateDirSource string

	// Network gates every outbound request. --no-network clears it, and a
	// cleared flag must produce coverage gaps rather than absence findings.
	Network bool

	// MinSeverity is the exit-code threshold, NOT a display filter. Findings
	// below it are still rendered by both Text and JSON -- deliberately, so a
	// report never hides what was observed (INV-3's spirit: the operator sees
	// everything examined) -- but they do not raise exit 1. Text sorts
	// severity-descending, so below-floor findings land last. Calling this a
	// "reporting floor" (as this comment previously did) invites the opposite
	// reading; JSONView's doc comment states the same rule from the JSON side.
	MinSeverity string
}

// DoctorLine is one row of `aurvet doctor` output: the resolved value plus
// where it came from, so a misconfiguration can be traced to its origin.
type DoctorLine struct {
	Key    string
	Value  string
	Source string

	// Warning is non-empty when this key resolved to something that will not
	// work. Empty for every healthy resolution, so a caller can render it
	// unconditionally without special-casing.
	Warning string
}

// Resolve derives all paths from root. euid and root together select the
// state directory across three cases (in order):
//
//  1. euid == 0 -> the system location, unconditionally. A privileged run
//     must never trust state under a caller-controlled path (spec §11): if
//     it followed XDG_STATE_HOME, an unprivileged attacker could redirect
//     what a root-privileged security tool trusts.
//  2. euid != 0 and root != "/" (--offline-root) -> state stays inside the
//     tree being inspected, alongside the DB paths above.
//  3. euid != 0 and root == "/" (the live unprivileged run, the primary use
//     case) -> a per-user XDG state location. /var/lib/aurvet is NOT reused
//     here: it is root-owned and not writable by a normal user, so reusing
//     it silently breaks report persistence and therefore --since-last (the
//     defect this case closes). os.Getenv is read here, and only here --
//     Resolve is the one place ambient environment is legitimately consulted
//     (INV-4); collectors downstream only ever see the resolved Config.
func Resolve(root string, euid int) (Config, error) {
	if root == "" {
		root = "/"
	}

	state, source := resolveStateDir(root, euid)

	return Config{
		Root:           root,
		DBPath:         filepath.Join(root, "var/lib/pacman/local"),
		SyncPath:       filepath.Join(root, "var/lib/pacman/sync"),
		StateDir:       state,
		stateDirSource: source,
		Network:        true,
		MinSeverity:    "suspicious",
	}, nil
}

// resolveStateDir implements the three-case StateDir resolution documented
// on Resolve, and returns a self-describing source token alongside the path
// so Doctor can report which case fired.
func resolveStateDir(root string, euid int) (dir, source string) {
	if euid == 0 {
		return "/var/lib/aurvet", "system-euid0"
	}

	if root != "/" {
		return filepath.Join(root, "var/lib/aurvet"), "offline-root"
	}

	// Live unprivileged run. Prefer XDG_STATE_HOME, then $HOME, then fall
	// back to the unwritable system path -- Resolve must not error even in
	// the fallback case, so doctor has something to report.
	//
	// A relative (or empty) XDG_STATE_HOME is ignored rather than joined:
	// filepath.Join would silently produce a path relative to the process
	// CWD, exactly the ambient-path failure INV-4 exists to prevent.
	if xdg := os.Getenv("XDG_STATE_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "aurvet"), "xdg-state-home"
	}
	if home := os.Getenv("HOME"); filepath.IsAbs(home) {
		return filepath.Join(home, ".local/state/aurvet"), "home-default"
	}
	return "/var/lib/aurvet", SourceFallbackUnwritable
}

// SourceFallbackUnwritable is the state_dir provenance for the one resolution
// case that is known-degraded: an unprivileged live run with neither
// XDG_STATE_HOME nor HOME set to an absolute path. Named rather than inlined so
// Doctor can test for it without matching a string literal in two places.
const SourceFallbackUnwritable = "fallback-unwritable"

// Doctor reports the resolved configuration with per-key provenance.
//
// A resolution that cannot work is reported as such rather than printed as
// though it were fine. `state_dir` is the only key with that failure mode: in
// the fallback case an unprivileged process gets /var/lib/aurvet, every write
// fails with EACCES, and --since-last therefore cannot persist a baseline. That
// used to surface only as a mkdir error at the moment of use, which reads as a
// bug in --since-last rather than as a configuration problem doctor could have
// named. Reporting it here is the INV-3 habit applied to configuration: do not
// present something as working when it is known not to be.
func (c Config) Doctor() []DoctorLine {
	stateDir := DoctorLine{Key: "state_dir", Value: c.StateDir, Source: c.stateDirSource}
	if c.stateDirSource == SourceFallbackUnwritable {
		stateDir.Warning = "not writable by this user — neither XDG_STATE_HOME nor HOME is an absolute path, so --since-last cannot persist a baseline"
	}

	return []DoctorLine{
		{Key: "root", Value: c.Root, Source: "flag-or-default"},
		{Key: "db_path", Value: c.DBPath, Source: "derived"},
		{Key: "sync_path", Value: c.SyncPath, Source: "derived"},
		stateDir,
		{Key: "min_severity", Value: c.MinSeverity, Source: "default"},
	}
}
