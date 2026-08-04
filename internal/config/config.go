// Package config resolves every filesystem location aurvet touches from a
// single explicit root.
//
// INV-4: no collector may read an ambient path. --offline-root is therefore a
// parameter to this resolution, not a second code path through the scanners.
package config

import "path/filepath"

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

	// Network gates every outbound request. --no-network clears it, and a
	// cleared flag must produce coverage gaps rather than absence findings.
	Network bool

	// MinSeverity is the reporting floor.
	MinSeverity string
}

// DoctorLine is one row of `aurvet doctor` output: the resolved value plus
// where it came from, so a misconfiguration can be traced to its origin.
type DoctorLine struct {
	Key    string
	Value  string
	Source string
}

// Resolve derives all paths from root. euid selects the state directory:
// a privileged run must never trust state under a caller-controlled path, so
// root gets the system location unconditionally (spec §11).
func Resolve(root string, euid int) (Config, error) {
	if root == "" {
		root = "/"
	}

	// Unprivileged runs, including offline-root inspection, keep state inside
	// the tree they are examining. Root does not: /var/lib/aurvet is the
	// only location an unprivileged attacker cannot pre-seed.
	state := "/var/lib/aurvet"
	if euid != 0 {
		state = filepath.Join(root, "var/lib/aurvet")
	}

	return Config{
		Root:        root,
		DBPath:      filepath.Join(root, "var/lib/pacman/local"),
		SyncPath:    filepath.Join(root, "var/lib/pacman/sync"),
		StateDir:    state,
		Network:     true,
		MinSeverity: "suspicious",
	}, nil
}

// Doctor reports the resolved configuration with per-key provenance.
func (c Config) Doctor() []DoctorLine {
	return []DoctorLine{
		{"root", c.Root, "flag-or-default"},
		{"db_path", c.DBPath, "derived"},
		{"sync_path", c.SyncPath, "derived"},
		{"state_dir", c.StateDir, "derived"},
		{"min_severity", c.MinSeverity, "default"},
	}
}
