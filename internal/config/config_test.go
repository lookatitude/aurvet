package config

import "testing"

// INV-4: every path derives from an explicit root, so a collector never reads
// an ambient location. This is what makes --offline-root a parameter rather
// than a second code path.
func TestResolveDerivesPathsFromRoot(t *testing.T) {
	c, err := Resolve("/mnt/target", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.DBPath != "/mnt/target/var/lib/pacman/local" {
		t.Errorf("DBPath = %q", c.DBPath)
	}
	if c.SyncPath != "/mnt/target/var/lib/pacman/sync" {
		t.Errorf("SyncPath = %q", c.SyncPath)
	}
}

// An empty root must mean "/", not an empty prefix that would silently produce
// relative paths.
func TestResolveEmptyRootMeansFilesystemRoot(t *testing.T) {
	c, err := Resolve("", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.DBPath != "/var/lib/pacman/local" {
		t.Errorf("DBPath = %q, want /var/lib/pacman/local", c.DBPath)
	}
}

// doctor is the operability command: it must show not just the resolved value
// but where each value came from, or it cannot be used to debug a bad config.
func TestDoctorReportsProvenancePerKey(t *testing.T) {
	c, err := Resolve("/", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	lines := c.Doctor()
	if len(lines) == 0 {
		t.Fatal("Doctor returned no lines")
	}
	for _, l := range lines {
		if l.Key == "" || l.Source == "" {
			t.Errorf("line missing key or source: %+v", l)
		}
	}
}

// Spec §11: when euid == 0 the tool must never resolve state into a
// user-writable location, because an unprivileged attacker could then control
// what a root-privileged security tool trusts.
func TestResolveStateDirIsSystemOwnedForRoot(t *testing.T) {
	c, err := Resolve("/", 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/var/lib/aurvet" {
		t.Errorf("root StateDir = %q, want /var/lib/aurvet", c.StateDir)
	}
}

// Defect regression: the live unprivileged run (root == "/") must not resolve
// StateDir to the system location, because an unprivileged user cannot write
// there and report persistence (and therefore --since-last) silently breaks.
func TestResolveStateDirLiveUnprivilegedUsesXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/home/alice/.state")
	t.Setenv("HOME", "/home/alice")

	c, err := Resolve("/", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/home/alice/.state/aurvet" {
		t.Errorf("StateDir = %q, want /home/alice/.state/aurvet", c.StateDir)
	}
	if c.StateDir == "/var/lib/aurvet" {
		t.Errorf("StateDir regressed to unwritable system path %q", c.StateDir)
	}
}

func TestResolveStateDirLiveUnprivilegedFallsBackToHomeDefault(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "/home/bob")

	c, err := Resolve("/", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/home/bob/.local/state/aurvet" {
		t.Errorf("StateDir = %q, want /home/bob/.local/state/aurvet", c.StateDir)
	}
	if c.StateDir == "/var/lib/aurvet" {
		t.Errorf("StateDir regressed to unwritable system path %q", c.StateDir)
	}
}

// Security-relevant half of the fix: a privileged run must ignore
// XDG_STATE_HOME entirely. Otherwise an unprivileged attacker who controls
// the environment of a root-invoked process could redirect where a
// root-privileged security tool trusts its state.
func TestResolveStateDirRootIgnoresXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/home/attacker/.state")
	t.Setenv("HOME", "/home/attacker")

	c, err := Resolve("/", 0)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/var/lib/aurvet" {
		t.Errorf("root StateDir = %q, want /var/lib/aurvet (must not follow XDG_STATE_HOME)", c.StateDir)
	}
}

// --offline-root inspection must keep resolving state inside the inspected
// tree, not redirect to the caller's XDG state location.
func TestResolveStateDirOfflineRootIgnoresXDG(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "/home/alice/.state")
	t.Setenv("HOME", "/home/alice")

	c, err := Resolve("/mnt/target", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/mnt/target/var/lib/aurvet" {
		t.Errorf("StateDir = %q, want /mnt/target/var/lib/aurvet", c.StateDir)
	}
}

// A relative XDG_STATE_HOME must be ignored, not joined -- otherwise the
// resolved path depends on the process CWD, exactly the ambient-path failure
// INV-4 exists to prevent.
func TestResolveStateDirIgnoresRelativeXDGStateHome(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "relative/path")
	t.Setenv("HOME", "/home/carol")

	c, err := Resolve("/", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/home/carol/.local/state/aurvet" {
		t.Errorf("StateDir = %q, want /home/carol/.local/state/aurvet (relative XDG_STATE_HOME ignored)", c.StateDir)
	}
}

// When neither XDG_STATE_HOME nor HOME is usable, Resolve must still fall
// back to a value -- doctor has to be able to report it rather than Resolve
// erroring outright.
func TestResolveStateDirFallsBackWhenNoHomeOrXDG(t *testing.T) {
	t.Setenv("XDG_STATE_HOME", "")
	t.Setenv("HOME", "")

	c, err := Resolve("/", 1000)
	if err != nil {
		t.Fatalf("Resolve: %v", err)
	}
	if c.StateDir != "/var/lib/aurvet" {
		t.Errorf("StateDir = %q, want fallback /var/lib/aurvet", c.StateDir)
	}
}

// Doctor's state_dir Source must name which of the three resolution cases
// fired, not a blanket "derived" -- that is the whole point of doctor's
// per-key provenance.
func TestDoctorStateDirSourceNamesTheCaseThatFired(t *testing.T) {
	cases := []struct {
		name       string
		root       string
		euid       int
		xdg        string
		home       string
		wantSource string
	}{
		{"root euid0", "/", 0, "/home/x/.state", "/home/x", "system-euid0"},
		{"offline root", "/mnt/target", 1000, "/home/x/.state", "/home/x", "offline-root"},
		{"xdg state home", "/", 1000, "/home/x/.state", "/home/x", "xdg-state-home"},
		{"home default", "/", 1000, "", "/home/x", "home-default"},
		{"fallback unwritable", "/", 1000, "", "", "fallback-unwritable"},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("XDG_STATE_HOME", tc.xdg)
			t.Setenv("HOME", tc.home)

			c, err := Resolve(tc.root, tc.euid)
			if err != nil {
				t.Fatalf("Resolve: %v", err)
			}
			var got string
			for _, l := range c.Doctor() {
				if l.Key == "state_dir" {
					got = l.Source
				}
			}
			if got != tc.wantSource {
				t.Errorf("state_dir Source = %q, want %q", got, tc.wantSource)
			}
		})
	}
}
