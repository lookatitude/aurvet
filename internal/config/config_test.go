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
