// internal/alpm/files_test.go
package alpm

import (
	"strings"
	"testing"
)

// Measured: %BACKUP% is in `files`, NOT `desc`, and its digests are MD5.
// Format is path<TAB>md5. 348 entries across 94 packages.
const sampleFiles = "%FILES%\netc/pacman.conf\nusr/bin/pacman\n\n%BACKUP%\netc/pacman.conf\t615a81e46afa8d939f47824e83e9d444\n"

func TestParseFilesSplitsPathsAndBackup(t *testing.T) {
	paths, backup, err := ParseFiles(strings.NewReader(sampleFiles))
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %v, want 2", paths)
	}
	if paths[0] != "etc/pacman.conf" {
		t.Errorf("paths[0] = %q", paths[0])
	}
	md5, ok := backup["etc/pacman.conf"]
	if !ok {
		t.Fatal("etc/pacman.conf missing from backup map")
	}
	if md5 != "615a81e46afa8d939f47824e83e9d444" {
		t.Errorf("md5 = %q", md5)
	}
}

func TestParseFilesNoBackupSection(t *testing.T) {
	_, backup, err := ParseFiles(strings.NewReader("%FILES%\nusr/bin/x\n"))
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}
	if len(backup) != 0 {
		t.Errorf("backup = %v, want empty", backup)
	}
}

func TestParseFilesBackupLineWithoutTab(t *testing.T) {
	_, backup, err := ParseFiles(strings.NewReader("%BACKUP%\netc/pacman.conf-no-tab\n"))
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}
	if len(backup) != 0 {
		t.Errorf("backup = %v, want empty (no tab means skipped, not stored under empty digest)", backup)
	}
	if _, ok := backup["etc/pacman.conf-no-tab"]; ok {
		t.Error("malformed line without a tab must not land in backup")
	}
}

func TestParseFilesBackupBeforeFiles(t *testing.T) {
	const in = "%BACKUP%\netc/pacman.conf\t615a81e46afa8d939f47824e83e9d444\n\n%FILES%\netc/pacman.conf\nusr/bin/pacman\n"
	paths, backup, err := ParseFiles(strings.NewReader(in))
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}
	if len(paths) != 2 {
		t.Fatalf("paths = %v, want 2", paths)
	}
	if paths[0] != "etc/pacman.conf" {
		t.Errorf("paths[0] = %q", paths[0])
	}
	md5, ok := backup["etc/pacman.conf"]
	if !ok {
		t.Fatal("etc/pacman.conf missing from backup map")
	}
	if md5 != "615a81e46afa8d939f47824e83e9d444" {
		t.Errorf("md5 = %q", md5)
	}
}

func TestParseFilesEmptyInput(t *testing.T) {
	paths, backup, err := ParseFiles(strings.NewReader(""))
	if err != nil {
		t.Fatalf("ParseFiles: %v", err)
	}
	if len(paths) != 0 {
		t.Errorf("paths = %v, want empty", paths)
	}
	if len(backup) != 0 {
		t.Errorf("backup = %v, want empty", backup)
	}
}
