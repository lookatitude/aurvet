# arch-drift P1-A — Provenance Sweep Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Ship `arch-drift scan` that reports whether any installed foreign (AUR) package is known-malicious or provenance-anomalous, plus `explain`, `doctor`, and `--since-last`, running entirely unprivileged.

**Architecture:** Pure collectors of shape `(root, cfg) -> evidence` read the world-readable pacman local DB and sync DBs; a network client queries the AUR in one batched request and checks cgit for malware tombstones; a check layer turns evidence into findings with explicit coverage gaps; a report layer renders text/JSON and maps to contractual exit codes. No file hashing, no root, no privilege staging — those arrive in P1-B.

**Tech Stack:** Go 1.26 (Arch ships 1.26.5), standard library only — `archive/tar`, `compress/gzip`, `net/http`, `encoding/json`, `crypto/sha256`, `testing`. No third-party dependencies.

## Global Constraints

- **Go floor: 1.24** (for `os.Root`, used in P1-B). Build with `CGO_ENABLED=0`, `-trimpath`, `-buildvcs=false`.
- **Zero third-party dependencies in P1-A.** Every dependency added to this project must be justified in the PR that adds it (spec §16). Stdlib covers everything here.
- **INV-2 — parse, never execute.** No shelling out to `pacman`, `bash`, `git`, or any helper. Parse the on-disk formats directly.
- **INV-3 — never claim clean for what was not examined.** Coverage gaps are first-class and force exit `3`.
- **INV-4 — collectors are pure `(root, cfg) -> evidence`.** No ambient `$HOME`, no hardcoded `/`. Every path derives from an explicit root parameter. This is what makes every test a fixture-root test.
- **INV-6 — findings state their own limits** in output, not docs.
- **INV-10 — every check declares its evidence precondition** and reports *unavailable* rather than passing when evidence is missing.
- **Exit codes are contractual:** `0` no findings ≥ threshold **and** coverage complete · `1` findings ≥ threshold · `2` usage/config error · `3` no findings but coverage incomplete.
- **Severity vocabulary:** `critical`, `suspicious`, `info`. Rendered as text tokens, never colour alone.
- **JSON output carries `schema_version`**; breaking changes are reserved for major releases.
- **No network in tests.** The AUR client sits behind an interface with a recorded-fixture implementation.
- **Fixture roots live in `testdata/roots/<scenario>/`** and mirror real on-disk layout: `var/lib/pacman/local/<name>-<ver>/{desc,files}` and `var/lib/pacman/sync/<repo>.db`.

## Verified platform facts this plan depends on

These were measured on the reference system; the parsers are written against them, not against assumption.

- `desc` is `%KEY%\n<value>\n\n` repeating. Fields are **not guaranteed present** — `%SIZE%` missing on 9 packages, `%XDATA%` on 6, `%LICENSE%` on 1.
- `%BACKUP%` lives in **`files`, not `desc`**, formatted `path\t<md5>` (348 entries across 94 packages). Zero `desc` files contain it.
- Sync DBs are **gzipped tar** archives whose entries are `<name>-<ver>-<rel>/desc`. Package name = directory name with the last two hyphen-separated fields stripped.
- `%VALIDATION%` distribution is 1371 `pgp` / 38 `none`, but there are **39** foreign packages — `python-pkg_resources` is foreign yet `pgp` (a dropped-from-repo, Arch-dev-signed package). So `%VALIDATION%` is recorded as evidence but **never used as the foreign test**.
- AUR RPC accepts **all 39 foreign packages in one request** (~819-byte URL) and distinguishes failure from absence: `type: "error"` vs `type: "multiinfo"` with `resultcount: 0`.
- Removed-for-malware packages **retain a cgit repo** with a tombstone commit message. Verified: `librewolf-fix-bin`, `firefox-patch-bin`, `zen-browser-patched-bin` all serve `history removed due to malware`; `brave-bin` does not.

## File structure

| File | Responsibility |
|---|---|
| `go.mod` | Module definition, Go floor |
| `cmd/arch-drift/main.go` | Subcommand dispatch, flag parsing, exit-code mapping |
| `internal/alpm/desc.go` | `desc` field parser |
| `internal/alpm/files.go` | `files` + `%BACKUP%` parser |
| `internal/alpm/localdb.go` | Enumerate local DB, assemble `Package` values |
| `internal/alpm/syncdb.go` | Sync DB name oracle (gzip+tar) |
| `internal/finding/finding.go` | `Finding`, `Severity`, `Coverage`, `Result`, `Fingerprint` |
| `internal/aur/client.go` | `Client` interface, `Pkg` type |
| `internal/aur/http.go` | Live HTTP implementation (RPC batch + cgit tombstone) |
| `internal/aur/fake.go` | Recorded-fixture implementation for tests |
| `internal/check/provenance.go` | The provenance checks |
| `internal/report/text.go` | Human-readable renderer |
| `internal/report/json.go` | Versioned JSON renderer |
| `internal/report/store.go` | Report persistence + `--since-last` diff |
| `internal/config/config.go` | Path resolution, `doctor` data |
| `testdata/roots/stock/` | Clean fixture root — FP gate |
| `testdata/roots/cruft/` | Cruft-laden fixture root — FP gate |
| `testdata/roots/malicious/` | Tombstoned-package fixture — acceptance |

---

### Task 1: Module scaffold, config resolution, and `doctor`

**Files:**
- Create: `go.mod`
- Create: `internal/config/config.go`
- Create: `internal/config/config_test.go`
- Create: `cmd/arch-drift/main.go`

**Interfaces:**
- Consumes: nothing (first task)
- Produces: `config.Config{Root string, DBPath string, SyncPath string, StateDir string, Network bool, MinSeverity string}`; `config.Resolve(root string, euid int) (Config, error)`; `config.Config.Doctor() []config.DoctorLine` where `DoctorLine{Key, Value, Source string}`

- [ ] **Step 1: Write the failing test**

```go
// internal/config/config_test.go
package config

import "testing"

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

func TestDoctorReportsProvenancePerKey(t *testing.T) {
	c, _ := Resolve("/", 1000)
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/config/ -run TestResolve -v`
Expected: FAIL — build error, `undefined: Resolve`

- [ ] **Step 3: Write minimal implementation**

```go
// go.mod
module github.com/lookatitude/arch-drift

go 1.24
```

```go
// internal/config/config.go
package config

import "path/filepath"

// Config holds every path and toggle a collector needs. Per INV-4 all paths
// derive from Root, so nothing reads an ambient location.
type Config struct {
	Root        string
	DBPath      string
	SyncPath    string
	StateDir    string
	Network     bool
	MinSeverity string
}

// DoctorLine is one resolved setting plus where it came from.
type DoctorLine struct {
	Key    string
	Value  string
	Source string
}

// Resolve derives config from a root. euid selects the state directory: root
// gets the system location, an unprivileged user gets a per-user one. P1-A
// never reads a user config file, so Source is always "derived" or "default".
func Resolve(root string, euid int) (Config, error) {
	if root == "" {
		root = "/"
	}
	state := "/var/lib/arch-drift"
	if euid != 0 {
		state = filepath.Join(root, "var/lib/arch-drift")
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

func (c Config) Doctor() []DoctorLine {
	return []DoctorLine{
		{"root", c.Root, "flag-or-default"},
		{"db_path", c.DBPath, "derived"},
		{"sync_path", c.SyncPath, "derived"},
		{"state_dir", c.StateDir, "derived"},
		{"min_severity", c.MinSeverity, "default"},
	}
}
```

```go
// cmd/arch-drift/main.go
package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/lookatitude/arch-drift/internal/config"
)

const (
	exitClean      = 0
	exitFindings   = 1
	exitUsage      = 2
	exitIncomplete = 3
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

func run(args []string, stdout, stderr *os.File) int {
	if len(args) == 0 {
		fmt.Fprintln(stderr, "usage: arch-drift <scan|explain|doctor> [flags]")
		return exitUsage
	}
	fs := flag.NewFlagSet(args[0], flag.ContinueOnError)
	fs.SetOutput(stderr)
	root := fs.String("offline-root", "/", "operate against this root")
	if err := fs.Parse(args[1:]); err != nil {
		return exitUsage
	}
	cfg, err := config.Resolve(*root, os.Geteuid())
	if err != nil {
		fmt.Fprintln(stderr, "config:", err)
		return exitUsage
	}
	switch args[0] {
	case "doctor":
		for _, l := range cfg.Doctor() {
			fmt.Fprintf(stdout, "%-14s %-46s (%s)\n", l.Key, l.Value, l.Source)
		}
		return exitClean
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return exitUsage
	}
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/config/ -v && go build ./... && go run ./cmd/arch-drift doctor`
Expected: PASS, build succeeds, `doctor` prints five resolved lines

- [ ] **Step 5: Commit**

```bash
git add go.mod internal/config cmd/arch-drift
git commit -m "feat: module scaffold, root-derived config, doctor command"
```

---

### Task 2: `desc` parser tolerant of missing fields

**Files:**
- Create: `internal/alpm/desc.go`
- Create: `internal/alpm/desc_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `alpm.ParseDesc(r io.Reader) (map[string][]string, error)`

- [ ] **Step 1: Write the failing test**

```go
// internal/alpm/desc_test.go
package alpm

import (
	"strings"
	"testing"
)

const sampleDesc = `%NAME%
python-pkg_resources

%VERSION%
81.0.0-1

%BASE%
python-pkg_resources

%VALIDATION%
pgp

%DEPENDS%
python
python-packaging

`

func TestParseDescReadsFields(t *testing.T) {
	got, err := ParseDesc(strings.NewReader(sampleDesc))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if v := got["NAME"]; len(v) != 1 || v[0] != "python-pkg_resources" {
		t.Errorf("NAME = %v", v)
	}
	if v := got["DEPENDS"]; len(v) != 2 {
		t.Errorf("DEPENDS = %v, want 2 entries", v)
	}
}

// Measured: %SIZE% is absent on 9 of 1409 packages, %LICENSE% on 1.
// Absent must parse as absent, never as an error.
func TestParseDescToleratesMissingFields(t *testing.T) {
	got, err := ParseDesc(strings.NewReader(sampleDesc))
	if err != nil {
		t.Fatalf("ParseDesc: %v", err)
	}
	if _, ok := got["SIZE"]; ok {
		t.Error("SIZE should be absent")
	}
	if _, ok := got["LICENSE"]; ok {
		t.Error("LICENSE should be absent")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/alpm/ -run TestParseDesc -v`
Expected: FAIL — `undefined: ParseDesc`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/alpm/desc.go
package alpm

import (
	"bufio"
	"io"
	"strings"
)

// ParseDesc reads the pacman local-DB `desc` format: a %KEY% line followed by
// one or more value lines, terminated by a blank line. Unknown and absent keys
// are not errors — measured on the reference system, several packages omit
// %SIZE%, %XDATA% or %LICENSE%.
func ParseDesc(r io.Reader) (map[string][]string, error) {
	out := make(map[string][]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	key := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			key = ""
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2:
			key = line[1 : len(line)-1]
			if _, ok := out[key]; !ok {
				out[key] = nil
			}
		case key != "":
			out[key] = append(out[key], line)
		}
	}
	return out, sc.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/alpm/ -v`
Expected: PASS (both tests)

- [ ] **Step 5: Commit**

```bash
git add internal/alpm/desc.go internal/alpm/desc_test.go
git commit -m "feat(alpm): desc parser tolerant of absent fields"
```

---

### Task 3: `files` parser including the `%BACKUP%` section

**Files:**
- Create: `internal/alpm/files.go`
- Create: `internal/alpm/files_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `alpm.ParseFiles(r io.Reader) (paths []string, backup map[string]string, err error)`

- [ ] **Step 1: Write the failing test**

```go
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
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/alpm/ -run TestParseFiles -v`
Expected: FAIL — `undefined: ParseFiles`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/alpm/files.go
package alpm

import (
	"bufio"
	"io"
	"strings"
)

// ParseFiles reads the local-DB `files` format. Two sections matter: %FILES%
// lists owned paths (the ownership oracle), and %BACKUP% lists config files
// pacman expects to change, as path<TAB>md5. The digest is MD5, not SHA256 —
// verified against the reference system.
func ParseFiles(r io.Reader) ([]string, map[string]string, error) {
	var paths []string
	backup := make(map[string]string)
	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 0, 64*1024), 4*1024*1024)
	section := ""
	for sc.Scan() {
		line := sc.Text()
		switch {
		case line == "":
			continue
		case strings.HasPrefix(line, "%") && strings.HasSuffix(line, "%") && len(line) > 2:
			section = line[1 : len(line)-1]
		case section == "FILES":
			paths = append(paths, line)
		case section == "BACKUP":
			path, digest, found := strings.Cut(line, "\t")
			if found {
				backup[path] = digest
			}
		}
	}
	return paths, backup, sc.Err()
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/alpm/ -v`
Expected: PASS (all four tests)

- [ ] **Step 5: Commit**

```bash
git add internal/alpm/files.go internal/alpm/files_test.go
git commit -m "feat(alpm): files parser with MD5-keyed %BACKUP% section"
```

---

### Task 4: Local DB enumeration into `Package` values

**Files:**
- Create: `internal/alpm/localdb.go`
- Create: `internal/alpm/localdb_test.go`
- Create: `testdata/roots/stock/var/lib/pacman/local/zlib-1.3.1-2/desc`
- Create: `testdata/roots/stock/var/lib/pacman/local/zlib-1.3.1-2/files`
- Create: `testdata/roots/stock/var/lib/pacman/local/foo-bin-1.0-1/desc`
- Create: `testdata/roots/stock/var/lib/pacman/local/foo-bin-1.0-1/files`

**Interfaces:**
- Consumes: `alpm.ParseDesc`, `alpm.ParseFiles`
- Produces: `alpm.Package{Name, Version, Base, Validation, Packager string; InstallDate time.Time; Files []string; Backup map[string]string}`; `alpm.LoadLocalDB(dbPath string) ([]Package, []string, error)` returning packages and the names of unreadable entries (coverage gaps)

- [ ] **Step 1: Write the failing test**

```go
// internal/alpm/localdb_test.go
package alpm

import (
	"os"
	"path/filepath"
	"testing"
)

func writeEntry(t *testing.T, dbPath, dir, desc, files string) {
	t.Helper()
	full := filepath.Join(dbPath, dir)
	if err := os.MkdirAll(full, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "desc"), []byte(desc), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(full, "files"), []byte(files), 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestLoadLocalDBReadsPackages(t *testing.T) {
	db := t.TempDir()
	writeEntry(t, db, "zlib-1.3.1-2",
		"%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n%BASE%\nzlib\n\n%VALIDATION%\npgp\n\n%PACKAGER%\nA Dev <a@archlinux.org>\n\n%INSTALLDATE%\n1770760629\n\n",
		"%FILES%\nusr/lib/libz.so\n\n")
	writeEntry(t, db, "foo-bin-1.0-1",
		"%NAME%\nfoo-bin\n\n%VERSION%\n1.0-1\n\n%BASE%\nfoo-bin\n\n%VALIDATION%\nnone\n\n%PACKAGER%\nUnknown Packager\n\n%INSTALLDATE%\n1770760700\n\n",
		"%FILES%\nusr/bin/foo\n\n")

	pkgs, gaps, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v, want none", gaps)
	}
	if len(pkgs) != 2 {
		t.Fatalf("got %d packages, want 2", len(pkgs))
	}
	byName := map[string]Package{}
	for _, p := range pkgs {
		byName[p.Name] = p
	}
	if byName["zlib"].Validation != "pgp" {
		t.Errorf("zlib validation = %q", byName["zlib"].Validation)
	}
	if byName["foo-bin"].Packager != "Unknown Packager" {
		t.Errorf("foo-bin packager = %q", byName["foo-bin"].Packager)
	}
	if byName["zlib"].InstallDate.Unix() != 1770760629 {
		t.Errorf("zlib installdate = %v", byName["zlib"].InstallDate)
	}
}

// ALPM_DB_VERSION and other non-package files must be skipped, not parsed.
func TestLoadLocalDBSkipsNonPackageEntries(t *testing.T) {
	db := t.TempDir()
	if err := os.WriteFile(filepath.Join(db, "ALPM_DB_VERSION"), []byte("9\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	writeEntry(t, db, "zlib-1.3.1-2", "%NAME%\nzlib\n\n%VERSION%\n1.3.1-2\n\n", "%FILES%\nusr/lib/libz.so\n\n")
	pkgs, _, err := LoadLocalDB(db)
	if err != nil {
		t.Fatalf("LoadLocalDB: %v", err)
	}
	if len(pkgs) != 1 {
		t.Fatalf("got %d packages, want 1", len(pkgs))
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/alpm/ -run TestLoadLocalDB -v`
Expected: FAIL — `undefined: LoadLocalDB`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/alpm/localdb.go
package alpm

import (
	"os"
	"path/filepath"
	"strconv"
	"time"
)

// Package is one installed package as recorded in the local DB.
type Package struct {
	Name        string
	Version     string
	Base        string
	Validation  string
	Packager    string
	InstallDate time.Time
	Files       []string
	Backup      map[string]string
}

func first(m map[string][]string, key string) string {
	if v := m[key]; len(v) > 0 {
		return v[0]
	}
	return ""
}

// LoadLocalDB enumerates package directories under dbPath. It returns the
// packages it could read and the directory names it could not, which become
// coverage gaps under INV-3 rather than being silently dropped.
func LoadLocalDB(dbPath string) ([]Package, []string, error) {
	entries, err := os.ReadDir(dbPath)
	if err != nil {
		return nil, nil, err
	}
	var pkgs []Package
	var gaps []string
	for _, e := range entries {
		if !e.IsDir() {
			continue // ALPM_DB_VERSION and friends
		}
		dir := filepath.Join(dbPath, e.Name())
		df, err := os.Open(filepath.Join(dir, "desc"))
		if err != nil {
			gaps = append(gaps, e.Name())
			continue
		}
		fields, err := ParseDesc(df)
		df.Close()
		if err != nil {
			gaps = append(gaps, e.Name())
			continue
		}
		p := Package{
			Name:       first(fields, "NAME"),
			Version:    first(fields, "VERSION"),
			Base:       first(fields, "BASE"),
			Validation: first(fields, "VALIDATION"),
			Packager:   first(fields, "PACKAGER"),
			Backup:     map[string]string{},
		}
		if p.Base == "" {
			p.Base = p.Name
		}
		if secs, err := strconv.ParseInt(first(fields, "INSTALLDATE"), 10, 64); err == nil {
			p.InstallDate = time.Unix(secs, 0).UTC()
		}
		if ff, err := os.Open(filepath.Join(dir, "files")); err == nil {
			paths, backup, perr := ParseFiles(ff)
			ff.Close()
			if perr == nil {
				p.Files, p.Backup = paths, backup
			} else {
				gaps = append(gaps, e.Name()+"/files")
			}
		}
		if p.Name == "" {
			gaps = append(gaps, e.Name())
			continue
		}
		pkgs = append(pkgs, p)
	}
	return pkgs, gaps, nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/alpm/ -v`
Expected: PASS (all six tests)

- [ ] **Step 5: Commit**

```bash
git add internal/alpm/localdb.go internal/alpm/localdb_test.go
git commit -m "feat(alpm): local DB enumeration with unreadable-entry gaps"
```

---

### Task 5: Sync DB name oracle and foreign classification

**Files:**
- Create: `internal/alpm/syncdb.go`
- Create: `internal/alpm/syncdb_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `alpm.LoadSyncNames(syncPath string) (map[string]bool, []string, error)` returning the set of package names present in any sync DB plus unreadable DB filenames; `alpm.IsForeign(p Package, syncNames map[string]bool) bool`

- [ ] **Step 1: Write the failing test**

```go
// internal/alpm/syncdb_test.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"os"
	"path/filepath"
	"testing"
)

// Sync DBs are gzipped tar archives whose entries are <name>-<ver>-<rel>/desc.
func writeSyncDB(t *testing.T, path string, dirs []string) {
	t.Helper()
	f, err := os.Create(path)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	gz := gzip.NewWriter(f)
	tw := tar.NewWriter(gz)
	for _, d := range dirs {
		if err := tw.WriteHeader(&tar.Header{Name: d + "/", Typeflag: tar.TypeDir, Mode: 0o755}); err != nil {
			t.Fatal(err)
		}
		body := []byte("%NAME%\n")
		if err := tw.WriteHeader(&tar.Header{Name: d + "/desc", Size: int64(len(body)), Mode: 0o644}); err != nil {
			t.Fatal(err)
		}
		if _, err := tw.Write(body); err != nil {
			t.Fatal(err)
		}
	}
	if err := tw.Close(); err != nil {
		t.Fatal(err)
	}
	if err := gz.Close(); err != nil {
		t.Fatal(err)
	}
}

func TestLoadSyncNamesStripsVersion(t *testing.T) {
	dir := t.TempDir()
	writeSyncDB(t, filepath.Join(dir, "core.db"), []string{"zlib-1.3.1-2", "python-pkg_resources-81.0.0-1"})
	names, gaps, err := LoadSyncNames(dir)
	if err != nil {
		t.Fatalf("LoadSyncNames: %v", err)
	}
	if len(gaps) != 0 {
		t.Errorf("gaps = %v", gaps)
	}
	if !names["zlib"] {
		t.Error("zlib not found")
	}
	// Name contains hyphens and underscores; only the last two fields are version.
	if !names["python-pkg_resources"] {
		t.Errorf("python-pkg_resources not found; got %v", names)
	}
}

// python-pkg_resources is foreign yet carries %VALIDATION% pgp on the
// reference system. Foreignness must be decided by sync-DB absence, never
// by %VALIDATION%.
func TestIsForeignIgnoresValidation(t *testing.T) {
	sync := map[string]bool{"zlib": true}
	dropped := Package{Name: "python-pkg_resources", Validation: "pgp"}
	if !IsForeign(dropped, sync) {
		t.Error("pgp-validated package absent from sync DBs must be foreign")
	}
	repo := Package{Name: "zlib", Validation: "pgp"}
	if IsForeign(repo, sync) {
		t.Error("package present in a sync DB must not be foreign")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/alpm/ -run 'TestLoadSyncNames|TestIsForeign' -v`
Expected: FAIL — `undefined: LoadSyncNames`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/alpm/syncdb.go
package alpm

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"io"
	"os"
	"path/filepath"
	"strings"
)

// stripVersion turns "python-pkg_resources-81.0.0-1" into
// "python-pkg_resources" by removing the trailing <ver>-<rel> fields. Package
// names legitimately contain hyphens, so only the last two are removed.
func stripVersion(dir string) string {
	for i := 0; i < 2; i++ {
		idx := strings.LastIndex(dir, "-")
		if idx <= 0 {
			return ""
		}
		dir = dir[:idx]
	}
	return dir
}

// LoadSyncNames returns the set of package names present in any *.db sync
// archive. Unreadable archives are reported as gaps: a missing sync DB would
// otherwise make every repo package look foreign.
func LoadSyncNames(syncPath string) (map[string]bool, []string, error) {
	dbs, err := filepath.Glob(filepath.Join(syncPath, "*.db"))
	if err != nil {
		return nil, nil, err
	}
	names := make(map[string]bool)
	var gaps []string
	for _, db := range dbs {
		if err := readSyncDB(db, names); err != nil {
			gaps = append(gaps, filepath.Base(db))
		}
	}
	return names, gaps, nil
}

func readSyncDB(path string, into map[string]bool) error {
	f, err := os.Open(path)
	if err != nil {
		return err
	}
	defer f.Close()
	gz, err := gzip.NewReader(f)
	if err != nil {
		return err
	}
	defer gz.Close()
	tr := tar.NewReader(gz)
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return nil
		}
		if err != nil {
			return err
		}
		dir := strings.TrimSuffix(h.Name, "/")
		if i := strings.IndexByte(dir, '/'); i >= 0 {
			dir = dir[:i]
		}
		if n := stripVersion(dir); n != "" {
			into[n] = true
		}
	}
}

// IsForeign reports whether a package is absent from every configured sync DB.
// %VALIDATION% is deliberately not consulted: on the reference system
// python-pkg_resources is foreign (dropped from the repos) yet validated pgp.
func IsForeign(p Package, syncNames map[string]bool) bool {
	return !syncNames[p.Name]
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/alpm/ -v`
Expected: PASS (all tests)

- [ ] **Step 5: Commit**

```bash
git add internal/alpm/syncdb.go internal/alpm/syncdb_test.go
git commit -m "feat(alpm): sync DB name oracle; foreignness independent of %VALIDATION%"
```

---

### Task 6: Finding model, fingerprints, and coverage accounting

**Files:**
- Create: `internal/finding/finding.go`
- Create: `internal/finding/finding_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `finding.Severity` with `SevInfo`/`SevSuspicious`/`SevCritical` and `String()`; `finding.Finding{RuleID, SubjectKind, Subject, Severity, Summary, Evidence []string, Limits string}`; `finding.Gap{RuleID, Subject, Reason}`; `finding.Result{Findings []Finding, Gaps []Gap}`; `finding.Fingerprint(ruleID, subjectKind, subjectIdentity, scope string) string`; `(Result).Complete() bool`; `(Result).MaxSeverity() Severity`

- [ ] **Step 1: Write the failing test**

```go
// internal/finding/finding_test.go
package finding

import "testing"

// Fingerprints must be version-independent: with ~28 pacman transactions a
// day on the reference system, a version-bearing fingerprint would invalidate
// every suppression on every upgrade.
func TestFingerprintIsVersionIndependent(t *testing.T) {
	a := Fingerprint("aur-tombstone", "package", "foo-bin", "subject")
	b := Fingerprint("aur-tombstone", "package", "foo-bin", "subject")
	if a != b {
		t.Fatal("same inputs produced different fingerprints")
	}
	c := Fingerprint("aur-tombstone", "package", "bar-bin", "subject")
	if a == c {
		t.Error("different subjects produced the same fingerprint")
	}
	d := Fingerprint("aur-tombstone", "package", "foo-bin", "pin")
	if a == d {
		t.Error("different scopes produced the same fingerprint")
	}
}

func TestResultCompleteAndMaxSeverity(t *testing.T) {
	r := Result{}
	if !r.Complete() {
		t.Error("empty result should be complete")
	}
	if r.MaxSeverity() != SevInfo {
		t.Errorf("MaxSeverity = %v", r.MaxSeverity())
	}
	r.Gaps = append(r.Gaps, Gap{RuleID: "provenance", Subject: "foo-bin", Reason: "no cache clone"})
	if r.Complete() {
		t.Error("result with a gap must not be complete")
	}
	r.Findings = append(r.Findings,
		Finding{Severity: SevSuspicious}, Finding{Severity: SevCritical})
	if r.MaxSeverity() != SevCritical {
		t.Errorf("MaxSeverity = %v, want critical", r.MaxSeverity())
	}
}

func TestSeverityStrings(t *testing.T) {
	for sev, want := range map[Severity]string{
		SevInfo: "info", SevSuspicious: "suspicious", SevCritical: "critical",
	} {
		if got := sev.String(); got != want {
			t.Errorf("%d.String() = %q, want %q", sev, got, want)
		}
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/finding/ -v`
Expected: FAIL — `undefined: Fingerprint`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/finding/finding.go
package finding

import (
	"crypto/sha256"
	"encoding/hex"
	"strings"
)

type Severity int

const (
	SevInfo Severity = iota
	SevSuspicious
	SevCritical
)

func (s Severity) String() string {
	switch s {
	case SevCritical:
		return "critical"
	case SevSuspicious:
		return "suspicious"
	default:
		return "info"
	}
}

// Finding is one detection. Limits carries what this finding cannot prove and
// is rendered in output, satisfying INV-6.
type Finding struct {
	RuleID      string
	SubjectKind string
	Subject     string
	Severity    Severity
	Summary     string
	Evidence    []string
	Limits      string
}

// Gap records a check that could not run. Per INV-3 and INV-10 this is never
// silence and never a pass.
type Gap struct {
	RuleID  string
	Subject string
	Reason  string
}

type Result struct {
	Findings []Finding
	Gaps     []Gap
}

func (r Result) Complete() bool { return len(r.Gaps) == 0 }

func (r Result) MaxSeverity() Severity {
	max := SevInfo
	for _, f := range r.Findings {
		if f.Severity > max {
			max = f.Severity
		}
	}
	return max
}

// Fingerprint identifies a finding stably across package upgrades and rule
// rewordings. subjectIdentity must be version-independent — a package name,
// not name-version; a path, not its digest.
func Fingerprint(ruleID, subjectKind, subjectIdentity, scope string) string {
	h := sha256.Sum256([]byte(strings.Join([]string{ruleID, subjectKind, subjectIdentity, scope}, "\x00")))
	return hex.EncodeToString(h[:16])
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/finding/ -v`
Expected: PASS (three tests)

- [ ] **Step 5: Commit**

```bash
git add internal/finding
git commit -m "feat(finding): finding model, version-independent fingerprints, coverage gaps"
```

---

### Task 7: AUR client interface, fake, and live HTTP implementation

**Files:**
- Create: `internal/aur/client.go`
- Create: `internal/aur/fake.go`
- Create: `internal/aur/http.go`
- Create: `internal/aur/http_test.go`

**Interfaces:**
- Consumes: nothing
- Produces: `aur.Pkg{Name, PackageBase, Maintainer, Submitter string, FirstSubmitted, LastModified int64}`; `aur.Client` interface with `Info(ctx context.Context, bases []string) (map[string]Pkg, error)` and `Tombstone(ctx context.Context, base string) (bool, string, error)`; `aur.Fake{Known map[string]Pkg, Tombstones map[string]string, Err error}`; `aur.NewHTTP(baseURL string, hc *http.Client) *HTTP`

- [ ] **Step 1: Write the failing test**

```go
// internal/aur/http_test.go
package aur

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// The RPC distinguishes failure from absence: type "error" vs "multiinfo"
// with resultcount 0. Network failure must never be readable as "deleted".
func TestInfoParsesMultiinfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"multiinfo","resultcount":1,"results":[
		  {"Name":"foo-bin","PackageBase":"foo-bin","Maintainer":"alice","Submitter":"bob",
		   "FirstSubmitted":1700000000,"LastModified":1710000000}]}`))
	}))
	defer srv.Close()
	got, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"foo-bin"})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	p, ok := got["foo-bin"]
	if !ok {
		t.Fatalf("foo-bin missing from %v", got)
	}
	if p.Maintainer != "alice" || p.Submitter != "bob" {
		t.Errorf("got %+v", p)
	}
}

func TestInfoErrorTypeIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"error","error":"Incorrect request type specified.","resultcount":0,"results":[]}`))
	}))
	defer srv.Close()
	_, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"x"})
	if err == nil {
		t.Fatal("type=error must produce an error, not an empty result")
	}
}

func TestInfoBatchesAllArgsInOneRequest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if n := len(r.URL.Query()["arg[]"]); n != 3 {
			t.Errorf("arg[] count = %d, want 3", n)
		}
		w.Write([]byte(`{"type":"multiinfo","resultcount":0,"results":[]}`))
	}))
	defer srv.Close()
	if _, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"a", "b", "c"}); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1", calls)
	}
}

// A removed-for-malware package keeps its cgit repo with a tombstone commit.
func TestTombstoneDetectsMalwareRemoval(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "librewolf-fix-bin") {
			w.Write([]byte(`<html><td>history removed due to malware</td></html>`))
			return
		}
		w.Write([]byte(`<html><td>upgpkg: 1.2.3-1</td></html>`))
	}))
	defer srv.Close()
	c := NewHTTP(srv.URL, srv.Client())
	found, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !found {
		t.Fatal("tombstone not detected")
	}
	if !strings.Contains(msg, "malware") {
		t.Errorf("msg = %q", msg)
	}
	found, _, err = c.Tombstone(context.Background(), "brave-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if found {
		t.Error("false tombstone on an ordinary package")
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/aur/ -v`
Expected: FAIL — `undefined: NewHTTP`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/aur/client.go
package aur

import "context"

// Pkg is the subset of AUR metadata this tool uses. Submitter is retained
// because submitter != maintainer is an observable takeover signal.
type Pkg struct {
	Name           string
	PackageBase    string
	Maintainer     string
	Submitter      string
	FirstSubmitted int64
	LastModified   int64
}

// Client is the network seam. Tests use Fake so no test touches the network.
type Client interface {
	// Info looks up every base in ONE request. A missing key means the AUR
	// does not have that package; an error means the lookup failed. These are
	// never conflated.
	Info(ctx context.Context, bases []string) (map[string]Pkg, error)
	// Tombstone reports whether the package's cgit log records a
	// removal-for-malware commit, and the matching message.
	Tombstone(ctx context.Context, base string) (bool, string, error)
}
```

```go
// internal/aur/fake.go
package aur

import "context"

// Fake is the recorded-fixture Client used by every test outside http_test.go.
type Fake struct {
	Known      map[string]Pkg
	Tombstones map[string]string
	Err        error
}

func (f Fake) Info(_ context.Context, bases []string) (map[string]Pkg, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := make(map[string]Pkg)
	for _, b := range bases {
		if p, ok := f.Known[b]; ok {
			out[b] = p
		}
	}
	return out, nil
}

func (f Fake) Tombstone(_ context.Context, base string) (bool, string, error) {
	if f.Err != nil {
		return false, "", f.Err
	}
	msg, ok := f.Tombstones[base]
	return ok, msg, nil
}
```

```go
// internal/aur/http.go
package aur

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxBody       = 8 << 20 // hard cap; a bundle/response bomb must not exhaust memory
	userAgentName = "arch-drift"
)

type HTTP struct {
	base string
	hc   *http.Client
}

func NewHTTP(baseURL string, hc *http.Client) *HTTP {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &HTTP{base: strings.TrimRight(baseURL, "/"), hc: hc}
}

type rpcResponse struct {
	Type        string `json:"type"`
	Error       string `json:"error"`
	ResultCount int    `json:"resultcount"`
	Results     []Pkg  `json:"results"`
}

func (h *HTTP) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentName)
	resp, err := h.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	return io.ReadAll(io.LimitReader(resp.Body, maxBody))
}

func (h *HTTP) Info(ctx context.Context, bases []string) (map[string]Pkg, error) {
	if len(bases) == 0 {
		return map[string]Pkg{}, nil
	}
	q := url.Values{"v": {"5"}, "type": {"info"}}
	for _, b := range bases {
		q.Add("arg[]", b)
	}
	body, err := h.get(ctx, h.base+"/rpc/?"+q.Encode())
	if err != nil {
		return nil, err
	}
	var r rpcResponse
	if err := json.Unmarshal(body, &r); err != nil {
		return nil, err
	}
	if r.Type == "error" {
		return nil, fmt.Errorf("aur rpc: %s", r.Error)
	}
	out := make(map[string]Pkg, len(r.Results))
	for _, p := range r.Results {
		key := p.PackageBase
		if key == "" {
			key = p.Name
		}
		out[key] = p
	}
	return out, nil
}

// tombstoneRe matches AUR removal commit messages broadly. Breadth is
// deliberate — a reworded removal notice must still be noticed — but breadth
// alone must never drive a critical verdict, hence IsMalwareRemoval below.
var tombstoneRe = regexp.MustCompile(`(?i)(history removed|removed due to|removed for)[^<]{0,60}`)

// malwareRe matches removal wording that specifically indicates malicious
// content. Verified live wording is "history removed due to malware".
var malwareRe = regexp.MustCompile(`(?i)(malware|malicious|trojan|backdoor|compromised|security)`)

// IsMalwareRemoval reports whether a removal message indicates malicious
// content rather than an administrative removal such as a rename or merge.
// This is the difference between a critical verdict and a suspicious one:
// "removed due to rename" must not be reported as malware (L2 defect D2).
func IsMalwareRemoval(msg string) bool { return malwareRe.MatchString(msg) }

func (h *HTTP) Tombstone(ctx context.Context, base string) (bool, string, error) {
	q := url.Values{"h": {base}}
	body, err := h.get(ctx, h.base+"/cgit/aur.git/log/?"+q.Encode())
	if err != nil {
		return false, "", err
	}
	if m := tombstoneRe.Find(body); m != nil {
		return true, strings.TrimSpace(string(m)), nil
	}
	return false, "", nil
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/aur/ -v`
Expected: PASS (four tests)

- [ ] **Step 5: Commit**

```bash
git add internal/aur
git commit -m "feat(aur): batched RPC client, cgit tombstone check, fixture fake"
```

---

### Task 8: Provenance checks

**Files:**
- Create: `internal/check/provenance.go`
- Create: `internal/check/provenance_test.go`

**Interfaces:**
- Consumes: `alpm.Package`, `alpm.IsForeign`, `aur.Client`, `finding.*`
- Produces: `check.Provenance(ctx context.Context, pkgs []alpm.Package, syncNames map[string]bool, cl aur.Client, network bool) finding.Result`

- [ ] **Step 1: Write the failing test**

```go
// internal/check/provenance_test.go
package check

import (
	"context"
	"errors"
	"strings"
	"testing"

	"github.com/lookatitude/arch-drift/internal/alpm"
	"github.com/lookatitude/arch-drift/internal/aur"
	"github.com/lookatitude/arch-drift/internal/finding"
)

func pkg(name string) alpm.Package {
	return alpm.Package{Name: name, Base: name, Version: "1.0-1", Validation: "none"}
}

func findingFor(r finding.Result, ruleID string) (finding.Finding, bool) {
	for _, f := range r.Findings {
		if f.RuleID == ruleID {
			return f, true
		}
	}
	return finding.Finding{}, false
}

// Absent from the AUR AND carrying a malware tombstone is definitive.
func TestTombstonedPackageIsCritical(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"},
	}
	r := Provenance(context.Background(),
		[]alpm.Package{pkg("librewolf-fix-bin")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-tombstone")
	if !ok {
		t.Fatalf("no aur-tombstone finding; got %+v", r.Findings)
	}
	if f.Severity != finding.SevCritical {
		t.Errorf("severity = %v, want critical", f.Severity)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "malware") {
		t.Errorf("evidence = %v", f.Evidence)
	}
}

// D2 regression: a removal whose wording is administrative rather than
// malicious must NOT be critical. "removed due to rename" is the case.
func TestAdministrativeRemovalIsNotCritical(t *testing.T) {
	cl := aur.Fake{
		Known:      map[string]aur.Pkg{},
		Tombstones: map[string]string{"foo-bin": "history removed due to rename"},
	}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if r.MaxSeverity() == finding.SevCritical {
		t.Fatalf("administrative removal reported critical: %+v", r.Findings)
	}
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("expected aur-absent; got %+v", r.Findings)
	}
	if !strings.Contains(strings.Join(f.Evidence, " "), "rename") {
		t.Errorf("removal message not carried as evidence: %v", f.Evidence)
	}
}

// Absent with NO tombstone is only suspicious: it is the dropped-from-repo /
// renamed / never-published case (python-pkg_resources on the reference box).
func TestAbsentWithoutTombstoneIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{}, Tombstones: map[string]string{}}
	r := Provenance(context.Background(),
		[]alpm.Package{pkg("python-pkg_resources")}, map[string]bool{}, cl, true)
	f, ok := findingFor(r, "aur-absent")
	if !ok {
		t.Fatalf("no aur-absent finding; got %+v", r.Findings)
	}
	if f.Severity != finding.SevSuspicious {
		t.Errorf("severity = %v, want suspicious", f.Severity)
	}
	if f.Limits == "" {
		t.Error("finding must state its limits (INV-6)")
	}
}

// Submitter != Maintainer is an observable takeover trace.
func TestSubmitterMismatchIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo-bin": {Name: "foo-bin", PackageBase: "foo-bin", Maintainer: "alice", Submitter: "bob"},
	}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-submitter-mismatch"); !ok {
		t.Fatalf("no submitter-mismatch finding; got %+v", r.Findings)
	}
}

// Orphaned packages are a takeover precondition.
func TestOrphanedIsSuspicious(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{
		"foo-bin": {Name: "foo-bin", PackageBase: "foo-bin", Maintainer: "", Submitter: "bob"},
	}}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-orphaned"); !ok {
		t.Fatalf("no orphaned finding; got %+v", r.Findings)
	}
}

// CRITICAL BEHAVIOUR: an RPC failure must produce a coverage gap, never an
// "absent from the AUR" finding. Network failure must not be able to trigger
// the highest-severity rule.
func TestRPCFailureProducesGapNotAbsence(t *testing.T) {
	cl := aur.Fake{Err: errors.New("dial tcp: no route to host")}
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")}, map[string]bool{}, cl, true)
	if _, ok := findingFor(r, "aur-absent"); ok {
		t.Fatal("network failure produced an aur-absent finding")
	}
	if _, ok := findingFor(r, "aur-tombstone"); ok {
		t.Fatal("network failure produced a tombstone finding")
	}
	if r.Complete() {
		t.Fatal("network failure must leave coverage incomplete")
	}
}

// With network disabled the checks must report unavailable, not pass (INV-10).
func TestNetworkDisabledProducesGap(t *testing.T) {
	r := Provenance(context.Background(), []alpm.Package{pkg("foo-bin")},
		map[string]bool{}, aur.Fake{}, false)
	if len(r.Findings) != 0 {
		t.Errorf("findings = %+v, want none", r.Findings)
	}
	if r.Complete() {
		t.Fatal("disabled network must leave coverage incomplete")
	}
}

// Repo packages are not examined for AUR provenance at all.
func TestRepoPackagesAreSkipped(t *testing.T) {
	cl := aur.Fake{Known: map[string]aur.Pkg{}}
	r := Provenance(context.Background(), []alpm.Package{pkg("zlib")},
		map[string]bool{"zlib": true}, cl, true)
	if len(r.Findings) != 0 || !r.Complete() {
		t.Errorf("repo package produced %+v gaps=%v", r.Findings, r.Gaps)
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/check/ -v`
Expected: FAIL — `undefined: Provenance`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/check/provenance.go
package check

import (
	"context"
	"fmt"

	"github.com/lookatitude/arch-drift/internal/alpm"
	"github.com/lookatitude/arch-drift/internal/aur"
	"github.com/lookatitude/arch-drift/internal/finding"
)

const limitProvenance = "Packaging provenance only; says nothing about whether the upstream source is malicious."

// Provenance examines foreign packages against AUR metadata. Every rule
// declares its evidence precondition: when the network is unavailable or the
// lookup fails, the checks emit coverage gaps rather than passing (INV-10),
// and in particular a failure can never surface as "absent from the AUR".
func Provenance(ctx context.Context, pkgs []alpm.Package, syncNames map[string]bool, cl aur.Client, network bool) finding.Result {
	var res finding.Result

	var foreign []alpm.Package
	bases := map[string]bool{}
	for _, p := range pkgs {
		if alpm.IsForeign(p, syncNames) {
			foreign = append(foreign, p)
			bases[p.Base] = true
		}
	}
	if len(foreign) == 0 {
		return res
	}

	if !network {
		for _, p := range foreign {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-provenance", Subject: p.Name,
				Reason: "network disabled; AUR provenance checks did not run",
			})
		}
		return res
	}

	list := make([]string, 0, len(bases))
	for b := range bases {
		list = append(list, b)
	}
	info, err := cl.Info(ctx, list)
	if err != nil {
		for _, p := range foreign {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "aur-provenance", Subject: p.Name,
				Reason: fmt.Sprintf("AUR lookup failed: %v", err),
			})
		}
		return res
	}

	for _, p := range foreign {
		meta, present := info[p.Base]
		if !present {
			found, msg, terr := cl.Tombstone(ctx, p.Base)
			if terr != nil {
				res.Gaps = append(res.Gaps, finding.Gap{
					RuleID: "aur-tombstone", Subject: p.Name,
					Reason: fmt.Sprintf("cgit lookup failed: %v", terr),
				})
				continue
			}
			if found && aur.IsMalwareRemoval(msg) {
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-tombstone", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevCritical,
					Summary:  "package was removed from the AUR for malware",
					Evidence: []string{"cgit removal commit: " + msg, "absent from AUR index"},
					Limits:   "Confirms the AUR removed this package. Does not confirm the payload is still present on this system.",
				})
				continue
			}
			if found {
				// Removed, but the wording does not indicate malice — a rename,
				// merge or administrative deletion. Suspicious, never critical.
				res.Findings = append(res.Findings, finding.Finding{
					RuleID: "aur-absent", SubjectKind: "package", Subject: p.Name,
					Severity: finding.SevSuspicious,
					Summary:  "package was removed from the AUR, reason not malware-related",
					Evidence: []string{"cgit removal commit: " + msg, "absent from AUR index"},
					Limits:   "Administrative removals (rename, merge) look identical here. Not evidence of compromise.",
				})
				continue
			}
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-absent", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevSuspicious,
				Summary:  "installed foreign package is absent from the AUR",
				Evidence: []string{"absent from AUR index", "no removal tombstone found", "validation=" + p.Validation},
				Limits:   "Also matches a package dropped from the official repos, renamed, merged, or built locally and never published.",
			})
			continue
		}
		if meta.Maintainer == "" {
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-orphaned", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevSuspicious,
				Summary:  "package is orphaned in the AUR",
				Evidence: []string{"maintainer is unset", "submitter=" + meta.Submitter},
				Limits:   "Orphaning is a takeover precondition, not evidence of compromise. " + limitProvenance,
			})
		}
		if meta.Maintainer != "" && meta.Submitter != "" && meta.Maintainer != meta.Submitter {
			res.Findings = append(res.Findings, finding.Finding{
				RuleID: "aur-submitter-mismatch", SubjectKind: "package", Subject: p.Name,
				Severity: finding.SevSuspicious,
				Summary:  "current maintainer differs from the original submitter",
				Evidence: []string{"submitter=" + meta.Submitter, "maintainer=" + meta.Maintainer},
				Limits:   "Legitimate handoffs produce this too. Reported as an identity delta, not as malice. " + limitProvenance,
			})
		}
	}
	return res
}
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `go test ./internal/check/ -v`
Expected: PASS (seven tests)

- [ ] **Step 5: Commit**

```bash
git add internal/check
git commit -m "feat(check): provenance rules; failures become gaps, never absence"
```

---

### Task 9: Reporting, exit codes, and `scan`/`explain` wiring

**Files:**
- Create: `internal/report/text.go`
- Create: `internal/report/json.go`
- Create: `internal/report/report_test.go`
- Modify: `cmd/arch-drift/main.go`

**Interfaces:**
- Consumes: `finding.Result`
- Produces: `report.Summary{Total, Foreign int}`; `report.Text(w io.Writer, r finding.Result, s Summary) error`; `report.JSON(w io.Writer, r finding.Result, s Summary) error`; `report.ExitCode(r finding.Result, min finding.Severity) int`; `report.Explain(w io.Writer, r finding.Result, id string) error`

- [ ] **Step 1: Write the failing test**

```go
// internal/report/report_test.go
package report

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"

	"github.com/lookatitude/arch-drift/internal/finding"
)

func sample() finding.Result {
	return finding.Result{
		Findings: []finding.Finding{{
			RuleID: "aur-tombstone", SubjectKind: "package", Subject: "librewolf-fix-bin",
			Severity: finding.SevCritical, Summary: "removed from the AUR for malware",
			Evidence: []string{"cgit removal commit: history removed due to malware"},
			Limits:   "Does not confirm the payload is still present.",
		}},
		Gaps: []finding.Gap{{RuleID: "aur-provenance", Subject: "foo-bin", Reason: "no cache clone"}},
	}
}

func TestTextIncludesSeverityTokenAndCoverage(t *testing.T) {
	var b bytes.Buffer
	if err := Text(&b, sample(), Summary{Total: 1409, Foreign: 39}); err != nil {
		t.Fatal(err)
	}
	out := b.String()
	for _, want := range []string{"critical", "librewolf-fix-bin", "coverage", "1 gap"} {
		if !strings.Contains(out, want) {
			t.Errorf("output missing %q:\n%s", want, out)
		}
	}
}

func TestJSONCarriesSchemaVersion(t *testing.T) {
	var b bytes.Buffer
	if err := JSON(&b, sample(), Summary{Total: 1409, Foreign: 39}); err != nil {
		t.Fatal(err)
	}
	var got map[string]any
	if err := json.Unmarshal(b.Bytes(), &got); err != nil {
		t.Fatal(err)
	}
	if got["schema_version"] == nil {
		t.Error("schema_version absent")
	}
}

// Exit codes are contractual. 3 exists so a caller can never read
// "couldn't look" as "clean".
func TestExitCodes(t *testing.T) {
	if got := ExitCode(finding.Result{}, finding.SevSuspicious); got != 0 {
		t.Errorf("clean+complete = %d, want 0", got)
	}
	withGap := finding.Result{Gaps: []finding.Gap{{RuleID: "r", Subject: "s", Reason: "x"}}}
	if got := ExitCode(withGap, finding.SevSuspicious); got != 3 {
		t.Errorf("no findings + gap = %d, want 3", got)
	}
	if got := ExitCode(sample(), finding.SevSuspicious); got != 1 {
		t.Errorf("findings = %d, want 1", got)
	}
	onlyInfo := finding.Result{Findings: []finding.Finding{{Severity: finding.SevInfo}}}
	if got := ExitCode(onlyInfo, finding.SevSuspicious); got != 0 {
		t.Errorf("below-threshold findings = %d, want 0", got)
	}
}

func TestExplainStatesLimits(t *testing.T) {
	r := sample()
	id := finding.Fingerprint(r.Findings[0].RuleID, r.Findings[0].SubjectKind, r.Findings[0].Subject, "subject")
	var b bytes.Buffer
	if err := Explain(&b, r, id); err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(b.String(), "Does not confirm") {
		t.Errorf("explain omitted limits:\n%s", b.String())
	}
}
```

- [ ] **Step 2: Run test to verify it fails**

Run: `go test ./internal/report/ -v`
Expected: FAIL — `undefined: Text`

- [ ] **Step 3: Write minimal implementation**

```go
// internal/report/text.go
package report

import (
	"fmt"
	"io"
	"sort"

	"github.com/lookatitude/arch-drift/internal/finding"
)

type Summary struct {
	Total   int
	Foreign int
}

// Text renders the quiet default output: one header line carrying counts AND
// coverage, then findings sorted by descending severity.
func Text(w io.Writer, r finding.Result, s Summary) error {
	coverage := "complete"
	if !r.Complete() {
		coverage = fmt.Sprintf("incomplete, %d gap(s)", len(r.Gaps))
	}
	crit := 0
	for _, f := range r.Findings {
		if f.Severity == finding.SevCritical {
			crit++
		}
	}
	if _, err := fmt.Fprintf(w, "%d foreign / %d total · %d finding(s) (%d critical) · coverage: %s\n",
		s.Foreign, s.Total, len(r.Findings), crit, coverage); err != nil {
		return err
	}
	fs := make([]finding.Finding, len(r.Findings))
	copy(fs, r.Findings)
	sort.SliceStable(fs, func(i, j int) bool { return fs[i].Severity > fs[j].Severity })
	for _, f := range fs {
		id := finding.Fingerprint(f.RuleID, f.SubjectKind, f.Subject, "subject")
		if _, err := fmt.Fprintf(w, "\n[%s] %s — %s  (%s)\n", f.Severity, f.Subject, f.Summary, id); err != nil {
			return err
		}
		for _, e := range f.Evidence {
			if _, err := fmt.Fprintf(w, "    evidence: %s\n", e); err != nil {
				return err
			}
		}
		if f.Limits != "" {
			if _, err := fmt.Fprintf(w, "    limits:   %s\n", f.Limits); err != nil {
				return err
			}
		}
	}
	for _, g := range r.Gaps {
		if _, err := fmt.Fprintf(w, "\n[gap] %s — %s (%s)\n", g.Subject, g.Reason, g.RuleID); err != nil {
			return err
		}
	}
	return nil
}

// Explain prints the full rationale for one finding, including what it cannot
// prove (INV-6).
func Explain(w io.Writer, r finding.Result, id string) error {
	for _, f := range r.Findings {
		if finding.Fingerprint(f.RuleID, f.SubjectKind, f.Subject, "subject") != id {
			continue
		}
		fmt.Fprintf(w, "finding:  %s\nrule:     %s\nseverity: %s\nsubject:  %s\n\n",
			id, f.RuleID, f.Severity, f.Subject)
		fmt.Fprintln(w, "evidence:")
		for _, e := range f.Evidence {
			fmt.Fprintf(w, "  - %s\n", e)
		}
		fmt.Fprintf(w, "\nwhat this does NOT prove:\n  %s\n", f.Limits)
		fmt.Fprintf(w, "\ninvestigate:\n  pacman -Qi %s\n  pacman -Qlq %s\n", f.Subject, f.Subject)
		return nil
	}
	return fmt.Errorf("no finding with id %s", id)
}

// ExitCode maps a result to the contractual codes. 3 is deliberately distinct
// from 0 so an automated caller cannot mistake "couldn't look" for "clean".
func ExitCode(r finding.Result, min finding.Severity) int {
	for _, f := range r.Findings {
		if f.Severity >= min {
			return 1
		}
	}
	if !r.Complete() {
		return 3
	}
	return 0
}
```

```go
// internal/report/json.go
package report

import (
	"encoding/json"
	"io"

	"github.com/lookatitude/arch-drift/internal/finding"
)

const schemaVersion = 1

type jsonFinding struct {
	ID       string   `json:"id"`
	RuleID   string   `json:"rule_id"`
	Subject  string   `json:"subject"`
	Severity string   `json:"severity"`
	Summary  string   `json:"summary"`
	Evidence []string `json:"evidence"`
	Limits   string   `json:"limits"`
}

type jsonGap struct {
	RuleID  string `json:"rule_id"`
	Subject string `json:"subject"`
	Reason  string `json:"reason"`
}

type jsonReport struct {
	SchemaVersion int           `json:"schema_version"`
	Total         int           `json:"total_packages"`
	Foreign       int           `json:"foreign_packages"`
	Complete      bool          `json:"coverage_complete"`
	Findings      []jsonFinding `json:"findings"`
	Gaps          []jsonGap     `json:"coverage_gaps"`
}

func JSON(w io.Writer, r finding.Result, s Summary) error {
	out := jsonReport{
		SchemaVersion: schemaVersion,
		Total:         s.Total,
		Foreign:       s.Foreign,
		Complete:      r.Complete(),
		Findings:      []jsonFinding{},
		Gaps:          []jsonGap{},
	}
	for _, f := range r.Findings {
		out.Findings = append(out.Findings, jsonFinding{
			ID:       finding.Fingerprint(f.RuleID, f.SubjectKind, f.Subject, "subject"),
			RuleID:   f.RuleID, Subject: f.Subject, Severity: f.Severity.String(),
			Summary: f.Summary, Evidence: f.Evidence, Limits: f.Limits,
		})
	}
	for _, g := range r.Gaps {
		out.Gaps = append(out.Gaps, jsonGap{g.RuleID, g.Subject, g.Reason})
	}
	enc := json.NewEncoder(w)
	enc.SetIndent("", "  ")
	return enc.Encode(out)
}
```

Now wire `scan` and `explain` into `main.go`, replacing the `switch` from Task 1:

```go
// cmd/arch-drift/main.go — replace the switch statement
	switch args[0] {
	case "doctor":
		for _, l := range cfg.Doctor() {
			fmt.Fprintf(stdout, "%-14s %-46s (%s)\n", l.Key, l.Value, l.Source)
		}
		return exitClean
	case "scan", "explain":
		pkgs, dbGaps, err := alpm.LoadLocalDB(cfg.DBPath)
		if err != nil {
			fmt.Fprintln(stderr, "local db:", err)
			return exitUsage
		}
		syncNames, syncGaps, err := alpm.LoadSyncNames(cfg.SyncPath)
		if err != nil {
			fmt.Fprintln(stderr, "sync db:", err)
			return exitUsage
		}
		var client aur.Client = aur.NewHTTP("https://aur.archlinux.org", &http.Client{Timeout: 20 * time.Second})
		res := check.Provenance(context.Background(), pkgs, syncNames, client, cfg.Network && !*noNet)
		for _, g := range dbGaps {
			res.Gaps = append(res.Gaps, finding.Gap{RuleID: "local-db", Subject: g, Reason: "package entry unreadable"})
		}
		for _, g := range syncGaps {
			res.Gaps = append(res.Gaps, finding.Gap{RuleID: "sync-db", Subject: g, Reason: "sync database unreadable"})
		}
		foreign := 0
		for _, p := range pkgs {
			if alpm.IsForeign(p, syncNames) {
				foreign++
			}
		}
		sum := report.Summary{Total: len(pkgs), Foreign: foreign}
		if args[0] == "explain" {
			if fs.NArg() < 1 {
				fmt.Fprintln(stderr, "usage: arch-drift explain <finding-id>")
				return exitUsage
			}
			if err := report.Explain(stdout, res, fs.Arg(0)); err != nil {
				fmt.Fprintln(stderr, err)
				return exitUsage
			}
			return exitClean
		}
		var rerr error
		if *asJSON {
			rerr = report.JSON(stdout, res, sum)
		} else {
			rerr = report.Text(stdout, res, sum)
		}
		if rerr != nil {
			fmt.Fprintln(stderr, "report:", rerr)
			return exitUsage
		}
		return report.ExitCode(res, finding.SevSuspicious)
	default:
		fmt.Fprintf(stderr, "unknown command %q\n", args[0])
		return exitUsage
	}
```

Add these flags next to `root` in `run`, and the corresponding imports:

```go
	asJSON := fs.Bool("json", false, "emit the versioned JSON schema")
	noNet := fs.Bool("no-network", false, "skip all network checks; they become coverage gaps")
```

```go
import (
	"context"
	"flag"
	"fmt"
	"net/http"
	"os"
	"time"

	"github.com/lookatitude/arch-drift/internal/alpm"
	"github.com/lookatitude/arch-drift/internal/aur"
	"github.com/lookatitude/arch-drift/internal/check"
	"github.com/lookatitude/arch-drift/internal/config"
	"github.com/lookatitude/arch-drift/internal/finding"
	"github.com/lookatitude/arch-drift/internal/report"
)
```

- [ ] **Step 4: Run tests and exercise the binary**

Run: `go test ./... && go build ./... && go run ./cmd/arch-drift scan --no-network`
Expected: tests PASS; `scan --no-network` prints a header with `coverage: incomplete` and exits `3`

- [ ] **Step 5: Commit**

```bash
git add internal/report cmd/arch-drift
git commit -m "feat(report): text/JSON renderers, explain, contractual exit codes"
```

---

### Task 10: Report persistence, `--since-last`, and the false-positive gate

**Files:**
- Create: `internal/report/store.go`
- Create: `internal/report/store_test.go`
- Create: `internal/check/fpgate_test.go`
- Modify: `cmd/arch-drift/main.go`

**Interfaces:**
- Consumes: `finding.Result`, `report.Summary`, `config.Config`
- Produces: `report.Save(stateDir string, r finding.Result, s Summary, stamp string) (string, error)`; `report.LoadLatest(stateDir string) (finding.Result, bool, error)`; `report.Diff(prev, cur finding.Result) (added, resolved []finding.Finding)`

- [ ] **Step 1: Write the failing test**

```go
// internal/report/store_test.go
package report

import (
	"testing"

	"github.com/lookatitude/arch-drift/internal/finding"
)

func TestSaveThenLoadLatestRoundTrips(t *testing.T) {
	dir := t.TempDir()
	if _, err := Save(dir, sample(), Summary{Total: 1409, Foreign: 39}, "2026-08-04T00:00:00Z"); err != nil {
		t.Fatalf("Save: %v", err)
	}
	got, ok, err := LoadLatest(dir)
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if !ok {
		t.Fatal("LoadLatest found nothing")
	}
	if len(got.Findings) != 1 || got.Findings[0].Subject != "librewolf-fix-bin" {
		t.Errorf("round-trip mismatch: %+v", got.Findings)
	}
	if len(got.Gaps) != 1 {
		t.Errorf("gaps lost in round-trip: %+v", got.Gaps)
	}
}

func TestLoadLatestOnEmptyDir(t *testing.T) {
	_, ok, err := LoadLatest(t.TempDir())
	if err != nil {
		t.Fatalf("LoadLatest: %v", err)
	}
	if ok {
		t.Error("empty dir reported a previous report")
	}
}

func TestDiffReportsAddedAndResolved(t *testing.T) {
	prev := sample()
	cur := finding.Result{Findings: []finding.Finding{{
		RuleID: "aur-orphaned", SubjectKind: "package", Subject: "foo-bin",
		Severity: finding.SevSuspicious, Summary: "orphaned",
	}}}
	added, resolved := Diff(prev, cur)
	if len(added) != 1 || added[0].Subject != "foo-bin" {
		t.Errorf("added = %+v", added)
	}
	if len(resolved) != 1 || resolved[0].Subject != "librewolf-fix-bin" {
		t.Errorf("resolved = %+v", resolved)
	}
}
```

```go
// internal/check/fpgate_test.go
package check

import (
	"context"
	"testing"

	"github.com/lookatitude/arch-drift/internal/alpm"
	"github.com/lookatitude/arch-drift/internal/aur"
	"github.com/lookatitude/arch-drift/internal/finding"
)

// INV-8: the false-positive corpus is a release gate. A stock system and a
// cruft-laden system must both yield ZERO critical findings. This is the test
// that stops severity inflation.
func TestFPGateNoCriticalsOnBenignSystems(t *testing.T) {
	cases := map[string][]alpm.Package{
		"stock": {
			{Name: "zlib", Base: "zlib", Validation: "pgp"},
			{Name: "pacman", Base: "pacman", Validation: "pgp"},
		},
		"cruft": {
			{Name: "zlib", Base: "zlib", Validation: "pgp"},
			// Foreign, present in the AUR, cleanly maintained by its submitter.
			{Name: "brave-bin", Base: "brave-bin", Validation: "none"},
			// Foreign, orphaned — suspicious, but must NOT be critical.
			{Name: "tty-clock", Base: "tty-clock", Validation: "none"},
			// Foreign, dropped from the official repos: absent from the AUR with
			// no tombstone. Must be suspicious, never critical.
			{Name: "python-pkg_resources", Base: "python-pkg_resources", Validation: "pgp"},
		},
	}
	sync := map[string]bool{"zlib": true, "pacman": true}
	cl := aur.Fake{
		Known: map[string]aur.Pkg{
			"brave-bin":  {Name: "brave-bin", PackageBase: "brave-bin", Maintainer: "brave", Submitter: "brave"},
			"tty-clock":  {Name: "tty-clock", PackageBase: "tty-clock", Maintainer: "", Submitter: "someone"},
		},
		Tombstones: map[string]string{},
	}
	for name, pkgs := range cases {
		t.Run(name, func(t *testing.T) {
			r := Provenance(context.Background(), pkgs, sync, cl, true)
			for _, f := range r.Findings {
				if f.Severity == finding.SevCritical {
					t.Errorf("critical finding on benign system: %+v", f)
				}
			}
		})
	}
}

// The acceptance counterpart: a tombstoned package MUST be critical, or the
// gate above would be satisfiable by a scanner that reports nothing.
func TestFPGateStillCatchesMalware(t *testing.T) {
	r := Provenance(context.Background(),
		[]alpm.Package{{Name: "librewolf-fix-bin", Base: "librewolf-fix-bin", Validation: "none"}},
		map[string]bool{},
		aur.Fake{Tombstones: map[string]string{"librewolf-fix-bin": "history removed due to malware"}},
		true)
	if r.MaxSeverity() != finding.SevCritical {
		t.Fatalf("malware not flagged critical: %+v", r.Findings)
	}
}
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `go test ./internal/report/ ./internal/check/ -v`
Expected: FAIL — `undefined: Save`; the FP gate tests fail to build alongside it

- [ ] **Step 3: Write minimal implementation**

```go
// internal/report/store.go
package report

import (
	"encoding/json"
	"os"
	"path/filepath"
	"sort"

	"github.com/lookatitude/arch-drift/internal/finding"
)

const reportsSubdir = "reports"

type stored struct {
	SchemaVersion int              `json:"schema_version"`
	Stamp         string           `json:"stamp"`
	Summary       Summary          `json:"summary"`
	Findings      []finding.Finding `json:"findings"`
	Gaps          []finding.Gap     `json:"gaps"`
}

// Save writes a report atomically: temp file then rename, so an interrupted
// write never leaves a half-parsed report behind.
func Save(stateDir string, r finding.Result, s Summary, stamp string) (string, error) {
	dir := filepath.Join(stateDir, reportsSubdir)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return "", err
	}
	blob, err := json.MarshalIndent(stored{schemaVersion, stamp, s, r.Findings, r.Gaps}, "", "  ")
	if err != nil {
		return "", err
	}
	final := filepath.Join(dir, stamp+".json")
	tmp, err := os.CreateTemp(dir, ".report-*")
	if err != nil {
		return "", err
	}
	defer os.Remove(tmp.Name())
	if _, err := tmp.Write(blob); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Sync(); err != nil {
		tmp.Close()
		return "", err
	}
	if err := tmp.Close(); err != nil {
		return "", err
	}
	if err := os.Rename(tmp.Name(), final); err != nil {
		return "", err
	}
	return final, nil
}

// LoadLatest returns the most recent stored report. Absence is not an error —
// the first run has no predecessor.
func LoadLatest(stateDir string) (finding.Result, bool, error) {
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
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	if len(names) == 0 {
		return finding.Result{}, false, nil
	}
	sort.Strings(names)
	blob, err := os.ReadFile(filepath.Join(dir, names[len(names)-1]))
	if err != nil {
		return finding.Result{}, false, err
	}
	var st stored
	if err := json.Unmarshal(blob, &st); err != nil {
		return finding.Result{}, false, err
	}
	return finding.Result{Findings: st.Findings, Gaps: st.Gaps}, true, nil
}

func key(f finding.Finding) string {
	return finding.Fingerprint(f.RuleID, f.SubjectKind, f.Subject, "subject")
}

// Diff reports findings new since prev and findings that have gone away.
func Diff(prev, cur finding.Result) (added, resolved []finding.Finding) {
	prevSet := map[string]finding.Finding{}
	for _, f := range prev.Findings {
		prevSet[key(f)] = f
	}
	curSet := map[string]finding.Finding{}
	for _, f := range cur.Findings {
		curSet[key(f)] = f
	}
	for k, f := range curSet {
		if _, ok := prevSet[k]; !ok {
			added = append(added, f)
		}
	}
	for k, f := range prevSet {
		if _, ok := curSet[k]; !ok {
			resolved = append(resolved, f)
		}
	}
	sort.Slice(added, func(i, j int) bool { return added[i].Subject < added[j].Subject })
	sort.Slice(resolved, func(i, j int) bool { return resolved[i].Subject < resolved[j].Subject })
	return added, resolved
}
```

Wire persistence and `--since-last` into `scan` in `main.go`, immediately before the render block.

**Ordering is load-bearing** (L2 defect D1): persist the *full* result first, then
derive the display set from an unmutated copy. Saving after filtering would
persist only the newly-added findings, so the next `--since-last` would diff
against a truncated baseline and re-report every persisting finding as new —
turning the feature into the noise it exists to prevent.

```go
		// Persist the FULL result before any filtering. Never move this below
		// the --since-last block.
		if _, serr := report.Save(cfg.StateDir, res, sum, time.Now().UTC().Format("20060102T150405Z")); serr != nil {
			res.Gaps = append(res.Gaps, finding.Gap{
				RuleID: "report-store", Subject: cfg.StateDir,
				Reason: "could not persist report: " + serr.Error(),
			})
		}
		display := res
		if *sinceLast {
			prev, ok, lerr := report.LoadPrevious(cfg.StateDir)
			if lerr != nil {
				fmt.Fprintln(stderr, "load previous report:", lerr)
				return exitUsage
			}
			if ok {
				added, resolved := report.Diff(prev, res)
				fmt.Fprintf(stdout, "since last scan: %d new, %d resolved\n", len(added), len(resolved))
				for _, f := range resolved {
					fmt.Fprintf(stdout, "  - [%s] %s — %s\n", f.Severity, f.Subject, f.Summary)
				}
				display = finding.Result{Findings: added, Gaps: res.Gaps}
			} else {
				fmt.Fprintln(stdout, "since last scan: no previous report; showing all findings")
			}
		}
```

Then render `display` rather than `res`, and compute the exit code from `res` —
the true state — so `--since-last` changes what is *shown*, never what is
*reported* to a caller:

```go
		var rerr error
		if *asJSON {
			rerr = report.JSON(stdout, display, sum)
		} else {
			rerr = report.Text(stdout, display, sum)
		}
		if rerr != nil {
			fmt.Fprintln(stderr, "report:", rerr)
			return exitUsage
		}
		return report.ExitCode(res, finding.SevSuspicious)
```

Because Save now runs before the diff, `LoadLatest` would return the report just
written. Add `LoadPrevious`, which returns the second-newest:

```go
// LoadPrevious returns the second-most-recent stored report — the correct
// baseline once the current run has already been persisted.
func LoadPrevious(stateDir string) (finding.Result, bool, error) {
	return loadNthNewest(stateDir, 1)
}

// LoadLatest returns the most recent stored report.
func LoadLatest(stateDir string) (finding.Result, bool, error) {
	return loadNthNewest(stateDir, 0)
}

func loadNthNewest(stateDir string, back int) (finding.Result, bool, error) {
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
		if !e.IsDir() && filepath.Ext(e.Name()) == ".json" {
			names = append(names, e.Name())
		}
	}
	if len(names) <= back {
		return finding.Result{}, false, nil
	}
	sort.Strings(names)
	blob, err := os.ReadFile(filepath.Join(dir, names[len(names)-1-back]))
	if err != nil {
		return finding.Result{}, false, err
	}
	var st stored
	if err := json.Unmarshal(blob, &st); err != nil {
		return finding.Result{}, false, err
	}
	return finding.Result{Findings: st.Findings, Gaps: st.Gaps}, true, nil
}
```

Replace the body of the original `LoadLatest` from Step 3 with these three
functions. Add this test asserting the baseline is not self-poisoning:

```go
// D1 regression: the persisted report must be the full result, so a finding
// present in two consecutive runs is not re-reported as new in the third.
func TestSaveIsNotFilteredBySinceLast(t *testing.T) {
	dir := t.TempDir()
	full := sample()
	if _, err := Save(dir, full, Summary{}, "20260804T000000Z"); err != nil {
		t.Fatal(err)
	}
	if _, err := Save(dir, full, Summary{}, "20260804T010000Z"); err != nil {
		t.Fatal(err)
	}
	prev, ok, err := LoadPrevious(dir)
	if err != nil || !ok {
		t.Fatalf("LoadPrevious: %v ok=%v", err, ok)
	}
	added, _ := Diff(prev, full)
	if len(added) != 0 {
		t.Errorf("unchanged findings reported as new: %+v", added)
	}
}
```

Add the flag next to the others:

```go
	sinceLast := fs.Bool("since-last", false, "show only findings new or resolved since the previous scan")
```

- [ ] **Step 4: Run the full suite**

Run: `go test ./... -v && go vet ./... && go build ./...`
Expected: all PASS, including `TestFPGateNoCriticalsOnBenignSystems` and `TestFPGateStillCatchesMalware`

- [ ] **Step 5: Commit**

```bash
git add internal/report/store.go internal/report/store_test.go internal/check/fpgate_test.go cmd/arch-drift
git commit -m "feat(report): persistence, --since-last diff, INV-8 false-positive gate"
```

---

## Definition of done for P1-A

- [ ] `go test ./...` green; `go vet ./...` clean
- [ ] `arch-drift doctor` prints resolved paths with per-key provenance
- [ ] `arch-drift scan` on the reference system reports 39 foreign of 1409 total and exits `0`, `1`, or `3` — never a bare success when coverage is incomplete
- [ ] `arch-drift scan --no-network` exits `3` with a gap per foreign package, never `0`
- [ ] `arch-drift scan --json` emits `schema_version`
- [ ] `arch-drift explain <id>` prints evidence and the "what this does NOT prove" section
- [ ] `TestFPGateNoCriticalsOnBenignSystems` passes — zero criticals on stock and cruft fixtures
- [ ] `TestFPGateStillCatchesMalware` passes — the gate is not satisfiable by a silent scanner
- [ ] `TestRPCFailureProducesGapNotAbsence` passes — network failure can never trigger the highest-severity rule
- [ ] No third-party dependencies in `go.mod`

## Deferred to P1-B and P1-C

Not in this plan, and deliberately so: file integrity hashing, the mtree parser with vis(3) escapes, the staged-privilege collector, TOCTOU-safe `open`-then-`fstat` I/O, panic containment boundaries, performance tiers, persistence-surface checks, correlation keys, the helper-cache git provenance checks, and `snapshot`. P1-A needs no root and no hashing, which is what makes it shippable on its own.
