package main

import (
	"debug/elf"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

// This file tests the built artifact rather than the source, because the
// properties it guards only exist after linking:
//
//   - that -ldflags version injection actually reaches the binary, and
//   - that injecting it did not turn a static binary into a dynamic one.
//
// The second is the subtle one and the reason this file exists. Spec §16
// records that GOFLAGS' -ldflags is REPLACED, not merged, by a command-line
// -ldflags, so "just add -X" can silently drop the flags that made the build
// static. A dynamically-linked aurvet can be subverted by LD_PRELOAD or
// /etc/ld.so.preload before it can report on /etc/ld.so.preload -- a condition
// this tool rates critical. So the linkage assertion runs against the INJECTED
// build specifically: testing a plain `go build` would pass while the release
// binary was broken.
//
// The ELF is parsed with debug/elf from the standard library rather than by
// shelling out to readelf or ldd. That keeps the test dependency-free and
// honours INV-2 (parse, never execute) -- and ldd in particular runs the
// binary's interpreter, which is the opposite of what a security tool's test
// suite should do.

const (
	testVersion = "0.0.1-test"
	testCommit  = "0123456789abcdef0123456789abcdef01234567"
)

// ldflagsFor returns the single merged -ldflags string, in the same shape the
// Makefile uses. One string, both -X inside it: two -ldflags flags would mean
// the second replaces the first and one -X vanishes without an error.
func ldflagsFor(version, commit string) string {
	const pkg = "github.com/lookatitude/aurvet/internal/buildinfo"
	return "-X " + pkg + ".Version=" + version + " -X " + pkg + ".Commit=" + commit
}

// buildBinary builds cmd/aurvet with the given -ldflags and returns its path.
// GOFLAGS is cleared explicitly for the reason in the file comment: an
// inherited GOFLAGS=-ldflags=... in the environment would replace ours, and the
// failure is silent.
func buildBinary(t *testing.T, ldflags string) string {
	t.Helper()
	if _, err := exec.LookPath("go"); err != nil {
		t.Skipf("go toolchain not available: %v", err)
	}

	out := filepath.Join(t.TempDir(), "aurvet")
	args := []string{"build", "-trimpath", "-buildvcs=false", "-mod=vendor"}
	if ldflags != "" {
		args = append(args, "-ldflags", ldflags)
	}
	args = append(args, "-o", out, ".")

	cmd := exec.Command("go", args...)
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOTOOLCHAIN=local",
		"GOFLAGS=",
	)
	if combined, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, combined)
	}
	return out
}

func runBinary(t *testing.T, bin string, args ...string) string {
	t.Helper()
	out, err := exec.Command(bin, args...).CombinedOutput()
	if err != nil {
		t.Fatalf("%s %v: %v\n%s", bin, args, err, out)
	}
	return string(out)
}

// TestVersionSubcommandReportsInjectedBuild is the end-to-end injection check:
// it exercises the real link step, not buildinfo.String in isolation. A unit
// test of String cannot catch a broken -ldflags invocation, which is the actual
// failure mode.
func TestVersionSubcommandReportsInjectedBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildBinary(t, ldflagsFor(testVersion, testCommit))

	got := runBinary(t, bin, "version")
	if !strings.Contains(got, testVersion) {
		t.Errorf("version output = %q, want the injected version %q", got, testVersion)
	}
	if !strings.Contains(got, testCommit[:12]) {
		t.Errorf("version output = %q, want the injected commit prefix %q", got, testCommit[:12])
	}
	if strings.Contains(got, "not injected") {
		t.Errorf("version output = %q claims not-injected on an injected build", got)
	}
}

// TestVersionSubcommandAdmitsUninjectedBuild is the honesty half. A plain
// `go build` must not print anything that could be mistaken for a release
// identity.
func TestVersionSubcommandAdmitsUninjectedBuild(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	bin := buildBinary(t, "")

	got := runBinary(t, bin, "version")
	if !strings.Contains(got, "not injected") {
		t.Errorf("uninjected build: version output = %q, want it to say so", got)
	}
	for _, fake := range []string{"0.0.0", "dev", "unknown", "(devel)"} {
		if strings.Contains(got, fake) {
			t.Errorf("uninjected build: version output = %q contains placeholder %q", got, fake)
		}
	}
}

// TestBinaryIsStaticallyLinked asserts no DT_NEEDED and no PT_INTERP, per spec
// §16. It runs against the INJECTED build deliberately -- see the file comment.
func TestBinaryIsStaticallyLinked(t *testing.T) {
	if testing.Short() {
		t.Skip("builds a binary; skipped under -short")
	}
	if runtime.GOOS != "linux" {
		t.Skipf("ELF assertions are linux-specific; GOOS=%s", runtime.GOOS)
	}
	bin := buildBinary(t, ldflagsFor(testVersion, testCommit))

	f, err := elf.Open(bin)
	if err != nil {
		t.Fatalf("elf.Open: %v", err)
	}
	defer f.Close()

	// PT_INTERP names a dynamic loader. Its presence means the kernel hands
	// the binary to ld.so, which is what makes LD_PRELOAD and
	// /etc/ld.so.preload effective against it.
	for _, p := range f.Progs {
		if p.Type == elf.PT_INTERP {
			t.Errorf("binary has PT_INTERP: it is dynamically linked, so LD_PRELOAD can " +
				"subvert it before it can report on /etc/ld.so.preload (spec §16)")
		}
	}

	// DT_NEEDED entries are shared-library dependencies. ErrNoSymbols / a
	// missing .dynamic section is the expected, passing case for a static
	// binary, so a lookup error here is not a test failure.
	if libs, err := f.ImportedLibraries(); err == nil && len(libs) > 0 {
		t.Errorf("binary has DT_NEEDED entries %v: it is dynamically linked (spec §16)", libs)
	}

	if f.Type == elf.ET_DYN {
		// A PIE with no interpreter and no needed libraries is still static,
		// so this is reported for visibility rather than failed on: Arch's Go
		// guidelines mandate PIE, and §16 documents deviating from them.
		t.Logf("note: ELF type is ET_DYN (static-pie); no PT_INTERP and no DT_NEEDED, so linkage is static")
	}
}
