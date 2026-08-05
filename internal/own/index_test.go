// internal/own/index_test.go
package own

import (
	"errors"
	"os"
	"path/filepath"
	"testing"

	"github.com/lookatitude/aurvet/internal/alpm"
)

// pkgs is the fixture package set every test indexes. The paths are recorded
// exactly as pacman records them -- relative, no leading slash -- so a test
// cannot accidentally assert against a shape the local DB never produces.
func pkgs() []alpm.Package {
	return []alpm.Package{
		{Name: "coreutils", Files: []string{"usr/bin/hello", "usr/bin/", "usr/"}},
		{Name: "glibc", Files: []string{"usr/lib/libx.so", "./usr/lib/preloaded.so"}},
	}
}

// tree materializes a root containing the shapes the oracle has to survive.
// It is built at runtime rather than checked in for the reason recorded in
// testdata/own/README.md: git cannot carry a symlink loop or an escaping link
// without making a checkout hostile.
//
//	<tmp>/outside/secret          a path the oracle must never resolve into
//	<tmp>/root/usr/bin/hello      the package-owned file
//	<tmp>/root/usr/lib/libx.so    the package-owned library
//	<tmp>/root/usr/local/bin/rat  an unowned file that really exists
//	<tmp>/root/bin      -> usr/bin      (relative dir symlink, Arch's shape)
//	<tmp>/root/lib      -> usr/lib
//	<tmp>/root/sbin     -> /usr/bin     (absolute target, root-relative)
//	<tmp>/root/loopa    -> loopb        (symlink loop)
//	<tmp>/root/loopb    -> loopa
//	<tmp>/root/esc      -> ../outside   (escapes the root)
func tree(t *testing.T) *os.Root {
	t.Helper()
	tmp := t.TempDir()
	mk := func(rel string, content string) {
		p := filepath.Join(tmp, rel)
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, []byte(content), 0o644); err != nil {
			t.Fatal(err)
		}
	}
	ln := func(target, rel string) {
		if err := os.Symlink(target, filepath.Join(tmp, rel)); err != nil {
			t.Fatal(err)
		}
	}
	mk("outside/secret", "not reachable\n")
	mk("root/usr/bin/hello", "inert\n")
	mk("root/usr/lib/libx.so", "inert\n")
	mk("root/usr/local/bin/rat", "inert marker, not a payload\n")
	ln("usr/bin", "root/bin")
	ln("usr/lib", "root/lib")
	ln("/usr/bin", "root/sbin")
	ln("loopb", "root/loopa")
	ln("loopa", "root/loopb")
	ln("../outside", "root/esc")

	root, err := os.OpenRoot(filepath.Join(tmp, "root"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { root.Close() })
	return root
}

func TestResolveAcceptsBothPathForms(t *testing.T) {
	o := Index(pkgs())
	owned := func(t *testing.T, in, want string) {
		t.Helper()
		pkg, st, err := o.Resolve(in)
		if err != nil {
			t.Errorf("Resolve(%q): unexpected error %v", in, err)
			return
		}
		if st != Owned || pkg != want {
			t.Errorf("Resolve(%q) = (%q, %v), want (%s, Owned)", in, pkg, st, want)
		}
	}
	for _, in := range []string{"/usr/bin/hello", "usr/bin/hello", "./usr/bin/hello"} {
		owned(t, in, "coreutils")
	}
	// Recorded with a "./" prefix in the fixture: normalization has to happen
	// on the index side too, or the canonical form is only half-canonical.
	owned(t, "/usr/lib/preloaded.so", "glibc")
	// A trailing slash is how pacman records a directory; it must be the same
	// key as the slashless form.
	owned(t, "/usr/bin", "coreutils")
}

func TestOwnerThroughSymlinkedParentDirectory(t *testing.T) {
	o := IndexIn(tree(t), pkgs())
	cases := map[string]string{
		"/bin/hello":   "coreutils", // bin  -> usr/bin, relative
		"/lib/libx.so": "glibc",     // lib  -> usr/lib
		"/sbin/hello":  "coreutils", // sbin -> /usr/bin, absolute, root-relative
	}
	for in, want := range cases {
		pkg, st, err := o.Resolve(in)
		if err != nil {
			t.Errorf("Resolve(%q): unexpected error %v", in, err)
			continue
		}
		if st != Owned || pkg != want {
			t.Errorf("Resolve(%q) = (%q, %v), want (%s, Owned)", in, pkg, st, want)
		}
	}
}

func TestUnownedPathThatExistsIsUnownedNotAGap(t *testing.T) {
	o := IndexIn(tree(t), pkgs())
	pkg, st, err := o.Resolve("/usr/local/bin/rat")
	if err != nil || st != Unowned || pkg != "" {
		t.Fatalf("Resolve(rat) = (%q, %v, %v), want (\"\", Unowned, nil)", pkg, st, err)
	}
}

func TestAbsentPathIsUnownedNotAGap(t *testing.T) {
	// ENOENT is a definite answer -- nobody owns a path that is not there --
	// and an ExecStart naming a missing binary must reach the caller as a
	// finding-eligible fact, not as "I could not tell".
	o := IndexIn(tree(t), pkgs())
	for _, in := range []string{"/usr/bin/nope", "/nodir/nope", "/usr/bin/hello/under-a-file"} {
		pkg, st, err := o.Resolve(in)
		if err != nil || st != Unowned || pkg != "" {
			t.Errorf("Resolve(%q) = (%q, %v, %v), want (\"\", Unowned, nil)", in, pkg, st, err)
		}
	}
}

func TestUnresolvablePathIsAGapNotUnowned(t *testing.T) {
	// The whole point of the three-state result: "I know nobody owns this"
	// and "I could not tell" are different answers, and INV-9 makes the
	// second one a coverage gap for the caller to report.
	o := IndexIn(tree(t), pkgs())
	for _, in := range []string{
		"/loopa/hello", // symlink loop, exhausts the hop budget
		"/loopa",
		"/esc/secret", // resolves out of the scanned root
	} {
		pkg, st, err := o.Resolve(in)
		if err == nil {
			t.Errorf("Resolve(%q) = (%q, %v, nil), want an Unresolved gap", in, pkg, st)
			continue
		}
		if st != Unresolved || pkg != "" {
			t.Errorf("Resolve(%q) = (%q, %v, %v), want (\"\", Unresolved, err)", in, pkg, st, err)
		}
		if !errors.Is(err, ErrUnresolved) {
			t.Errorf("Resolve(%q) error %v does not match ErrUnresolved", in, err)
		}
	}
}

func TestUnsafeInputIsAGap(t *testing.T) {
	o := IndexIn(tree(t), pkgs())
	for _, in := range []string{"", "/", ".", "..", "/usr/../etc/passwd", "/usr/bin/hel\x00lo"} {
		pkg, st, err := o.Resolve(in)
		if err == nil || st != Unresolved || pkg != "" {
			t.Errorf("Resolve(%q) = (%q, %v, %v), want an Unresolved gap", in, pkg, st, err)
		}
	}
}

func TestThereIsNoTwoValueLookup(t *testing.T) {
	// Guards the removal of Owner(path) (string, bool) rather than its
	// behaviour: a two-value lookup collapses Unresolved into Unowned, and a
	// consumer that reports a finding on the false turns a coverage gap into a
	// false accusation (INV-9). If someone reintroduces the convenience, this
	// test is the note explaining why it was not an oversight.
	//
	// Compile-time, via the method set: any method returning exactly
	// (string, bool) fails the assertion.
	var forbidden interface {
		Owner(string) (string, bool)
	}
	if _, ok := any(&Owners{}).(interface {
		Owner(string) (string, bool)
	}); ok {
		t.Fatalf("*Owners has a two-value Owner again; use Resolve, which can say Unresolved (%T)", forbidden)
	}
}

func TestIndexWithoutARootPerformsNoResolution(t *testing.T) {
	// Index has no root, so it answers only from the recorded paths. A caller
	// that wants a symlinked path recognised must supply a root; this pins
	// that the rootless form fails closed (unowned) rather than pretending.
	o := Index(pkgs())
	if _, st, err := o.Resolve("/bin/hello"); st != Unowned || err != nil {
		t.Fatalf("rootless Resolve(/bin/hello) = (%v, %v), want (Unowned, nil)", st, err)
	}
}

func TestLenCountsCanonicalPaths(t *testing.T) {
	// 5 distinct paths after normalization: usr/bin/hello, usr/bin, usr,
	// usr/lib/libx.so, usr/lib/preloaded.so.
	if got := Index(pkgs()).Len(); got != 5 {
		t.Fatalf("Len() = %d, want 5", got)
	}
}

// TestLiveReferenceSystem measures the oracle against the machine it runs on.
// Skipped by default: it reads /var/lib/pacman/local and / , which no unit
// test may depend on. Run with AURVET_LIVE_OWN=1 to reproduce the numbers
// quoted in the P1-C receipt.
func TestLiveReferenceSystem(t *testing.T) {
	if os.Getenv("AURVET_LIVE_OWN") != "1" {
		t.Skip("set AURVET_LIVE_OWN=1 to measure against the live system")
	}
	pkgs, gaps, err := alpm.LoadLocalDB("/var/lib/pacman/local")
	if err != nil {
		t.Fatal(err)
	}
	root, err := os.OpenRoot("/")
	if err != nil {
		t.Fatal(err)
	}
	defer root.Close()
	o := IndexIn(root, pkgs)

	var owned, unowned, unresolved int
	for _, p := range pkgs {
		for _, f := range p.Files {
			_, st, _ := o.Resolve(f)
			switch st {
			case Owned:
				owned++
			case Unowned:
				unowned++
			default:
				unresolved++
			}
		}
	}
	t.Logf("packages=%d db-gaps=%d indexed-paths=%d owned=%d unowned=%d unresolved=%d",
		len(pkgs), len(gaps), o.Len(), owned, unowned, unresolved)

	// The loop above is answered entirely by the literal hit, so it measures
	// the index and not the resolver. Drive resolve() directly to get the
	// number the phase actually needs: of every recorded path, how many does
	// the confined walk arrive at, and how many does it refuse to answer for.
	var walked, sameKey, changed, failed, changedUnowned int
	reasons := map[string]int{}
	for key := range o.byPath {
		walked++
		got, err := o.resolve(key)
		switch {
		case err != nil:
			failed++
			reasons[err.Error()]++
		case got == key:
			sameKey++
		default:
			changed++
			// Not an error: a package-owned symlink may legitimately point
			// at something no package owns (etc/mtab -> proc/N/mounts,
			// ca-certificates' generated bundles). Counted, because the
			// count is what tells a later lane how much of the tree its
			// "unowned target" rule will see.
			if _, ok := o.byPath[got]; !ok {
				changedUnowned++
			}
		}
	}
	t.Logf("resolver: walked=%d unchanged=%d rewritten=%d rewritten-to-unowned=%d unresolvable=%d",
		walked, sameKey, changed, changedUnowned, failed)
	for r, n := range reasons {
		t.Logf("  unresolvable x%d: %s", n, r)
	}

	// The compat links are why this package resolves at all. If these come
	// back unowned on an Arch system, the oracle is broken in the exact way
	// that would flood P1-C with false positives.
	for _, probe := range []string{"/bin/sh", "/bin/ls", "/sbin/init", "/lib/ld-linux-x86-64.so.2"} {
		pkg, st, err := o.Resolve(probe)
		t.Logf("probe %-26s -> %-10v %-20s %v", probe, st, pkg, err)
	}
}
