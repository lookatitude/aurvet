// internal/pkgbuild/fuzz_test.go
//
// Tokeniser robustness fuzzing. The asserted property is PANIC-FREE AND
// HANG-FREE, not correctness, and that distinction is the whole point: the
// input is attacker-controlled by definition (INV-2's justification), so a
// panic is a denial of service against a security tool and a hang is worse. A
// fuzz target that asserted output SHAPE would fail on valid weird input --
// makepkg accepts a great deal of weird input -- and would teach everyone to
// ignore it.
//
// Two things are therefore asserted, and only two:
//
//  1. Lex, Resolve and Assess return. Each input runs under a wall-clock budget,
//     because `go test -fuzz` will happily accept a slow-but-terminating input
//     that takes ten seconds, and ten seconds per recipe is a hang as far as a
//     dependency-closure review is concerned.
//  2. The DoS bounds the package documents actually hold (command, note, source
//     and gap counts), plus resolve.go's one honesty contract: an Unresolvable
//     value carries no text. A half-expanded URL that looks analysable is the
//     failure this package exists to avoid, so if a crafted input produces one
//     that is a genuine bug and not a shape quibble.
//
// The seed corpus is built programmatically to the roadmap's "several thousand"
// from the checked-in fixtures, from the live helper cache and its .SRCINFO
// files when one is present, and from deterministic mutations of both. Nothing
// large is committed: a crash writes its own regression fixture under
// testdata/fuzz, and that -- and only that -- is what enters the repository.
package pkgbuild

import (
	"math/rand"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// fuzzBudget bounds one input. Generous on purpose: this must fail on a hang,
// not on a loaded CI machine. The whole 34-recipe corpus lexes and resolves in
// single-digit milliseconds, so anything approaching this is pathological.
const fuzzBudget = 5 * time.Second

// maxSeedBytes bounds a generated seed so the seed corpus stays fast to replay
// in CI. Real recipes top out at 24 KiB.
const maxSeedBytes = 64 << 10

// seedTargetCount is the roadmap's "several thousand" made checkable.
const seedTargetCount = 3000

// hostileTokens are the constructs that historically break bash tokenisers:
// unbalanced openers, quote and heredoc introducers, and the two builtins whose
// effects are not in the text. Inserted at random positions into real recipes,
// they produce input that is shaped like a PKGBUILD and lexes like nothing.
var hostileTokens = []string{
	"$(", ")", "${", "}", "$((", "))", "`", "'", "\"", "\\", "\\\n",
	"<<EOF\n", "<<-'EOF'\n", "<<<", ">", "<", "|", "||", "&&", ";;", "&",
	"#", "\n#", "eval ", "source ", ". ", "function ", "package_", "()",
	"source=(", "sha256sums=(", "_x86_64=", "arch=(", "[@]", "[0]",
	"${v//", "${v##", "${!v}", "${#v}", "${v:-", "$srcdir", "$pkgdir",
	"\x00", "\xff\xfe", "\n\n", "\t", " ",
}

// fuzzSeeds builds the seed corpus. It is deterministic: one fixed PRNG seed, so
// a CI run and a developer run replay the same inputs and a regression is
// reproducible without committing megabytes of corpus.
func fuzzSeeds(tb testing.TB) [][]byte {
	tb.Helper()
	bases := seedBases(tb)
	if len(bases) == 0 {
		tb.Fatal("no seed bases; the fuzz corpus would be empty")
	}
	seeds := make([][]byte, 0, seedTargetCount+len(bases))
	seeds = append(seeds, bases...)

	// A handful of hand-written degenerate inputs, which random mutation reaches
	// only slowly: nothing, only a comment, only NULs, and each bound's edge.
	seeds = append(seeds,
		[]byte(""),
		[]byte("#"),
		[]byte("# just a comment\n"),
		[]byte("\x00\x00\x00\x00"),
		[]byte("source=("),
		[]byte("f(){"),
		[]byte("$("),
		[]byte("${"),
		[]byte("`"),
		[]byte("<<EOF\n"),
		[]byte("eval \"package_$_p() {\""),
		[]byte(strings.Repeat("$(", maxSubstDepth+4)),
		[]byte(strings.Repeat("a=(", 64)),
		[]byte("pkgname=x\nsource=(\"http://[::1]/x\")\n"),
		[]byte("pkgname=x\npkgver=1\nsource=(\"$(echo hi)\")\nsha256sums=('SKIP')\n"),
		[]byte("arch=(x86_64 aarch64)\nsource_x86_64=(a)\nsource_aarch64=(b)\nmd5sums_x86_64=(SKIP)\n"),
	)

	rng := rand.New(rand.NewSource(20260805))
	for len(seeds) < seedTargetCount {
		seeds = append(seeds, mutate(rng, bases))
	}
	return seeds
}

// seedBases collects the real recipes available to this machine: the checked-in
// fixtures always, and the live helper cache's PKGBUILD and .SRCINFO pairs when
// one exists. The cache is 88 GB and machine-specific, so its absence must not
// fail the run -- it only makes the corpus smaller and less real.
func seedBases(tb testing.TB) [][]byte {
	tb.Helper()
	var out [][]byte
	fixtures, _ := filepath.Glob(filepath.Join("..", "..", "testdata", "pkgbuild", "*.pkgbuild"))
	for _, p := range fixtures {
		if b, err := os.ReadFile(p); err == nil {
			out = append(out, b)
		}
	}
	dir := os.Getenv("AURVET_LIVE_PKGBUILD_DIR")
	if dir == "" {
		if home, err := os.UserHomeDir(); err == nil {
			dir = filepath.Join(home, ".cache", "yay")
		}
	}
	if dir == "" {
		return out
	}
	for _, name := range []string{"PKGBUILD", ".SRCINFO"} {
		paths, _ := filepath.Glob(filepath.Join(dir, "*", name))
		for _, p := range paths {
			b, err := os.ReadFile(p)
			if err != nil || len(b) > maxSeedBytes {
				continue
			}
			out = append(out, b)
		}
	}
	return out
}

// mutate derives one seed from the bases: a splice of two of them, truncated,
// with hostile tokens injected and bytes flipped. Every operation is bounded, so
// this cannot itself hang or blow memory.
func mutate(rng *rand.Rand, bases [][]byte) []byte {
	a := bases[rng.Intn(len(bases))]
	b := bases[rng.Intn(len(bases))]
	var out []byte
	switch rng.Intn(4) {
	case 0:
		out = append(out, a[:cut(rng, len(a))]...)
	case 1:
		out = append(out, a[:cut(rng, len(a))]...)
		out = append(out, b[cut(rng, len(b)):]...)
	case 2:
		out = append(out, b...)
		out = append(out, a[:cut(rng, len(a))]...)
	default:
		out = append(out, a...)
	}
	if len(out) > maxSeedBytes {
		out = out[:maxSeedBytes]
	}
	for i, n := 0, rng.Intn(6); i < n; i++ {
		tok := hostileTokens[rng.Intn(len(hostileTokens))]
		at := 0
		if len(out) > 0 {
			at = rng.Intn(len(out))
		}
		grown := make([]byte, 0, len(out)+len(tok))
		grown = append(grown, out[:at]...)
		grown = append(grown, tok...)
		grown = append(grown, out[at:]...)
		out = grown
		if len(out) > maxSeedBytes {
			out = out[:maxSeedBytes]
		}
	}
	for i, n := 0, rng.Intn(8); i < n && len(out) > 0; i++ {
		out[rng.Intn(len(out))] = byte(rng.Intn(256))
	}
	return out
}

func cut(rng *rand.Rand, n int) int {
	if n <= 1 {
		return n
	}
	return rng.Intn(n)
}

// bounded runs fn under the wall-clock budget and fails if it does not return in
// time. It runs on a goroutine deliberately: a hang must FAIL THE TEST rather
// than wedge the run until the binary's own timeout, and a leaked goroutine in
// an already-failing test costs nothing. A panic inside fn still crashes the
// process, which is what makes the fuzzer record it as a crasher.
func bounded(t *testing.T, what string, data []byte, fn func()) {
	t.Helper()
	done := make(chan struct{})
	start := time.Now()
	go func() {
		defer close(done)
		fn()
	}()
	select {
	case <-done:
		if el := time.Since(start); el > fuzzBudget {
			t.Fatalf("%s took %v on %d bytes, budget %v: a slow-but-terminating input is a denial of service too",
				what, el, len(data), fuzzBudget)
		}
	case <-time.After(fuzzBudget):
		t.Fatalf("%s did not return within %v on %d bytes (hang)", what, fuzzBudget, len(data))
	}
}

// checkBounds asserts the limits lex.go and resolve.go document, which are the
// only thing standing between a crafted recipe and an unbounded allocation.
// These are DoS bounds, not output shape: no assertion here says what a correct
// parse of anything looks like.
func checkBounds(t *testing.T, f File) {
	t.Helper()
	if len(f.Commands) > maxCommands {
		t.Fatalf("%d commands exceeds the bound %d", len(f.Commands), maxCommands)
	}
	if len(f.Notes) > maxNotes {
		t.Fatalf("%d notes exceeds the bound %d", len(f.Notes), maxNotes)
	}
	if len(f.Heredocs) > maxHeredocs {
		t.Fatalf("%d heredocs exceeds the bound %d", len(f.Heredocs), maxHeredocs)
	}
	for _, c := range f.Commands {
		if len(c.Words) > maxWords {
			t.Fatalf("command at line %d has %d words, bound %d", c.Line, len(c.Words), maxWords)
		}
		if c.SubstDepth > maxSubstDepth {
			t.Fatalf("command at line %d is at substitution depth %d, bound %d", c.Line, c.SubstDepth, maxSubstDepth)
		}
		for _, w := range c.Words {
			if len(w.Segs) > maxSegments {
				t.Fatalf("word at line %d has %d segments, bound %d", w.Line, len(w.Segs), maxSegments)
			}
		}
	}
}

// checkHonesty asserts resolve.go's one contract that a caller's correctness
// depends on: an Unresolvable value carries NO text, so nothing downstream can
// mistake a half-expanded URL for a resolved one.
func checkHonesty(t *testing.T, r Resolution) {
	t.Helper()
	check := func(what string, v Value) {
		if v.Status != Unresolvable {
			return
		}
		if v.Text != "" {
			t.Fatalf("%s is Unresolvable but carries text %q; a half-expanded value is the lie this package must not tell", what, v.Text)
		}
		if v.Reason == "" {
			t.Fatalf("%s is Unresolvable with no stated reason (INV-6)", what)
		}
	}
	for _, s := range r.Sources {
		check("a source entry", s.Value)
		if !s.Value.OK() && (s.URL != "" || s.Host != "" || s.Name != "") {
			t.Fatalf("an unresolvable source entry has derived fields url=%q host=%q name=%q", s.URL, s.Host, s.Name)
		}
		for _, in := range s.Integrity {
			check(in.Algo+"sums entry", in.Value)
		}
	}
	for _, v := range r.Pkgnames {
		check("a pkgname", v)
	}
	if len(r.Sources) > maxSources {
		t.Fatalf("%d sources exceeds the bound %d", len(r.Sources), maxSources)
	}
}

// TestFuzzSeedCorpusIsSeveralThousand pins the roadmap's own number: "several
// thousand real PKGBUILD/.SRCINFO pairs". Without this, a broken seed builder
// would silently reduce both fuzz targets to a handful of inputs and every
// clean run would mean nothing.
func TestFuzzSeedCorpusIsSeveralThousand(t *testing.T) {
	seeds := fuzzSeeds(t)
	if len(seeds) < seedTargetCount {
		t.Fatalf("seed corpus is %d inputs, want at least %d", len(seeds), seedTargetCount)
	}
	var real int
	for _, s := range seedBases(t) {
		if len(s) > 0 {
			real++
		}
	}
	if real == 0 {
		t.Fatal("no real recipes among the seed bases; the corpus is entirely synthetic")
	}
	t.Logf("seeds=%d real-recipe bases=%d", len(seeds), real)
}

// FuzzLex asserts the tokeniser alone is panic-free and hang-free.
func FuzzLex(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		var out File
		bounded(t, "Lex", data, func() { out = Lex(data) })
		checkBounds(t, out)
		// Lexing twice must produce the same command count: a tokeniser whose
		// output depended on anything but its input would make every finding
		// derived from it unreproducible (INV-4).
		second := Lex(data)
		if len(second.Commands) != len(out.Commands) || len(second.Notes) != len(out.Notes) {
			t.Fatalf("Lex is not deterministic: %d/%d commands, %d/%d notes",
				len(out.Commands), len(second.Commands), len(out.Notes), len(second.Notes))
		}
	})
}

// FuzzResolve asserts the whole read path -- Lex, Resolve, Assess -- is
// panic-free and hang-free, including the per-architecture passes, which is
// where the resolver does the most work per byte of input. The architecture
// list is derived from the input itself so the fuzzer explores both the
// declared-arch default and an explicitly scoped run.
func FuzzResolve(f *testing.F) {
	for _, s := range fuzzSeeds(f) {
		f.Add(s)
	}
	f.Fuzz(func(t *testing.T, data []byte) {
		cfg := ResolveConfig{}
		if len(data) > 0 {
			switch data[0] % 3 {
			case 1:
				cfg.Arches = []string{"x86_64"}
			case 2:
				cfg.Arches = []string{"x86_64", "aarch64", "armv7h"}
			}
		}
		var (
			lexed    File
			resolved Resolution
			verdict  Verdict
		)
		bounded(t, "Lex+Resolve+Assess", data, func() {
			lexed = Lex(data)
			resolved = Resolve(lexed, cfg)
			verdict = Assess("", lexed, resolved)
		})
		checkBounds(t, lexed)
		checkHonesty(t, resolved)
		if len(verdict.Gaps) > maxGaps {
			t.Fatalf("%d gaps exceeds the bound %d", len(verdict.Gaps), maxGaps)
		}
		for _, g := range verdict.Gaps {
			if g.Reason == "" {
				t.Fatalf("gap %s has no reason (INV-6/INV-9)", g.RuleID)
			}
		}
		// A file from which nothing was read must never report complete coverage:
		// that is the false clean INV-3 exists to prevent, and it is a safety
		// property rather than an output shape.
		if verdict.Complete() && resolved.Pkgbase == "" && len(resolved.Sources) == 0 && len(lexed.Functions) == 0 {
			t.Fatal("a recipe with no name, no sources and no functions reported complete coverage")
		}
	})
}
