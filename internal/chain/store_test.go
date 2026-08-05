// internal/chain/store_test.go
//
// Task 12: concurrency and crash safety, written as the failures rather than
// as the round trip.
package chain

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/finding"
)

// -- db.lck: warn for scan, REFUSE for append --------------------------------

// The asymmetry is the point. A noisy scan is recoverable; a signed lie is not,
// because every later run compares against it.
func TestDBLockRefusesAppendButOnlyWarnsScan(t *testing.T) {
	locked := filepath.Join("..", "..", "testdata", "chain", "root-locked")
	clean := filepath.Join("..", "..", "testdata", "chain", "root-clean")

	lock, err := DetectDBLock(locked)
	if err != nil {
		t.Fatal(err)
	}
	if !lock.Present {
		t.Fatalf("fixture %s does not carry db.lck", locked)
	}

	// scan: a gap and a non-critical finding, never a refusal.
	adv := lock.ScanAdvisory()
	if len(adv.Gaps) == 0 {
		t.Fatal("a transaction in flight must be a coverage gap, not silence")
	}
	if adv.MaxSeverity() == finding.SevCritical {
		t.Fatal("db.lck during a scan is a warning, not an accusation")
	}

	// append: refusal.
	if err := lock.GuardAppend(); !errors.Is(err, ErrDBLocked) {
		t.Fatalf("baseline append did not refuse with db.lck present: %v", err)
	}

	// And the clean root does neither.
	free, err := DetectDBLock(clean)
	if err != nil {
		t.Fatal(err)
	}
	if free.Present {
		t.Fatalf("fixture %s should have no db.lck", clean)
	}
	if adv := free.ScanAdvisory(); len(adv.Gaps) != 0 || len(adv.Findings) != 0 {
		t.Fatal("a clean root produced a db.lck advisory")
	}
	if err := free.GuardAppend(); err != nil {
		t.Fatalf("append refused with no db.lck: %v", err)
	}
}

// The whole-path version: Append itself must refuse, not merely the guard.
func TestAppendRefusesWhileDBIsLocked(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	s := Open(dir)
	root := filepath.Join("..", "..", "testdata", "chain", "root-locked")

	_, err := s.Append(AppendOptions{Trusted: trust(k), Root: root}, func(head *Record) (Record, error) {
		t.Fatal("the entry builder ran despite db.lck; the refusal must come first")
		return Record{}, nil
	})
	if !errors.Is(err, ErrDBLocked) {
		t.Fatalf("want ErrDBLocked, got %v", err)
	}
	if _, err := os.Stat(s.Path()); !errors.Is(err, os.ErrNotExist) {
		t.Fatal("a refused append still created the chain file")
	}
}

// -- crash safety ------------------------------------------------------------

// Interrupted between the temp file and the rename, the OLD chain must still be
// the one that is read, and no partial file may be left where the chain is.
func TestCrashBetweenTempAndRenameKeepsTheOldChain(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	s := Open(dir)
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture()}

	first := mustAppend(t, s, opt, "manifest 0")
	before, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}

	boom := errors.New("power cut")
	s.beforeRename = func() error { return boom }
	_, err = s.Append(opt, func(head *Record) (Record, error) {
		return NewRecord(k, Link(head, Entry{
			Schema: Schema, Time: "2026-08-05T12:00:09+0200", Kind: KindAppend,
			Host: "reference", Payload: payloadFor("manifest 1"),
		}))
	})
	if !errors.Is(err, boom) {
		t.Fatalf("the injected crash did not surface: %v", err)
	}
	s.beforeRename = nil

	after, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if string(after) != string(before) {
		t.Fatal("the chain file changed despite the crash before rename")
	}
	recs, err := s.Load(trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != 1 || recs[0].Hash() != first.Hash() {
		t.Fatalf("the old chain is not what is read back: %d records", len(recs))
	}
	// No debris in the chain directory beyond the chain and its lock.
	ents, err := os.ReadDir(dir)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range ents {
		switch e.Name() {
		case ChainFile, lockFileName:
		default:
			t.Fatalf("a partial write was left behind: %s", e.Name())
		}
	}
}

// -- unsigned payload reads as ABSENT, not corrupt ---------------------------

// The two provoke different responses: absent means "no baseline yet, make
// one"; corrupt means "something is wrong, investigate". A payload whose
// signature is missing or bad must read as the first.
func TestUnsignedPayloadReadsAsAbsentNotCorrupt(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	m, err := baseline.BuildManifest(liveishInput())
	if err != nil {
		t.Fatal(err)
	}
	raw, sig, err := baseline.SignManifest(k, m)
	if err != nil {
		t.Fatal(err)
	}
	dg, err := s.PutPayload(baseline.NamespaceManifest, raw, sig)
	if err != nil {
		t.Fatal(err)
	}

	got, err := s.LoadPayload(dg, baseline.NamespaceManifest, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != PayloadPresent {
		t.Fatalf("a correctly signed payload read as %v: %s", got.State, got.Reason)
	}

	cases := map[string]func(t *testing.T, s *Store, dg string){
		"signature file removed": func(t *testing.T, s *Store, dg string) {
			if err := os.Remove(s.payloadPath(dg) + SignatureSuffix); err != nil {
				t.Fatal(err)
			}
		},
		"signature truncated to nothing": func(t *testing.T, s *Store, dg string) {
			if err := os.WriteFile(s.payloadPath(dg)+SignatureSuffix, nil, 0o600); err != nil {
				t.Fatal(err)
			}
		},
		"signature is garbage": func(t *testing.T, s *Store, dg string) {
			if err := os.WriteFile(s.payloadPath(dg)+SignatureSuffix, []byte("not a signature\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		},
	}
	for name, breakIt := range cases {
		t.Run(name, func(t *testing.T) {
			s := Open(t.TempDir())
			dg, err := s.PutPayload(baseline.NamespaceManifest, raw, sig)
			if err != nil {
				t.Fatal(err)
			}
			breakIt(t, s, dg)
			got, err := s.LoadPayload(dg, baseline.NamespaceManifest, trust(k))
			if err != nil {
				t.Fatalf("an unsigned payload must not be an error: %v", err)
			}
			if got.State != PayloadAbsent {
				t.Fatalf("state %v, want absent", got.State)
			}
			if got.Reason == "" {
				t.Fatal("absent with no reason is silence")
			}
			if len(got.Raw) != 0 {
				t.Fatal("unauthenticated bytes were handed back to the caller")
			}
		})
	}

	// A payload that was never written is absent too, and identically so.
	missing, err := s.LoadPayload(digestOf("never written"), baseline.NamespaceManifest, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if missing.State != PayloadAbsent || missing.Reason == "" {
		t.Fatalf("a missing payload read as %v", missing.State)
	}
}

// A payload signed under the wrong namespace is absent, not present: it is a
// document of another kind that happens to be lying in this slot.
func TestPayloadInWrongNamespaceIsAbsent(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	raw := []byte(`{"a":1}`)
	sig, err := baseline.Sign(k, baseline.NamespaceChainEntry, raw)
	if err != nil {
		t.Fatal(err)
	}
	dg, err := s.PutPayload(baseline.NamespaceChainEntry, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPayload(dg, baseline.NamespaceManifest, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != PayloadAbsent {
		t.Fatal("a chain-entry payload read as a manifest")
	}
}

// A payload whose bytes no longer match the digest it is filed under is absent:
// it is not the document that was asked for.
func TestPayloadWithMismatchedDigestIsAbsent(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	raw := []byte(`{"a":1}`)
	sig, err := baseline.Sign(k, baseline.NamespaceManifest, raw)
	if err != nil {
		t.Fatal(err)
	}
	dg, err := s.PutPayload(baseline.NamespaceManifest, raw, sig)
	if err != nil {
		t.Fatal(err)
	}
	other := []byte(`{"a":2}`)
	otherSig, err := baseline.Sign(k, baseline.NamespaceManifest, other)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.payloadPath(dg), other, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(s.payloadPath(dg)+SignatureSuffix, otherSig, 0o600); err != nil {
		t.Fatal(err)
	}
	got, err := s.LoadPayload(dg, baseline.NamespaceManifest, trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if got.State != PayloadAbsent {
		t.Fatal("a substituted, validly signed payload read as present under the wrong digest")
	}
}

// -- an absent chain is absent, not an error ---------------------------------

func TestMissingChainLoadsAsEmpty(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	recs, err := s.Load(trust(k))
	if err != nil {
		t.Fatalf("a missing chain must read as absent: %v", err)
	}
	if len(recs) != 0 {
		t.Fatalf("%d records from nothing", len(recs))
	}
}

// A chain file whose header is not ours is an error, not an empty chain: this
// one IS corruption, and treating it as "no baseline yet" would invite writing
// a fresh chain over whatever is there.
func TestForeignChainFileIsAnError(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	s := Open(dir)
	if err := os.WriteFile(s.Path(), []byte("something else entirely\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(trust(k)); !errors.Is(err, ErrChainFile) {
		t.Fatalf("want ErrChainFile, got %v", err)
	}
}

// Tampering with a stored record must be caught on load, before the entry is
// parsed into anything a caller could act on.
func TestTamperedChainFileRejectedOnLoad(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture()}
	mustAppend(t, s, opt, "manifest 0")
	mustAppend(t, s, opt, "manifest 1")

	b, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	tampered := strings.Replace(string(b), "reference", "referenca", 1)
	if tampered == string(b) {
		t.Fatal("nothing was tampered with")
	}
	if err := os.WriteFile(s.Path(), []byte(tampered), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := s.Load(trust(k)); err == nil {
		t.Fatal("a tampered chain loaded cleanly")
	}
}

// -- append discipline -------------------------------------------------------

// Append must refuse a record that does not link to the head it was given, even
// when it is perfectly signed: the builder gets the head, so a mismatch is a
// bug or an attack, never a merge.
func TestAppendRefusesUnlinkedRecord(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture()}
	mustAppend(t, s, opt, "manifest 0")

	_, err := s.Append(opt, func(head *Record) (Record, error) {
		return NewRecord(k, Entry{
			Schema: Schema, Seq: 1, PrevHash: GenesisPrev,
			Time: "2026-08-05T12:00:09+0200", Kind: KindAppend, Host: "reference",
			Payload: payloadFor("manifest 1"),
		})
	})
	if !errors.Is(err, ErrPrevHash) {
		t.Fatalf("want ErrPrevHash, got %v", err)
	}
}

// The file only ever grows, and each append leaves a chain that verifies.
func TestAppendIsAppendOnly(t *testing.T) {
	k := testKey(t)
	s := Open(t.TempDir())
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture()}
	var sizes []int
	for i := 0; i < 5; i++ {
		mustAppend(t, s, opt, fmt.Sprintf("manifest %d", i))
		b, err := os.ReadFile(s.Path())
		if err != nil {
			t.Fatal(err)
		}
		sizes = append(sizes, len(b))
		recs, err := s.Load(trust(k))
		if err != nil {
			t.Fatal(err)
		}
		if len(recs) != i+1 {
			t.Fatalf("%d records after %d appends", len(recs), i+1)
		}
		if _, err := Verify(recs, VerifyOptions{Trusted: trust(k)}); err != nil {
			t.Fatalf("chain does not verify after append %d: %v", i, err)
		}
	}
	for i := 1; i < len(sizes); i++ {
		if sizes[i] <= sizes[i-1] {
			t.Fatalf("the chain file did not grow: %v", sizes)
		}
	}
	// Every earlier record is still a byte-identical prefix of the file.
	b, err := os.ReadFile(s.Path())
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != sizes[len(sizes)-1] {
		t.Fatal("the file changed size without an append")
	}
}

// -- concurrency -------------------------------------------------------------

// Concurrent appenders must serialise on the advisory lock and produce a chain
// that still verifies. Run this one with -race.
func TestConcurrentAppendsSerialise(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	opt := AppendOptions{Trusted: trust(k), Root: cleanRootFixture(), LockTimeout: 10 * time.Second}

	const n = 8
	var wg sync.WaitGroup
	errs := make([]error, n)
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func(i int) {
			defer wg.Done()
			s := Open(dir) // a separate handle, as a separate process would have
			_, errs[i] = s.Append(opt, func(head *Record) (Record, error) {
				return NewRecord(k, Link(head, Entry{
					Schema: Schema, Time: "2026-08-05T12:00:00+0200", Kind: KindAppend,
					Host: "reference", Payload: payloadFor(fmt.Sprintf("manifest %d", i)),
				}))
			})
		}(i)
	}
	wg.Wait()
	for i, err := range errs {
		if err != nil {
			t.Fatalf("appender %d failed: %v", i, err)
		}
	}
	s := Open(dir)
	recs, err := s.Load(trust(k))
	if err != nil {
		t.Fatal(err)
	}
	if len(recs) != n {
		t.Fatalf("%d records from %d concurrent appends", len(recs), n)
	}
	if _, err := Verify(recs, VerifyOptions{Trusted: trust(k)}); err != nil {
		t.Fatalf("concurrent appends produced a chain that does not verify: %v", err)
	}
}

// A held lock times out rather than blocking forever or writing anyway.
func TestLockContentionTimesOut(t *testing.T) {
	k := testKey(t)
	dir := t.TempDir()
	s := Open(dir)
	release, err := s.lock(time.Second)
	if err != nil {
		t.Fatal(err)
	}
	defer release()

	other := Open(dir)
	start := time.Now()
	_, err = other.Append(AppendOptions{
		Trusted: trust(k), Root: cleanRootFixture(), LockTimeout: 150 * time.Millisecond,
	}, func(head *Record) (Record, error) {
		t.Fatal("the builder ran while another holder had the lock")
		return Record{}, nil
	})
	if !errors.Is(err, ErrBusy) {
		t.Fatalf("want ErrBusy, got %v", err)
	}
	if time.Since(start) > 5*time.Second {
		t.Fatal("the lock wait was not bounded")
	}
}

// -- offline root ------------------------------------------------------------

// INV-5: no writes under --offline-root.
func TestAppendRefusesToWriteInsideTheExaminedTree(t *testing.T) {
	k := testKey(t)
	root := t.TempDir()
	s := Open(filepath.Join(root, "var", "lib", "aurvet", "chain"))
	_, err := s.Append(AppendOptions{Trusted: trust(k), Root: root, OfflineRoot: root},
		func(head *Record) (Record, error) {
			t.Fatal("the builder ran despite an INV-5 refusal")
			return Record{}, nil
		})
	if !errors.Is(err, ErrOfflineRoot) {
		t.Fatalf("want ErrOfflineRoot, got %v", err)
	}
}

// -- helpers -----------------------------------------------------------------

func cleanRootFixture() string {
	return filepath.Join("..", "..", "testdata", "chain", "root-clean")
}

func mustAppend(t *testing.T, s *Store, opt AppendOptions, payload string) Record {
	t.Helper()
	rec, err := s.Append(opt, func(head *Record) (Record, error) {
		return NewRecord(testKey(t), Link(head, Entry{
			Schema: Schema, Time: "2026-08-05T12:00:00+0200", Kind: KindAppend,
			Host: "reference", Payload: payloadFor(payload),
		}))
	})
	if err != nil {
		t.Fatalf("append %q: %v", payload, err)
	}
	return rec
}

func liveishInput() baseline.ManifestInput {
	return baseline.ManifestInput{
		Host: "reference", Root: "/", CreatedAt: "2026-08-05T12:00:00+0200", Tier: "full",
		Packages: []baseline.PackageInput{
			{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)},
		},
		Log: baseline.LogInput{Earliest: "2025-11-11T00:50:40+0000", Latest: "2026-08-05T11:00:00+0200"},
	}
}
