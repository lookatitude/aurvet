// cmd/aurvet/baseline_test.go
//
// The `baseline` subcommand end to end. Every refusal is proved through the
// command, separately, and the two prominence claims -- the unpushed banner in
// NORMAL scan output, and truncation caught by the recorded push -- are proved
// against real files on disk.
package main

import (
	"bytes"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/chain"
	"github.com/lookatitude/aurvet/internal/finding"
)

const (
	testKeyPath = "../../testdata/baseline/testkey"
	testPubPath = "../../testdata/baseline/testkey.pub"
	cleanRoot   = "../../testdata/chain/root-clean"
	lockedRoot  = "../../testdata/chain/root-locked"
)

func rootEuid() *int { z := 0; return &z }

func baselineNow(t *testing.T) time.Time {
	t.Helper()
	v, err := time.Parse(time.RFC3339, "2026-08-06T09:00:00+02:00")
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// stateWithTrust is a state directory that trusts the committed throwaway test
// key. No key is generated anywhere in this file.
func stateWithTrust(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	pub, err := os.ReadFile(testPubPath)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, trustedKeysFile), pub, 0o600); err != nil {
		t.Fatal(err)
	}
	return dir
}

// fakeEvidence is a scan result the bootstrap would ACCEPT: full tier, no
// criticals, and one gap that is declared recordable.
func fakeEvidence(t *testing.T) scanEvidence {
	t.Helper()
	return scanEvidence{
		Tier: "full",
		Result: finding.Result{Gaps: []finding.Gap{{
			RuleID: "aur-provenance", Subject: "pkg:evil", Reason: "no snapshot exists",
		}}},
		Packages: []baseline.PackageInput{
			{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64), MtreeBytes: 10},
			{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64), MtreeBytes: 20},
		},
		Observed: []baseline.ObservedPackage{
			{Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64)},
			{Name: "openssl", Version: "3.4.0-1", MtreeSHA256: strings.Repeat("b", 64)},
		},
		Log: baseline.LogInput{
			Earliest: "2025-11-11T00:50:40+0000", Latest: "2026-08-06T08:00:00+0200",
		},
		LogObs: baseline.LogObservation{
			Earliest: mustParse(t, "2025-11-11T00:50:40+0000"),
			Latest:   mustParse(t, "2026-08-06T08:00:00+0200"),
		},
	}
}

func mustParse(t *testing.T, s string) time.Time {
	t.Helper()
	v, err := baseline.ParseStamp(s)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// initOpts is the invocation that WOULD be allowed. Each refusal test breaks
// exactly one thing about it, so the assertion is about that one thing.
func initOpts(t *testing.T, state string, ev scanEvidence) baselineOpts {
	t.Helper()
	return baselineOpts{
		offlineRoot: cleanRoot,
		keyPath:     testKeyPath,
		args:        []string{"init"},
		stateDir:    state,
		now:         baselineNow(t),
		euid:        rootEuid(),
		scan:        func(baselineEnv) (scanEvidence, error) { return ev, nil },
	}
}

// -- the permitted path, first, because every refusal test depends on it -------

func TestInitWritesABaselineWhenNothingRefuses(t *testing.T) {
	state := stateWithTrust(t)
	var out, errb bytes.Buffer
	code := runBaseline(initOpts(t, state, fakeEvidence(t)), &out, &errb)
	if code != exitClean {
		t.Fatalf("init = %d, want %d\nstdout: %s\nstderr: %s", code, exitClean, out.String(), errb.String())
	}
	if !strings.Contains(out.String(), "baseline written") {
		t.Fatalf("stdout does not report the write:\n%s", out.String())
	}
	// The entry just written is unpushed by construction, and the banner must say so
	// immediately rather than waiting for the next run.
	if !strings.Contains(out.String(), "NOT pushed") {
		t.Fatalf("init did not report the new entry as unpushed:\n%s", out.String())
	}

	// And it is a real, verifiable chain on disk.
	store := chain.Open(filepath.Join(state, chainSubdir))
	trusted := trustFromFile(t, state)
	recs, err := store.Load(trusted)
	if err != nil || len(recs) != 1 {
		t.Fatalf("chain did not load: %v (%d records)", err, len(recs))
	}
	if _, err := chain.Verify(recs, chain.VerifyOptions{Trusted: trusted}); err != nil {
		t.Fatalf("the written chain does not verify: %v", err)
	}
	pay, err := store.LoadPayload(recs[0].Entry.Payload.SHA256, baseline.NamespaceManifest, trusted)
	if err != nil || pay.State != chain.PayloadPresent {
		t.Fatalf("the manifest the chain commits to is not present: %v %s", err, pay.Reason)
	}

	// A second init refuses: init writes the first entry only.
	var out2, err2 bytes.Buffer
	if code := runBaseline(initOpts(t, state, fakeEvidence(t)), &out2, &err2); code != exitUsage {
		t.Fatalf("second init = %d, want %d: %s", code, exitUsage, err2.String())
	}
}

// -- refusal 1: unresolved criticals, and the adjudication that clears one -----

func TestInitRefusesAnUnresolvedCriticalAndAcceptsAnAdjudicatedOne(t *testing.T) {
	crit := finding.Finding{
		RuleID: "integrity-digest-mismatch", SubjectKind: "package", Subject: "sudo",
		Severity: finding.SevCritical,
		Summary:  "a packaged file's digest does not match the mtree",
		Evidence: []string{"recorded aaa, observed bbb"},
		Limits:   "may be a legitimate local edit",
	}
	ev := fakeEvidence(t)
	ev.Result.Findings = append(ev.Result.Findings, crit)

	state := stateWithTrust(t)
	var out, errb bytes.Buffer
	code := runBaseline(initOpts(t, state, ev), &out, &errb)
	if code != exitFindings {
		t.Fatalf("init = %d, want %d (findings, not incomplete)\n%s", code, exitFindings, errb.String())
	}
	msg := errb.String()
	for _, want := range []string{"unresolved-criticals", "sudo", "integrity-digest-mismatch", "adjudicate"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not mention %q:\n%s", want, msg)
		}
	}
	if _, err := os.Stat(filepath.Join(state, chainSubdir, chain.ChainFile)); !os.IsNotExist(err) {
		t.Fatal("a refused init still wrote a chain")
	}

	// Now adjudicate it, with a signed store, and init proceeds.
	writeAdjudications(t, state, crit)
	var out2, err2 bytes.Buffer
	if code := runBaseline(initOpts(t, state, ev), &out2, &err2); code != exitClean {
		t.Fatalf("init after adjudication = %d, want %d\nstdout: %s\nstderr: %s",
			code, exitClean, out2.String(), err2.String())
	}

	// The reason is inside the SIGNED manifest, not merely in a log line.
	trusted := trustFromFile(t, state)
	store := chain.Open(filepath.Join(state, chainSubdir))
	recs, err := store.Load(trusted)
	if err != nil || len(recs) != 1 {
		t.Fatalf("chain: %v", err)
	}
	pay, err := store.LoadPayload(recs[0].Entry.Payload.SHA256, baseline.NamespaceManifest, trusted)
	if err != nil || pay.State != chain.PayloadPresent {
		t.Fatalf("payload: %v %s", err, pay.Reason)
	}
	if !bytes.Contains(pay.Raw, []byte("verified by hand against upstream")) {
		t.Fatalf("the adjudication reason is not inside the signed manifest:\n%s", pay.Raw)
	}
}

// -- refusal 2: unprivileged --------------------------------------------------

func TestInitRefusesUnprivileged(t *testing.T) {
	state := stateWithTrust(t)
	opts := initOpts(t, state, fakeEvidence(t))
	opts.euid = nil // the real euid: this suite does not run as root
	if os.Geteuid() == 0 {
		t.Skip("running as root: the unprivileged refusal cannot be exercised")
	}
	var out, errb bytes.Buffer
	code := runBaseline(opts, &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("init = %d, want %d\n%s", code, exitIncomplete, errb.String())
	}
	if !strings.Contains(errb.String(), "unprivileged") || !strings.Contains(errb.String(), "sudo") {
		t.Fatalf("the refusal does not name the problem or the remedy:\n%s", errb.String())
	}
}

// -- refusal 3: the tier -------------------------------------------------------

func TestInitRefusesATriageTierScan(t *testing.T) {
	ev := fakeEvidence(t)
	ev.Tier = "triage"
	state := stateWithTrust(t)
	var out, errb bytes.Buffer
	code := runBaseline(initOpts(t, state, ev), &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("init = %d, want %d\n%s", code, exitIncomplete, errb.String())
	}
	if !strings.Contains(errb.String(), "insufficient-tier") || !strings.Contains(errb.String(), "triage") {
		t.Fatalf("the refusal does not name the tier:\n%s", errb.String())
	}
}

// -- refusal 4: coverage that matters ------------------------------------------

func TestInitRefusesABlockingCoverageGap(t *testing.T) {
	ev := fakeEvidence(t)
	ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
		RuleID: "integrity-coverage", Subject: "pkg:linux", Reason: "the mtree could not be read",
	})
	state := stateWithTrust(t)
	var out, errb bytes.Buffer
	code := runBaseline(initOpts(t, state, ev), &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("init = %d, want %d\n%s", code, exitIncomplete, errb.String())
	}
	if !strings.Contains(errb.String(), "coverage-incomplete") ||
		!strings.Contains(errb.String(), "integrity-coverage") {
		t.Fatalf("the refusal does not name the gap:\n%s", errb.String())
	}
}

// db.lck: scan warns, init REFUSES.
func TestInitRefusesWhileAPacmanTransactionIsInFlight(t *testing.T) {
	state := stateWithTrust(t)
	opts := initOpts(t, state, fakeEvidence(t))
	opts.offlineRoot = lockedRoot
	var out, errb bytes.Buffer
	code := runBaseline(opts, &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("init = %d, want %d\n%s", code, exitIncomplete, errb.String())
	}
	if !strings.Contains(errb.String(), "db.lck") {
		t.Fatalf("the refusal does not name the lock:\n%s", errb.String())
	}
}

// An untrusted signing key is refused BEFORE anything is scanned or signed: a
// baseline signed by a key this host does not trust would not verify on the next
// run, which reads as an absent baseline.
func TestInitRefusesASigningKeyThatIsNotTrusted(t *testing.T) {
	state := t.TempDir() // no trusted-keys file
	var out, errb bytes.Buffer
	code := runBaseline(initOpts(t, state, fakeEvidence(t)), &out, &errb)
	if code != exitUsage {
		t.Fatalf("init = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), "trusted-keys") || !strings.Contains(errb.String(), "SHA256:") {
		t.Fatalf("the refusal does not name the file or print the fingerprint to check:\n%s", errb.String())
	}
}

func TestInitRefusesWithNoSigningKeyAtAllAndNeverOffersToMakeOne(t *testing.T) {
	state := stateWithTrust(t)
	opts := initOpts(t, state, fakeEvidence(t))
	opts.keyPath = ""
	var out, errb bytes.Buffer
	if code := runBaseline(opts, &out, &errb); code != exitUsage {
		t.Fatalf("init = %d, want %d", code, exitUsage)
	}
	msg := errb.String()
	if !strings.Contains(msg, "ssh-keygen") {
		t.Fatalf("the error does not tell the operator how to make a key themselves:\n%s", msg)
	}
	if !strings.Contains(msg, "does not generate keys") {
		t.Fatalf("the error does not say that aurvet generates no keys:\n%s", msg)
	}
}

// -- task 6 through the command ------------------------------------------------

// The prominence claim, asserted where it matters: NORMAL `scan` output, no flag.
func TestScanReportsUnpushedEntriesInNormalOutput(t *testing.T) {
	root := evilRoot(t)
	state := stateWithTrust(t)
	writeChain(t, state, 2)

	var out, errb bytes.Buffer
	runScan(sinceLastOpts(root, state, false, aur.Fake{
		Known: map[string]aur.Pkg{}, Tombstones: map[string]string{},
	}), &out, &errb)

	got := out.String()
	if !strings.Contains(got, "NOT pushed") {
		t.Fatalf("normal scan output does not report the unpushed tail:\n%s", got)
	}
	if !strings.Contains(got, "truncation") {
		t.Fatalf("the banner does not say what the unpushed tail costs:\n%s", got)
	}
	// Prominent means FIRST: before the header, before any finding.
	head := strings.SplitN(got, "\n", 2)[0]
	if !strings.HasPrefix(head, "!! CHAIN:") {
		t.Fatalf("the banner is not the first thing printed; it read %q", head)
	}
}

// And the attack the recorded push exists to catch: truncate the chain, and
// `baseline verify` must refuse rather than report a chain that still verifies.
func TestVerifyDetectsTruncationOnlyBecauseOfTheRecordedPush(t *testing.T) {
	state := stateWithTrust(t)
	writeChain(t, state, 3)
	opts := baselineOpts{
		keyPath: testKeyPath, stateDir: state, now: baselineNow(t), euid: rootEuid(),
		offlineRoot: cleanRoot, remote: "git@example.invalid:ops/chain.git#refs/heads/main",
		protectedRemote: true, args: []string{"pushed"},
	}
	var out, errb bytes.Buffer
	if code := runBaseline(opts, &out, &errb); code != exitClean {
		t.Fatalf("pushed = %d: %s", code, errb.String())
	}

	// Before truncation: verifies, and truncation was actually checked.
	verify := opts
	verify.args = []string{"verify"}
	var vout, verr bytes.Buffer
	if code := runBaseline(verify, &vout, &verr); code != exitClean {
		t.Fatalf("verify = %d, want %d\nstdout: %s\nstderr: %s", code, exitClean, vout.String(), verr.String())
	}
	if !strings.Contains(vout.String(), "truncation checked against an anchor: true") {
		t.Fatalf("verify did not use the recorded push as an anchor:\n%s", vout.String())
	}

	// Truncate: drop the last record. The remaining chain is internally perfect.
	path := filepath.Join(state, chainSubdir, chain.ChainFile)
	b, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	lines := strings.Split(strings.TrimSuffix(string(b), "\n"), "\n")
	if err := os.WriteFile(path, []byte(strings.Join(lines[:len(lines)-1], "\n")+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}

	var tout, terr bytes.Buffer
	if code := runBaseline(verify, &tout, &terr); code != exitIncomplete {
		t.Fatalf("verify after truncation = %d, want %d\nstdout: %s\nstderr: %s",
			code, exitIncomplete, tout.String(), terr.String())
	}
	if !strings.Contains(terr.String(), "missing from the end") {
		t.Fatalf("verify did not name the truncation:\n%s", terr.String())
	}
}

// A replication state signed by a key the host does not trust reads as absent, so
// everything reads as unpushed. Loud, never silently "all pushed".
func TestAnUntrustedReplicationStateLeavesEverythingUnpushed(t *testing.T) {
	state := stateWithTrust(t)
	writeChain(t, state, 2)
	opts := baselineOpts{
		keyPath: testKeyPath, stateDir: state, now: baselineNow(t), euid: rootEuid(),
		offlineRoot: cleanRoot, remote: "git@example.invalid:r.git#refs/heads/main",
		args: []string{"pushed"},
	}
	if code := runBaseline(opts, &bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("pushed failed")
	}
	// Replace the trust set with a different key: the state no longer authenticates.
	other := stateWithTrust(t)
	_ = other
	if err := os.WriteFile(filepath.Join(state, trustedKeysFile), []byte(
		"ssh-ed25519 AAAAC3NzaC1lZDI1NTE5AAAAIAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA nobody\n"),
		0o600); err != nil {
		t.Fatal(err)
	}
	status := opts
	status.args = []string{"status"}
	var out, errb bytes.Buffer
	runBaseline(status, &out, &errb)
	combined := out.String() + errb.String()
	if !strings.Contains(combined, "NOT pushed") && !strings.Contains(combined, "does not verify") {
		t.Fatalf("a chain under an unknown key was not reported as unverifiable or unpushed:\n%s", combined)
	}
}

// -- task 11 through the command ------------------------------------------------

func TestDiffReportsUnexplainedDriftAsCritical(t *testing.T) {
	state := stateWithTrust(t)
	if code := runBaseline(initOpts(t, state, fakeEvidence(t)), &bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("init failed")
	}
	drifted := fakeEvidence(t)
	drifted.Observed[0].MtreeSHA256 = strings.Repeat("c", 64)

	opts := initOpts(t, state, drifted)
	opts.args = []string{"diff"}
	var out, errb bytes.Buffer
	// exit 3, not 1: the evidence also carries a coverage gap, and INV-3 puts
	// "could not cover" above "found something". The critical is still listed.
	code := runBaseline(opts, &out, &errb)
	if code != exitIncomplete {
		t.Fatalf("diff = %d, want %d\nstdout: %s\nstderr: %s", code, exitIncomplete, out.String(), errb.String())
	}
	got := out.String()
	for _, want := range []string{"1 unexplained", "[critical]", "zlib"} {
		if !strings.Contains(got, want) {
			t.Fatalf("diff output does not contain %q:\n%s", want, got)
		}
	}
}

func TestDiffWithoutABaselineIsIncompleteAndNotClean(t *testing.T) {
	state := stateWithTrust(t)
	opts := initOpts(t, state, fakeEvidence(t))
	opts.args = []string{"diff"}
	var out, errb bytes.Buffer
	if code := runBaseline(opts, &out, &errb); code != exitIncomplete {
		t.Fatalf("diff with no baseline = %d, want %d", code, exitIncomplete)
	}
	if !strings.Contains(errb.String(), "not the same as no drift") {
		t.Fatalf("the message lets an absent baseline read as no drift:\n%s", errb.String())
	}
}

// -- helpers -------------------------------------------------------------------

func trustFromFile(t *testing.T, state string) []*baseline.PublicKey {
	t.Helper()
	keys, reason := loadTrustedKeys(state)
	if len(keys) == 0 {
		t.Fatalf("no trusted keys in %s: %s", state, reason)
	}
	return keys
}

func testSigningKey(t *testing.T) *baseline.PrivateKey {
	t.Helper()
	pem, err := os.ReadFile(testKeyPath)
	if err != nil {
		t.Fatal(err)
	}
	k, err := baseline.ParsePrivateKey(pem)
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// writeChain puts n genuinely signed, correctly linked entries in the store.
func writeChain(t *testing.T, state string, n int) {
	t.Helper()
	k := testSigningKey(t)
	store := chain.Open(filepath.Join(state, chainSubdir))
	trusted := trustFromFile(t, state)
	for i := 0; i < n; i++ {
		payload := []byte(strings.Repeat("m", i+1))
		raw, sig, err := baseline.SignManifest(k, manifestFor(t, i))
		if err != nil {
			t.Fatal(err)
		}
		digest, err := store.PutPayload(baseline.NamespaceManifest, raw, sig)
		if err != nil {
			t.Fatal(err)
		}
		kind := chain.KindAppend
		if i == 0 {
			kind = chain.KindBaseline
		}
		_, err = store.Append(chain.AppendOptions{Trusted: trusted, Root: cleanRoot},
			func(head *chain.Record) (chain.Record, error) {
				return chain.NewRecord(k, chain.Link(head, chain.Entry{
					Schema: chain.Schema,
					Time:   baselineNow(t).Add(time.Duration(i) * time.Minute).Format(baselineStamp),
					Kind:   kind, Host: "test",
					Payload: chain.Payload{
						Kind: chain.PayloadManifest, Namespace: string(baseline.NamespaceManifest),
						SHA256: digest, Bytes: int64(len(raw)), KeyFingerprint: k.PublicKey().Fingerprint(),
					},
				}))
			})
		if err != nil {
			t.Fatalf("append %d: %v", i, err)
		}
		_ = payload
	}
}

func manifestFor(t *testing.T, i int) baseline.Manifest {
	t.Helper()
	m, err := baseline.BuildManifest(baseline.ManifestInput{
		Host: "test", Root: "/",
		CreatedAt: baselineNow(t).Add(time.Duration(i) * time.Minute).Format(baselineStamp),
		Tier:      "full",
		Packages: []baseline.PackageInput{{
			Name: "zlib", Version: "1.3.1-2", MtreeSHA256: strings.Repeat("a", 64),
		}},
		Log: baseline.LogInput{Earliest: "2025-11-11T00:50:40+0000"},
		Gaps: []baseline.Gap{{
			RuleID: "note", Subject: "n", Reason: "entry " + strings.Repeat("x", i+1),
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return m
}

// writeAdjudications signs a real adjudication store covering one finding. The
// record is built by adjudicate.New, so the epoch binding and the reason rules are
// the production ones and not a hand-written JSON blob.
func writeAdjudications(t *testing.T, state string, f finding.Finding) {
	t.Helper()
	rec, err := adjudicate.New(adjudicate.BuiltIn(), adjudicate.Request{
		Finding: f,
		Scope:   adjudicate.ScopeSubject,
		Reason:  "local %BACKUP% file edited by the administrator; verified by hand against upstream",
		By:      "test",
		Now:     baselineNow(t).Add(-time.Hour),
	})
	if err != nil {
		t.Fatal(err)
	}
	raw, err := adjudicate.MarshalStore([]adjudicate.Record{rec})
	if err != nil {
		t.Fatal(err)
	}
	sig, err := adjudicate.SignStore(testSigningKey(t), raw)
	if err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(state, adjudicationsFile)
	if err := os.WriteFile(path, raw, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path+".sig", sig, 0o600); err != nil {
		t.Fatal(err)
	}
}

// -- the live machine, behind an env gate --------------------------------------

// TestLiveBaselineInitRefuses runs `baseline init` against THIS system with the
// real scan wired in (no scan seam): 1,400-odd packages, their mtree digests, the
// real pacman.log. It asserts a REFUSAL, because that is the correct answer on an
// unprivileged run of a build with no full-scan pipeline -- and because an init
// that succeeded here would mean one of the refusals had stopped working.
//
// Gated: it reads the whole local package database, which is not something an
// ordinary `go test` should do. AURVET_LIVE_BASELINE=1 to run it.
func TestLiveBaselineInitRefuses(t *testing.T) {
	if os.Getenv("AURVET_LIVE_BASELINE") == "" {
		t.Skip("set AURVET_LIVE_BASELINE=1 to run baseline init against this machine")
	}
	state := stateWithTrust(t)
	var out, errb bytes.Buffer
	code := runBaseline(baselineOpts{
		keyPath:  testKeyPath,
		args:     []string{"init"},
		stateDir: state,
		now:      time.Now(),
	}, &out, &errb)
	t.Logf("exit=%d\nstdout:\n%s\nstderr:\n%s", code, out.String(), errb.String())
	if code == exitClean {
		t.Fatal("baseline init succeeded on an unprivileged run of a build with no full-scan " +
			"pipeline; one of the refusals is not working")
	}
	if _, err := os.Stat(filepath.Join(state, chainSubdir, chain.ChainFile)); !os.IsNotExist(err) {
		t.Fatal("a refused init wrote a chain anyway")
	}
}

// -- append --------------------------------------------------------------------

// append is init's refusals applied to a later entry, plus the db.lck refusal
// task 12 names by command. Both directions are asserted: append onto nothing is a
// refusal, and append during a transaction is a refusal.
func TestAppendExtendsTheChainAndRefusesTheSameThingsAsInit(t *testing.T) {
	state := stateWithTrust(t)
	appendOpts := func(ev scanEvidence) baselineOpts {
		o := initOpts(t, state, ev)
		o.args = []string{"append"}
		o.now = baselineNow(t).Add(time.Hour)
		return o
	}

	// Nothing to append to: a refusal, never a silently created chain.
	var out0, err0 bytes.Buffer
	if code := runBaseline(appendOpts(fakeEvidence(t)), &out0, &err0); code != exitUsage {
		t.Fatalf("append with no chain = %d, want %d", code, exitUsage)
	}
	if !strings.Contains(err0.String(), "indistinguishable from a fresh one") {
		t.Fatalf("the refusal lets a lost chain read as a new one:\n%s", err0.String())
	}

	if code := runBaseline(initOpts(t, state, fakeEvidence(t)), &bytes.Buffer{}, &bytes.Buffer{}); code != exitClean {
		t.Fatal("init failed")
	}

	// db.lck present: append REFUSES, which is the asymmetry against scan's warning.
	locked := appendOpts(fakeEvidence(t))
	locked.offlineRoot = lockedRoot
	var lout, lerr bytes.Buffer
	if code := runBaseline(locked, &lout, &lerr); code != exitIncomplete {
		t.Fatalf("append during a transaction = %d, want %d\n%s", code, exitIncomplete, lerr.String())
	}
	if !strings.Contains(lerr.String(), "db.lck") {
		t.Fatalf("the refusal does not name the lock:\n%s", lerr.String())
	}

	// And the clean case extends the chain to two linked entries.
	second := fakeEvidence(t)
	second.Packages = append(second.Packages, baseline.PackageInput{
		Name: "curl", Version: "8.11.0-1", MtreeSHA256: strings.Repeat("e", 64),
	})
	var out, errb bytes.Buffer
	if code := runBaseline(appendOpts(second), &out, &errb); code != exitClean {
		t.Fatalf("append = %d, want %d\nstdout: %s\nstderr: %s", code, exitClean, out.String(), errb.String())
	}
	trusted := trustFromFile(t, state)
	recs, err := chain.Open(filepath.Join(state, chainSubdir)).Load(trusted)
	if err != nil || len(recs) != 2 {
		t.Fatalf("chain is %d entries: %v", len(recs), err)
	}
	if recs[1].Entry.Kind != chain.KindAppend || recs[1].Entry.PrevHash != recs[0].Hash() {
		t.Fatalf("the second entry does not link to the first: %+v", recs[1].Entry)
	}
	if _, err := chain.Verify(recs, chain.VerifyOptions{Trusted: trusted}); err != nil {
		t.Fatalf("the extended chain does not verify: %v", err)
	}
}
