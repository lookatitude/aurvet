// cmd/aurvet/baseline.go
//
// The `baseline` subcommand: init, status, verify, pushed, diff.
//
// # What is wired here and what is not
//
// `baseline init` must stand on a FULL scan (P4 task 7), and this build has no
// full-scan pipeline in cmd: internal/check's integrity verification is not called
// from any command, so the deepest scan `aurvet` currently performs is the
// provenance sweep, which reads no file contents. That is reported as tier "meta",
// which the bootstrap refusal then rejects -- correctly, and on every machine.
//
// This is deliberate and is the honest state of the tree, not a stub: the tier is
// DERIVED from what the code actually did, and there is no flag to assert a
// different one. A `--tier full` that only relabelled a metadata scan would be a
// way to sign a baseline over unverified contents, which is the exact failure the
// refusal exists to prevent. The seam is baselineOpts.scan, which tests use to
// exercise the permitted path hermetically.
//
// # No key is ever generated here
//
// A signing key is a human artefact: `ssh-keygen -t ed25519` (or
// `-t ed25519-sk` for a FIDO2 token), with the private half held offline or in an
// agent. This command reads a key or talks to ssh-agent and never creates one.
package main

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/chain"
	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/pacmanlog"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/snapshot"
)

// Layout inside the state directory.
const (
	// chainSubdir holds the chain, its payloads and the replication state.
	chainSubdir = "chain"

	// trustedKeysFile is an authorized_keys-format list of the public keys whose
	// signatures count. An empty or missing file is a refusal, never a pass:
	// "no keys configured" must not mean "any key will do".
	trustedKeysFile = "trusted-keys"

	// adjudicationsFile and its detached signature hold the signed adjudication
	// store (P4 task 9).
	adjudicationsFile = "adjudications.json"
)

// baselineStamp is the timestamp layout written into signed documents: RFC3339
// with an explicit offset, the same spelling pacman.log uses.
const baselineStamp = "2006-01-02T15:04:05-0700"

type baselineOpts struct {
	offlineRoot string
	noNet       bool
	jsonOut     bool

	// keyPath is an OpenSSH private key file; signerFP names a key held by
	// ssh-agent (which is also the only route to a FIDO2 token).
	keyPath  string
	signerFP string

	// remote and protectedRemote are `baseline pushed`.
	remote          string
	protectedRemote bool

	args []string

	// Seams. Their zero values select production behaviour, so run() constructs
	// one from flags alone and never mentions them.
	//
	// euid is a pointer rather than an int because 0 is a meaningful value: nil
	// means "ask the kernel". It exists so the PERMITTED path can be exercised
	// hermetically -- the test suite does not run as root, and a bootstrap whose
	// success path is never executed is a bootstrap nobody has run.
	stateDir string
	now      time.Time
	scan     func(env baselineEnv) (scanEvidence, error)
	euid     *int
}

// baselineEnv is everything resolved once, before any subcommand runs.
type baselineEnv struct {
	cfg              config.Config
	euid             int
	stateDir         string
	stateDirWritable bool
	store            *chain.Store
	trusted          []*baseline.PublicKey
	trustReason      string
	offlineRoot      string
	noNet            bool
	now              time.Time
}

// scanEvidence is what a scan produced, in the shape the baseline needs. Tier is
// the tier the scan ACTUALLY ran at, never an assertion by the caller.
type scanEvidence struct {
	Tier       string
	Result     finding.Result
	Packages   []baseline.PackageInput
	Observed   []baseline.ObservedPackage
	Provenance []baseline.ProvenanceInput
	Surfaces   []baseline.SurfaceInput
	Log        baseline.LogInput
	LogObs     baseline.LogObservation
	Summary    report.Summary
}

func runBaseline(opts baselineOpts, stdout, stderr io.Writer) int {
	if len(opts.args) == 0 {
		baselineUsage(stderr)
		return exitUsage
	}
	env, err := resolveBaselineEnv(opts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	switch opts.args[0] {
	case "init":
		return baselineWrite(env, opts, true, stdout, stderr)
	case "append":
		return baselineWrite(env, opts, false, stdout, stderr)
	case "status":
		return baselineStatus(env, stdout, stderr)
	case "verify":
		return baselineVerify(env, stdout, stderr)
	case "pushed":
		return baselinePushed(env, opts, stdout, stderr)
	case "diff":
		return baselineDiff(env, opts, stdout, stderr)
	default:
		fmt.Fprintf(stderr, "aurvet: unknown baseline subcommand %q\n", opts.args[0])
		baselineUsage(stderr)
		return exitUsage
	}
}

func baselineUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aurvet baseline <init|status|verify|pushed|diff> [flags]")
	fmt.Fprintln(w, "  init    run a scan and, if nothing refuses, sign the first baseline")
	fmt.Fprintln(w, "  append  the same, for a later entry: it refuses on the same conditions, and")
	fmt.Fprintln(w, "          additionally refuses while db.lck exists (a scan of a database")
	fmt.Fprintln(w, "          mid-transaction would sign spurious findings into the chain)")
	fmt.Fprintln(w, "  status  the chain, the unpushed tail, and what was not checked")
	fmt.Fprintln(w, "  verify  verify the chain against the last confirmed push")
	fmt.Fprintln(w, "  pushed  record that the chain has been pushed (-remote, -protected-remote)")
	fmt.Fprintln(w, "  diff    classify drift against the signed baseline")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "signing: -key <openssh private key> or -signer <ssh-agent key fingerprint>")
	fmt.Fprintln(w, "  aurvet never generates a signing key: `ssh-keygen -t ed25519` (or -t ed25519-sk")
	fmt.Fprintln(w, "  for a FIDO2 token) is a human action, and the private half belongs offline")
}

func resolveBaselineEnv(opts baselineOpts) (baselineEnv, error) {
	euid := os.Geteuid()
	if opts.euid != nil {
		euid = *opts.euid
	}
	cfg, err := config.Resolve(opts.offlineRoot, euid)
	if err != nil {
		return baselineEnv{}, err
	}
	stateDir, writable := opts.stateDir, true
	if stateDir == "" {
		stateDir = cfg.StateDir
		for _, l := range cfg.Doctor() {
			if l.Key == "state_dir" && l.Source == config.SourceFallbackUnwritable {
				writable = false
			}
		}
	}
	now := opts.now
	if now.IsZero() {
		now = time.Now()
	}
	trusted, reason := loadTrustedKeys(stateDir)
	return baselineEnv{
		cfg:              cfg,
		euid:             euid,
		stateDir:         stateDir,
		stateDirWritable: writable,
		store:            chain.Open(filepath.Join(stateDir, chainSubdir)),
		trusted:          trusted,
		trustReason:      reason,
		offlineRoot:      opts.offlineRoot,
		noNet:            opts.noNet,
		now:              now,
	}, nil
}

// loadTrustedKeys reads the trust set. A missing or empty file yields no keys and
// a reason, never an error: the caller decides what to do, and every path that
// needs to verify something refuses without keys.
func loadTrustedKeys(stateDir string) ([]*baseline.PublicKey, string) {
	path := filepath.Join(stateDir, trustedKeysFile)
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return nil, fmt.Sprintf("%s does not exist, so no signature can be trusted", path)
	}
	if err != nil {
		return nil, fmt.Sprintf("%s could not be read: %v", path, err)
	}
	var keys []*baseline.PublicKey
	var bad []string
	for i, line := range strings.Split(string(b), "\n") {
		s := strings.TrimSpace(line)
		if s == "" || strings.HasPrefix(s, "#") {
			continue
		}
		k, err := baseline.ParsePublicKey([]byte(s))
		if err != nil {
			bad = append(bad, fmt.Sprintf("line %d: %v", i+1, err))
			continue
		}
		keys = append(keys, k)
	}
	switch {
	case len(keys) == 0 && len(bad) > 0:
		return nil, fmt.Sprintf("%s holds no usable key (%s)", path, strings.Join(bad, "; "))
	case len(keys) == 0:
		return nil, fmt.Sprintf("%s holds no key", path)
	case len(bad) > 0:
		return keys, fmt.Sprintf("%s: %d line(s) unusable: %s", path, len(bad), strings.Join(bad, "; "))
	}
	return keys, ""
}

// resolveSigner produces the Signer, and the closer for an agent connection.
//
// No branch here creates a key. The FIDO2 path is the agent path: a token-held
// sk-ssh-ed25519 key appears in ssh-agent like any other, which is how INV-7 is
// satisfied by hardware rather than by discipline.
func resolveSigner(opts baselineOpts) (baseline.Signer, func(), error) {
	switch {
	case opts.keyPath != "":
		pem, err := os.ReadFile(opts.keyPath)
		if err != nil {
			return nil, nil, fmt.Errorf("-key %s: %w", opts.keyPath, err)
		}
		k, err := baseline.ParsePrivateKey(pem)
		if err != nil {
			return nil, nil, fmt.Errorf("-key %s: %w (an encrypted key file is not supported; "+
				"load it into ssh-agent and use -signer instead)", opts.keyPath, err)
		}
		return k, func() {}, nil

	case opts.signerFP != "":
		sock := os.Getenv("SSH_AUTH_SOCK")
		if sock == "" {
			return nil, nil, errors.New("-signer names an ssh-agent key but SSH_AUTH_SOCK is not set")
		}
		ag, err := baseline.DialAgent(sock)
		if err != nil {
			return nil, nil, fmt.Errorf("ssh-agent: %w", err)
		}
		keys, err := ag.Keys()
		if err != nil {
			ag.Close()
			return nil, nil, fmt.Errorf("ssh-agent: %w", err)
		}
		for _, k := range keys {
			if k.Fingerprint() == opts.signerFP {
				return ag.Signer(k), func() { ag.Close() }, nil
			}
		}
		var have []string
		for _, k := range keys {
			have = append(have, k.Fingerprint())
		}
		ag.Close()
		return nil, nil, fmt.Errorf("ssh-agent holds no key with fingerprint %s (it holds: %s)",
			opts.signerFP, strings.Join(have, ", "))
	}
	return nil, nil, errors.New("no signing key: pass -key <openssh private key file> or " +
		"-signer <fingerprint of a key in ssh-agent>. aurvet does not generate keys: " +
		"`ssh-keygen -t ed25519 -f ~/.ssh/aurvet-baseline` (or -t ed25519-sk for a FIDO2 token)")
}

// -- init ---------------------------------------------------------------------

// baselineWrite is `init` (first == true) and `append` (first == false).
//
// One function, deliberately: every refusal that protects the first entry protects
// every later one, and two code paths would eventually disagree about which. The
// only differences are whether a chain must already exist and what the entry's kind
// and note say.
func baselineWrite(env baselineEnv, opts baselineOpts, first bool, stdout, stderr io.Writer) int {
	verb := "append"
	if first {
		verb = "init"
	}
	signer, closeSigner, err := resolveSigner(opts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer closeSigner()

	// The signing key must already be in the trust set. Adding it here would mean
	// whoever runs init chooses what this host trusts forever after, which is a
	// decision that belongs to a human with the key's fingerprint in front of them.
	if !trusts(env.trusted, signer.PublicKey()) {
		fmt.Fprintf(stderr, "aurvet: the signing key is not in %s, so a baseline signed with it "+
			"would not verify on the next run (%s)\n", filepath.Join(env.stateDir, trustedKeysFile),
			env.trustReason)
		fmt.Fprintf(stderr, "  add it deliberately, after checking the fingerprint (%s):\n",
			signer.PublicKey().Fingerprint())
		fmt.Fprintf(stderr, "    install -Dm600 /dev/stdin %s <<'EOF'\n    %s\n    EOF\n",
			filepath.Join(env.stateDir, trustedKeysFile), signer.PublicKey().AuthorizedKey())
		return exitUsage
	}

	existing, err := env.store.Load(env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	switch {
	case first && len(existing) > 0:
		fmt.Fprintf(stderr, "aurvet: a chain of %d entries already exists at %s; init writes the "+
			"first entry only. Use `aurvet baseline append` for later ones\n",
			len(existing), env.store.Path())
		return exitUsage
	case !first && len(existing) == 0:
		fmt.Fprintf(stderr, "aurvet: no chain at %s to append to; run `aurvet baseline init` first. "+
			"An append that silently created a chain would mean a lost chain is indistinguishable "+
			"from a fresh one\n", env.store.Path())
		return exitUsage
	}

	ev, err := runBaselineScan(env, opts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	lock, err := chain.DetectDBLock(env.cfg.Root)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	// Adjudications, applied at `now`, decide which criticals are unresolved.
	set := loadAdjudications(env)
	outcome := adjudicate.ApplyWith(adjudicate.BuiltIn(), set, ev.Result, env.now)

	var criticals []baseline.Critical
	for _, f := range outcome.Kept.Findings {
		if f.Severity == finding.SevCritical {
			criticals = append(criticals, baseline.Critical{
				RuleID: f.RuleID, SubjectKind: f.SubjectKind, Subject: f.Subject,
				Fingerprint: report.FindingID(f), Summary: f.Summary,
			})
		}
	}
	var adjudicated []baseline.AdjudicatedCritical
	for _, s := range outcome.Suppressed {
		if s.Finding.Severity != finding.SevCritical {
			continue
		}
		adjudicated = append(adjudicated, baseline.AdjudicatedCritical{
			Critical: baseline.Critical{
				RuleID: s.Finding.RuleID, SubjectKind: s.Finding.SubjectKind,
				Subject: s.Finding.Subject, Fingerprint: s.Record.Fingerprint,
				Summary: s.Finding.Summary,
			},
			Reason:           s.Record.Reason,
			Scope:            string(s.Record.Scope),
			ExpiresAt:        s.Record.ExpiresAt,
			FingerprintEpoch: s.Record.FingerprintEpoch,
		})
	}
	var critRules []string
	for _, c := range criticals {
		critRules = append(critRules, c.RuleID)
	}

	decision := baseline.Bootstrap(baseline.BootstrapInput{
		Euid:             env.euid,
		Tier:             ev.Tier,
		Host:             hostname(),
		Root:             env.cfg.Root,
		StateDir:         env.stateDir,
		StateDirWritable: env.stateDirWritable,
		Criticals:        criticals,
		Adjudicated:      adjudicated,
		UndeclaredRules:  adjudicate.BuiltIn().Undeclared(critRules),
		Gaps:             asBaselineGaps(outcome.Kept.Gaps),
		DBLocked:         lock.Present,
		DBLockPath:       lock.Path,
		Now:              env.now,
	})
	if !decision.Allowed {
		fmt.Fprintf(stderr, "aurvet: %v\n", decision.Err())
		// A refusal about coverage, privilege, tier or the lock is "could not do
		// what was asked" (exit 3). Unresolved criticals alone are findings (exit
		// 1). Where both apply, 3 outranks 1 per INV-3.
		code := exitFindings
		for _, r := range decision.Refusals {
			if r.Code != baseline.RefusalCriticals {
				code = exitIncomplete
			}
		}
		return code
	}

	m, err := baseline.BuildManifest(baseline.ManifestInput{
		Host: hostname(), Root: env.cfg.Root,
		CreatedAt:     env.now.Format(baselineStamp),
		Tier:          ev.Tier,
		Packages:      ev.Packages,
		Provenance:    ev.Provenance,
		Surfaces:      ev.Surfaces,
		Adjudications: decision.Adjudications,
		Log:           ev.Log,
		Gaps:          decision.RecordedGaps,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	raw, sig, err := baseline.SignManifest(signer, m)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	digest, err := env.store.PutPayload(baseline.NamespaceManifest, raw, sig)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	rec, err := env.store.Append(chain.AppendOptions{
		Trusted: env.trusted, Root: env.cfg.Root, OfflineRoot: env.offlineRoot,
	}, func(head *chain.Record) (chain.Record, error) {
		return chain.NewRecord(signer, chain.Link(head, chain.Entry{
			Schema: chain.Schema,
			Time:   env.now.Format(baselineStamp),
			Kind:   entryKind(first),
			Host:   hostname(),
			Payload: chain.Payload{
				Kind: chain.PayloadManifest, Namespace: string(baseline.NamespaceManifest),
				SHA256: digest, Bytes: int64(len(raw)),
				KeyFingerprint: signer.PublicKey().Fingerprint(),
			},
			Note: "baseline " + verb,
		}))
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	fmt.Fprintf(stdout, "baseline written (%s): %d package(s), tier %s, manifest %s\n", verb,
		len(m.Packages), m.Tier, short12(digest))
	fmt.Fprintf(stdout, "chain entry seq %d, hash %s, signed by %s\n",
		rec.Entry.Seq, short12(rec.Hash()), signer.PublicKey().Fingerprint())
	for _, n := range decision.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	for _, g := range decision.RecordedGaps {
		fmt.Fprintf(stdout, "  recorded gap: %s %s: %s\n", g.RuleID, g.Subject, g.Reason)
	}
	// The banner immediately: the entry just written is unpushed by construction,
	// and until it is pushed nothing detects its removal.
	writeReplicationBanner(stdout, replicationStatusFor(env))
	return exitClean
}

func entryKind(first bool) string {
	if first {
		return chain.KindBaseline
	}
	return chain.KindAppend
}

// -- status and verify --------------------------------------------------------

func baselineStatus(env baselineEnv, stdout, stderr io.Writer) int {
	records, err := env.store.Load(env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if len(records) == 0 {
		fmt.Fprintf(stdout, "no chain at %s\n", env.store.Path())
		if env.trustReason != "" {
			fmt.Fprintf(stdout, "trust: %s\n", env.trustReason)
		}
		fmt.Fprintln(stdout, "run `aurvet baseline init` to make one")
		return exitClean
	}
	st := replicationStatusFor(env)
	writeReplicationBanner(stdout, st)

	rep, verr := chain.Verify(records, chain.VerifyOptions{Trusted: env.trusted, Anchor: st.AnchorOption()})
	fmt.Fprintf(stdout, "chain: %d entries, head %s, %d of them pushed\n",
		rep.Length, short12(rep.Head), st.PushedLength)
	if verr != nil {
		fmt.Fprintf(stderr, "aurvet: the chain does not verify: %v\n", verr)
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	fmt.Fprintf(stdout, "  signed by: %s\n", strings.Join(rep.SignerFingerprints, ", "))
	fmt.Fprintf(stdout, "  limits: %s\n", chain.LimitsText)

	res := st.Result()
	for _, f := range res.Findings {
		fmt.Fprintf(stdout, "\n[%s] %s: %s\n", f.Severity, f.Subject, f.Summary)
		for _, e := range f.Evidence {
			fmt.Fprintf(stdout, "    evidence: %s\n", e)
		}
		fmt.Fprintf(stdout, "    limits:   %s\n", f.Limits)
	}
	for _, g := range res.Gaps {
		fmt.Fprintf(stdout, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason)
	}
	if verr != nil {
		return exitIncomplete
	}
	return report.ExitCode(res, finding.SevSuspicious)
}

func baselineVerify(env baselineEnv, stdout, stderr io.Writer) int {
	records, err := env.store.Load(env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if len(records) == 0 {
		fmt.Fprintf(stderr, "aurvet: no chain at %s; there is nothing to verify, which is not the "+
			"same as a chain that verified\n", env.store.Path())
		return exitIncomplete
	}
	st := replicationStatusFor(env)
	rep, verr := chain.Verify(records, chain.VerifyOptions{Trusted: env.trusted, Anchor: st.AnchorOption()})
	if verr != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", verr)
		writeReplicationBanner(stderr, st)
		return exitIncomplete
	}
	fmt.Fprintf(stdout, "chain verified: %d entries, head %s\n", rep.Length, short12(rep.Head))
	fmt.Fprintf(stdout, "truncation checked against an anchor: %v\n", rep.TruncationChecked)
	writeReplicationBanner(stdout, st)
	fmt.Fprintf(stdout, "limits: %s\n", chain.LimitsText)
	if !rep.TruncationChecked {
		return exitIncomplete
	}
	return report.ExitCode(st.Result(), finding.SevSuspicious)
}

// -- pushed -------------------------------------------------------------------

func baselinePushed(env baselineEnv, opts baselineOpts, stdout, stderr io.Writer) int {
	if strings.TrimSpace(opts.remote) == "" {
		fmt.Fprintln(stderr, "usage: aurvet baseline pushed -remote <url#ref> [-protected-remote] "+
			"-key <file>|-signer <fingerprint>")
		fmt.Fprintln(stderr, "  records that the chain has been pushed. It does NOT push: aurvet runs "+
			"no git and holds no credentials")
		return exitUsage
	}
	signer, closeSigner, err := resolveSigner(opts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	defer closeSigner()

	records, err := env.store.Load(env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if len(records) == 0 {
		fmt.Fprintf(stderr, "aurvet: no chain at %s to record a push for\n", env.store.Path())
		return exitUsage
	}
	if _, err := chain.Verify(records, chain.VerifyOptions{Trusted: env.trusted}); err != nil {
		fmt.Fprintf(stderr, "aurvet: refusing to record a push for a chain that does not verify: %v\n", err)
		return exitIncomplete
	}
	anchor := chain.HeadAnchor(records)
	rep, err := chain.BuildReplication(chain.ReplicationInput{
		Remote:          opts.remote,
		Length:          anchor.Length,
		Head:            anchor.Head,
		ConfirmedAt:     env.now.Format(baselineStamp),
		ProtectedRemote: opts.protectedRemote,
		Note:            "recorded by `aurvet baseline pushed`",
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	if err := env.store.PutReplication(signer, rep, env.offlineRoot); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	fmt.Fprintf(stdout, "recorded: %d entries pushed to %s, head %s\n",
		rep.Length, rep.Remote, short12(rep.Head))
	if !rep.ProtectedRemote {
		fmt.Fprintln(stdout, "WARNING: the remote is not recorded as protected. Force-push denial and "+
			"branch protection are what make this anchor mean anything -- pass -protected-remote only "+
			"once the remote actually refuses non-fast-forward updates and branch deletion.")
	}
	fmt.Fprintf(stdout, "limits: %s\n", chain.ReplicationLimitsText)
	return exitClean
}

// -- diff ---------------------------------------------------------------------

func baselineDiff(env baselineEnv, opts baselineOpts, stdout, stderr io.Writer) int {
	records, err := env.store.Load(env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if len(records) == 0 {
		fmt.Fprintf(stderr, "aurvet: no baseline at %s; there is nothing to diff against, which is "+
			"not the same as no drift\n", env.store.Path())
		return exitIncomplete
	}
	head := records[len(records)-1]
	payload, err := env.store.LoadPayload(head.Entry.Payload.SHA256, baseline.NamespaceManifest, env.trusted)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}
	if payload.State != chain.PayloadPresent {
		fmt.Fprintf(stderr, "aurvet: the baseline the chain commits to reads as ABSENT: %s\n", payload.Reason)
		return exitIncomplete
	}
	// LoadPayload has already authenticated these bytes against the trusted set and
	// checked that they hash to the digest the chain commits to. Only then are they
	// parsed (INV-2): nothing on this path decodes bytes whose signature has not
	// been verified first.
	m, err := manifestFromVerified(payload.Raw)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	ev, err := runBaselineScan(env, opts)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	set := loadAdjudications(env)
	var adjs []baseline.DriftAdjudication
	for _, r := range set.Records {
		if r.RuleID != baseline.DriftRule {
			continue
		}
		adjs = append(adjs, baseline.DriftAdjudication{
			RuleID: r.RuleID, Subject: r.Subject, Scope: string(r.Scope),
			Reason: r.Reason, ExpiresAt: r.ExpiresAt,
		})
	}

	rep, err := baseline.Drift(baseline.DriftInput{
		Manifest:      m,
		Observed:      ev.Observed,
		Log:           ev.LogObs,
		Adjudications: adjs,
		Now:           env.now,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitIncomplete
	}

	writeReplicationBanner(stdout, replicationStatusFor(env))
	fmt.Fprintf(stdout, "drift against baseline of %s: %d corroborated, %d adjudicated, "+
		"%d unexplained, %d log-coverage gap\n", m.CreatedAt,
		rep.Counts[baseline.BucketCorroborated], rep.Counts[baseline.BucketAdjudicated],
		rep.Counts[baseline.BucketUnexplained], rep.Counts[baseline.BucketLogCoverageGap])
	if rep.Truncated {
		fmt.Fprintln(stdout, "!! pacman.log has been TRUNCATED since the baseline was signed: it now "+
			"begins later than the baseline recorded")
	}
	for _, n := range rep.Notes {
		fmt.Fprintf(stdout, "  note: %s\n", n)
	}
	res := rep.Result
	res.Gaps = append(res.Gaps, ev.Result.Gaps...)
	for _, f := range res.Findings {
		fmt.Fprintf(stdout, "\n[%s] %s (%s): %s\n", f.Severity, f.Subject, f.RuleID, f.Summary)
		for _, e := range f.Evidence {
			fmt.Fprintf(stdout, "    evidence: %s\n", e)
		}
		fmt.Fprintf(stdout, "    limits:   %s\n", f.Limits)
	}
	for _, g := range res.Gaps {
		fmt.Fprintf(stdout, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason)
	}
	return report.ExitCode(res, finding.SevSuspicious)
}

// manifestFromVerified decodes bytes that LoadPayload has already authenticated.
// It exists so the diff path never parses unauthenticated bytes: the only way in
// is through a PayloadResult whose State is PayloadPresent.
func manifestFromVerified(raw []byte) (baseline.Manifest, error) {
	var m baseline.Manifest
	dec := json.NewDecoder(bytes.NewReader(raw))
	dec.DisallowUnknownFields()
	if err := dec.Decode(&m); err != nil {
		return baseline.Manifest{}, fmt.Errorf("the stored baseline does not parse: %w", err)
	}
	if dec.More() {
		return baseline.Manifest{}, errors.New("trailing data after the stored baseline")
	}
	again, err := baseline.Marshal(m)
	if err != nil {
		return baseline.Manifest{}, err
	}
	if string(again) != string(raw) {
		return baseline.Manifest{}, errors.New("the parsed baseline does not re-encode to the bytes " +
			"that were signed")
	}
	return m, nil
}

// -- the replication banner ---------------------------------------------------

// replicationStatusFor loads the chain and the replication state and derives the
// status. Every failure degrades to "nothing is known to be pushed", which is the
// loudest reading and therefore the safe one.
func replicationStatusFor(env baselineEnv) chain.ReplicationStatus {
	records, err := env.store.Load(env.trusted)
	if err != nil {
		return chain.ReplicationReport(nil, chain.ReplicationResult{
			Reason: fmt.Sprintf("the chain could not be read: %v", err),
		}, env.now)
	}
	res := chain.ReplicationResult{Reason: "no replication state was read"}
	if len(env.trusted) == 0 {
		res.Reason = "no trusted keys are configured, so no replication state can be authenticated: " +
			env.trustReason
	} else if loaded, lerr := env.store.LoadReplication(env.trusted); lerr != nil {
		res.Reason = fmt.Sprintf("the replication state could not be read: %v", lerr)
	} else {
		res = loaded
	}
	return chain.ReplicationReport(records, res, env.now)
}

// scanReplicationStatus is the banner's input on the `scan` path, where no key,
// no signer and no subcommand argument exist. It resolves the same environment and
// derives the same status, so `scan` and `baseline status` cannot disagree about
// what is pushed.
func scanReplicationStatus(offlineRoot string, noNet bool, stateDir string) chain.ReplicationStatus {
	env, err := resolveBaselineEnv(baselineOpts{
		offlineRoot: offlineRoot, noNet: noNet, stateDir: stateDir,
	})
	if err != nil {
		return chain.ReplicationStatus{}
	}
	return replicationStatusFor(env)
}

// writeReplicationBanner prints the unpushed report.
//
// It goes to the same stream as the report and above it, unconditionally and
// behind no flag: an unpushed tail invalidates the completeness of every other
// statement the chain makes, so it is not a footnote. See
// chain.ReplicationLimitsText for why the remote's force-push denial is the
// load-bearing control and not this file.
func writeReplicationBanner(w io.Writer, st chain.ReplicationStatus) {
	for _, line := range st.Banner() {
		fmt.Fprintln(w, line)
	}
}

// -- the scan -----------------------------------------------------------------

func runBaselineScan(env baselineEnv, opts baselineOpts) (scanEvidence, error) {
	if opts.scan != nil {
		return opts.scan(env)
	}
	return liveEvidence(env)
}

// liveEvidence assembles what this build can actually measure.
//
// The tier it reports is check.TierMeta, because nothing here verifies file
// contents: the provenance sweep reads package metadata and the AUR, and the mtree
// digests below commit to what pacman recorded rather than to what is on disk. That
// is exactly what the bootstrap refusal rejects, and relabelling it would be the
// weakening the refusal exists to prevent.
func liveEvidence(env baselineEnv) (scanEvidence, error) {
	ev := scanEvidence{Tier: check.TierMeta.String()}

	res, summary, err := sweep(context.Background(), env.cfg, env.noNet, nil)
	if err != nil {
		return scanEvidence{}, err
	}
	ev.Result, ev.Summary = res, summary

	pkgs, dbGaps, err := alpm.LoadLocalDB(env.cfg.DBPath)
	if err != nil {
		return scanEvidence{}, err
	}
	for _, g := range dbGaps {
		ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
			RuleID: "local-db", Subject: g, Reason: "package database entry could not be read",
		})
	}
	syncNames, _, err := alpm.LoadSyncNames(env.cfg.SyncPath)
	if err != nil {
		return scanEvidence{}, err
	}
	for _, p := range pkgs {
		pin := baseline.PackageInput{
			Name: p.Name, Version: p.Version, Foreign: alpm.IsForeign(p, syncNames),
		}
		obs := baseline.ObservedPackage{Name: p.Name, Version: p.Version, InstallDate: p.InstallDate}
		d, n, derr := mtreeDigestFor(env.cfg.DBPath, p)
		if derr != nil {
			pin.MtreeUnread = derr.Error()
			obs.MtreeUnread = derr.Error()
		} else {
			pin.MtreeSHA256, pin.MtreeBytes = d, n
			obs.MtreeSHA256 = d
		}
		ev.Packages = append(ev.Packages, pin)
		ev.Observed = append(ev.Observed, obs)
	}

	// pacman.log: the earliest timestamp is the field that makes later truncation
	// detectable, so it is read even though nothing else here needs it.
	lg, err := pacmanlog.Read(pacmanlog.Config{Root: env.cfg.Root})
	if err != nil {
		ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
			RuleID: pacmanlog.RuleAbsent, Subject: "pacman-log",
			Reason: fmt.Sprintf("pacman.log could not be read: %v", err),
		})
	} else {
		ev.Result.Findings = append(ev.Result.Findings, lg.Findings...)
		ev.Result.Gaps = append(ev.Result.Gaps, lg.Gaps...)
		ev.Log = baseline.LogInput{
			Earliest: lg.EarliestString(),
			Files:    logPaths(lg),
			Bounded:  logBounded(lg),
		}
		if !lg.Latest.IsZero() {
			ev.Log.Latest = lg.Latest.Format(baselineStamp)
		}
		ev.LogObs = baseline.LogObservation{
			Earliest: lg.Earliest, Latest: lg.Latest, Bounded: logBounded(lg),
		}
		for _, tx := range lg.Entries {
			ev.LogObs.Transactions = append(ev.LogObs.Transactions, baseline.LogTransaction{
				Time: tx.Time, Op: tx.Op, Pkg: tx.Pkg, Version: tx.Version,
			})
		}
	}

	// Provenance snapshots, by digest.
	snaps := snapshot.StoreAt(env.stateDir)
	bases, lerr := snaps.List()
	if lerr != nil {
		ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
			RuleID: "aur-provenance", Subject: snaps.Dir(),
			Reason: fmt.Sprintf("the snapshot store could not be listed: %v", lerr),
		})
	}
	for _, b := range bases {
		rec, ok, rerr := snaps.Latest(b)
		if rerr != nil || !ok {
			continue
		}
		ev.Provenance = append(ev.Provenance, baseline.ProvenanceInput{
			PkgBase: b, SnapshotSHA256: rec.Digest(), CapturedAt: capturedAt(rec.CapturedAt),
		})
	}

	// The surfaces inventory is NOT collected here, and that is a blocking gap
	// rather than an omission: a manifest missing its surfaces inventory would
	// commit to a system whose execution surfaces were never recorded, and nothing
	// in the signed document would say so.
	ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
		RuleID:  "baseline-surfaces-not-collected",
		Subject: "surfaces",
		Reason: "no surfaces inventory was collected: internal/surfaces is not wired into any " +
			"command in this build, so hooks, units, generators, preload and autostart entries " +
			"would be absent from the signed manifest with nothing in it to say they are missing",
	})
	// And the tier, stated as a gap as well as through the refusal, so the reason
	// survives into any report derived from this evidence.
	ev.Result.Gaps = append(ev.Result.Gaps, finding.Gap{
		RuleID:  "integrity-coverage",
		Subject: "files",
		Reason: "no file contents were verified: this build performs the provenance sweep only, so " +
			"the mtree digests recorded here commit to what pacman recorded and not to what is on " +
			"disk. A baseline must stand on a full-tier scan",
	})
	return ev, nil
}

func mtreeDigestFor(dbPath string, p alpm.Package) (string, int64, error) {
	dir := filepath.Join(dbPath, p.Name+"-"+p.Version)
	f, err := os.Open(filepath.Join(dir, "mtree"))
	if err != nil {
		return "", 0, fmt.Errorf("the package's mtree could not be opened: %v", err)
	}
	defer f.Close()
	d, n, err := baseline.MtreeDigest(f)
	if err != nil {
		return "", 0, fmt.Errorf("the package's mtree could not be digested: %v", err)
	}
	return baseline.Hex(d[:]), n, nil
}

func logPaths(r pacmanlog.Result) []string {
	var out []string
	for _, f := range r.Files {
		out = append(out, f.Path)
	}
	return out
}

func logBounded(r pacmanlog.Result) bool {
	for _, f := range r.Files {
		if f.Bounded {
			return true
		}
	}
	return false
}

// capturedAt converts a snapshot's RFC3339 UTC stamp into the explicit-offset
// spelling the manifest requires. An unparseable one becomes empty rather than
// wrong: the manifest treats a missing captured_at as unknown and refuses a
// malformed one.
func capturedAt(s string) string {
	t, err := time.Parse(time.RFC3339, s)
	if err != nil {
		return ""
	}
	return t.Format(baselineStamp)
}

// -- adjudications ------------------------------------------------------------

// loadAdjudications reads the signed adjudication store. Every failure yields a
// Set with faults, which Apply turns into coverage gaps: an adjudication store a
// caller cannot read must never read as an empty one (INV-9).
func loadAdjudications(env baselineEnv) adjudicate.Set {
	path := filepath.Join(env.stateDir, adjudicationsFile)
	raw, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return adjudicate.Set{Source: path}
	}
	if err != nil {
		return adjudicate.Set{Source: path, Faults: []adjudicate.Fault{{
			Where: "file", Reason: fmt.Sprintf("%s could not be read: %v", path, err),
		}}}
	}
	sig, serr := os.ReadFile(path + ".sig")
	if serr != nil {
		return adjudicate.Set{Source: path, Faults: []adjudicate.Fault{{
			Where:  "signature",
			Reason: fmt.Sprintf("%s.sig could not be read: %v; the store suppresses nothing", path, serr),
		}}}
	}
	return adjudicate.ParseSignedStore(path, raw, sig, env.trusted)
}

// -- small helpers ------------------------------------------------------------

func asBaselineGaps(gaps []finding.Gap) []baseline.Gap {
	out := make([]baseline.Gap, 0, len(gaps))
	for _, g := range gaps {
		out = append(out, baseline.Gap{RuleID: g.RuleID, Subject: g.Subject, Reason: g.Reason})
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].RuleID != out[j].RuleID {
			return out[i].RuleID < out[j].RuleID
		}
		return out[i].Subject < out[j].Subject
	})
	return out
}

func trusts(trusted []*baseline.PublicKey, k *baseline.PublicKey) bool {
	for _, t := range trusted {
		if t.Equal(k) {
			return true
		}
	}
	return false
}

func hostname() string {
	h, err := os.Hostname()
	if err != nil || strings.TrimSpace(h) == "" {
		return "unknown-host"
	}
	return h
}
