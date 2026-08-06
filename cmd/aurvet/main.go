// Command aurvet detects compromised AUR packages and verifies that a
// system has not been tampered with.
package main

import (
	"bytes"
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"runtime"
	"sort"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/lookatitude/aurvet/internal/adjudicate"
	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/collect"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/correlate"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
	"github.com/lookatitude/aurvet/internal/hook"
	"github.com/lookatitude/aurvet/internal/mtree"
	"github.com/lookatitude/aurvet/internal/own"
	"github.com/lookatitude/aurvet/internal/privdrop"
	"github.com/lookatitude/aurvet/internal/report"
	"github.com/lookatitude/aurvet/internal/safe"
	"github.com/lookatitude/aurvet/internal/surfaces"
	"github.com/lookatitude/aurvet/internal/triage"
)

// Exit codes are contractual (spec §14). They are the machine-readable result
// of a scan, so they must never drift: automation branches on them.
const (
	exitClean      = 0 // analysis completed, nothing at or above the floor
	exitFindings   = 1 // analysis completed, findings reported
	exitUsage      = 2 // the invocation itself was wrong
	exitIncomplete = 3 // analysis could not cover what it was asked to cover
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable body: everything it touches arrives as a parameter,
// and it returns the exit code rather than calling os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("aurvet", flag.ContinueOnError)
	fs.SetOutput(stderr)
	offlineRoot := fs.String("offline-root", "", "examine a mounted filesystem instead of the running system")
	noNet := fs.Bool("no-network", false,
		"skip every outbound request; the checks that needed the network become coverage gaps, never absence findings")
	jsonOut := fs.Bool("json", false, "emit machine-readable JSON instead of text")
	sinceLast := fs.Bool("since-last", false,
		"list only findings new since the previous scan; the exit code still reflects the full result")
	// -since is `diff` only, and is NOT a variant of -since-last: that one narrows
	// a scan's listing against the previous report, this one chooses which signed
	// baseline the drift is measured from. The names are close enough that the help
	// text for each says what the other is.
	since := fs.String("since", "",
		"diff only: measure drift from this chain entry instead of the newest -- a seq, a hash prefix, "+
			"or head~N (unrelated to -since-last, which filters a scan)")
	minSeverity := fs.String("min-severity", "",
		"reporting floor: info, suspicious, critical (default from config)")
	// The verification tier. It selects how much work the scan DOES; it is never
	// an assertion about what it did. What a run reports is derived from the work
	// that actually happened -- see fullScan.
	tier := fs.String("tier", "",
		"verification tier: meta, triage, full (default), paranoid -- how much of each file is examined")
	// The privilege policy (spec §11). Unprivileged `scan` REFUSES without this
	// flag; with it, the report is stamped and the run cannot exit 0. See
	// privilege.go for the measurement the policy rests on.
	allowDegraded := fs.Bool("allow-degraded", false,
		"scan: proceed unprivileged -- the report is stamped DEGRADED, every refused read is a "+
			"coverage gap, and the run can never exit 0")
	// --pkg is repeatable (§14's `[--pkg N]...`). An unknown name is a usage
	// error, never an empty result: see pkgselect.go.
	var only pkgList
	fs.Var(&only, "pkg",
		"scan: analyse only this package (repeatable); an unknown name is a usage error, not an "+
			"empty result")
	// review/install lead with rule hits and a diff against the last approved
	// recipe. The full text is available on request, because a gate that prints
	// a 400-line PKGBUILD by default teaches its operator to scroll past it.
	showRecipe := fs.Bool("show-recipe", false,
		"review/install: print the recipe text in full as well as the rule hits and the diff")
	// baseline flags. Signing is a key the operator supplies: aurvet generates none.
	keyPath := fs.String("key", "",
		"baseline: an OpenSSH ed25519 private key file to sign with")
	signerFP := fs.String("signer", "",
		"baseline: the fingerprint of a key held by ssh-agent to sign with (the FIDO2 route)")
	remote := fs.String("remote", "",
		"baseline pushed: the remote the chain was pushed to, e.g. git@host:repo.git#refs/heads/main")
	protectedRemote := fs.Bool("protected-remote", false,
		"baseline pushed: assert that the remote denies force-push and protects the branch — the "+
			"controls that make an anchor mean anything")

	// adjudicate. A judgement is recorded, signed and dated, so every input it
	// needs is explicit: there is no flag here that means "ignore this".
	reason := fs.String("reason", "",
		"adjudicate: why this finding is acceptable — mandatory, and stored inside the signed "+
			"record. triage: the note, required by `triage note` and optional for ack and snooze")
	scope := fs.String("scope", "",
		"adjudicate/triage: pin (this evidence only, the default), subject (this rule for this "+
			"subject), rule (THIS CHECK OFF EVERYWHERE — adjudicate only)")
	expiryDays := fs.Int("expiry-days", 0,
		"adjudicate: how many days the judgement lasts (default 180, maximum 365). triage: default "+
			"30/max 90 for ack and note, 7/30 for snooze. There is no non-expiring suppression")
	forceRuleScope := fs.Bool("force-rule-scope", false,
		"adjudicate: the explicit force -scope rule requires, because turning a check off "+
			"everywhere is a standing property of the host")

	// update. The origin is compiled in; naming another one is a deliberate act.
	bundleURL := fs.String("bundle-url", "",
		"update: the indicator bundle origin to fetch from (default "+DefaultBundleURL+")")
	// `update --check` (§14). internal/bundle already separates deciding from
	// persisting -- Verify performs no I/O and reads no clock -- so this suppresses
	// the two writes and nothing else: the verdict is reached in full.
	checkOnly := fs.Bool("check", false,
		"update: report what an update would do without caching anything or advancing the "+
			"anti-rollback floor")

	// --version is the same output as the `version` subcommand: build identity,
	// root key fingerprints, delegation expiry and the cached bundle version.
	// Both spellings exist because both are typed.
	versionFlag := fs.Bool("version", false,
		"print build identity, root key fingerprints, delegation expiry and the cached bundle version")

	// Go's flag package stops parsing at the first non-flag argument, so a
	// single fs.Parse would leave `aurvet scan --no-network` with noNet unset
	// and "--no-network" sitting in Args() as a positional -- the tool would
	// reach the network on the one invocation that forbids it. Parsing in a
	// loop and collecting positionals as we go accepts flags on either side
	// of the subcommand, which is what users type.
	var operands []string
	rem := args
	for {
		if err := fs.Parse(rem); err != nil {
			return exitUsage
		}
		rest := fs.Args()
		if len(rest) == 0 {
			break
		}
		operands = append(operands, rest[0])
		rem = rest[1:]
	}

	// --version before the operand check: `aurvet --version` has no operands, and
	// answering it with a usage error would be answering the one question that is
	// always legitimate with a complaint about the invocation.
	if *versionFlag {
		if len(operands) != 0 {
			fmt.Fprintf(stderr, "aurvet: --version takes no command (got %q)\n", operands)
			return exitUsage
		}
		writeVersion(stdout, versionFacts{})
		return exitClean
	}

	if len(operands) == 0 {
		fmt.Fprintln(stderr, "usage: aurvet [flags] <command>")
		// One source line, deliberately: completions_test.go reads this literal to
		// check that every dispatched subcommand is discoverable, and a wrapped
		// string would hide half of them from the check.
		fmt.Fprintln(stderr, "commands: scan, diff, baseline, triage, adjudicate, bundle, update, review, install, snapshot, explain, doctor, version")
		return exitUsage
	}

	// Validated once, here, before dispatch -- not inside runScan. A bad
	// -min-severity used to reach ParseSeverity only on the scan path, so
	// `doctor` and `explain` accepted a typo'd floor and exited 0: a wrapper
	// that smoke-tests its flags against `doctor` would pass, then silently
	// change the verdict class of every `scan`. A bad flag is a bad
	// invocation; the subcommand does not enter into it. An empty flag is
	// left unvalidated here -- it means "use the config default", which
	// runScan resolves and validates itself once cfg is available.
	if *minSeverity != "" {
		if _, err := report.ParseSeverity(*minSeverity); err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
	}
	// The tier, on the same terms and for the same reason. check.ParseTier
	// refuses an unknown name rather than defaulting to one: a typo in a systemd
	// unit or a cron line must not quietly downgrade verification, and it must
	// not do so on `doctor` either -- a wrapper that smoke-tests its flags
	// against a cheap subcommand would otherwise pass with a tier `scan` rejects.
	if _, err := check.ParseTier(*tier); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	cmd, cmdArgs := operands[0], operands[1:]

	switch cmd {
	// version is dispatched before every other command because the moment someone
	// asks which build they are running is usually the moment the system is
	// broken: a `version` that needed a readable pacman DB would be unavailable
	// exactly when it is needed to report a bug.
	//
	// It now reads the bundle cache and the root-only floor as well, to print the
	// three facts that decide whether this build's indicator data can be trusted
	// (P5 task 7). That does not cost the property above: the build identity is
	// printed first and unconditionally, and every failure below it renders as a
	// line rather than an error. See writeVersion.
	case "version":
		if len(cmdArgs) != 0 {
			fmt.Fprintf(stderr, "aurvet: version takes no arguments (got %q)\n", cmdArgs)
			return exitUsage
		}
		writeVersion(stdout, versionFacts{})
		return exitClean

	// update is the ONLY path that fetches indicator data, and it runs only when
	// asked. Nothing else in this binary reaches the network for a bundle: no
	// update-on-scan, no background refresh, no "check for updates" side effect.
	case "update":
		if len(cmdArgs) != 0 {
			fmt.Fprintf(stderr, "aurvet: update takes no arguments (got %q)\n", cmdArgs)
			return exitUsage
		}
		return runUpdate(updateOpts{
			offlineRoot: *offlineRoot,
			jsonOut:     *jsonOut,
			baseURL:     *bundleURL,
			check:       *checkOnly,
		}, stdout, stderr)

	// triage is spec §12's MIDDLE weight: local, unsigned, keyless, expiring. It
	// is dispatched next to adjudicate because the two are constantly confused,
	// and separated by everything else: a different store, a different package,
	// and no path from either to the other. Nothing it writes can unblock
	// `baseline init`; see cmd/aurvet/triage.go and internal/triage.
	case "triage":
		return runTriage(triageOpts{
			baselineOpts: baselineOpts{
				offlineRoot: *offlineRoot,
				noNet:       *noNet,
				jsonOut:     *jsonOut,
				tier:        *tier,
				args:        cmdArgs,
			},
			note:       *reason,
			scope:      *scope,
			expiryDays: *expiryDays,
		}, stdout, stderr)

	// bundle emits the redacted reproducer (spec §12). It writes a directory the
	// operator names, reaches no verdict about the system, and never copies a
	// file's own bytes.
	case "bundle":
		if len(cmdArgs) == 0 || len(cmdArgs) > 2 {
			bundleUsage(stderr)
			return exitUsage
		}
		bo := bundleOpts{
			offlineRoot: *offlineRoot,
			noNet:       *noNet,
			jsonOut:     *jsonOut,
			tier:        *tier,
			fingerprint: cmdArgs[0],
		}
		if len(cmdArgs) == 2 {
			bo.dir = cmdArgs[1]
		}
		return runBundle(bo, stdout, stderr)

	// adjudicate is what `baseline init`'s refusal tells the operator to run. It
	// signs, so like baseline it needs a key the operator supplies, and it never
	// generates one.
	case "adjudicate":
		return runAdjudicate(adjudicateOpts{
			baselineOpts: baselineOpts{
				offlineRoot: *offlineRoot,
				noNet:       *noNet,
				jsonOut:     *jsonOut,
				keyPath:     *keyPath,
				signerFP:    *signerFP,
				tier:        *tier,
				args:        cmdArgs,
			},
			reason:         *reason,
			scope:          *scope,
			expiryDays:     *expiryDays,
			forceRuleScope: *forceRuleScope,
		}, stdout, stderr)

	case "doctor":
		cfg, err := config.Resolve(*offlineRoot, os.Geteuid())
		if err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
		for _, l := range cfg.Doctor() {
			fmt.Fprintf(stdout, "%-14s %-46s (%s)\n", l.Key, l.Value, l.Source)
			// A degraded resolution is printed on stderr as well as being
			// visible in the report, so it survives `aurvet doctor | grep`
			// and is not lost in a wall of healthy lines.
			if l.Warning != "" {
				fmt.Fprintf(stdout, "%-14s   ! %s\n", "", l.Warning)
				fmt.Fprintf(stderr, "aurvet: %s %s\n", l.Key, l.Warning)
			}
		}
		return exitClean

	case "scan":
		if len(cmdArgs) != 0 {
			fmt.Fprintf(stderr, "aurvet: scan takes no arguments (got %q)\n", cmdArgs)
			return exitUsage
		}
		return runScan(scanOpts{
			offlineRoot:   *offlineRoot,
			noNet:         *noNet,
			jsonOut:       *jsonOut,
			sinceLast:     *sinceLast,
			minSeverity:   *minSeverity,
			tier:          *tier,
			allowDegraded: *allowDegraded,
			only:          only,
		}, stdout, stderr)

	// snapshot captures provenance for ONE pkgbase. Not a package name, and not
	// a list: one subject keeps the exit code unambiguous about whose evidence
	// was incomplete.
	case "snapshot":
		if len(cmdArgs) != 1 {
			fmt.Fprintln(stderr, "usage: aurvet snapshot <pkgbase>")
			fmt.Fprintln(stderr, "  the subject is a pkgbase, not a package name: one recipe can build several packages")
			return exitUsage
		}
		return runSnapshot(*offlineRoot, *jsonOut, cmdArgs[0], stdout, stderr)

	// review ANALYSES and never builds (INV-2). One subject, like snapshot, so
	// the exit code is unambiguous about whose recipe was incomplete.
	case "review":
		if len(cmdArgs) != 1 {
			fmt.Fprintln(stderr, "usage: aurvet review <dir|pkgbase>")
			fmt.Fprintln(stderr, "  analyses a recipe and never builds it; leads with rule hits and the diff against the last approved recipe")
			return exitUsage
		}
		return runReview(reviewOpts{
			offlineRoot: *offlineRoot,
			jsonOut:     *jsonOut,
			minSeverity: *minSeverity,
			showRecipe:  *showRecipe,
			subject:     cmdArgs[0],
		}, stdout, stderr)

	// install fetches, reviews the whole dependency closure, prompts,
	// snapshots, and then hands the vetted directory to the helper. It never
	// runs makepkg and never runs the helper (INV-2).
	case "install":
		if len(cmdArgs) != 1 {
			fmt.Fprintln(stderr, "usage: aurvet install <pkgbase>")
			fmt.Fprintln(stderr, "  fetches and reviews the dependency closure, prompts, snapshots, then hands the vetted directory over")
			fmt.Fprintln(stderr, "  it does NOT build: aurvet never runs makepkg or your helper for you")
			return exitUsage
		}
		return runInstall(installOpts{
			offlineRoot: *offlineRoot,
			noNet:       *noNet,
			jsonOut:     *jsonOut,
			minSeverity: *minSeverity,
			showRecipe:  *showRecipe,
			pkgbase:     cmdArgs[0],
		}, stdout, stderr)

	// diff is top-level because spec §14 and §1 both put it there: §1 names it as
	// one of the four verbs the product IS ("`scan` compares live state to
	// expectation, `diff` to recorded state"), so a user who read the spec types
	// `aurvet diff`. It is the same code as `aurvet baseline diff`, reached by
	// prepending the subcommand rather than by a second implementation -- two
	// spellings of one behaviour must not be two behaviours.
	case "diff":
		return runBaseline(baselineOpts{
			offlineRoot:     *offlineRoot,
			noNet:           *noNet,
			jsonOut:         *jsonOut,
			keyPath:         *keyPath,
			signerFP:        *signerFP,
			remote:          *remote,
			protectedRemote: *protectedRemote,
			tier:            *tier,
			since:           *since,
			args:            append([]string{"diff"}, cmdArgs...),
		}, stdout, stderr)

	// baseline is the P4 trust chain: init, status/show, verify, pushed, diff. It
	// signs, so it is the one command that needs a key, and it never generates one.
	case "baseline":
		return runBaseline(baselineOpts{
			offlineRoot:     *offlineRoot,
			noNet:           *noNet,
			jsonOut:         *jsonOut,
			keyPath:         *keyPath,
			signerFP:        *signerFP,
			remote:          *remote,
			protectedRemote: *protectedRemote,
			tier:            *tier,
			since:           *since,
			args:            cmdArgs,
		}, stdout, stderr)

	case "explain":
		if len(cmdArgs) == 0 {
			fmt.Fprintln(stderr, "usage: aurvet explain <fingerprint>")
			return exitUsage
		}
		return runExplain(*offlineRoot, *noNet, *tier, cmdArgs[0], stdout, stderr)

	default:
		fmt.Fprintf(stderr, "aurvet: unknown command %q\n", cmd)
		return exitUsage
	}
}

// scanOpts carries scan's inputs. It is a struct rather than a parameter list
// because the last three fields are test seams: their zero values select
// production behaviour, so run() constructs one from flags alone and never
// mentions them.
type scanOpts struct {
	offlineRoot string
	noNet       bool
	jsonOut     bool
	sinceLast   bool
	minSeverity string

	// tier is the verification tier ASKED FOR, as the flag spelled it. It is a
	// string rather than a check.Tier so that the ZERO VALUE is the default tier
	// and not TierMeta: a caller that forgot the field would otherwise silently
	// run the shallowest scan there is, which is the one failure mode this
	// lane's flag exists to prevent. What the scan REPORTS is what it executed,
	// which is a different value and lives on scanRun.
	tier string

	// allowDegraded is spec §11's opt-in: an unprivileged live scan refuses
	// without it, and stamps itself and forbids exit 0 with it. See privilege.go.
	allowDegraded bool

	// only restricts the analysis to the named packages (--pkg, repeatable). See
	// pkgselect.go for what is restricted and what is not.
	only []string

	// stateDir overrides where reports are persisted. "" means "decide from
	// config", which is what run() always passes.
	stateDir string

	// euid overrides the effective uid the privilege staging decides from. nil
	// means "ask the kernel", which is what run() always passes; a test uses it
	// to reach the privileged path without being root.
	euid *int
	// cl is the aur.Client seam sweep already documents. nil means "build the
	// real HTTP client".
	cl aur.Client
}

// reportStamp names a stored report. Nanosecond precision, not the seconds the
// plan specified: two scans inside the same second would otherwise produce the
// same filename, and Save's atomic rename would silently overwrite the first
// with the second. The next --since-last would then diff against a baseline
// one run older than it believed. The layout stays fixed-width and
// zero-padded, so lexicographic order is still chronological order -- which is
// the assumption report.LoadPrevious sorts on.
const reportStamp = "20060102T150405.000000000Z"

// scanStateDir decides where -- and whether -- this run may persist its report.
// An empty path means "do not persist", with the returned string explaining
// why; that reason is printed, never converted into a coverage gap.
//
// The offline-root rule is INV-5, spelled out in spec §11's storage table:
// "Offline-root mode -- all output to --report-dir; nothing written under the
// target". Two distinct failures hide behind that one line, and both are why
// this returns empty rather than picking some other directory:
//
//   - Unprivileged, config.Resolve puts StateDir INSIDE the examined tree, so
//     persisting would write to the very filesystem we are auditing.
//   - Privileged, §11 deliberately pins StateDir to /var/lib/aurvet OUTSIDE
//     the target -- so a report about a rescue mount would be filed as this
//     host's own baseline, and the next `sudo aurvet scan --since-last` would
//     diff the live system against /mnt. Every finding on this host would look
//     "already seen" and be suppressed.
//
// --report-dir does not exist in P1-A, so there is no correct destination yet
// and the honest move is to skip and say so.
func scanStateDir(cfg config.Config, opts scanOpts, euid int) (string, string) {
	// A --pkg run is not this system's report, and it must not become the
	// --since-last baseline. The reasoning is the one runScan gives for never
	// saving a FILTERED view: a stored result covering two packages would truncate
	// the next run's baseline, so every finding on the system would re-report as
	// new on the run after that. First, before the stateDir seam, because a test
	// that supplies a state directory must not be able to reintroduce it.
	if len(opts.only) > 0 {
		return "", "--pkg: report not persisted (it covers the named packages only, and a scoped " +
			"report stored as this system's baseline would make every other finding read as new on " +
			"the next --since-last)"
	}
	if opts.stateDir != "" {
		return opts.stateDir, ""
	}
	if opts.offlineRoot != "" {
		return "", "--offline-root: report not persisted (INV-5: nothing is written under the examined tree, " +
			"and the privileged state directory describes a different system); --since-last is unavailable"
	}
	// spec §11's resolution order is "--flag > environment > system config >
	// user config > compiled defaults", and its danger callout requires a
	// euid==0 run to ignore the environment entirely for trust-bearing paths --
	// otherwise an unprivileged local attacker chooses what a root-privileged
	// security tool trusts. Hence: environment honoured, but never as root.
	//
	// INTERIM. This exists because config.Resolve currently hands an
	// unprivileged live-system run StateDir=/var/lib/aurvet, which no ordinary
	// user can write, making --since-last unreachable for everyone but root.
	// spec §11's storage table says the user context is the XDG state dir; when
	// config.Resolve implements that, this override loses its reason to exist.
	if euid != 0 {
		if env := os.Getenv("AURVET_STATE_DIR"); env != "" {
			return env, ""
		}
	}
	return cfg.StateDir, ""
}

// runScan resolves config, runs the full scan, persists the result, renders the
// report and returns report.ExitCode(verdict, floor) -- and nothing else -- on
// the success path (spec §14).
func runScan(opts scanOpts, stdout, stderr io.Writer) int {
	euid := os.Geteuid()
	if opts.euid != nil {
		euid = *opts.euid
	}

	// The privilege policy FIRST, before anything is resolved or read: a refusal
	// means no analysis was attempted, and a refusal that had already opened the
	// package database would be a refusal that did some of the work it declined to
	// do. Exit 2, because what is wrong is the invocation (spec §11).
	priv := privilegePolicy(euid, opts.offlineRoot, opts.allowDegraded)
	if priv.Refuse {
		for _, line := range priv.Refusal {
			fmt.Fprintln(stderr, line)
		}
		return exitUsage
	}

	cfg, err := config.Resolve(opts.offlineRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	floorStr := opts.minSeverity
	if floorStr == "" {
		floorStr = cfg.MinSeverity
	}
	floor, err := report.ParseSeverity(floorStr)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	want, err := check.ParseTier(opts.tier)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	run, err := fullScan(context.Background(), pipeline{
		cfg: cfg, tier: want, noNet: opts.noNet, cl: opts.cl, euid: euid, only: opts.only,
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		// A scan that could not be staged never ran, so it covered nothing:
		// that is exit 3, not "your command line was wrong".
		if errors.Is(err, errPrivilegeStaging) {
			return exitIncomplete
		}
		return exitUsage
	}
	res, summary := run.Result, run.Summary

	// The degradation, as a coverage GAP and therefore as part of the result:
	// stamping the output alone would leave the exit code, the JSON document and
	// the stored report all claiming complete coverage. It is appended before the
	// report is persisted, so the baseline the next --since-last diffs against
	// carries it too. -min-severity cannot reach it (INV-3).
	if priv.Degraded {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: rulePrivilegeCoverage, Subject: "process", Reason: priv.Gap,
		})
	}

	// ORDERING IS LOAD-BEARING. Persist the FULL result here, before the
	// --since-last block below derives anything from it, and never move this
	// call below that block. Saving a filtered result would truncate the next
	// run's baseline, so every persisting finding would re-report as new on the
	// run after that -- turning the feature into precisely the noise it exists
	// to remove. `res` is not mutated anywhere below; the filtered set lives in
	// the View, which is why report.View keeps display and verdict apart.
	stateDir, skipReason := scanStateDir(cfg, opts, euid)
	switch {
	case skipReason != "":
		fmt.Fprintf(stderr, "aurvet: %s\n", skipReason)
	default:
		if _, serr := report.Save(stateDir, res, summary, time.Now().UTC().Format(reportStamp)); serr != nil {
			// NOT a coverage gap, and deliberately not: a Gap means "a check
			// could not run" (INV-3/INV-10) and forces exit 3. Failing to write
			// a cache file is an operational problem with the host, not an
			// incomplete analysis -- the scan examined everything it was asked
			// to. Manufacturing a gap here would flip an otherwise-clean scan to
			// exit 3 on any read-only or full state directory, training
			// operators to ignore code 3 on exactly the tool whose value is that
			// code 3 means something.
			fmt.Fprintf(stderr, "aurvet: could not persist report to %s: %v\n", stateDir, serr)
		}
	}

	// The unpushed report, FIRST and unconditionally.
	//
	// It precedes the header rather than trailing the findings, and it is behind no
	// flag, because an unpushed chain tail invalidates the completeness of every
	// other statement below it: entries removed from the end of a chain leave one
	// that still verifies, so nothing here detects their removal until they exist
	// somewhere this machine cannot rewrite. A tail reported after 40 findings, or
	// only under a flag, is a tail nobody reads.
	//
	// A machine with no chain prints nothing: an absent chain is not an unpushed
	// one, and announcing on every run that `baseline init` has not been run is the
	// noise that teaches an operator to skip the banner.
	if stateDir != "" {
		w := stdout
		if opts.jsonOut {
			// Never into the JSON document: a caller parsing stdout must get JSON
			// and nothing else. Stderr keeps it in front of a human.
			w = stderr
		}
		writeReplicationBanner(w, scanReplicationStatus(opts.offlineRoot, opts.noNet, stateDir))
	}

	// The degradation stamp and the --pkg scope, above the findings and above the
	// tier line. Both bound what every statement below them means -- one by
	// permissions, one by subject -- and a caveat printed under 40 findings is a
	// caveat nobody reads. Stderr under -json for the same reason the tier line
	// goes there: stdout must be JSON and nothing else.
	stampOut := stdout
	if opts.jsonOut {
		stampOut = stderr
	}
	for _, line := range append(append([]string{}, priv.Stamp...), scopeLine(opts.only)...) {
		fmt.Fprintln(stampOut, line)
	}

	// The tier, before the findings and unconditionally: every verdict below is
	// qualified by it, and a scan that degraded says so here rather than leaving
	// the reader to assume the flag was honoured. After the replication banner,
	// which stays first for the reason its own comment gives. Stderr under -json,
	// so a caller parsing stdout still gets JSON and nothing else.
	tierOut := stdout
	if opts.jsonOut {
		tierOut = stderr
	}
	fmt.Fprintln(tierOut, run.TierLine())
	// The wall time on stderr, never in the report: a scan of a whole system at
	// tier full reads tens of gigabytes, and an operator deciding whether to run
	// it hourly needs the number.
	fmt.Fprintf(stderr, "aurvet: scan completed in %s\n", run.Elapsed.Round(time.Millisecond))

	view := report.FullView(res)
	if opts.sinceLast {
		var prev finding.Result
		var ok bool
		// stateDir is empty exactly when persistence was skipped. Passing "" to
		// LoadPrevious would resolve to the relative path "reports" in the
		// working directory -- an attacker-plantable baseline in any directory
		// the operator happens to cd into. Treat it as "no baseline".
		if stateDir == "" {
			fmt.Fprintln(stderr, "aurvet: --since-last has no stored baseline in this mode; showing all findings")
		} else {
			var lerr error
			prev, ok, lerr = report.LoadPrevious(stateDir)
			if lerr != nil {
				// Reading the baseline failed. Degrade to showing everything rather
				// than failing the scan: too much output is recoverable, a
				// suppressed critical is not.
				fmt.Fprintf(stderr, "aurvet: could not read the previous report from %s: %v\n", stateDir, lerr)
				ok = false
			}
		}
		view = report.SinceLastView(prev, ok, res)
	}

	// Triage, applied to the DISPLAY and never to the verdict.
	//
	// spec §12 says an `ack` or a `snooze` "suppresses from the default view", and
	// the default view is this listing. It is deliberately NOT allowed to reach
	// the exit code, the coverage verdict or the persisted report -- report.View
	// exists to keep those apart, and a local unsigned record that could turn a
	// critical into exit 0 would be the blindfold the whole lifecycle is arranged
	// to prevent. What it hides, it hides from the eye only.
	//
	// The one thing it CAN change is coverage: an unreadable triage store is a
	// coverage gap (INV-9), so a store nobody can parse pushes the run to exit 3
	// rather than being quietly treated as empty.
	if stateDir != "" {
		var tout triage.Outcome
		res, view, tout = applyTriage(stateDir, res, view, time.Now())
		writeTriageBanner(stampOut, tout)
	}

	if opts.jsonOut {
		err = report.JSONView(stdout, view, summary, floor)
	} else {
		err = report.TextView(stdout, view, summary)
	}
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		// The analysis completed; only the rendering failed. Returning
		// exitUsage here told an operator "your invocation was wrong" about a
		// host that was, say, never fully checked -- 2 and 3 mean opposite
		// things. Never downgrade a real verdict; a lost report on an
		// otherwise-clean scan is still a usage-class failure, because the
		// caller received nothing.
		if code := report.ExitCode(res, floor); code != exitClean {
			return code
		}
		return exitUsage
	}

	return report.ExitCode(res, floor)
}

// applyTriage narrows what a scan LISTS by the local triage records, and returns
// the verdict result, the narrowed view and the outcome.
//
// The verdict result is returned rather than mutated in place because it gains
// the coverage gaps an unusable store raises: those are a real statement about
// what this run could not establish, and they must reach the exit code. Nothing
// else about the verdict changes -- the finding list it is computed from is the
// full one.
func applyTriage(stateDir string, res finding.Result, view report.View, now time.Time) (finding.Result, report.View, triage.Outcome) {
	set := triage.Load(stateDir)
	if len(set.Records) == 0 && len(set.Faults) == 0 {
		return res, view, triage.Outcome{}
	}
	out := triage.ApplyWith(adjudicate.BuiltIn(), set, res, now)

	hidden := make(map[string]bool, len(out.Suppressed))
	for _, s := range out.Suppressed {
		hidden[report.FindingID(s.Finding)] = true
	}
	kept := make([]finding.Finding, 0, len(view.Display.Findings))
	for _, f := range view.Display.Findings {
		if hidden[report.FindingID(f)] {
			continue
		}
		kept = append(kept, f)
	}

	// The fault gaps join the verdict AND the display: a gap is never diffed away
	// and never triaged away.
	res.Gaps = out.Kept.Gaps
	view.Verdict = res
	view.Display = finding.Result{Findings: kept, Gaps: res.Gaps}
	return res, view, out
}

// writeTriageBanner states what the listing is not showing. INV-6: a report that
// silently omits suppressed findings lies by omission, and a local unsigned
// record is the cheapest suppression in the tool -- so its effect is announced
// above the findings rather than left to `aurvet triage list`.
func writeTriageBanner(w io.Writer, out triage.Outcome) {
	if len(out.Suppressed) == 0 && len(out.Annotated) == 0 && len(out.NeedsAttention()) == 0 {
		return
	}
	if n := len(out.Suppressed); n > 0 {
		fmt.Fprintf(w, "triage: %d finding(s) are NOT listed below, hidden by local UNSIGNED triage "+
			"records; the exit code and the coverage verdict still count them\n", n)
	}
	if n := len(out.Annotated); n > 0 {
		fmt.Fprintf(w, "triage: %d finding(s) carry a note and are still listed in full\n", n)
	}
	if n := len(out.NeedsAttention()); n > 0 {
		fmt.Fprintf(w, "triage: %d record(s) suppress nothing (stale, expired, spent or dead); "+
			"`aurvet triage list` says which\n", n)
	}
}

// runExplain re-runs the same sweep as scan, then renders the rationale for
// one finding. A successful explain always returns exitClean: it is a query
// against the sweep's findings, not a verdict on the sweep itself, so it must
// not be "fixed" later to return the scan's own exit code.
func runExplain(offlineRoot string, noNet bool, tier, fingerprint string, stdout, stderr io.Writer) int {
	euid := os.Geteuid()
	cfg, err := config.Resolve(offlineRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	want, err := check.ParseTier(tier)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	// The SAME scan, deliberately: explain must be able to resolve the
	// fingerprint of any finding scan produced, and a cheaper re-run here would
	// make the integrity and correlation findings unexplainable -- the tool would
	// print a finding and then deny knowing it.
	run, err := fullScan(context.Background(), pipeline{cfg: cfg, tier: want, noNet: noNet, euid: euid})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	res := run.Result

	if err := report.Explain(stdout, res, fingerprint); err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	return exitClean
}

// sweep loads the local and sync databases, runs check.Provenance and merges
// in the coverage gaps scan/explain are each responsible for (spec §14 steps
// 2-9). A non-nil error means a hard failure occurred before anything could
// be analysed -- callers map that to exit 2, never 3.
//
// cl is a test seam: nil means "build the real HTTP client". Without it no
// hermetic test could reach scan's exit-0 path through a network check --
// sweep hardcoded aur.NewHTTP with no way to inject aur.Fake, which is why two
// exit-0 criticals (report-sec findings 1 and 4) survived task 9's own suite.
//
// Since the full pipeline landed, sweep has NO production caller: runScan and
// runExplain both go through fullScan, which needs the parsed package set for
// the ownership oracle, the derived exemptions and correlation's attribution,
// and so calls loadDBs/sweepWith itself. What remains here is the
// provenance-only path, kept because the tests that pin P1-A's exit-code
// contract are about provenance alone and should not have to stand up an
// integrity and surfaces scan to assert it. It is a test entry point living in
// a production file; do not add a caller to it.
func sweep(ctx context.Context, cfg config.Config, noNet bool, cl aur.Client) (finding.Result, report.Summary, error) {
	d, err := loadDBs(cfg)
	if err != nil {
		return finding.Result{}, report.Summary{}, err
	}
	res, summary := sweepWith(ctx, cfg, d, noNet, cl)
	return res, summary, nil
}

// dbs is the two databases every analyser in a scan needs, loaded once.
//
// It exists because the full pipeline needs the PARSED package set -- for the
// ownership oracle, the derived exemptions and correlation's attribution -- and
// re-reading a 59 MB local database per analyser would spend a second of I/O to
// produce a second copy of data the first read already had, with the two copies
// able to disagree if the database changes underneath.
type dbs struct {
	pkgs      []alpm.Package
	syncNames map[string]bool

	// syncGaps are the unreadable sync databases, in the shape
	// check.SyncCoverageGaps wants; gaps are the load's own coverage gaps.
	syncGaps []string
	gaps     []finding.Gap

	dbPath string
}

// dbsFromRaw builds the same two databases from what phase 1 already buffered,
// which is what a scan uses.
//
// The local database is not read again here. It was read once, under the read
// capability, by internal/collect; parsing those bytes rather than opening the
// 59 MB tree a second time removes a duplicate read of an attacker-writable
// input whose two copies could disagree, and it is the precondition for the
// desc parser ever moving to the unprivileged side of the drop (spec §11.1).
//
// The SYNC database is still read from disk here, and that is stated rather
// than hidden: phase 1 does not buffer var/lib/pacman/sync, so alpm's tar+gzip
// reader still runs inside the privileged window. See the note on
// alpm.LoadSyncNames' caller in the receipt for this lane.
func dbsFromRaw(cfg config.Config, raw collect.Raw) (dbs, error) {
	if !raw.DBListed {
		// Not a gap: with no local database there is no package set, no
		// ownership oracle and no notion of what is supposed to be on this
		// system. The scan does not start, exactly as it did not when this
		// function read the directory itself.
		reason := "it could not be listed"
		for _, g := range raw.Gaps {
			if g.RuleID == "collect-db" && strings.HasSuffix(cfg.DBPath, g.Subject) {
				reason = g.Reason
				break
			}
		}
		return dbs{}, fmt.Errorf("the local package database at %s was not read: %s", cfg.DBPath, reason)
	}
	buf := make([]alpm.Buffered, 0, len(raw.Packages))
	for _, p := range raw.Packages {
		buf = append(buf, alpm.Buffered{Dir: p.Dir, Desc: p.Desc, Files: p.FileList})
	}
	pkgs, localGaps := alpm.PackagesFrom(buf)
	return withSyncDB(cfg, pkgs, localGaps)
}

// loadDBs reads the local and sync databases and states what it could not read.
//
// A scan does not come through here -- it comes through dbsFromRaw, over phase
// 1's buffers. This is the provenance-only entry point's loader.
func loadDBs(cfg config.Config) (dbs, error) {
	pkgs, localGaps, err := alpm.LoadLocalDB(cfg.DBPath)
	if err != nil {
		return dbs{}, err
	}
	return withSyncDB(cfg, pkgs, localGaps)
}

// withSyncDB completes a dbs from a local package set: it loads the sync
// database and states, as gaps, the two emptinesses that would otherwise be
// reported as a clean sweep.
func withSyncDB(cfg config.Config, pkgs []alpm.Package, localGaps []string) (dbs, error) {
	d := dbs{dbPath: cfg.DBPath, pkgs: pkgs}

	var extraGaps []finding.Gap
	for _, g := range localGaps {
		extraGaps = append(extraGaps, finding.Gap{
			RuleID: "local-db", Subject: g,
			Reason: "package database entry could not be read",
		})
	}
	if len(pkgs) == 0 {
		// A sweep that saw no packages must not report a clean bill of
		// health: without this, an empty (or wrong) -offline-root yields
		// zero packages, zero findings, zero gaps and exit 0 -- a confident
		// all-clear on a scan that read nothing.
		extraGaps = append(extraGaps, finding.Gap{
			RuleID: "local-db", Subject: cfg.DBPath,
			Reason: "no packages found in the local database; this sweep had nothing to analyse",
		})
	}

	syncNames, syncGaps, err := alpm.LoadSyncNames(cfg.SyncPath)
	if err != nil {
		return dbs{}, err
	}
	d.syncNames, d.syncGaps = syncNames, syncGaps
	if len(syncNames) == 0 {
		// Foreignness is !syncNames[name], so an empty oracle silently
		// reclassifies every installed package as foreign and reports it as
		// complete coverage. check.SyncCoverageGaps's own doc comment argues
		// a len(syncNames) == 0 guard is the wrong fix INSIDE Provenance --
		// it would fire on a legitimately empty repository set. At this
		// level it is the right call, and for a different reason: scan
		// looks at a whole system, and a system with zero known repository
		// names cannot distinguish foreign from repo at all.
		extraGaps = append(extraGaps, finding.Gap{
			RuleID: "sync-coverage", Subject: cfg.SyncPath,
			Reason: "no repository package names were loaded; every installed package will be " +
				"treated as foreign, so every foreignness verdict in this run is unreliable",
		})
	}
	d.gaps = extraGaps
	return d, nil
}

// sweepWith is sweep's analysis half, over databases the caller already loaded.
func sweepWith(ctx context.Context, cfg config.Config, d dbs, noNet bool, cl aur.Client) (finding.Result, report.Summary) {
	network := cfg.Network && !noNet
	if network && cl == nil {
		cl = aur.NewHTTP("https://aur.archlinux.org", &http.Client{Timeout: 20 * time.Second})
	}

	pkgs, syncNames := d.pkgs, d.syncNames
	res := check.Provenance(ctx, pkgs, syncNames, d.syncGaps, cl, network)
	res.Gaps = append(res.Gaps, d.gaps...)

	if !network {
		// P1-A success criterion 4: --no-network must never exit 0.
		// Provenance already gaps each foreign package on this path, which
		// is redundant with this gap whenever a foreign package exists --
		// and that redundancy is the point. With zero foreign packages
		// Provenance returns an empty Result and the run would otherwise
		// exit 0 having deliberately skipped every network check.
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: "aur-provenance", Subject: "sweep",
			Reason: "--no-network: no AUR provenance check was attempted in this run",
		})
	}

	foreign := 0
	for _, p := range pkgs {
		if alpm.IsForeign(p, syncNames) {
			foreign++
		}
	}

	return res, report.Summary{Total: len(pkgs), Foreign: foreign}
}

// ---------------------------------------------------------------------------
// The full scan
//
// Four analysers run here, and merging them is where the invariants are easiest
// to lose:
//
//   - provenance (P1-A): the package database and the AUR.
//   - integrity (P1-B): the mtree digests, verified against file contents.
//   - surfaces and correlation (P1-C): units, enablement links, hooks, the
//     remaining execution surfaces, and the clusters they form.
//
// Their gaps are merged, so exit 3 outranks exit 1 across all of them (INV-3),
// and no analyser's Limits text is rewritten on the way through (INV-6): this
// code appends findings and never edits one.
//
// WHAT THIS PIPELINE DOES NOT DO, stated because the omissions are real:
//
//   - It does not walk the whole filesystem at any tier. Below paranoid it opens
//     exactly the paths the local database RECORDS -- 386,645 non-directory
//     entries on the reference system, learned in phase 1 from a newline split of
//     the plain-text `files`, not from the gzipped mtree. Paranoid adds a
//     metadata-only sweep of usr, etc, opt, boot and srv minus the collector's
//     skip list, which is what check.UnownedSUID needs and what spec §13 assigns
//     to that tier. So integrity-unowned-setuid fires at paranoid and nowhere
//     else, and the trees the sweep still cannot see are stated in the rule's own
//     limits rather than left to be discovered.
//   - It does not read pacman.log. Correlation's temporal key therefore rests on
//     mtree time= against %INSTALLDATE% only; `baseline init` supplies the
//     transaction times as well, so its correlation is strictly stronger than
//     `scan`'s on the same machine.
// ---------------------------------------------------------------------------

// errPrivilegeStaging reports that the staged-privilege model could not be
// established. It is distinguished from every other scan failure because the
// exit code differs: a scan that refused to run covered nothing (exit 3), which
// is not the same statement as "your invocation was wrong" (exit 2).
var errPrivilegeStaging = errors.New("privileges could not be staged for the scan")

// privReduceToRead and privDropAll are seams over internal/privdrop. Production
// leaves them alone; the ordering test replaces them, because the real calls
// cannot be exercised without root and a test that asserted only "the call
// exists" would not notice a reduction that happened after the first read.
var (
	privReduceToRead = privdrop.ReduceToRead
	privDropAll      = privdrop.DropAll
)

// beforeCollectForTest runs immediately before phase 1, and beforeVerifyForTest
// immediately before each package's records are COMPARED against phase 1's
// evidence. Production leaves both nil.
//
// The pair is what makes the staged model testable from outside. Every read of a
// file's contents happens between them; nothing after beforeVerifyForTest reads
// anything for integrity. A test that only asserted "ReduceToRead was called"
// would pass on a build that reduced after the first read, and a test that
// marked the comparison as though it were a read would assert nothing at all
// once the reads moved into collect -- which is exactly what happened here.
// afterCollectForTest runs the instant phase 1 returns, which is the window the
// package set is now parsed in: a test mutates the database there and asserts
// the parsed package set did not follow, because it came off buffered bytes and
// not off a second read.
var (
	beforeCollectForTest func()
	afterCollectForTest  func()
	beforeVerifyForTest  func()
)

// stagePrivilege reduces the process to CAP_DAC_READ_SEARCH before the first
// read and returns the function that destroys what is left of its privilege
// afterwards.
//
// Unprivileged it does NOTHING, deliberately: there is nothing to reduce, and an
// unprivileged scan does not silently do less either -- every read it is refused
// becomes a coverage gap (INV-9), which is what makes `baseline init`'s
// unprivileged refusal a true statement rather than a decorative one.
func stagePrivilege(euid int) (func() error, error) {
	if euid != 0 {
		return func() error { return nil }, nil
	}
	if err := privReduceToRead(); err != nil {
		return nil, fmt.Errorf("%w: %v", errPrivilegeStaging, err)
	}
	return privDropAll, nil
}

// pipeline is one full scan's whole input. It is a struct because the fields are
// what INV-4 requires: a scan is a pure function of (root, config), and
// everything ambient it would otherwise reach for is named here.
type pipeline struct {
	cfg   config.Config
	tier  check.Tier
	noNet bool
	cl    aur.Client
	euid  int

	// txs are pacman.log transaction times for correlation's temporal key. nil
	// means the log was not read, which weakens attribution and is never a
	// finding.
	txs []correlate.Transaction

	// inventory asks for the surfaces inventory a signed baseline commits to. It
	// costs a second pass over the unit and hook directories, so `scan`, which
	// has no use for it, does not pay.
	inventory bool

	// only restricts the analysed package set to these package names (--pkg).
	// Empty means the whole system. A name the database does not carry aborts the
	// run with errUnknownPackage rather than yielding an empty scope; the
	// system-wide passes do not run at all under a restriction, because the
	// ownership oracle is then partial by construction. See pkgselect.go.
	only []string
}

// scanRun is what one full scan produced.
type scanRun struct {
	Result  finding.Result
	Summary report.Summary

	// Tier is the tier the scan ACTUALLY EXECUTED, derived from whether contents
	// were read at all. Requested is what was asked for. They differ when a scan
	// degrades, and the difference is a gap rather than a relabelling: there is
	// no way for a flag to make a shallower scan report as a deeper one.
	Tier      check.Tier
	Requested check.Tier

	// Packages and Surfaces are the evidence a baseline commits to. Both are
	// empty unless pipeline.inventory asked for them.
	Packages []baseline.PackageInput
	Observed []baseline.ObservedPackage
	Surfaces []baseline.SurfaceInput

	// Hashed and HashedBytes are what verification actually read, so a report can
	// state coverage as a measured quantity rather than as an intention.
	// MetadataOnly counts the paths whose verdict rests on stat alone, which is
	// what distinguishes "nothing needed hashing" from "nothing was hashed".
	Hashed       int
	HashedBytes  int64
	MetadataOnly int
	Verified     int
	Elapsed      time.Duration
}

// TierLine is the one-line statement of what this run actually did. A degraded
// run says so on the same line, because the reader who needs that fact is
// reading this line and not the gap list.
//
// It carries no timing, deliberately: this line is part of the report, and two
// scans of the same unchanged root must produce the same report. The wall time is
// operational and goes to stderr.
func (r scanRun) TierLine() string {
	s := fmt.Sprintf("scan ran at tier %s: %d package(s) verified, %d path(s) hashed (%.1f MiB)",
		r.Tier, r.Verified, r.Hashed, float64(r.HashedBytes)/(1<<20))
	if r.Tier != r.Requested {
		s += fmt.Sprintf("\n  ! tier %s was requested and NOT achieved; the difference is a coverage gap, not a relabelling",
			r.Requested)
	}
	return s
}

// fullScan runs every analyser over one root and merges what they found.
//
// The order is not arbitrary. Privilege is staged before the first read and
// destroyed after the last one; the database is buffered by internal/collect
// while the capability is held and PARSED afterwards, so a parser bug in the
// mtree reader is an unprivileged bug (spec §11.1).
func fullScan(ctx context.Context, p pipeline) (scanRun, error) {
	start := time.Now()
	out := scanRun{Requested: p.tier, Tier: p.tier}

	dropAll, err := stagePrivilege(p.euid)
	if err != nil {
		return scanRun{}, err
	}

	// Phase 1: buffer the database bytes through confined opens, while the read
	// capability is held. Nothing here parses.
	//
	// It runs FIRST, before anything needs the package set, because the package
	// set is now derived from these buffers rather than from a second read of
	// the same 59 MB database. Two reads of one attacker-writable input can
	// disagree, and the loser of that disagreement was the ownership oracle
	// every check downstream consults.
	if beforeCollectForTest != nil {
		beforeCollectForTest()
	}
	raw, cerr := collect.Collect(collectConfig(p.cfg, p.tier))
	if afterCollectForTest != nil {
		afterCollectForTest()
	}

	d, err := dbsFromRaw(p.cfg, raw)
	if err != nil {
		// The database could not be read at all: nothing below has an oracle to
		// work from, and a scan of a system whose package set is unknown would be
		// a scan with no notion of what is supposed to be there.
		_ = dropAll()
		return scanRun{}, err
	}

	// --pkg, applied between phase 1 and every analyser: the package set and the
	// buffers are narrowed together, so nothing is verified that was not asked
	// about and nothing asked about goes unverified.
	if len(p.only) > 0 {
		var rerr error
		if d, raw, rerr = restrictPackages(d, raw, p.only); rerr != nil {
			_ = dropAll()
			return scanRun{}, rerr
		}
	}

	res, summary := sweepWith(ctx, p.cfg, d, p.noNet, p.cl)
	out.Summary = summary
	if cerr != nil {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: "collect-db", Subject: p.cfg.DBPath,
			Reason: fmt.Sprintf("the collector refused this configuration (%v); no package metadata was "+
				"buffered, so nothing was verified", cerr),
		})
	}
	res.Gaps = append(res.Gaps, raw.Gaps...)

	root, rerr := os.OpenRoot(p.cfg.Root)
	if rerr != nil {
		// No confined root means no confined I/O, and there is no unconfined
		// fallback: the whole point of internal/fsx is that a path is resolved
		// once. The scan reports the tier it achieved -- meta, having hashed
		// nothing -- and gaps the difference.
		out.Tier = check.TierMeta
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: "integrity-coverage", Subject: p.cfg.Root,
			Reason: fmt.Sprintf("the scanned root could not be opened (%v), so no file contents were "+
				"verified and no persistence surface was examined; this run reached tier %s",
				rerr, check.TierMeta),
		})
		out.Result = res
		out.Elapsed = time.Since(start)
		finishPrivilege(&out.Result, dropAll)
		return out, nil
	}
	defer root.Close()

	owners := own.IndexIn(root, d.pkgs)

	// The exemption set, derived from the hooks pacman would actually run plus
	// %BACKUP%. ScanHooks' own findings and gaps are NOT taken here: correlate
	// runs the same scan below and reports them once. Its report is reused for
	// the inventory for the same reason.
	hookRep, _ := surfaces.ScanHooks(root, owners)
	active := make([]hook.Hook, 0, len(hookRep.Hooks))
	for _, h := range hookRep.ActiveHooks() {
		if h.Parsed {
			active = append(active, h.Hook)
		}
	}
	ex := check.DeriveExemptions(active, d.pkgs)

	// Phase 2: parse, compare. Parsing happens here, on buffered bytes, after the
	// privileged phase is over, and NOTHING below reads the filesystem for
	// integrity: every digest, mode and link target compared here came off the
	// descriptor collect opened once.
	observed := raw.Index()
	ires := verifyPackages(p.tier, raw.Packages, observed, ex, &out)
	res.Findings = append(res.Findings, ires.Findings...)
	res.Gaps = append(res.Gaps, ires.Gaps...)

	// The unowned setuid sweep, which has input only at paranoid because only
	// paranoid asks collect for the metadata sweep those files live in.
	//
	// Skipped entirely under --pkg: `owners` is then built from the named packages
	// alone, so every setuid binary on the system would resolve to "owned by
	// nobody" and be accused. A restricted oracle may narrow a question, never
	// widen an accusation.
	if len(p.only) == 0 {
		sres := check.UnownedSUID(suidFiles(raw, owners))
		res.Findings = append(res.Findings, sres.Findings...)
		res.Gaps = append(res.Gaps, sres.Gaps...)
	}

	// A tier is a claim about work, so it is derived from the work.
	//
	// Two cases degrade, and the distinction is load-bearing: no package was
	// verified at all (an unreadable or unparseable database), or paths were
	// examined by metadata alone. A run that hashed nothing because every path it
	// found was exempt, absent or a symlink did execute at the tier it was asked
	// for -- there was simply nothing there to hash -- and calling that meta would
	// report a degradation that did not happen.
	if p.tier != check.TierMeta && out.Hashed == 0 && (out.Verified == 0 || out.MetadataOnly > 0) {
		out.Tier = check.TierMeta
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: "integrity-coverage", Subject: "files",
			Reason: fmt.Sprintf("tier %s was requested but no file contents were verified in this run, "+
				"so it reached tier %s: every integrity verdict here rests on metadata that anyone who "+
				"can write a file can also set", p.tier, check.TierMeta),
		})
	}

	// Surfaces and correlation. Correlate returns the surface checks' own
	// findings unchanged plus the clusters they earn; nothing here re-rates them.
	//
	// Skipped under --pkg, for the reason the setuid sweep above is: these checks
	// ask "does any package own this unit / hook / preload entry", and under a
	// restriction the answer is no for everything, which would report a stock
	// system as entirely unowned. The scope line says so above the findings rather
	// than the omission being silent.
	if len(p.only) == 0 {
		cres := correlate.Correlate(root, correlate.Config{
			Owners: owners, Pkgs: d.pkgs, SyncNames: d.syncNames,
			Transactions: p.txs, DBPath: dbRel(p.cfg),
		})
		res.Findings = append(res.Findings, cres.Findings...)
		res.Gaps = append(res.Gaps, cres.Gaps...)
	}

	if p.inventory {
		out.Packages, out.Observed = packageEvidence(raw, d)
		out.Surfaces = surfaceInventory(root, owners, hookRep)
	}

	res.Gaps = dedupeGaps(res.Gaps)
	out.Result = res
	out.Elapsed = time.Since(start)
	finishPrivilege(&out.Result, dropAll)
	return out, nil
}

// finishPrivilege destroys what is left of the process's privilege and records a
// failure as a coverage gap.
//
// A failed drop is not cosmetic: the report is then rendered, and the state
// directory written, by a process still holding read capability over the whole
// filesystem. That is not what this build promises, so the run says so and
// cannot exit 0.
func finishPrivilege(res *finding.Result, dropAll func() error) {
	if err := dropAll(); err != nil {
		res.Gaps = append(res.Gaps, finding.Gap{
			RuleID: "privdrop", Subject: "process",
			Reason: fmt.Sprintf("privileges could not be dropped after the scan (%v); everything after "+
				"the scan ran with more privilege than this build promises", err),
		})
	}
}

// sweepTrees are the subtrees tier paranoid enumerates for metadata, on top of
// the recorded paths every tier opens. They are the trees packages install into,
// which is where an unowned setuid file has to be to matter; collect.DefaultSkip
// still applies inside them, and what that hides is stated in the rule's limits
// rather than here, because the reader who needs it is reading a finding.
var sweepTrees = []string{"usr", "etc", "opt", "boot", "srv"}

// collectConfig is the collector's configuration for a scan at one tier.
//
// The tier travels INTO phase 1 rather than being applied after it. That is the
// whole shape of spec §11.1's staged model: the process holds the read
// capability only during collection, so a decision to read a root-only file has
// to be taken while it still can be acted on. collect learns which paths to open
// from the plain-text `files` of each package -- a newline split, no
// decompression and no mtree parse -- and the gzip, the vis(3) unescaping and
// every other format parser stay on the unprivileged side of the drop.
func collectConfig(cfg config.Config, t check.Tier) collect.Config {
	cc := collect.DefaultConfig(cfg.Root)
	cc.DBPath = cfg.DBPath
	cc.Walk = []string{dbRel(cfg)}
	cc.Recorded = t.CollectPolicy()
	if t == check.TierParanoid {
		cc.Sweep = sweepTrees
	}
	return cc
}

// dbRel is the local database's path relative to the scanned root.
func dbRel(cfg config.Config) string {
	rel, err := filepath.Rel(cfg.Root, cfg.DBPath)
	if err != nil || rel == ".." || strings.HasPrefix(rel, "../") {
		// Outside the root: collect refuses it, and correlate's default is the
		// only honest answer left.
		return "var/lib/pacman/local"
	}
	return rel
}

// maxVerifyWorkers caps the mtree parses running at once, and it is a MEMORY
// bound rather than a throughput one.
//
// Each in-flight parse holds a decompressed mtree and the []Entry it produces,
// and profiling put 24 concurrent parses -- one per core on the reference
// machine -- at ~130 MiB of live heap, the second-largest single contributor to
// peak RSS. Verification is not the bottleneck: the wall time is in hashing,
// which internal/collect parallelises separately, so capping this costs nothing
// measurable and removes two thirds of the in-flight parse memory. Measured at
// 8: no wall-time change at any tier, RSS down ~13 %. On a machine with fewer
// than 8 cores this is a no-op, which is the right shape -- the cap exists to
// stop a high core count turning into a memory bill.
const maxVerifyWorkers = 8

// verifyPackages parses each buffered mtree, verifies the paths it records
// against the filesystem at the requested tier, and compares the two.
//
// The parse is bounded by internal/mtree's own limits, and every package is
// contained: one crafted mtree costs one coverage gap, not the other 1,409. Each
// worker goroutine carries its own recover, because a panic in a goroutine
// cannot be recovered by the goroutine that started it (INV-9).
func verifyPackages(t check.Tier, pkgs []collect.Package, observed collect.Index, ex check.Exemptions, out *scanRun) finding.Result {
	var (
		mu  sync.Mutex
		res finding.Result
	)
	// The result is merged whatever happened -- an unparseable mtree yields a gap
	// and no observations, and dropping it would turn the one package nobody could
	// verify into silence. Only the COUNT of verified packages is conditional.
	add := func(r finding.Result, o obsCounts, verified bool) {
		mu.Lock()
		defer mu.Unlock()
		res.Findings = append(res.Findings, r.Findings...)
		res.Gaps = append(res.Gaps, r.Gaps...)
		out.Hashed += o.hashed
		out.HashedBytes += o.bytes
		out.MetadataOnly += o.metadataOnly
		if verified {
			out.Verified++
		}
	}
	gap := func(g finding.Gap) {
		mu.Lock()
		defer mu.Unlock()
		res.Gaps = append(res.Gaps, g)
	}

	var next atomic.Int64
	var wg sync.WaitGroup
	workers := min(max(runtime.NumCPU(), 1), maxVerifyWorkers, len(pkgs))
	for w := range workers {
		wg.Add(1)
		go func(worker int) {
			defer wg.Done()
			// The recover that keeps the process alive has to be here, in the
			// goroutine's own top-level body.
			err, _ := safe.Run(fmt.Sprintf("verify-worker-%d", worker), func() error {
				for {
					i := int(next.Add(1)) - 1
					if i >= len(pkgs) {
						return nil
					}
					pkg := pkgs[i]
					name := pkgNameFromDir(pkg.Dir)
					perr, panicked := safe.Run(pkg.Dir, func() error {
						add(verifyOne(t, name, pkg, observed, ex))
						return nil
					})
					if perr != nil {
						reason := fmt.Sprintf("%v; its recorded paths were not verified", perr)
						if panicked {
							reason = fmt.Sprintf("%v; the failure is in aurvet, not necessarily in the "+
								"package, and its recorded paths were not verified", perr)
						}
						gap(finding.Gap{RuleID: "integrity-coverage", Subject: name, Reason: reason})
					}
				}
			})
			if err != nil {
				gap(finding.Gap{
					RuleID: "integrity-coverage", Subject: fmt.Sprintf("verify-worker-%d", worker),
					Reason: fmt.Sprintf("%v; the packages it had not yet reached were not verified", err),
				})
			}
		}(w)
	}
	wg.Wait()

	sort.SliceStable(res.Findings, func(i, j int) bool { return res.Findings[i].Subject < res.Findings[j].Subject })
	sort.SliceStable(res.Gaps, func(i, j int) bool { return res.Gaps[i].Subject < res.Gaps[j].Subject })
	return res
}

// obsCounts is what one package's observations amounted to, in the terms the
// achieved tier is derived from.
type obsCounts struct {
	hashed       int
	metadataOnly int
	bytes        int64
}

// verifyOne handles one package: parse, join, compare. The bool reports
// whether this package was verified at all, so a package that never got past its
// mtree is not counted as covered.
func verifyOne(t check.Tier, name string, pkg collect.Package, observed collect.Index, ex check.Exemptions) (finding.Result, obsCounts, bool) {
	if len(pkg.MTree) == 0 {
		// collect already gapped the read that failed. A second gap for the same
		// shortfall teaches an operator to skim.
		return finding.Result{}, obsCounts{}, false
	}
	entries, err := mtree.ParseGzip(bytes.NewReader(pkg.MTree))
	if err != nil {
		return finding.Result{Gaps: []finding.Gap{{
			RuleID: "integrity-mtree", Subject: name,
			Reason: fmt.Sprintf("the package's mtree could not be parsed (%v); none of its recorded "+
				"paths were verified, so this package is not covered by this run", err),
		}}}, obsCounts{}, false
	}
	if beforeVerifyForTest != nil {
		beforeVerifyForTest()
	}
	obs := t.ObserveFiles(entries, observed, ex)

	var c obsCounts
	for _, o := range obs {
		switch o.Kind {
		case check.ObsHashed:
			c.hashed++
			c.bytes += o.Size
		case check.ObsMetadataOnly:
			c.metadataOnly++
		}
	}
	return check.Integrity(name, entries, obs, ex, t), c, true
}

// suidFiles is check.UnownedSUID's input: every setuid or setgid regular file
// phase 1 described, with the package that claims it if the ownership index knew
// one.
//
// The mode comes from the fstat of the descriptor the collector opened, not from
// what any package recorded, because the mode that matters is the one the kernel
// will honour. An ownership lookup that FAILED yields no finding: Resolve's third
// state exists precisely so "I could not tell" cannot masquerade as "nobody owns
// it", which here would be a fabricated accusation.
func suidFiles(raw collect.Raw, owners *own.Owners) []check.SUIDFile {
	var out []check.SUIDFile
	for _, f := range raw.Files {
		if f.Kind != collect.KindFile || f.Mode&0o6000 == 0 {
			continue
		}
		pkg, st, err := owners.Resolve(f.Path)
		if err != nil || st == own.Unresolved {
			continue
		}
		if st == own.Owned && pkg == "" {
			// Owned by a package the index could not name. Reporting it as
			// unowned would turn a naming failure into an accusation.
			continue
		}
		out = append(out, check.SUIDFile{Path: f.Path, Mode: f.Mode, Owner: pkg})
	}
	return out
}

// pkgNameFromDir recovers a package name from its local-database directory,
// whose layout is name-version-release. Splitting on the last two hyphens is
// pacman's own rule; a directory that does not have two is returned unchanged
// rather than guessed at, because the name is only ever used as a subject.
func pkgNameFromDir(dir string) string {
	i := strings.LastIndex(dir, "-")
	if i <= 0 {
		return dir
	}
	j := strings.LastIndex(dir[:i], "-")
	if j <= 0 {
		return dir
	}
	return dir[:j]
}

// packageEvidence is the per-package evidence a baseline commits to: the version,
// the foreignness verdict, and the digest of the mtree ITSELF.
//
// The mtree digest is the one genuinely new capability in this half of the tool.
// `pacman -Qkk` verifies files against these digests and cannot detect a change
// to the record it verifies against; a signed baseline over the mtree digests
// can. The digest is taken from the bytes the collector buffered, so it describes
// the same read that verification used.
func packageEvidence(raw collect.Raw, d dbs) ([]baseline.PackageInput, []baseline.ObservedPackage) {
	byDir := make(map[string]collect.Package, len(raw.Packages))
	for _, p := range raw.Packages {
		byDir[p.Dir] = p
	}
	var (
		pins []baseline.PackageInput
		obs  []baseline.ObservedPackage
	)
	for _, p := range d.pkgs {
		pin := baseline.PackageInput{
			Name: p.Name, Version: p.Version, Foreign: alpm.IsForeign(p, d.syncNames),
		}
		o := baseline.ObservedPackage{Name: p.Name, Version: p.Version, InstallDate: p.InstallDate}
		cp, ok := byDir[p.Name+"-"+p.Version]
		switch {
		case !ok || len(cp.MTree) == 0:
			pin.MtreeUnread = "the package's mtree was not buffered by the collector"
			o.MtreeUnread = pin.MtreeUnread
		default:
			sum, n, err := baseline.MtreeDigest(bytes.NewReader(cp.MTree))
			if err != nil {
				pin.MtreeUnread = fmt.Sprintf("the package's mtree could not be digested: %v", err)
				o.MtreeUnread = pin.MtreeUnread
				break
			}
			pin.MtreeSHA256, pin.MtreeBytes = baseline.Hex(sum[:]), n
			o.MtreeSHA256 = pin.MtreeSHA256
		}
		pins = append(pins, pin)
		obs = append(obs, o)
	}
	return pins, obs
}

// surfaceInventory records the execution surfaces a baseline commits to: every
// hook pacman would read, every unit file, and every enablement link.
//
// WHAT IT DOES NOT COVER, and the reason is structural rather than an oversight:
// internal/surfaces exposes an enumerable inventory for hooks, units and
// enablement links (HookReport, LoadUnits, WantsSurvey) but not for the remaining
// surfaces -- ld.so.preload, generator directories, profile.d and autostart are
// reachable only through Misc's FINDINGS, which are the unowned subset. So those
// four families appear in a baseline only where a check already had something to
// say about them, and a baseline diff cannot notice a package-owned generator
// being replaced except through its package's digest.
func surfaceInventory(root *os.Root, owners *own.Owners, rep surfaces.HookReport) []baseline.SurfaceInput {
	var out []baseline.SurfaceInput
	add := func(kind, rel, pkg string, st own.State) {
		out = append(out, baseline.SurfaceInput{
			Kind: kind, Path: "/" + strings.TrimPrefix(rel, "/"), Owner: pkg,
			State: st.String(), SHA256: surfaceDigest(root, rel),
		})
	}
	for _, h := range rep.Hooks {
		add("hook", h.Path, h.Pkg, h.State)
	}
	units, _ := surfaces.LoadUnits(root, surfaces.DefaultUnitDirs)
	for _, u := range units {
		pkg, st, _ := owners.Resolve(u.Path)
		add("unit", u.Path, pkg, st)
	}
	survey, _ := surfaces.SurveyWants(root, owners, surfaces.DefaultUnitDirs)
	for _, e := range append(append([]surfaces.WantsEntry{}, survey.Subjects...), survey.OwnedTargets...) {
		add("enablement", e.Path, e.Pkg, e.State)
	}
	sort.SliceStable(out, func(i, j int) bool {
		if out[i].Kind != out[j].Kind {
			return out[i].Kind < out[j].Kind
		}
		return out[i].Path < out[j].Path
	})
	return out
}

// surfaceDigest is the digest of one surface file, read through the same confined
// open every other read uses. An empty result means "not established" and is
// never a claim about content: baseline.Manifest treats an empty digest as absent.
func surfaceDigest(root *os.Root, rel string) string {
	f, st, err := fsx.OpenConfined(root, strings.TrimPrefix(rel, "/"))
	if err != nil {
		return ""
	}
	defer f.Close()
	sum, _, err := fsx.Digest(f, st)
	if err != nil {
		return ""
	}
	return sum
}

// dedupeGaps collapses gaps that are identical in rule, subject and reason.
//
// They arise because two analysers legitimately read the same directory: the
// hook scan that derives the exemptions and the one correlation runs are the same
// scan, and a directory neither could list is one shortfall, not two. Only exact
// triples are collapsed, so a gap that says anything different survives.
func dedupeGaps(gaps []finding.Gap) []finding.Gap {
	seen := make(map[[3]string]bool, len(gaps))
	out := make([]finding.Gap, 0, len(gaps))
	for _, g := range gaps {
		k := [3]string{g.RuleID, g.Subject, g.Reason}
		if seen[k] {
			continue
		}
		seen[k] = true
		out = append(out, g)
	}
	return out
}
