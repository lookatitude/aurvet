// Command aurvet detects compromised AUR packages and verifies that a
// system has not been tampered with.
package main

import (
	"context"
	"flag"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/aur"
	"github.com/lookatitude/aurvet/internal/buildinfo"
	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/report"
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
	minSeverity := fs.String("min-severity", "",
		"reporting floor: info, suspicious, critical (default from config)")

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

	if len(operands) == 0 {
		fmt.Fprintln(stderr, "usage: aurvet [flags] <command>")
		fmt.Fprintln(stderr, "commands: scan, explain, doctor, version")
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

	cmd, cmdArgs := operands[0], operands[1:]

	switch cmd {
	// version resolves no config and touches no filesystem, deliberately. It
	// is dispatched before every other command for that reason: the moment
	// someone asks which build they are running is usually the moment the
	// system is broken, and a `version` that needed a readable pacman DB would
	// be unavailable exactly when it is needed to report a bug.
	case "version":
		if len(cmdArgs) != 0 {
			fmt.Fprintf(stderr, "aurvet: version takes no arguments (got %q)\n", cmdArgs)
			return exitUsage
		}
		fmt.Fprintln(stdout, buildinfo.String())
		return exitClean

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
			offlineRoot: *offlineRoot,
			noNet:       *noNet,
			jsonOut:     *jsonOut,
			sinceLast:   *sinceLast,
			minSeverity: *minSeverity,
		}, stdout, stderr)

	case "explain":
		if len(cmdArgs) == 0 {
			fmt.Fprintln(stderr, "usage: aurvet explain <fingerprint>")
			return exitUsage
		}
		return runExplain(*offlineRoot, *noNet, cmdArgs[0], stdout, stderr)

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

	// stateDir overrides where reports are persisted. "" means "decide from
	// config", which is what run() always passes.
	stateDir string
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

// runScan resolves config, runs the provenance sweep, persists the result,
// renders the report and returns report.ExitCode(verdict, floor) -- and nothing
// else -- on the success path (spec §14).
func runScan(opts scanOpts, stdout, stderr io.Writer) int {
	euid := os.Geteuid()
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

	res, summary, err := sweep(context.Background(), cfg, opts.noNet, opts.cl)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
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

// runExplain re-runs the same sweep as scan, then renders the rationale for
// one finding. A successful explain always returns exitClean: it is a query
// against the sweep's findings, not a verdict on the sweep itself, so it must
// not be "fixed" later to return the scan's own exit code.
func runExplain(offlineRoot string, noNet bool, fingerprint string, stdout, stderr io.Writer) int {
	cfg, err := config.Resolve(offlineRoot, os.Geteuid())
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	res, _, err := sweep(context.Background(), cfg, noNet, nil)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

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
// cl is a test seam: nil means "build the real HTTP client", so production
// call sites (runScan, runExplain) are unchanged by its presence. Without it
// no hermetic test could reach scan's exit-0 path through a network check --
// sweep hardcoded aur.NewHTTP with no way to inject aur.Fake, which is why two
// exit-0 criticals (report-sec findings 1 and 4) survived task 9's own suite.
func sweep(ctx context.Context, cfg config.Config, noNet bool, cl aur.Client) (finding.Result, report.Summary, error) {
	pkgs, localGaps, err := alpm.LoadLocalDB(cfg.DBPath)
	if err != nil {
		return finding.Result{}, report.Summary{}, err
	}

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
		return finding.Result{}, report.Summary{}, err
	}
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

	network := cfg.Network && !noNet
	if network && cl == nil {
		cl = aur.NewHTTP("https://aur.archlinux.org", &http.Client{Timeout: 20 * time.Second})
	}

	res := check.Provenance(ctx, pkgs, syncNames, syncGaps, cl, network)
	res.Gaps = append(res.Gaps, extraGaps...)

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

	return res, report.Summary{Total: len(pkgs), Foreign: foreign}, nil
}
