// cmd/aurvet/bundle.go
//
// The `bundle` subcommand: spec §12's redacted reproducer.
//
// > `bundle <fingerprint>` emits a redacted, self-contained fixture root
// > reproducing the finding -- which costs almost nothing because offline-root
// > already exists, and makes every false-positive report a test case.
//
// The "costs almost nothing" is true only because --offline-root exists and
// testdata/roots/{stock,cruft,malicious} already fix the shape. This command
// emits that shape and nothing more.
//
// # What is deliberate here
//
//   - The output directory is a POSITIONAL, not a flag, and it defaults to
//     ./aurvet-bundle-<id> in the working directory. A required flag on a
//     command an operator reaches for once, mid-frustration, is a command they
//     get wrong; a default that wrote somewhere central would be a command that
//     surprises them.
//
//   - Under --offline-root the output directory must lie OUTSIDE the examined
//     tree (INV-5). Bundling FROM an offline root is legitimate and useful --
//     that is how a maintainer re-bundles a bundle -- so this is a check on the
//     destination rather than a blanket refusal.
//
//   - The redaction and the reproduction verdict both live in internal/repro,
//     which owns the honesty of the artefact. This file's job is to resolve the
//     finding, place the directory, and say out loud what the operator is about
//     to publish.
package main

import (
	"context"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/alpm"
	"github.com/lookatitude/aurvet/internal/buildinfo"
	"github.com/lookatitude/aurvet/internal/check"
	"github.com/lookatitude/aurvet/internal/config"
	"github.com/lookatitude/aurvet/internal/repro"
)

type bundleOpts struct {
	offlineRoot string
	noNet       bool
	jsonOut     bool
	tier        string

	// fingerprint is the finding id from the report, and dir the destination.
	fingerprint string
	dir         string

	// scan is a test seam. nil means "run the real full scan".
	scan func(cfg config.Config, tier check.Tier) (scanRun, error)

	// now is a test seam for the README's timestamp. The zero value means
	// time.Now(); nothing about the bundle's CONTENT depends on it.
	now time.Time
}

// runBundle is `aurvet bundle <fingerprint> [directory]`.
//
// Exit codes, chosen deliberately and documented in the man page:
//
//	0  the bundle was written AND this finding's class reproduces from it.
//	2  usage: no such finding id, a destination that is not usable, a
//	   destination inside the examined tree.
//	3  the bundle was written but this finding's class CANNOT be reproduced from
//	   it, or the builder could not include something it meant to. Both are
//	   incomplete coverage of the thing that was asked for, and exit 3 is what
//	   the contract calls that.
//
// 1 is never returned. `bundle` reaches no verdict about the system -- it copies
// a shape into a directory -- and returning "findings at or above the floor"
// would make a shell script treat a successful bundle of a critical as a
// failure of the bundling.
func runBundle(opts bundleOpts, stdout, stderr io.Writer) int {
	if strings.TrimSpace(opts.fingerprint) == "" {
		bundleUsage(stderr)
		return exitUsage
	}
	euid := os.Geteuid()
	cfg, err := config.Resolve(opts.offlineRoot, euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	tier, err := check.ParseTier(opts.tier)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	dir := opts.dir
	if strings.TrimSpace(dir) == "" {
		dir = "aurvet-bundle-" + opts.fingerprint
	}
	abs, err := filepath.Abs(dir)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	if code := refuseDestinationInsideTheExaminedTree(cfg.Root, opts.offlineRoot, abs, stderr); code != 0 {
		return code
	}

	// The SAME scan every other command runs. A cheaper one here and `bundle`
	// could not resolve the id of a finding `scan` printed -- the tool would
	// report a finding and then deny knowing it.
	run, err := runBundleScan(opts, cfg, tier)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	f, ok := findingByID(run.Result, opts.fingerprint)
	if !ok {
		writeUnknownFingerprint(stderr, run.Result, opts.fingerprint)
		return exitUsage
	}

	pkgs, perr := bundlePackages(cfg)
	if perr != nil {
		// Not fatal: the bundle is still worth having, and the missing ownership
		// data is stated rather than papered over.
		fmt.Fprintf(stderr, "aurvet: the local package database could not be read (%v); the bundle "+
			"will carry no package entries, so every path in it will read as unowned\n", perr)
	}

	rep, err := repro.Build(abs, repro.Input{
		Root: cfg.Root, Finding: f, FindingID: opts.fingerprint,
		Packages: pkgs, Version: buildinfo.String(), Now: bundleNow(opts),
	})
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}

	if opts.jsonOut {
		if err := writeJSON(stdout, bundleDoc(rep)); err != nil {
			fmt.Fprintf(stderr, "aurvet: %v\n", err)
			return exitUsage
		}
		return bundleExit(rep)
	}
	writeBundleReport(stdout, rep)
	return bundleExit(rep)
}

func bundleExit(rep repro.Report) int {
	if !rep.Reproduction.Reproduces || len(rep.Gaps) > 0 {
		return exitIncomplete
	}
	return exitClean
}

func bundleUsage(w io.Writer) {
	fmt.Fprintln(w, "usage: aurvet bundle <fingerprint> [directory]")
	fmt.Fprintln(w, "  Emits a redacted, self-contained fixture root reproducing one finding, so a")
	fmt.Fprintln(w, "  false-positive report can be a test case instead of a description.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  NO FILE'S OWN BYTES ARE COPIED. Every regular file in the bundle is a")
	fmt.Fprintln(w, "  zero-byte placeholder or a file rebuilt from the few directives aurvet's")
	fmt.Fprintln(w, "  compiled checks parse -- and within a command, only the program is kept:")
	fmt.Fprintln(w, "  `ExecStart=/usr/bin/foo --token <secret>` is emitted without its arguments.")
	fmt.Fprintln(w, "  Package database entries are synthesised and never")
	fmt.Fprintln(w, "  carry %PACKAGER%. Home paths inside file contents are redacted; a home path")
	fmt.Fprintln(w, "  the finding is ABOUT is published as-is and is listed for you before you send it.")
	fmt.Fprintln(w, "")
	fmt.Fprintln(w, "  The directory defaults to ./aurvet-bundle-<fingerprint> and must be empty.")
	fmt.Fprintln(w, "  exit 0 the bundle was written and this class of finding reproduces from it")
	fmt.Fprintln(w, "  exit 2 no such finding id, or the destination is unusable")
	fmt.Fprintln(w, "  exit 3 written, but this class cannot be reproduced from a bundle, or")
	fmt.Fprintln(w, "         something it meant to include could not be read")
}

// refuseDestinationInsideTheExaminedTree is INV-5. An --offline-root run is
// examining somebody else's filesystem, usually from a rescue environment;
// writing the reproducer into that tree modifies the evidence.
func refuseDestinationInsideTheExaminedTree(root, offlineRoot, dst string, stderr io.Writer) int {
	if offlineRoot == "" {
		return 0
	}
	absRoot, err := filepath.Abs(root)
	if err != nil {
		return 0
	}
	rel, err := filepath.Rel(absRoot, dst)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return 0
	}
	fmt.Fprintf(stderr, "aurvet: refusing to write the bundle to %s: it is inside --offline-root %s, "+
		"and nothing is written under the examined tree (INV-5). Name a destination outside it.\n",
		dst, absRoot)
	return exitUsage
}

// runBundleScan runs the same full scan `scan` runs, through a seam so a test
// can exercise the command hermetically.
func runBundleScan(opts bundleOpts, cfg config.Config, tier check.Tier) (scanRun, error) {
	if opts.scan != nil {
		return opts.scan(cfg, tier)
	}
	return fullScan(context.Background(), pipeline{
		cfg: cfg, tier: tier, noNet: opts.noNet, euid: os.Geteuid(),
	})
}

// bundlePackages loads the local package set the bundle narrows its database
// entries from.
func bundleNow(opts bundleOpts) time.Time {
	if !opts.now.IsZero() {
		return opts.now
	}
	return time.Now().UTC()
}

func bundlePackages(cfg config.Config) ([]alpm.Package, error) {
	d, err := loadDBs(cfg)
	if err != nil {
		return nil, err
	}
	return d.pkgs, nil
}

func writeBundleReport(w io.Writer, rep repro.Report) {
	fmt.Fprintf(w, "bundle written to %s\n", rep.Dir)
	fmt.Fprintf(w, "  finding: [%s] %s %s:%s (%s)\n", rep.Severity, rep.RuleID,
		rep.SubjectKind, rep.Subject, rep.FindingID)
	fmt.Fprintf(w, "  files:   %d, package entries: %d\n", len(rep.Files), len(rep.Packages))
	fmt.Fprintln(w, "  contents: NO file's own bytes were copied. Every regular file is a zero-byte")
	fmt.Fprintln(w, "            placeholder or a file rebuilt from the directives a check parses, and")
	fmt.Fprintln(w, "            a rebuilt command keeps its PROGRAM without its arguments; package")
	fmt.Fprintln(w, "            entries are synthesised and carry no %PACKAGER%; home paths inside")
	fmt.Fprintln(w, "            file contents are redacted. README.md says it per file.")
	if rep.Reproduction.Reproduces {
		fmt.Fprintf(w, "  reproduce: %s\n",
			strings.Replace(rep.Reproduction.Command, "<bundle>", rep.Dir, 1))
		fmt.Fprintf(w, "             the finding should reappear with the same id, %s\n", rep.FindingID)
	} else {
		fmt.Fprintf(w, "  !! THIS FINDING DOES NOT REPRODUCE FROM THIS BUNDLE.\n     %s\n",
			rep.Reproduction.Why)
		fmt.Fprintln(w, "     The bundle still carries the shape of the paths involved and is worth")
		fmt.Fprintln(w, "     attaching; it is labelled so nobody debugs the wrong absence.")
		if rep.RedactedEntryPoint != "" {
			fmt.Fprintf(w, "     The redacted program was %s. It is printed HERE and nowhere in the\n",
				rep.RedactedEntryPoint)
			fmt.Fprintln(w, "     bundle, because the bundle is the part you publish.")
		}
	}
	if len(rep.HomePaths) > 0 {
		fmt.Fprintf(w, "\n  !! %d path(s) under /home are published AS THEY ARE, because the finding is\n",
			len(rep.HomePaths))
		fmt.Fprintln(w, "     about them and redacting them would leave nothing to reproduce:")
		for _, p := range rep.HomePaths {
			fmt.Fprintf(w, "       /%s\n", p)
		}
		fmt.Fprintln(w, "     Delete the bundle rather than publishing it if that is not acceptable.")
	}
	for _, g := range rep.Gaps {
		fmt.Fprintf(w, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason)
	}
}

func bundleDoc(rep repro.Report) map[string]any {
	gaps := make([]map[string]string, 0, len(rep.Gaps))
	for _, g := range rep.Gaps {
		gaps = append(gaps, map[string]string{
			"rule_id": g.RuleID, "subject": g.Subject, "reason": g.Reason,
		})
	}
	files := make([]map[string]any, 0, len(rep.Files))
	for _, f := range rep.Files {
		files = append(files, map[string]any{
			"path": f.Path, "disposition": string(f.Disposition),
			"bytes": f.Bytes, "target": f.Target, "note": f.Note,
		})
	}
	return map[string]any{
		"action": "bundle", "dir": rep.Dir, "schema_version": rep.Schema,
		"finding_id": rep.FindingID, "rule_id": rep.RuleID,
		"subject": rep.Subject, "subject_kind": rep.SubjectKind, "severity": rep.Severity,
		"reproduces": rep.Reproduction.Reproduces,
		"why_not":    rep.Reproduction.Why,
		"command":    rep.Reproduction.Command,
		"files":      files, "packages": rep.Packages,
		"home_paths_published_as_is": rep.HomePaths,
		"gaps":                       gaps,
	}
}
