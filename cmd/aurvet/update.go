// cmd/aurvet/update.go
//
// The `update` subcommand and the trust facts `--version` prints (P5 task 7).
//
// # Never automatic
//
// There is no background fetch, no update-on-scan and no "check for updates"
// side effect anywhere in this tool. `update` is the only code path that reaches
// the network for indicator data, and it runs when an operator -- or a timer the
// operator enabled by hand -- says so. packaging/systemd/aurvet-update.timer is
// not enabled by the package.
//
// # The verification order is not reimplemented here
//
// internal/bundle owns it: signature over RAW bytes before any parse, size cap
// and timeout before any read, no cross-host redirects. This file fetches bytes
// through bundle.Fetcher, which has no reference to any parser type, and hands
// them to bundle.Verify. It never decodes a byte of either document itself, and
// it stores nothing that Verify did not authenticate.
//
// # Fail closed, in three distinguishable ways
//
//	refused      not trustworthy. Nothing is cached, nothing is believed, the
//	             operator is told why. Exit 3.
//	expired      trustworthy but stale. The bytes are cached (stale indicators
//	             still find known-bad things), coverage is INCOMPLETE, and the
//	             run cannot report clean. Exit 3.
//	unavailable  there is no bundle. Its own state, not a clean result.
//
// A retired root set refuses with the publisher's upgrade message, and the
// active indicator count is printed on every run so a drop toward zero is
// visible: a signed bundle that removes detections is an attack, not an update.
package main

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/buildinfo"
	"github.com/lookatitude/aurvet/internal/bundle"
	"github.com/lookatitude/aurvet/internal/config"
)

// DefaultBundleURL is where the published indicator bundle lives.
//
// It is a compiled-in constant rather than configuration on purpose: a
// configurable update origin is a second place an attacker can aim a tool at,
// and the signature -- not the URL -- is what makes a bundle trustworthy anyway.
// -bundle-url exists so a mirror or an air-gapped copy can be named explicitly
// by whoever runs the command, which is a deliberate act and visible in the
// process table.
const DefaultBundleURL = "https://aurvet.dev/indicators"

// updateOpts is `update`'s input.
type updateOpts struct {
	offlineRoot string
	jsonOut     bool
	baseURL     string

	// check is `update --check` (§14): decide, report, write nothing. It is a
	// suppression of the two writes and of nothing else -- the delegation and the
	// bundle are still fetched, authenticated and judged, because a --check that
	// reported anything less than the real verdict would be a --check nobody could
	// act on. internal/bundle makes this possible rather than approximate: Verify
	// performs no I/O and reads no clock, so the deciding half is already separate
	// from the persisting half.
	check bool

	// Seams. Their zero values select production behaviour.
	//
	// roots overrides bundle.EmbeddedRoots. THIS IS THE MARKED SEAM for the
	// human-gated release key material: this build embeds no root keys (the
	// 2-of-3 hardware generation has not happened), so EmbeddedRoots returns
	// ErrNoRootKeys and every production run of `update` refuses. The seam lets
	// the accept path be exercised with throwaway software keys; it is
	// unreachable from any flag, and nothing in this file generates a key.
	roots      *bundle.RootSet
	stateDir   string
	cacheDir   string
	euid       *int
	now        time.Time
	client     *http.Client
	allowPlain bool
}

// refuseUpdate is every early exit from `update`.
//
// It exists so that no refusal can be written that forgets to say what it costs.
// An operator (or a systemd unit) reading "the delegation could not be fetched"
// still has to be told the consequence in the same breath: indicator coverage is
// incomplete, and no run may report clean on the strength of it. Exit 3, always
// -- there is no refusal here that means "fine".
func refuseUpdate(stderr io.Writer, format string, args ...any) int {
	fmt.Fprintf(stderr, "aurvet: "+format+"\n", args...)
	fmt.Fprintln(stderr, "aurvet: indicator coverage is INCOMPLETE: nothing was cached, nothing was "+
		"believed, and no scan may present a clean bill of health on the strength of the indicator set.")
	return exitIncomplete
}

func runUpdate(opts updateOpts, stdout, stderr io.Writer) int {
	// INV-5 first, before anything is resolved: an update WRITES -- the cache and
	// the anti-rollback floor -- and under --offline-root there is no correct
	// destination for either. The floor in particular describes this host's own
	// update history, and writing one while inspecting a rescue mount would file a
	// claim about the wrong machine. A usage error, never a silent no-op.
	if opts.offlineRoot != "" {
		fmt.Fprintln(stderr, "aurvet: `update` writes the bundle cache and the anti-rollback floor, "+
			"and --offline-root means nothing is written (INV-5). The floor is a record of THIS host's "+
			"update history; there is no correct place to put it while examining another filesystem. "+
			"Run `aurvet update` without --offline-root.")
		return exitUsage
	}
	euid := os.Geteuid()
	if opts.euid != nil {
		euid = *opts.euid
	}
	now := opts.now
	if now.IsZero() {
		now = time.Now()
	}
	cfg, err := config.Resolve("", euid)
	if err != nil {
		fmt.Fprintf(stderr, "aurvet: %v\n", err)
		return exitUsage
	}
	stateDir := opts.stateDir
	if stateDir == "" {
		stateDir = cfg.StateDir
	}
	cacheDir := opts.cacheDir
	if cacheDir == "" {
		cacheDir = bundleCacheDir(euid)
	}

	// The root set BEFORE the network. A build that cannot authenticate a bundle
	// has no business fetching one: it would burn a request, write bytes it can
	// never believe, and give an operator the impression that something was
	// updated.
	roots, err := resolveRoots(opts)
	if err != nil {
		fmt.Fprintln(stderr, "aurvet: no request was made: a build that cannot authenticate a bundle "+
			"has no business fetching one. Every other subsystem (provenance, integrity, surfaces, "+
			"baseline) is unaffected.")
		return refuseUpdate(stderr, "%v", err)
	}

	fs, err := bundle.OpenFloor(stateDir, bundle.FloorOptions{
		CacheDir: cacheDir, OfflineRoot: opts.offlineRoot, EUID: euid,
	})
	if err != nil {
		return refuseUpdate(stderr, "%v", err)
	}
	floor, present, err := fs.Load()
	if err != nil {
		// Not "there is no floor". An unreadable or unsafely permissioned floor is
		// exactly the state a rollback attack wants to manufacture, so it is a
		// refusal to proceed rather than a fresh start.
		fmt.Fprintln(stderr, "aurvet: refusing to continue. An unreadable floor is not an absent one, "+
			"and treating it as absent is how a replayed bundle gets accepted.")
		return refuseUpdate(stderr, "the anti-rollback floor at %s could not be read: %v",
			fs.Path(), err)
	}

	base := strings.TrimSuffix(opts.baseURL, "/")
	if base == "" {
		base = DefaultBundleURL
	}
	arts, gaps, err := fetchArtifacts(context.Background(), opts, roots, base)
	if err != nil {
		fmt.Fprintln(stderr, "aurvet: the previously cached bundle, if any, is untouched.")
		return refuseUpdate(stderr, "%v", err)
	}

	st := bundle.Verify(bundle.Input{
		Roots:          roots,
		DelegationRaw:  arts.DelegationRaw,
		DelegationSigs: arts.DelegationSigs,
		BundleRaw:      arts.BundleRaw,
		BundleSig:      arts.BundleSig,
		Floor:          floor,
		FloorPresent:   present,
		Now:            now,
	})

	// Only authenticated bytes are ever cached. A refused document is not written:
	// the cache is untrusted storage, but writing something we have just judged
	// hostile into it would turn every later run into a re-refusal and hide the
	// last artefact that did verify.
	//
	// Under --check neither write happens. What WOULD have happened is recorded
	// instead, so the report can state it: "nothing was written" and "there was
	// nothing to write" are different answers, and an operator deciding whether to
	// run the real update needs the first one to be distinguishable.
	wouldStore, wouldAdvance := st.State.UsableIndicators(), st.FloorAdvances
	stored := false
	if wouldStore && !opts.check {
		if err := bundle.OpenCache(cacheDir).Store(arts); err != nil {
			return refuseUpdate(stderr, "the verified bundle could not be cached: %v", err)
		}
		stored = true
	}
	floorSaved := false
	if st.FloorAdvances && !opts.check {
		if err := fs.Save(st.NextFloor); err != nil {
			fmt.Fprintln(stderr, "aurvet: the bundle verified, but this host has no record that it "+
				"did, so an older bundle would not be recognised as a replay on the next run.")
			return refuseUpdate(stderr, "the anti-rollback floor could not be advanced: %v", err)
		}
		floorSaved = true
	}

	outcome := updateOutcome{
		stored: stored, floorSaved: floorSaved, softSigs: gaps,
		check: opts.check, wouldStore: wouldStore, wouldAdvance: wouldAdvance,
	}
	if opts.jsonOut {
		return jsonOr(stdout, stderr, updateDoc(st, base, cacheDir, fs.Path(), outcome))
	}
	writeUpdateReport(stdout, stderr, st, base, cacheDir, outcome)
	return updateExit(st, gaps)
}

// updateExit maps the outcome onto the exit-code contract.
//
// Anything short of an active bundle with no coverage statements is exit 3, and
// there is no path here that returns 0 on a refusal or an expiry. That is what
// "never report clean" means in a code: exit 0 from `update` says the indicator
// set is current and complete, and nothing else may say it.
func updateExit(st bundle.Status, gaps int) int {
	if !st.State.CoverageComplete() || gaps > 0 || len(st.Gaps) > 0 {
		return exitIncomplete
	}
	return exitClean
}

// -- fetching -----------------------------------------------------------------

// fetchArtifacts retrieves the delegation, its root signatures and the bundle.
//
// It returns BYTES. Nothing here parses, and the returned count of soft failures
// is a coverage statement rather than a suppressed error: a root signature that
// could not be fetched is not an error while the threshold is still met, but it
// is not nothing either -- the next rotation may need it.
func fetchArtifacts(ctx context.Context, opts updateOpts, roots bundle.RootSet, base string) (bundle.Artifacts, int, error) {
	f := bundle.NewFetcher(opts.client, bundle.DefaultFetchTimeout, bundle.MaxBundleBytes)
	// requireTLS is true in production. The only caller that passes false is a
	// test pointing at a local httptest server; there is no flag for it, because a
	// flag that turns off transport security on a security tool will be found and
	// used.
	tls := !opts.allowPlain

	get := func(name string) ([]byte, error) {
		return f.Get(ctx, base+"/"+name, tls)
	}

	var a bundle.Artifacts
	var err error
	if a.DelegationRaw, err = get(bundle.CacheDelegationFile); err != nil {
		return bundle.Artifacts{}, 0, fmt.Errorf("the root-signed delegation could not be fetched: %w", err)
	}
	// One signature file per root key, numbered. The threshold count is REQUIRED;
	// the rest are optional, because a 2-of-3 set legitimately publishes two.
	soft := 0
	for i := 1; i <= roots.Size(); i++ {
		sig, serr := get(fmt.Sprintf("%s.sig.%d", bundle.CacheDelegationFile, i))
		if serr != nil {
			if i <= roots.Threshold() {
				return bundle.Artifacts{}, 0, fmt.Errorf("delegation signature %d of the required %d "+
					"could not be fetched: %w", i, roots.Threshold(), serr)
			}
			soft++
			continue
		}
		a.DelegationSigs = append(a.DelegationSigs, sig)
	}
	if a.BundleRaw, err = get(bundle.CacheBundleFile); err != nil {
		return bundle.Artifacts{}, 0, fmt.Errorf("the indicator bundle could not be fetched: %w", err)
	}
	if a.BundleSig, err = get(bundle.CacheBundleFile + ".sig"); err != nil {
		return bundle.Artifacts{}, 0, fmt.Errorf("the bundle's signature could not be fetched, so the "+
			"bundle cannot be authenticated and was discarded: %w", err)
	}
	return a, soft, nil
}

// resolveRoots returns the root key set this run will trust.
//
// The seam is a struct field, never a flag: a build whose root set could be
// chosen at the command line would have no root set at all.
func resolveRoots(opts updateOpts) (bundle.RootSet, error) {
	if opts.roots != nil {
		return *opts.roots, nil
	}
	return bundle.EmbeddedRoots()
}

// bundleCacheDir resolves where fetched bundles are parked.
//
// Root gets /var/cache/aurvet (spec §11's storage table). An unprivileged run
// gets the XDG cache directory, because /var/cache/aurvet is root-owned and an
// unprivileged `update` that failed with EACCES would look like a network
// problem.
//
// AURVET_CACHE_DIR is honoured only when euid != 0, for the same reason
// AURVET_STATE_DIR is: otherwise an unprivileged local account chooses where a
// root-privileged security tool puts the data it later trusts.
func bundleCacheDir(euid int) string {
	if euid == 0 {
		return "/var/cache/aurvet"
	}
	if env := os.Getenv("AURVET_CACHE_DIR"); filepath.IsAbs(env) {
		return env
	}
	if xdg := os.Getenv("XDG_CACHE_HOME"); filepath.IsAbs(xdg) {
		return filepath.Join(xdg, "aurvet")
	}
	if home := os.Getenv("HOME"); filepath.IsAbs(home) {
		return filepath.Join(home, ".cache/aurvet")
	}
	return "/var/cache/aurvet"
}

// -- output -------------------------------------------------------------------

// updateOutcome is what this run did to durable state, and -- under --check --
// what it would have done. It is a struct because the two halves must travel
// together: a report that printed "cached" without saying whether the write
// happened is the report a --check would be misread from.
type updateOutcome struct {
	stored     bool
	floorSaved bool
	softSigs   int

	check        bool
	wouldStore   bool
	wouldAdvance bool
}

func writeUpdateReport(stdout, stderr io.Writer, st bundle.Status, base, cacheDir string, o updateOutcome) {
	stored, floorSaved, softSigs := o.stored, o.floorSaved, o.softSigs

	// The refusal goes to stderr and leads, because it is the one line that
	// invalidates everything else the run might say.
	if st.State == bundle.StateRefused {
		fmt.Fprintf(stderr, "aurvet: REFUSED: %s\n", st.Refusal)
		if st.UpgradeMessage != "" {
			fmt.Fprintf(stderr, "aurvet: %s\n", st.UpgradeMessage)
		}
	}

	fmt.Fprintf(stdout, "indicator bundle: %s\n", st.State)
	fmt.Fprintf(stdout, "  origin:      %s\n", base)
	if st.BundleVersion > 0 {
		fmt.Fprintf(stdout, "  version:     %d (digest %s)\n", st.BundleVersion, short12(st.Digest))
	}
	// The active count, always, whatever the state. A drop toward zero is the
	// visible signature of a bundle that removes detections.
	fmt.Fprintf(stdout, "  indicators:  %d active", st.Coverage.Active)
	if n := len(st.Coverage.Inert); n > 0 {
		fmt.Fprintf(stdout, ", %d inert (carried but not matched on by this build)", n)
	}
	fmt.Fprintln(stdout)
	if st.DelegationExpiry != "" {
		fmt.Fprintf(stdout, "  delegation:  serial %d, expires %s\n", st.DelegationSerial, st.DelegationExpiry)
	}
	fmt.Fprintf(stdout, "  root set:    generation %d, %s\n", st.RootGeneration,
		strings.Join(st.RootFingerprints, ", "))
	switch {
	case o.check:
		// The --check lines say what WOULD happen, and say which run they came
		// from: an output that read like a real update would have an operator
		// believing the cache was current.
		fmt.Fprintf(stdout, "  cached:      nothing was written to %s (--check)\n", cacheDir)
		if o.wouldStore {
			fmt.Fprintln(stdout, "  would cache: yes -- a real `aurvet update` would store these "+
				"authenticated bytes")
		} else {
			fmt.Fprintln(stdout, "  would cache: no -- these bytes are not usable, so a real "+
				"`aurvet update` would store nothing either")
		}
		if o.wouldAdvance {
			fmt.Fprintln(stdout, "  would floor: yes -- a real `aurvet update` would advance the "+
				"anti-rollback floor to this bundle")
		} else {
			fmt.Fprintln(stdout, "  would floor: no -- the anti-rollback floor already stands at or "+
				"above this bundle")
		}
	case stored:
		fmt.Fprintf(stdout, "  cached:      %s\n", cacheDir)
	default:
		fmt.Fprintf(stdout, "  cached:      nothing was written to %s\n", cacheDir)
	}
	if floorSaved {
		fmt.Fprintln(stdout, "  floor:       advanced in root-only state")
	}
	if softSigs > 0 {
		fmt.Fprintf(stdout, "  note:        %d optional root signature(s) were not published; the "+
			"threshold was still met\n", softSigs)
	}
	for _, g := range st.Gaps {
		fmt.Fprintf(stdout, "\n[gap] %s (%s): %s\n", g.Subject, g.RuleID, g.Reason)
	}
	if !st.State.CoverageComplete() {
		fmt.Fprintln(stdout, "\nindicator coverage is INCOMPLETE: this run does not report the "+
			"indicator set as current, and no scan may present a clean bill of health on the strength "+
			"of it.")
	}
	fmt.Fprintf(stdout, "\nlimits: %s\n", st.Limits)
}

func updateDoc(st bundle.Status, base, cacheDir, floorPath string, o updateOutcome) map[string]any {
	stored, floorSaved, softSigs := o.stored, o.floorSaved, o.softSigs

	gaps := make([]map[string]string, 0, len(st.Gaps))
	for _, g := range st.Gaps {
		gaps = append(gaps, map[string]string{"rule_id": g.RuleID, "subject": g.Subject, "reason": g.Reason})
	}
	return map[string]any{
		"state": st.State.String(),
		// coverage_complete is the STATE's own reading (active, and nothing else).
		// reports_clean is what the exit code reflects, and it is the stricter of
		// the two: an active bundle can still carry coverage statements -- a
		// software root key, an inert indicator, a dropped count -- and each of
		// those is a reason this run may not be read as complete.
		"coverage_complete": st.State.CoverageComplete(),
		"reports_clean":     st.State.CoverageComplete() && len(st.Gaps) == 0 && softSigs == 0,
		"refusal":           st.Refusal,
		"upgrade_message":   st.UpgradeMessage,
		"origin":            base,
		"bundle_version":    st.BundleVersion,
		"digest":            st.Digest,
		"indicators_active": st.Coverage.Active,
		"indicators_inert":  st.Coverage.Inert,
		"delegation_serial": st.DelegationSerial,
		"delegation_expiry": st.DelegationExpiry,
		"root_generation":   st.RootGeneration,
		"root_fingerprints": st.RootFingerprints,
		"cache_dir":         cacheDir,
		"cached":            stored,
		"floor":             floorPath,
		// floor_advanced and cached are what HAPPENED; would_* are what a real
		// update would do. A caller automating `--check` reads the second pair and
		// must not have to infer it from the first.
		"floor_advanced":                   floorSaved,
		"check_only":                       o.check,
		"would_cache":                      o.wouldStore,
		"would_advance_floor":              o.wouldAdvance,
		"optional_root_signatures_missing": softSigs,
		"gaps":                             gaps,
		"limits":                           st.Limits,
	}
}

// -- the version facts --------------------------------------------------------

// versionFacts is what `aurvet version` / `aurvet --version` needs beyond the
// build identity. Every field is a seam with a production default.
type versionFacts struct {
	roots    *bundle.RootSet
	stateDir string
	cacheDir string
	euid     *int
	now      time.Time
}

// writeVersion prints the build identity and the three trust facts.
//
// # Why these three, and why here
//
// Root fingerprints, delegation expiry and the cached bundle version are the
// facts that decide whether a build's indicator data can be trusted at all, and
// `--version` is where a person already looks. An operator can compare the
// fingerprints against a source the attacker does not control -- which is the
// only way to detect a build whose root set is not the published one.
//
// # Nothing here can fail the command
//
// `version` used to touch no filesystem, deliberately: the moment someone asks
// which build they are running is usually the moment the system is broken. That
// property is preserved by printing the build identity FIRST and unconditionally,
// and by rendering every subsequent failure as a line rather than an error. An
// unreadable cache produces a sentence, not a non-zero exit.
//
// A refusal is PRINTED, never hidden behind a nil check. On this build
// bundle.EmbeddedRoots returns ErrNoRootKeys, and that is the honest state of the
// binary: a build that silently showed no fingerprints would be
// indistinguishable from one whose fingerprints failed to load, and the whole
// point of putting them here is that they can be compared.
func writeVersion(w io.Writer, f versionFacts) {
	fmt.Fprintln(w, buildinfo.String())

	euid := os.Geteuid()
	if f.euid != nil {
		euid = *f.euid
	}
	now := f.now
	if now.IsZero() {
		now = time.Now()
	}
	cacheDir := f.cacheDir
	if cacheDir == "" {
		cacheDir = bundleCacheDir(euid)
	}
	stateDir := f.stateDir
	if stateDir == "" {
		cfg, err := config.Resolve("", euid)
		if err == nil {
			stateDir = cfg.StateDir
		}
	}

	fmt.Fprintln(w, "\nindicator bundle trust:")

	var (
		roots   bundle.RootSet
		rootErr error
	)
	if f.roots != nil {
		roots = *f.roots
	} else {
		roots, rootErr = bundle.EmbeddedRoots()
	}
	switch {
	case rootErr != nil:
		fmt.Fprintf(w, "  root keys:         REFUSED -- %v\n", rootErr)
	default:
		fmt.Fprintf(w, "  root keys:         generation %d, %d-of-%d: %s\n", roots.Generation(),
			roots.Threshold(), roots.Size(), strings.Join(roots.Fingerprints(), ", "))
		if soft := roots.SoftwareKeys(); len(soft) > 0 {
			fmt.Fprintf(w, "  !! software root keys (not hardware-held): %s\n", strings.Join(soft, ", "))
		}
	}

	// The cached bundle's version and the delegation's expiry are only reportable
	// through Verify, because reporting either one means having authenticated the
	// document it came from. Printing a version number read out of an
	// unauthenticated cache file would be printing an attacker's chosen number.
	arts, cacheErr := bundle.OpenCache(cacheDir).Load()
	if cacheErr != nil {
		fmt.Fprintf(w, "  cached bundle:     UNREADABLE at %s -- %v\n", cacheDir, cacheErr)
		fmt.Fprintln(w, "  delegation expiry: unavailable (the cache could not be read)")
		return
	}
	if rootErr != nil {
		fmt.Fprintf(w, "  cached bundle:     %d byte(s) at %s, NOT authenticated: this build has no "+
			"root keys, so neither its version nor the delegation's expiry can be reported. Reading "+
			"either out of an unverified file would be reporting whatever was written there.\n",
			len(arts.BundleRaw), cacheDir)
		fmt.Fprintln(w, "  delegation expiry: unavailable (no root keys to verify it against)")
		return
	}

	var floor bundle.Floor
	var present bool
	if stateDir != "" {
		if fs, err := bundle.OpenFloor(stateDir, bundle.FloorOptions{
			CacheDir: cacheDir, EUID: euid,
		}); err == nil {
			var lerr error
			if floor, present, lerr = fs.Load(); lerr != nil {
				fmt.Fprintf(w, "  rollback floor:    UNREADABLE at %s -- %v\n", fs.Path(), lerr)
				floor, present = bundle.Floor{}, false
			}
		}
	}

	st := bundle.Verify(bundle.Input{
		Roots: roots, DelegationRaw: arts.DelegationRaw, DelegationSigs: arts.DelegationSigs,
		BundleRaw: arts.BundleRaw, BundleSig: arts.BundleSig,
		Floor: floor, FloorPresent: present, Now: now,
	})
	if st.BundleVersion > 0 {
		fmt.Fprintf(w, "  cached bundle:     version %d, %s, %d active indicator(s) (digest %s)\n",
			st.BundleVersion, st.State, st.Coverage.Active, short12(st.Digest))
	} else {
		fmt.Fprintf(w, "  cached bundle:     %s -- no authenticated bundle version to report\n", st.State)
	}
	if st.DelegationExpiry != "" {
		fmt.Fprintf(w, "  delegation expiry: %s (serial %d)\n", st.DelegationExpiry, st.DelegationSerial)
	} else {
		fmt.Fprintln(w, "  delegation expiry: unavailable (no delegation verified against this "+
			"build's root keys)")
	}
	if st.State == bundle.StateRefused {
		fmt.Fprintf(w, "  !! %s\n", st.Refusal)
	}
	if !st.State.CoverageComplete() {
		fmt.Fprintln(w, "  indicator coverage is INCOMPLETE on this build; run `aurvet update`")
	}
	if present {
		fmt.Fprintf(w, "  rollback floor:    bundle >= %d, delegation serial >= %d, accepted %s\n",
			floor.MinBundleVersion, floor.MinDelegationSerial, floor.AcceptedAt)
	}
}
