// cmd/aurvet/update_test.go
//
// `update` and the `--version` trust facts.
//
// The fail-closed cases come first, and each one asserts the same two things:
// the exit code is not 0, and the output does not read as a clean result. An
// `update` that exited 0 on an expired bundle would tell a systemd timer that
// the indicator set is current when it is not, and nothing downstream would ever
// question it.
//
// # Keys
//
// No key is generated here and no production key exists. The root PUBLIC keys
// below are recomputed from the same fixed one-byte seeds
// internal/bundle/helpers_test.go uses, so the committed fixtures under
// testdata/bundle -- which are genuinely signed by those throwaway keys -- verify
// against them. Only public halves are built: this file never signs anything.
package main

import (
	"bytes"
	"crypto/ed25519"
	"encoding/base64"
	"encoding/binary"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/lookatitude/aurvet/internal/baseline"
	"github.com/lookatitude/aurvet/internal/bundle"
)

const bundleFixtureDir = "../../testdata/bundle"

// The instants the committed fixtures were signed around. The bundle is valid
// until 2026-09-01 and the delegation until 2026-10-01, so there is a window in
// which the bundle is expired and the delegation is not -- which is exactly the
// state the expiry test needs.
const (
	updateNowValid   = "2026-08-06T12:00:00+02:00"
	updateNowExpired = "2026-09-15T12:00:00+02:00"
)

func stampOrDie(t *testing.T, s string) time.Time {
	t.Helper()
	ts, err := baseline.ParseStamp(s)
	if err != nil {
		t.Fatal(err)
	}
	return ts
}

// throwawayRootSet rebuilds the 2-of-3 set the committed fixtures were signed
// under. Public halves only.
func throwawayRootSet(t *testing.T) *bundle.RootSet {
	t.Helper()
	var keys []*baseline.PublicKey
	for _, seed := range []byte{0x01, 0x02, 0x03} {
		keys = append(keys, throwawayPublicKey(t, seed))
	}
	set, err := bundle.NewRootSet(1, bundle.RootThreshold, keys)
	if err != nil {
		t.Fatal(err)
	}
	return &set
}

func throwawayPublicKey(t *testing.T, seed byte) *baseline.PublicKey {
	t.Helper()
	priv := ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize))
	blob := sshString(nil, []byte(baseline.AlgoEd25519))
	blob = sshString(blob, priv.Public().(ed25519.PublicKey))
	line := string(baseline.AlgoEd25519) + " " + base64.StdEncoding.EncodeToString(blob) + " throwaway"
	k, err := baseline.ParsePublicKey([]byte(line))
	if err != nil {
		t.Fatal(err)
	}
	return k
}

// throwawaySigner signs with one of the documented seeds. It exists for one
// reason: the committed fixture bundle and the online key that signed it expire
// at the SAME instant, so there is no `now` at which the fixture is expired and
// its delegation is still valid -- and "expired bundle, valid delegation" is the
// exact state the fail-closed expiry path is about. It signs test documents only;
// no key is generated and no production key exists.
type throwawaySigner struct {
	priv ed25519.PrivateKey
	pub  *baseline.PublicKey
}

func (s *throwawaySigner) PublicKey() *baseline.PublicKey { return s.pub }

func (s *throwawaySigner) SignSSH(data []byte) ([]byte, error) {
	b := sshString(nil, []byte(baseline.AlgoEd25519))
	return sshString(b, ed25519.Sign(s.priv, data)), nil
}

func throwawayOnlineKey(t *testing.T) *throwawaySigner {
	t.Helper()
	const seed = 0x10 // the same seed internal/bundle's fixture online key uses
	return &throwawaySigner{
		priv: ed25519.NewKeyFromSeed(bytes.Repeat([]byte{seed}, ed25519.SeedSize)),
		pub:  throwawayPublicKey(t, seed),
	}
}

// expiredBundleBytes is the fixture bundle with a valid_until in the past,
// re-signed by the online key the committed delegation names.
func expiredBundleBytes(t *testing.T) (raw, sig []byte) {
	t.Helper()
	b := &bundle.Bundle{
		SpecVersion:   bundle.SpecVersion,
		BundleVersion: 5,
		IssuedAt:      "2026-07-02T00:00:00Z",
		ValidUntil:    "2026-08-05T00:00:00Z", // before updateNowValid
		PrevDigest:    strings.Repeat("11", 32),
		Indicators: bundle.Indicators{
			KnownBadNames: []bundle.NameIndicator{
				{Name: "librewolf-fix-bin", Note: "removed from the AUR in 2025"},
			},
		},
	}
	raw, err := baseline.Marshal(b)
	if err != nil {
		t.Fatal(err)
	}
	sig, err = baseline.Sign(throwawayOnlineKey(t), baseline.NamespaceBundle, raw)
	if err != nil {
		t.Fatal(err)
	}
	return raw, sig
}

func sshString(dst, s []byte) []byte {
	var n [4]byte
	binary.BigEndian.PutUint32(n[:], uint32(len(s)))
	return append(append(dst, n[:]...), s...)
}

// bundleServer serves the committed fixtures. Anything not named in `only` 404s,
// which is what makes the "that signature was never published" cases reachable.
func bundleServer(t *testing.T, only ...string) *httptest.Server {
	return bundleServerWith(t, nil, only...)
}

// bundleServerWith serves the fixtures with some files replaced.
func bundleServerWith(t *testing.T, override map[string][]byte, only ...string) *httptest.Server {
	t.Helper()
	allow := map[string]bool{}
	for _, n := range only {
		allow[n] = true
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/indicators/")
		if len(allow) > 0 && !allow[name] {
			http.NotFound(w, r)
			return
		}
		if b, ok := override[name]; ok {
			_, _ = w.Write(b)
			return
		}
		b, err := os.ReadFile(filepath.Join(bundleFixtureDir, name))
		if err != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	t.Cleanup(srv.Close)
	return srv
}

// updateFor is the invocation that reaches the accept path. Each fail-closed test
// breaks exactly one thing about it.
func updateFor(t *testing.T, srv *httptest.Server, state, cache, now string) updateOpts {
	t.Helper()
	return updateOpts{
		baseURL:  srv.URL + "/indicators",
		stateDir: state,
		cacheDir: cache,
		// The REAL euid, not a forced 0: the floor refuses state that root does
		// not own, and a temp directory belongs to whoever runs the tests. That
		// refusal has its own coverage in internal/bundle.
		euid:       nil,
		now:        stampOrDie(t, now),
		roots:      throwawayRootSet(t),
		client:     srv.Client(),
		allowPlain: true, // the fixture server is http; production requires https
	}
}

func updateDirs(t *testing.T) (state, cache string) {
	t.Helper()
	base := t.TempDir()
	return filepath.Join(base, "state"), filepath.Join(base, "cache")
}

func assertNotClean(t *testing.T, code int, out string) {
	t.Helper()
	if code == exitClean {
		t.Fatalf("update exited 0 (clean) on a fail-closed path:\n%s", out)
	}
	// "clean" itself appears legitimately -- the limits text says a verified
	// bundle does not license a clean bill of health -- so what is forbidden is a
	// POSITIVE claim, and what is required is the incompleteness statement.
	for _, forbidden := range []string{"up to date", "coverage is complete", "nothing to do"} {
		if strings.Contains(strings.ToLower(out), forbidden) {
			t.Fatalf("output reads as a clean result (%q):\n%s", forbidden, out)
		}
	}
	if !strings.Contains(out, "INCOMPLETE") {
		t.Fatalf("a fail-closed path did not state that indicator coverage is incomplete:\n%s", out)
	}
}

// -- fail closed 1: this build has no root keys -------------------------------

// The production default. `bundle.EmbeddedRoots` returns ErrNoRootKeys because
// the 2-of-3 hardware key generation is a human action that has not happened, and
// the refusal is PRINTED rather than hidden: a build that silently reported no
// indicator coverage would be indistinguishable from one whose root keys failed
// to load.
//
// It also asserts the ordering: no request is made at all. There is nothing to
// fetch for a build that could never authenticate the answer.
func TestUpdateRefusesWithoutRootKeysAndNeverReachesTheNetwork(t *testing.T) {
	state, cache := updateDirs(t)
	reached := false
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		reached = true
		http.NotFound(w, r)
	}))
	defer srv.Close()

	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.roots = nil // the real, empty, compiled-in set

	var out, errb bytes.Buffer
	code := runUpdate(opts, &out, &errb)
	assertNotClean(t, code, out.String()+errb.String())
	if code != exitIncomplete {
		t.Fatalf("update with no root keys = %d, want %d", code, exitIncomplete)
	}
	if reached {
		t.Fatal("a build that cannot authenticate a bundle fetched one anyway")
	}
	msg := errb.String()
	for _, want := range []string{"embeds no indicator-bundle root keys", "refusal, not a degraded mode",
		"no request was made"} {
		if !strings.Contains(msg, want) {
			t.Errorf("the refusal does not say %q:\n%s", want, msg)
		}
	}
	if _, err := os.Stat(cache); !os.IsNotExist(err) {
		t.Fatal("a refused update created the cache directory")
	}
}

// -- fail closed 2: an expired bundle -----------------------------------------

// The headline fail-closed case. The bundle is genuinely signed and its
// delegation is still valid; only valid_until has passed. Coverage is INCOMPLETE,
// the exit code is 3, and the indicators are still cached -- discarding stale
// indicators would make the tool worse at exactly the moment its data is oldest.
func TestUpdateRefusesToCallAnExpiredBundleCurrent(t *testing.T) {
	state, cache := updateDirs(t)
	raw, sig := expiredBundleBytes(t)
	srv := bundleServerWith(t, map[string][]byte{
		bundle.CacheBundleFile:          raw,
		bundle.CacheBundleFile + ".sig": sig,
	})

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if code != exitIncomplete {
		t.Fatalf("update with an expired bundle = %d, want %d\n%s", code, exitIncomplete, got)
	}
	for _, want := range []string{"expired", "INCOMPLETE", "aurvet update"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not say %q:\n%s", want, got)
		}
	}
	// The count is reported even here: a drop toward zero must be visible in
	// every state, not only the happy one.
	if !strings.Contains(got, "indicators:") {
		t.Errorf("the active indicator count was not reported:\n%s", got)
	}
	// The floor must NOT advance on an expired bundle: accepting it as the new
	// high-water mark would make the expiry permanent.
	fs, err := bundle.OpenFloor(state, bundle.FloorOptions{CacheDir: cache, EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	if _, present, err := fs.Load(); present || err != nil {
		t.Fatalf("an expired bundle advanced the anti-rollback floor: present=%v err=%v", present, err)
	}
}

// -- fail closed 3: rollback --------------------------------------------------

// A validly signed OLDER bundle, replayed. Every signature on it is perfect; the
// version is the only thing that says it is superseded, and that lives in
// root-only state.
func TestUpdateRefusesABundleBelowTheAntiRollbackFloor(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)

	fs, err := bundle.OpenFloor(state, bundle.FloorOptions{CacheDir: cache, EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	// The host has already accepted version 9; the server offers 5.
	if err := fs.Save(bundle.Floor{
		Schema: bundle.FloorSchema, MinBundleVersion: 9,
		HeadDigest: strings.Repeat("ab", 32), MinDelegationSerial: 7,
		IndicatorCount: 6, RootGeneration: 1,
		AcceptedAt: "2026-08-01T00:00:00Z", CheckedAt: "2026-08-01T00:00:00Z",
	}); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if code != exitIncomplete {
		t.Fatalf("rollback = %d, want %d\n%s", code, exitIncomplete, got)
	}
	if !strings.Contains(got, "below the floor") {
		t.Errorf("the refusal does not name the floor:\n%s", got)
	}
	// And nothing was cached: a refused document is not written anywhere.
	if _, err := os.Stat(filepath.Join(cache, bundle.CacheBundleFile)); !os.IsNotExist(err) {
		t.Fatal("a rolled-back bundle was cached")
	}
	// The floor is untouched.
	f, present, err := fs.Load()
	if err != nil || !present || f.MinBundleVersion != 9 {
		t.Fatalf("the floor moved: %+v present=%v err=%v", f, present, err)
	}
}

// -- fail closed 4: the delegation is withheld --------------------------------

// Without a root-signed delegation there is nothing that says which online key
// may sign a bundle. The bundle's own signature cannot establish that -- a bundle
// that could name its own signing key would make the offline root set
// decorative.
func TestUpdateRefusesWhenTheDelegationCannotBeFetched(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t, bundle.CacheBundleFile, bundle.CacheBundleFile+".sig")

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if code != exitIncomplete {
		t.Fatalf("missing delegation = %d, want %d\n%s", code, exitIncomplete, got)
	}
	if !strings.Contains(got, "delegation could not be fetched") {
		t.Errorf("the refusal does not name what was missing:\n%s", got)
	}
	if !strings.Contains(got, "nothing was cached") {
		t.Errorf("the refusal does not say the previous cache is untouched:\n%s", got)
	}
}

// A 2-of-3 set needs two root signatures. One is not a threshold, and a fetch
// that collected only one must refuse rather than proceed with what it has.
func TestUpdateRefusesWhenFewerThanThresholdRootSignaturesArePublished(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t, bundle.CacheDelegationFile, bundle.CacheDelegationFile+".sig.1",
		bundle.CacheBundleFile, bundle.CacheBundleFile+".sig")

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if !strings.Contains(got, "signature 2 of the required 2") {
		t.Errorf("the refusal does not say which signature was missing:\n%s", got)
	}
}

// -- fail closed 5: a flipped byte --------------------------------------------

// One byte of the bundle, changed in flight. The signature is over the raw bytes
// and is checked before anything parses them, so this is a refusal and not a
// parse error.
func TestUpdateRefusesABundleWithOneAlteredByte(t *testing.T) {
	state, cache := updateDirs(t)
	raw, err := os.ReadFile(filepath.Join(bundleFixtureDir, bundle.CacheBundleFile))
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		name := strings.TrimPrefix(r.URL.Path, "/indicators/")
		if name == bundle.CacheBundleFile {
			tampered := append([]byte(nil), raw...)
			tampered[len(tampered)/2] ^= 0x20
			_, _ = w.Write(tampered)
			return
		}
		b, rerr := os.ReadFile(filepath.Join(bundleFixtureDir, name))
		if rerr != nil {
			http.NotFound(w, r)
			return
		}
		_, _ = w.Write(b)
	}))
	defer srv.Close()

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if !strings.Contains(got, "does not verify") {
		t.Errorf("the refusal does not name the signature:\n%s", got)
	}
	if _, err := os.Stat(filepath.Join(cache, bundle.CacheBundleFile)); !os.IsNotExist(err) {
		t.Fatal("a bundle that failed verification was cached")
	}
}

// -- fail closed 6: INV-5 ------------------------------------------------------

func TestUpdateUnderAnOfflineRootIsAUsageErrorNotASilentNoOp(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)
	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.offlineRoot = cleanRoot

	var out, errb bytes.Buffer
	if code := runUpdate(opts, &out, &errb); code != exitUsage {
		t.Fatalf("update --offline-root = %d, want %d\n%s", code, exitUsage, errb.String())
	}
	if !strings.Contains(errb.String(), "INV-5") {
		t.Fatalf("the refusal does not cite the invariant:\n%s", errb.String())
	}
}

// An unreadable anti-rollback floor is not an absent one. Treating it as absent
// is precisely the state a rollback attacker wants to manufacture.
func TestUpdateRefusesAnUnreadableFloorRatherThanTreatingItAsAbsent(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)
	if err := os.MkdirAll(state, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(state, bundle.FloorFile),
		[]byte(`{ "schema": 1, "min_bundle_version": 3 }`), 0o600); err != nil {
		t.Fatal(err)
	}

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String() + errb.String()
	assertNotClean(t, code, got)
	if !strings.Contains(got, "not an absent one") {
		t.Errorf("the refusal lets an unreadable floor read as absent:\n%s", got)
	}
}

// -- the accept path -----------------------------------------------------------

// The path that caches a bundle and advances the floor.
//
// It exits 3, not 0, and that is correct rather than a compromise: the root keys
// available to a test are SOFTWARE keys, and Verify reports a software root key
// as a coverage gap because a copied root key is indistinguishable from the real
// one. Exit 0 from `update` therefore requires the hardware-held release set,
// which does not exist yet -- the seam is marked in updateOpts.roots. What is
// asserted here is everything else: the bytes are cached, the floor advances, and
// the three facts are printed.
func TestUpdateCachesAVerifiedBundleAndAdvancesTheFloor(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)

	var out, errb bytes.Buffer
	code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &out, &errb)
	got := out.String()
	if code != exitIncomplete {
		t.Fatalf("update = %d, want %d (the software-root-key gap)\nstdout: %s\nstderr: %s",
			code, exitIncomplete, got, errb.String())
	}
	if !strings.Contains(got, "software keys") {
		t.Fatalf("exit 3 was returned for some reason other than the software root keys:\n%s", got)
	}
	for _, want := range []string{"indicator bundle: active", "version:     5", "indicators:  6 active",
		"delegation:", "root set:", "cached:"} {
		if !strings.Contains(got, want) {
			t.Errorf("output does not report %q:\n%s", want, got)
		}
	}

	// The cache holds exactly the bytes that were served, and they re-verify.
	for _, name := range []string{
		bundle.CacheBundleFile, bundle.CacheBundleFile + ".sig",
		bundle.CacheDelegationFile, bundle.CacheDelegationFile + ".sig.1",
		bundle.CacheDelegationFile + ".sig.2",
	} {
		wantBytes, err := os.ReadFile(filepath.Join(bundleFixtureDir, name))
		if err != nil {
			t.Fatal(err)
		}
		gotBytes, err := os.ReadFile(filepath.Join(cache, name))
		if err != nil {
			t.Fatalf("%s was not cached: %v", name, err)
		}
		if !bytes.Equal(wantBytes, gotBytes) {
			t.Fatalf("%s in the cache differs from what was served", name)
		}
	}

	fs, err := bundle.OpenFloor(state, bundle.FloorOptions{CacheDir: cache, EUID: os.Geteuid()})
	if err != nil {
		t.Fatal(err)
	}
	f, present, err := fs.Load()
	if err != nil || !present {
		t.Fatalf("the floor did not advance: present=%v err=%v", present, err)
	}
	if f.MinBundleVersion != 5 || f.MinDelegationSerial != 7 || f.IndicatorCount != 6 {
		t.Fatalf("the floor records the wrong high-water mark: %+v", f)
	}
	fi, err := os.Stat(fs.Path())
	if err != nil {
		t.Fatal(err)
	}
	if fi.Mode().Perm() != 0o600 {
		t.Errorf("floor mode %04o, want 0600", fi.Mode().Perm())
	}

	// Re-running is idempotent: the same version is not a rollback and not a
	// fork, because the digest matches what root-only state recorded.
	var o2, e2 bytes.Buffer
	if code := runUpdate(updateFor(t, srv, state, cache, updateNowValid), &o2, &e2); code != exitIncomplete {
		t.Fatalf("second update = %d, want %d\n%s%s", code, exitIncomplete, o2.String(), e2.String())
	}
	if strings.Contains(o2.String(), "fork") || strings.Contains(e2.String(), "fork") {
		t.Fatalf("re-fetching the same bundle was reported as a fork:\n%s%s", o2.String(), e2.String())
	}
}

func TestUpdateJSONReportsTheStateAndTheCount(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)
	opts := updateFor(t, srv, state, cache, updateNowValid)
	opts.jsonOut = true

	var out, errb bytes.Buffer
	if code := runUpdate(opts, &out, &errb); code != exitClean && code != exitIncomplete {
		t.Fatalf("update -json = %d\n%s", code, errb.String())
	}
	var doc map[string]any
	if err := json.Unmarshal(out.Bytes(), &doc); err != nil {
		t.Fatalf("stdout is not one JSON document: %v\n%s", err, out.String())
	}
	if doc["state"] != "active" {
		t.Errorf("state = %v, want active", doc["state"])
	}
	if doc["indicators_active"] != float64(6) {
		t.Errorf("indicators_active = %v, want 6", doc["indicators_active"])
	}
	// coverage_complete is the state's own reading, which IS complete here: the
	// bundle is active. reports_clean is the stricter one the exit code follows,
	// and it must be false while a coverage statement stands -- here the
	// software-root-key gap.
	if doc["coverage_complete"] != true {
		t.Errorf("coverage_complete = %v, want true for an active bundle", doc["coverage_complete"])
	}
	if doc["reports_clean"] != false {
		t.Errorf("reports_clean = %v: a build with software root keys carries a coverage gap and "+
			"must not read as clean", doc["reports_clean"])
	}
}

// -- never automatic -----------------------------------------------------------

// The property is structural, so it is asserted structurally: nothing outside
// update.go may construct a Fetcher or call runUpdate. A background refresh
// hidden inside `scan` would be invisible to every other test in this suite.
func TestNothingButUpdateFetchesABundle(t *testing.T) {
	entries, err := os.ReadDir(".")
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		name := e.Name()
		if e.IsDir() || !strings.HasSuffix(name, ".go") ||
			name == "update.go" || strings.HasSuffix(name, "_test.go") {
			continue
		}
		src, err := os.ReadFile(name)
		if err != nil {
			t.Fatal(err)
		}
		for _, forbidden := range []string{"bundle.NewFetcher", "runUpdate("} {
			if bytes.Contains(src, []byte(forbidden)) && name != "main.go" {
				t.Errorf("%s references %s: an update must happen only when an operator asks for "+
					"one, so nothing outside update.go and main.go's dispatch may start one",
					name, forbidden)
			}
		}
		if bytes.Contains(src, []byte("bundle.NewFetcher")) {
			t.Errorf("%s constructs a bundle fetcher; only update.go may", name)
		}
	}
}

// -- --version -----------------------------------------------------------------

// The three facts, on the build that actually ships today: root fingerprints,
// delegation expiry, cached bundle version. All three are unavailable here, and
// each one says so with its reason. A blank line where a fingerprint should be is
// indistinguishable from a fingerprint that failed to load.
func TestVersionPrintsTheRefusalWhenThisBuildHasNoRootKeys(t *testing.T) {
	state, cache := updateDirs(t)
	var out bytes.Buffer
	writeVersion(&out, versionFacts{stateDir: state, cacheDir: cache, euid: rootEuid(),
		now: stampOrDie(t, updateNowValid)})

	got := out.String()
	if !strings.Contains(got, "root keys:") || !strings.Contains(got, "REFUSED") {
		t.Fatalf("--version does not print the root-key refusal:\n%s", got)
	}
	if !strings.Contains(got, "embeds no indicator-bundle root keys") {
		t.Fatalf("the refusal is not the operator-facing one:\n%s", got)
	}
	if !strings.Contains(got, "delegation expiry:") {
		t.Fatalf("--version does not mention the delegation expiry at all:\n%s", got)
	}
	if !strings.Contains(got, "cached bundle:") {
		t.Fatalf("--version does not mention the cached bundle at all:\n%s", got)
	}
	// The build identity comes first and unconditionally: the moment someone asks
	// which build they are running is usually the moment the system is broken.
	if !strings.HasPrefix(got, "aurvet") {
		t.Fatalf("--version does not lead with the build identity: %q", strings.SplitN(got, "\n", 2)[0])
	}
}

// With a root set and a cached bundle, all three facts are printed as values.
func TestVersionPrintsAllThreeFactsWhenTheyAreAvailable(t *testing.T) {
	state, cache := updateDirs(t)
	srv := bundleServer(t)
	if code := runUpdate(updateFor(t, srv, state, cache, updateNowValid),
		&bytes.Buffer{}, &bytes.Buffer{}); code != exitIncomplete {
		t.Fatalf("seeding the cache failed with %d", code)
	}

	var out bytes.Buffer
	writeVersion(&out, versionFacts{
		roots: throwawayRootSet(t), stateDir: state, cacheDir: cache,
		euid: rootEuid(), now: stampOrDie(t, updateNowValid),
	})
	got := out.String()
	for _, want := range []string{
		"generation 1, 2-of-3", "SHA256:", // the root fingerprints
		"delegation expiry: 2026-10-01", // the delegation expiry
		"cached bundle:     version 5",  // the cached bundle version
		"6 active indicator(s)",         // the count, so a drop is visible
		"rollback floor:",
	} {
		if !strings.Contains(got, want) {
			t.Errorf("--version does not report %q:\n%s", want, got)
		}
	}
	// A software root key is a real weakening of INV-7 and is reported as such.
	if !strings.Contains(got, "software root keys") {
		t.Errorf("--version does not warn about software root keys:\n%s", got)
	}
}

// An unreadable cache must not take `version` down with it: the whole point of
// the subcommand is that it answers when everything else is broken.
func TestVersionSurvivesAnUnreadableCache(t *testing.T) {
	state, cache := updateDirs(t)
	if err := os.MkdirAll(cache, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cache, bundle.CacheBundleFile), []byte("x"), 0o000); err != nil {
		t.Fatal(err)
	}
	if os.Geteuid() == 0 {
		t.Skip("running as root: a 0000 file is still readable")
	}

	var out bytes.Buffer
	writeVersion(&out, versionFacts{stateDir: state, cacheDir: cache, euid: nil,
		now: stampOrDie(t, updateNowValid)})
	got := out.String()
	if !strings.HasPrefix(got, "aurvet") {
		t.Fatalf("version lost the build identity: %q", got)
	}
	if !strings.Contains(got, "UNREADABLE") {
		t.Fatalf("an unreadable cache was not reported:\n%s", got)
	}
}
