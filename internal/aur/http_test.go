package aur

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// fixtureDir holds cgit pages captured from the live AUR
// (testdata/aur/cgit/PROVENANCE.md). Every matcher test below is driven from
// these bytes rather than from hand-written HTML: the matcher this suite
// replaces was written against markup cgit does not emit, and the only defence
// against repeating that is to test against markup cgit actually emitted.
//
// No test in this file touches the network. Fixtures come off disk and are
// served by httptest.Server on loopback.
const fixtureDir = "../../testdata/aur/cgit"

func readFixture(t *testing.T, name string) string {
	t.Helper()
	b, err := os.ReadFile(filepath.Join(fixtureDir, name))
	if err != nil {
		t.Fatalf("read fixture %s: %v", name, err)
	}
	return string(b)
}

// serveBody stands up a loopback server answering every request with status and
// body, and returns a client pointed at it.
func serveBody(t *testing.T, status int, body string) *HTTP {
	t.Helper()
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(status)
		io.WriteString(w, body)
	}))
	t.Cleanup(srv.Close)
	return NewHTTP(srv.URL, srv.Client())
}

// realTombstoneSubject is the verified wording of the 2025 librewolf-fix-bin
// removal, as it appears in the captured fixture.
const realTombstoneSubject = "history removed due to malware"

// tombstoneFixtureRow returns the captured tombstone fixture and the exact byte
// range of its single commit row, so tests can rewrite or repeat that row while
// leaving every other byte of real cgit markup intact — the table, the header
// row, the empty pager, the tab links and the search form that mentions the base.
func tombstoneFixtureRow(t *testing.T) (body, row string) {
	t.Helper()
	body = readFixture(t, "log-tombstoned-librewolf-fix-bin.html")
	const marker = "<tr><td><span title='2025-07-18"
	i := strings.Index(body, marker)
	if i < 0 {
		t.Fatalf("tombstone fixture commit row not found")
	}
	j := strings.Index(body[i:], "</tr>")
	if j < 0 {
		t.Fatal("tombstone fixture commit row is unterminated")
	}
	return body, body[i : i+j+len("</tr>")]
}

// tombstoneFixtureWithSubjects rewrites the captured tombstone fixture's single
// commit row into one row per subject, newest first.
func tombstoneFixtureWithSubjects(t *testing.T, subjects ...string) string {
	t.Helper()
	body, row := tombstoneFixtureRow(t)
	old := ">" + realTombstoneSubject + "</a>"
	if n := strings.Count(row, old); n != 1 {
		t.Fatalf("tombstone fixture row marker %q occurs %d times, want 1", old, n)
	}
	var rows strings.Builder
	for _, s := range subjects {
		rows.WriteString(strings.Replace(row, old, ">"+s+"</a>", 1))
	}
	return strings.Replace(body, row, rows.String(), 1)
}

// tombstoneFixtureWithSubject is the single-row case: a sole-commit log, the
// shape of the one verified real tombstone.
func tombstoneFixtureWithSubject(t *testing.T, subject string) string {
	t.Helper()
	return tombstoneFixtureWithSubjects(t, subject)
}

// yayNewestSubject is the subject of row 1 of the 50-row yay fixture, i.e.
// commit index 0 — the newest row, which the deleted position gate admitted
// unconditionally (R4).
const yayNewestSubject = "merge"

// yayMiddleSubject is the subject of row 14 of the 50-row yay fixture, i.e.
// commit index 13 — neither the newest nor the oldest row.
const yayMiddleSubject = "update pkgver"

// yayFixtureWithSubject rewrites one row's subject in the captured 50-row yay
// page, keeping its 50 rows and its non-empty `[next]` pager.
func yayFixtureWithSubject(t *testing.T, oldSubject, newSubject string) string {
	t.Helper()
	body := readFixture(t, "log-present-yay.html")
	old := ">" + oldSubject + "</a>"
	if n := strings.Count(body, old); n != 1 {
		t.Fatalf("yay fixture row marker %q occurs %d times, want 1", old, n)
	}
	return strings.Replace(body, old, ">"+newSubject+"</a>", 1)
}

func yayFixtureWithNewestSubject(t *testing.T, subject string) string {
	t.Helper()
	return yayFixtureWithSubject(t, yayNewestSubject, subject)
}

func yayFixtureWithMiddleSubject(t *testing.T, subject string) string {
	t.Helper()
	return yayFixtureWithSubject(t, yayMiddleSubject, subject)
}

// r4OrdinarySubjects are the twelve measured ordinary commit subjects that the
// deleted row-position gate turned into false criticals when they appeared in
// the newest row of a live 50-commit log. Every one of them is an anchored
// removal AND malware-word-bearing, which is exactly why row 0's unconditional
// admission was fatal.
var r4OrdinarySubjects = []string{
	"remove the vendored miner binary, upstream ships it now",
	"drop miner support, use the upstream release",
	"removed payload directory from the tarball",
	"dropped the compromised upstream mirror from sources",
	"removed the malware test corpus",
	"dropped the backdoor ruleset",
	"delete the virus signature database, it is fetched at runtime",
	"removing the rootkit detection module, it needs kernel headers",
	"deleting the keylogger demo from the examples dir",
	"drops the beacon example config",
	"purge stale payload fixtures",
	"remove obfuscated vendored javascript",
}

// The RPC distinguishes failure from absence: type "error" vs "multiinfo"
// with resultcount 0. Network failure must never be readable as "deleted".
func TestInfoParsesMultiinfo(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"multiinfo","resultcount":1,"results":[
		  {"Name":"foo-bin","PackageBase":"foo-bin","Maintainer":"alice","Submitter":"bob",
		   "FirstSubmitted":1700000000,"LastModified":1710000000}]}`))
	}))
	defer srv.Close()
	got, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"foo-bin"})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	p, ok := got["foo-bin"]
	if !ok {
		t.Fatalf("foo-bin missing from %v", got)
	}
	if p.Maintainer != "alice" || p.Submitter != "bob" {
		t.Errorf("got %+v", p)
	}
}

func TestInfoErrorTypeIsAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write([]byte(`{"type":"error","error":"Incorrect request type specified.","resultcount":0,"results":[]}`))
	}))
	defer srv.Close()
	_, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"x"})
	if err == nil {
		t.Fatal("type=error must produce an error, not an empty result")
	}
}

func TestInfoBatchesAllArgsInOneRequest(t *testing.T) {
	var calls int
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls++
		if n := len(r.URL.Query()["arg[]"]); n != 3 {
			t.Errorf("arg[] count = %d, want 3", n)
		}
		w.Write([]byte(`{"type":"multiinfo","resultcount":0,"results":[]}`))
	}))
	defer srv.Close()
	if _, err := NewHTTP(srv.URL, srv.Client()).Info(context.Background(), []string{"a", "b", "c"}); err != nil {
		t.Fatalf("Info: %v", err)
	}
	if calls != 1 {
		t.Errorf("made %d requests, want 1", calls)
	}
}

// TestInfoRejectsErrorFieldWithoutErrorType pins F10: aurweb reports "Too many
// package results." in the error field with no type:"error", and reading that
// as an empty result set reports every requested package as absent.
func TestInfoRejectsErrorFieldWithoutErrorType(t *testing.T) {
	c := serveBody(t, http.StatusOK,
		`{"resultcount":0,"results":[],"error":"Too many package results."}`)
	_, err := c.Info(context.Background(), []string{"a"})
	if err == nil {
		t.Fatal("a non-empty error field must be an error regardless of type")
	}
	if !strings.Contains(err.Error(), "Too many package results.") {
		t.Errorf("error must carry the RPC message, got %v", err)
	}
}

// TestInfoRejectsUnknownType pins F10: a bare `{}` — a truncated or intercepted
// response — must not read as "none of these packages exist".
func TestInfoRejectsUnknownType(t *testing.T) {
	for _, body := range []string{`{}`, `{"type":"search","resultcount":0,"results":[]}`} {
		c := serveBody(t, http.StatusOK, body)
		if _, err := c.Info(context.Background(), []string{"a"}); err == nil {
			t.Errorf("Info(%s) = nil error, want an error", body)
		}
	}
	// The recognised success types must still succeed.
	for _, body := range []string{
		`{"type":"multiinfo","resultcount":0,"results":[]}`,
		`{"type":"info","resultcount":0,"results":[]}`,
	} {
		c := serveBody(t, http.StatusOK, body)
		if _, err := c.Info(context.Background(), []string{"a"}); err != nil {
			t.Errorf("Info(%s) = %v, want success", body, err)
		}
	}
}

// TestInfoRejectsResultCountMismatch pins F10: resultcount 3 with an empty
// results array is a broken response, not three absent packages.
func TestInfoRejectsResultCountMismatch(t *testing.T) {
	c := serveBody(t, http.StatusOK, `{"type":"multiinfo","resultcount":3,"results":[]}`)
	if _, err := c.Info(context.Background(), []string{"a", "b", "c"}); err == nil {
		t.Fatal("resultcount disagreeing with results must be an error")
	}
}

// TestInfoCrossKeysNameAndPackageBase pins F15: the v5 endpoint matches package
// NAMES (by=pkgbase is rejected outright), so a base whose name differs from
// every package it builds must still be retrievable by base.
func TestInfoCrossKeysNameAndPackageBase(t *testing.T) {
	c := serveBody(t, http.StatusOK, `{"type":"multiinfo","resultcount":1,"results":[
	  {"Name":"librewolf-bin","PackageBase":"librewolf-fix-bin","Maintainer":"alice",
	   "Submitter":"alice","FirstSubmitted":1700000000,"LastModified":1710000000}]}`)
	got, err := c.Info(context.Background(), []string{"librewolf-bin"})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	for _, key := range []string{"librewolf-bin", "librewolf-fix-bin"} {
		p, ok := got[key]
		if !ok {
			t.Fatalf("key %q missing from %v", key, got)
		}
		if p.Maintainer != "alice" {
			t.Errorf("got[%q] = %+v", key, p)
		}
	}
}

// TestInfoNameWinsOverAnotherPackagesBase pins R6. THE INVARIANT: if any result
// is NAMED k, then got[k] is that result. Names and bases share one map, so
// without a keying order one result's PackageBase key overwrites another
// result's Name key — and Maintainer/Submitter is exactly the field a takeover
// check compares, so the caller is handed a different package's provenance under
// a name that package does not own.
//
// Both orderings are exercised because only one of them exhibits the defect: the
// single-pass loop it replaces fails when the base-carrying result comes SECOND.
func TestInfoNameWinsOverAnotherPackagesBase(t *testing.T) {
	const aliceResult = `{"Name":"librewolf-bin","PackageBase":"librewolf","Maintainer":"alice",` +
		`"Submitter":"alice","FirstSubmitted":1700000000,"LastModified":1710000000}`
	const malloryResult = `{"Name":"librewolf","PackageBase":"librewolf-other","Maintainer":"mallory",` +
		`"Submitter":"mallory","FirstSubmitted":1700000000,"LastModified":1710000000}`

	for _, tc := range []struct{ name, results string }{
		{"base-carrying result second", malloryResult + "," + aliceResult},
		{"base-carrying result first", aliceResult + "," + malloryResult},
	} {
		t.Run(tc.name, func(t *testing.T) {
			c := serveBody(t, http.StatusOK,
				`{"type":"multiinfo","resultcount":2,"results":[`+tc.results+`]}`)
			got, err := c.Info(context.Background(), []string{"librewolf", "librewolf-bin"})
			if err != nil {
				t.Fatalf("Info: %v", err)
			}
			// The package actually NAMED librewolf is mallory's, so the
			// librewolf key must carry mallory's provenance and alice's
			// PackageBase claim on the same string must not displace it.
			p, ok := got["librewolf"]
			if !ok {
				t.Fatalf("librewolf missing from %v", got)
			}
			if p.Name != "librewolf" || p.Maintainer != "mallory" {
				t.Errorf(`got["librewolf"] = %+v, want the package NAMED librewolf`, p)
			}
			// alice's own name key is untouched.
			if a := got["librewolf-bin"]; a.Name != "librewolf-bin" || a.Maintainer != "alice" {
				t.Errorf(`got["librewolf-bin"] = %+v, want alice's package`, a)
			}
			// And no key may carry an entry that is neither named nor based on it.
			for k, v := range got {
				if v.Name != k && v.PackageBase != k {
					t.Errorf("key %q carries %+v, which is neither named nor based on it", k, v)
				}
			}
		})
	}
}

// TestInfoRejectsUnindexableResult pins R8: a result with neither Name nor
// PackageBase indexes nowhere, yet it satisfies the resultcount check — so a
// broken response made every requested base read as absent. Per contract rule 1
// that is a gap, not an absence.
func TestInfoRejectsUnindexableResult(t *testing.T) {
	c := serveBody(t, http.StatusOK, `{"type":"multiinfo","resultcount":1,"results":[
	  {"Maintainer":"alice","Submitter":"alice","FirstSubmitted":1700000000,"LastModified":1710000000}]}`)
	got, err := c.Info(context.Background(), []string{"librewolf-fix-bin"})
	if err == nil {
		t.Fatalf("a result with no Name and no PackageBase must error, got %v", got)
	}
	if got != nil {
		t.Errorf("got %v alongside the error, want nil", got)
	}
}

// TestGetRejectsOversizedBody pins F8: io.ReadAll over a LimitReader returns a
// short read with err == nil, so padding past the cap silently truncated the
// page and a tombstone beyond the cap vanished. The cap stays (it is a correct
// response-bomb defence) but exceeding it is now an error, so the caller
// records a Gap. bodyCap is lowered here only to keep the test cheap; the
// frozen NewHTTP signature is untouched.
func TestGetRejectsOversizedBody(t *testing.T) {
	const limit = 512
	atCap := strings.Repeat("x", limit)
	overCap := strings.Repeat("x", limit+1)

	c := serveBody(t, http.StatusOK, atCap)
	c.bodyCap = limit
	body, err := c.get(context.Background(), c.base+"/anything")
	if err != nil {
		t.Fatalf("body exactly at the cap must succeed: %v", err)
	}
	if len(body) != limit {
		t.Errorf("got %d bytes, want %d", len(body), limit)
	}

	c = serveBody(t, http.StatusOK, overCap)
	c.bodyCap = limit
	if _, err := c.get(context.Background(), c.base+"/anything"); err == nil {
		t.Fatal("body past the cap must error, not short-read silently")
	}

	// And the error must reach Tombstone's caller rather than becoming a clean
	// "no tombstone here": the padded page carries a real tombstone past the cap.
	c = serveBody(t, http.StatusOK,
		strings.Repeat(" ", limit)+readFixture(t, "log-tombstoned-librewolf-fix-bin.html"))
	c.bodyCap = limit
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err == nil {
		t.Fatal("an oversized cgit page must error, not report absence")
	}
	if present || msg != "" {
		t.Errorf("got (%v, %q), want the zero result alongside the error", present, msg)
	}
}

// TestTombstoneOnRealTombstonedFixture is the primary positive pin, driven from
// the captured page of the real 2025 removal.
func TestTombstoneOnRealTombstonedFixture(t *testing.T) {
	c := serveBody(t, http.StatusOK, readFixture(t, "log-tombstoned-librewolf-fix-bin.html"))
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !present {
		t.Fatal("the real tombstone must be detected")
	}
	// Exact equality proves the subject was extracted, unescaped and trimmed
	// rather than sliced out of surrounding markup.
	if msg != realTombstoneSubject {
		t.Errorf("msg = %q, want %q", msg, realTombstoneSubject)
	}
	if !IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
	}
}

// TestTombstoneSingleCommitRemovalIsATombstone is the structural gate's positive
// pin and must never regress: a history removal TRUNCATES the parent chain, so
// the one verified real tombstone is a single-commit log whose sole commit is a
// removal notice. That is branch 1 of the gate — every commit in the log is a
// removal — and it is why the gate needs no row positions at all.
func TestTombstoneSingleCommitRemovalIsATombstone(t *testing.T) {
	body := readFixture(t, "log-tombstoned-librewolf-fix-bin.html")

	// Pin the structural premise: exactly one commit, and it is a removal.
	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if len(subjects) != 1 {
		t.Fatalf("got %d subjects, want the captured 1-commit history", len(subjects))
	}
	if !anchoredRemoval(subjects[0]) {
		t.Fatalf("the sole subject %q must read as a removal notice", subjects[0])
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !present {
		t.Fatal("the real tombstone must be detected")
	}
	if msg != realTombstoneSubject {
		t.Errorf("msg = %q, want %q", msg, realTombstoneSubject)
	}
	if !IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
	}
}

// TestTombstoneOnRealPresentPackageFixture is the F5 regression pin: 50 real
// commit rows, a search form and six tab links naming the base, and a
// /commit/ link in the tab bar that is not a commit row. None of it may
// fabricate a tombstone.
func TestTombstoneOnRealPresentPackageFixture(t *testing.T) {
	c := serveBody(t, http.StatusOK, readFixture(t, "log-present-yay.html"))
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if present {
		t.Errorf("false tombstone on a live package: msg = %q", msg)
	}
}

// TestTombstonePaginatedLogNeedsNoGap pins R3 as DISSOLVED rather than fixed.
// The captured yay page is the newest 50 of N commits and carries a `[next]`
// pager, so 50 of an unknown total were read — and that is still a clean,
// error-free "no tombstone". Seeing two or more commits is already conclusive
// proof that the history is not truncated, which is the only thing the gate
// needs, so pagination is not a coverage gap.
func TestTombstonePaginatedLogNeedsNoGap(t *testing.T) {
	body := readFixture(t, "log-present-yay.html")
	if !strings.Contains(body, "[next]") {
		t.Fatal("the yay fixture is expected to carry a [next] pager link")
	}
	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if len(subjects) != 50 {
		t.Fatalf("got %d subjects, want 50", len(subjects))
	}
	// No subject in the captured page is a removal notice, so nothing pushes
	// this page into the ambiguity branch.
	for i, s := range subjects {
		if anchoredRemoval(s) {
			t.Fatalf("subjects[%d] = %q reads as a removal; the fixture is expected to be ordinary", i, s)
		}
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if err != nil {
		t.Fatalf("a paginated log must not be a coverage gap: %v", err)
	}
	if present || msg != "" {
		t.Errorf("got (%v, %q), want a clean (false, \"\")", present, msg)
	}
}

// TestTombstoneMissingLogTableIsAnError pins F7. A 200 response with no cgit
// log table — captive portal, proxy interception, maintenance page, or cgit's
// own error page — is a coverage gap, never a clean bill of health.
func TestTombstoneMissingLogTableIsAnError(t *testing.T) {
	notCgit := readFixture(t, "log-404-nonexistent-branch.html")
	if strings.Contains(notCgit, "list nowrap") {
		t.Fatal("the 404 fixture is expected to have no log table")
	}

	t.Run("200 with no log table", func(t *testing.T) {
		c := serveBody(t, http.StatusOK, notCgit)
		present, msg, err := c.Tombstone(context.Background(), "zzz-arch-drift-does-not-exist-zzz")
		if err == nil {
			t.Fatal("a 200 response with no cgit log table must be an error")
		}
		// Explicitly: not the old (false, "", nil) clean bill of health.
		if present != false || msg != "" || err == nil {
			t.Errorf("got (%v, %q, %v)", present, msg, err)
		}
	})

	t.Run("genuine 404", func(t *testing.T) {
		c := serveBody(t, http.StatusNotFound, notCgit)
		_, _, err := c.Tombstone(context.Background(), "zzz-arch-drift-does-not-exist-zzz")
		if err == nil {
			t.Fatal("an HTTP 404 must be an error, not an absence")
		}
	})

	t.Run("captive portal", func(t *testing.T) {
		c := serveBody(t, http.StatusOK,
			`<html><body><h1>Sign in to continue</h1><p>Guest WiFi</p></body></html>`)
		_, _, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
		if err == nil {
			t.Fatal("a non-cgit 200 page must be an error")
		}
	})
}

// TestParseCgitLogRowCountMismatchIsAnError pins R7: a commit row whose anchor
// the matcher cannot read used to be dropped in silence, shortening the log.
// Row indices no longer matter under the structural gate, but the row COUNT is
// what separates a truncated history from a live one, so a markup change must
// become a Gap rather than a quiet miscount.
func TestParseCgitLogRowCountMismatchIsAnError(t *testing.T) {
	body := readFixture(t, "log-present-yay.html")
	const anchor = "/cgit/aur.git/commit/?h=yay&amp;id=946126d6f244c64c2876cdfb443c65f1f4fd2a7d"
	if !strings.Contains(body, anchor) {
		t.Fatalf("yay fixture is expected to contain %q", anchor)
	}
	// Keep the row and its `<a>`, break only the href the matcher keys on.
	mangled := strings.Replace(body, anchor, "/cgit/aur.git/tree/?h=yay", 1)

	subjects, err := parseCgitLog(mangled)
	if err == nil {
		t.Fatalf("an unreadable commit row must error, got %d subjects", len(subjects))
	}
	if subjects != nil {
		t.Errorf("got %d subjects alongside the error, want none", len(subjects))
	}
	if !strings.Contains(err.Error(), "50 commit rows but 49") {
		t.Errorf("error must name the mismatch, got %v", err)
	}

	// And it must reach Tombstone's caller as a Gap, not as an absence.
	c := serveBody(t, http.StatusOK, mangled)
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if err == nil {
		t.Fatal("a miscounted log must be an error, not a clean absence")
	}
	if present || msg != "" {
		t.Errorf("got (%v, %q), want the zero result alongside the error", present, msg)
	}
}

// TestTombstoneClassifiesLongSubjectsWholly pins F2: the old 60-character
// window truncated at 74-75 chars, so this 103-character subject was
// classified as administrative because "trojan" fell outside the window.
func TestTombstoneClassifiesLongSubjectsWholly(t *testing.T) {
	const subject = "history removed due to the maintainer uploading a modified upstream tarball containing a trojan dropper"
	if len(subject) != 103 {
		t.Fatalf("subject length = %d, want 103", len(subject))
	}
	c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, subject))
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !present {
		t.Fatal("removal not detected")
	}
	if msg != subject {
		t.Errorf("msg = %q (%d chars), want the whole subject (%d chars)", msg, len(msg), len(subject))
	}
	if !IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
	}
}

// TestTombstoneUnescapesEntities pins F9: cgit escapes subjects, and the old
// window spent five of its sixty characters on each `&#39;`, flipping the same
// subject between malware and administrative on escaping alone.
//
// N1 changed the wording only, not the pin: the former `removed: malware in the
// maintainer's ...` carries no `history` qualifier, so as a sole commit it is no
// longer a tombstone but a Gap, and a Gap returns no message to compare. The
// history-bearing form keeps the entity-decoding assertions exact.
func TestTombstoneUnescapesEntities(t *testing.T) {
	const plain = "history removed due to malware in the maintainer's prebuilt binary"
	const escaped = "history removed due to malware in the maintainer&#39;s prebuilt binary"

	c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, escaped))
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !present {
		t.Fatal("removal not detected in an escaped subject")
	}
	if msg != plain {
		t.Errorf("msg = %q, want the unescaped %q", msg, plain)
	}
	if strings.Contains(msg, "&#") {
		t.Errorf("msg still carries an HTML entity: %q", msg)
	}
	if IsMalwareRemoval(msg) != IsMalwareRemoval(plain) {
		t.Errorf("escaped and unescaped forms classify differently: %v vs %v",
			IsMalwareRemoval(msg), IsMalwareRemoval(plain))
	}
	if !IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
	}
}

// TestTombstoneRowZeroOrdinaryCommitIsNotACritical is the R4 regression pin and
// the most important test in this round.
//
// The deleted gate admitted row 0 UNCONDITIONALLY, so each of these twelve
// ordinary subjects — every one a real thing a maintainer writes — became
// present=true, malware=true when substituted into the newest row of the
// captured live 50-commit yay page. The same twelve at row 13 were rejected, so
// the protection was temporal, not structural: every deep row was row 0 once.
//
// Under the structural gate a 50-commit history cannot be a truncated one, so
// none of them may come back as a critical. They come back as a Gap instead
// (branch 2), which is the honest answer: malware wording in a removal notice
// inside a live history is genuinely undecidable from this page alone.
func TestTombstoneRowZeroOrdinaryCommitIsNotACritical(t *testing.T) {
	for _, subject := range r4OrdinarySubjects {
		t.Run(subject, func(t *testing.T) {
			body := yayFixtureWithNewestSubject(t, subject)

			// Pin the setup: the subject really is at row 0 of a 50-commit log,
			// really reads as a removal, and really is malware-bearing —
			// otherwise the gate is untested.
			subjects, err := parseCgitLog(body)
			if err != nil {
				t.Fatalf("parseCgitLog: %v", err)
			}
			if len(subjects) != 50 {
				t.Fatalf("got %d subjects, want 50", len(subjects))
			}
			if subjects[0] != subject {
				t.Fatalf("subjects[0] = %q, want the injected %q", subjects[0], subject)
			}
			if !anchoredRemoval(subject) {
				t.Fatalf("%q must read as a removal, else the gate is untested", subject)
			}
			if !IsMalwareRemoval(subject) {
				t.Fatalf("%q must be malware-bearing, else the gate is untested", subject)
			}

			c := serveBody(t, http.StatusOK, body)
			present, msg, err := c.Tombstone(context.Background(), "yay")
			if present {
				t.Fatalf("FALSE CRITICAL: row 0 of a live 50-commit log became a tombstone: msg = %q", msg)
			}
			// The designed outcome is a Gap, not silence — for every subject
			// branch 2 can see. N4's `removalAnywhereRe` omits the bare `drop`
			// inflections that `removalHeadRe` admits (it carries `dropped` but
			// not `drop`/`drops`), so `drop miner support, use the upstream
			// release` and `drops the beacon example config` reach branch 3 and
			// answer a clean (false, "", nil) instead. Silence on an ordinary
			// commit is not a defect, but it IS a narrower answer than the round's
			// design states; see the lane report.
			if wantGap := removalAnywhereRe.MatchString(subject); wantGap && err == nil {
				t.Errorf("want the ambiguity gap, got a clean (%v, %q, nil)", present, msg)
			} else if !wantGap && err != nil {
				t.Errorf("no removal word for branch 2 to see, so want silence, got %v", err)
			}
		})
	}
}

// TestTombstoneAmbiguousHistoryIsAGap pins R2: a REAL tombstone wording at an
// interior row of a multi-commit log used to return (false, "", nil) — silence.
// The history is not truncated so it is not a tombstone, but a
// tombstone-plus-later-commits (a resurrected base) is indistinguishable from an
// ordinary commit that mentions malware, and per contract rule 1 that ambiguity
// is a coverage gap, never a clean pass.
func TestTombstoneAmbiguousHistoryIsAGap(t *testing.T) {
	body := yayFixtureWithMiddleSubject(t, realTombstoneSubject)

	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if len(subjects) != 50 {
		t.Fatalf("got %d subjects, want 50", len(subjects))
	}
	if subjects[13] != realTombstoneSubject {
		t.Fatalf("subjects[13] = %q, want the injected %q", subjects[13], realTombstoneSubject)
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if err == nil {
		t.Fatal("an interior tombstone wording must be a Gap, not silence")
	}
	// Explicitly NOT the old (false, "", nil).
	if present || msg != "" {
		t.Errorf("got (%v, %q), want the zero result alongside the error", present, msg)
	}
	if !strings.Contains(err.Error(), realTombstoneSubject) ||
		!strings.Contains(err.Error(), "50-commit history") {
		t.Errorf("the gap reason must name the wording and the history size, got %v", err)
	}
}

// TestTombstoneOldestRowOfCompleteLogIsAGap replaces the old
// TestTombstoneOldestRowOfCompleteLogIsATombstone. The oldest-row branch is
// gone: it guessed that a resurrected base carries its tombstone as the oldest
// commit of a complete log, and paid for the guess with a false critical
// whenever a live complete log's initial import mentioned malware. The same
// shape is now an honest Gap in either direction — and completeness no longer
// enters the decision at all, which is why R10 (an unclosed `<ul class='pager'>`
// read as a complete log) has nothing left to exploit.
func TestTombstoneOldestRowOfCompleteLogIsAGap(t *testing.T) {
	body := readFixture(t, "log-present-yay.html")
	// Empty the pager so the log reads as complete, then put the tombstone last.
	body = strings.Replace(body,
		`<ul class='pager'><li><a href='/cgit/aur.git/log/?h=yay&amp;ofs=50'>[next]</a></li></ul>`,
		`<ul class='pager'></ul>`, 1)
	if strings.Contains(body, "[next]") {
		t.Fatal("failed to empty the fixture's pager")
	}
	body = strings.Replace(body, ">upgpkg: yay 10.2.2-2</a>", ">"+realTombstoneSubject+"</a>", 1)

	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if subjects[len(subjects)-1] != realTombstoneSubject {
		t.Fatalf("oldest subject = %q, want the injected tombstone", subjects[len(subjects)-1])
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if err == nil {
		t.Fatal("the oldest row of a 50-commit log must be a Gap, not a tombstone")
	}
	if present || msg != "" {
		t.Errorf("got (%v, %q), want the zero result alongside the error", present, msg)
	}
}

// TestTombstoneDeepRowRemovalIsNotATombstone keeps the F5 case — a
// removal-sounding commit buried mid-history in a live 50-commit log is not a
// tombstone, and malware wording buys it no exemption — but the answer changed.
// It used to be (false, "", nil), which is false assurance: the same page shape
// could also be a resurrected base. It is now a Gap (branch 2), i.e. an
// explicit "I could not decide".
func TestTombstoneDeepRowRemovalIsNotATombstone(t *testing.T) {
	const subject = "removed malware samples from the git history"
	body := yayFixtureWithMiddleSubject(t, subject)

	// Pin the setup itself: middle row of a 50-commit log.
	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if len(subjects) != 50 {
		t.Fatalf("got %d subjects, want 50", len(subjects))
	}
	if subjects[13] != subject {
		t.Fatalf("subjects[13] = %q, want the injected %q", subjects[13], subject)
	}
	if !anchoredRemoval(subject) {
		t.Fatalf("the injected subject must itself look like a removal, else the gate is untested")
	}
	if !IsMalwareRemoval(subject) {
		t.Fatalf("the injected subject must itself be malware-bearing, else the gate is untested")
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "yay")
	if present {
		t.Fatalf("deep-row removal became a tombstone: msg = %q", msg)
	}
	if err == nil {
		t.Error("a deep-row malware-bearing removal must be a Gap, not (false, \"\", nil)")
	}
}

// TestTombstoneAlternatePhrasings is the F1 table: nine measured phrasings the
// old preposition-gated regex missed entirely, each served as the sole row of
// the real tombstone fixture.
//
// N1 SPLIT this table, and round 4 UNSPLIT it. The split was N1's visible price:
// branch 1 requires a DISTINCTIVE history-removal form, because "every subject is
// an anchored removal" is satisfied by any short ordinary history — which is how
// all twelve r4OrdinarySubjects produced false criticals as sole commits. Six of
// these nine phrasings carry no `history` qualifier, so they became Gaps.
//
// A Gap is not silence, so F1's original defect never returned — but "could not
// decide" is the wrong answer for a malware removal NOTICE, and the claim behind
// the split (that no regex can tell `removed: malware in the sources` from
// `removed the malware test corpus` on the removal verb alone) is true only if the
// verb is all you look at. REASON POSITION separates them: the notice states its
// reason immediately after the verb or a delimiter, the ordinary commit removes a
// THING and a noun phrase intervenes. `reasonPositionStrongRe` is that predicate,
// and it admits all six of these while rejecting all twelve r4OrdinarySubjects —
// which TestTombstoneShortLogOrdinaryCommitsAreNotCriticals pins from the other
// side, in all three log shapes.
//
// So all nine rows are tombstones again, and every one carries the malware
// verdict. `wantTombstone` survives as a field because the split may have to
// return if the predicate is ever narrowed.
func TestTombstoneAlternatePhrasings(t *testing.T) {
	cases := []struct {
		subject       string
		wantTombstone bool
	}{
		// The `history` qualifier is present.
		{"remove history: malware in the PKGBUILD", true},
		{"delete history due to malware", true},
		{"aur-general: history removed due to malware", true},
		// No `history` qualifier, but the malware term sits in REASON position
		// directly after the verb or a delimiter: a removal notice (F1, round 4).
		{"removed: malware in the sources", true},
		{"removed (malware)", true}, // `(` is a connector
		{"deleted due to malware", true},
		{"removed - malware", true},
		{"removed  due to malware", true}, // double space: whitespace must be collapsed
		// stripLeadingNoise turns this into `removed] malware …`, so `]` must be a
		// connector too.
		{"[removed] malware in the prebuilt binary", true},
	}
	for _, tc := range cases {
		t.Run(tc.subject, func(t *testing.T) {
			c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, tc.subject))
			present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
			if !tc.wantTombstone {
				if present {
					t.Fatalf("%q must not be a tombstone without a history qualifier: msg = %q", tc.subject, msg)
				}
				if err == nil {
					t.Fatalf("%q must be a Gap, not a clean (false, %q, nil)", tc.subject, msg)
				}
				return
			}
			if err != nil {
				t.Fatalf("Tombstone: %v", err)
			}
			if !present {
				t.Fatalf("removal not detected in %q", tc.subject)
			}
			if !IsMalwareRemoval(msg) {
				t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
			}
		})
	}
}

// TestTombstoneResetVerb pins R9. `reset` was excluded as a removal verb because
// `reset pkgrel to 1` is ordinary AUR wording, which missed three measured
// malware removals outright. Admitting it in the ANCHORED forms only is nearly
// free under the structural gate, and the second half of this test is the proof:
// `reset pkgrel to 1` at the head of a live 50-commit log stays clean, because
// branch 1 needs every commit to be a removal and branch 2 needs the subject to
// be malware-bearing.
// N1 moved one of its three rows: `reset: malware in the sources` carries no
// `history` qualifier, so it is not a historyRemoval and cannot fire branch 1.
// It is malware-bearing and carries a removal word, so it becomes a Gap on
// branch 2 — the decided outcome, because silence there would be false assurance
// while a critical would rest on nothing but the verb `reset`. The other two
// carry `history` in either word order and stay tombstones.
func TestTombstoneResetVerb(t *testing.T) {
	for _, tc := range []struct {
		subject       string
		wantTombstone bool
	}{
		{"history reset due to malware", true},
		{"reset history: malware in the PKGBUILD", true},
		{"reset: malware in the sources", false},
	} {
		t.Run(tc.subject, func(t *testing.T) {
			c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, tc.subject))
			present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
			if !tc.wantTombstone {
				if present {
					t.Fatalf("%q must not be a tombstone on the verb alone: msg = %q", tc.subject, msg)
				}
				if err == nil {
					t.Fatalf("%q must be a Gap, not silence", tc.subject)
				}
				return
			}
			if err != nil {
				t.Fatalf("Tombstone: %v", err)
			}
			if !present {
				t.Fatalf("removal not detected in %q", tc.subject)
			}
			if !IsMalwareRemoval(msg) {
				t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
			}
		})
	}

	t.Run("reset pkgrel to 1 at row 0 of a live log", func(t *testing.T) {
		c := serveBody(t, http.StatusOK, yayFixtureWithNewestSubject(t, "reset pkgrel to 1"))
		present, msg, err := c.Tombstone(context.Background(), "yay")
		if err != nil {
			t.Fatalf("Tombstone: %v", err)
		}
		if present {
			t.Errorf("ordinary `reset pkgrel` wording became a tombstone: msg = %q", msg)
		}
	})
}

// TestTombstoneRejectsMidSubjectRemovalWord pins the reason the removal verb is
// anchored at position 0: an ordinary version bump that happens to mention a
// removal must not become a tombstone.
func TestTombstoneRejectsMidSubjectRemovalWord(t *testing.T) {
	const subject = "upgpkg: 2.1.0-1: patch removed for security reasons upstream"
	c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, subject))
	present, msg, err := c.Tombstone(context.Background(), "some-pkg")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if present {
		t.Errorf("mid-subject removal word became a tombstone: msg = %q", msg)
	}
}

// TestTombstoneDoesNotStripBasePrefix pins the reviewer's measured cost of
// stripping a leading `<base>:` prefix: security-tooling bases legitimately
// describe removing malware corpora, and no base-prefixed tombstone has ever
// been observed.
//
// The rejection rests entirely on anchoredRemoval declining a subject whose
// first token is the base name — the structural gate never gets a candidate to
// weigh, so these are never CRITICALS even as the SOLE commit of a log, which is
// the tombstone shape. `reset pkgrel to 1` used to be pinned here too and has moved
// to TestTombstoneResetVerb: R9 makes it an anchored removal, so as a sole
// commit it now reads as a (non-malware) removal-only history. It is pinned
// against the live 50-commit log instead, which is where the wording occurs.
//
// N4 changed the answer from clean to Gap: branch 2 no longer requires the
// removal verb at position 0, so a malware-bearing subject with a removal word
// anywhere is undecidable rather than clean. That is the intended trade — the
// alternative was staying silent on `base removed: malware in the PKGBUILD`.
func TestTombstoneDoesNotStripBasePrefix(t *testing.T) {
	for _, subject := range []string{
		"pev: removed the malware test corpus",
		"yara: dropped the backdoor ruleset",
	} {
		t.Run(subject, func(t *testing.T) {
			if anchoredRemoval(subject) {
				t.Fatalf("%q must not read as a removal notice", subject)
			}
			if historyRemoval(subject) {
				t.Fatalf("%q must not read as a history removal", subject)
			}
			c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, subject))
			present, msg, err := c.Tombstone(context.Background(), "pev")
			if present {
				t.Errorf("false tombstone on %q: msg = %q", subject, msg)
			}
			// A Gap, not a critical and not silence.
			if err == nil {
				t.Errorf("want the ambiguity gap on %q, got a clean (%v, %q, nil)", subject, present, msg)
			}
		})
	}
}

// A removed-for-malware package keeps its cgit repo with a tombstone commit.
//
// Rewritten onto the captured fixtures: the hand-written
// `<html><td>...</td></html>` bodies this test used to serve carry no cgit log
// table, which is now an error (F7) rather than a matchable page. The behaviour
// pinned is unchanged.
func TestTombstoneDetectsMalwareRemoval(t *testing.T) {
	tombstone := readFixture(t, "log-tombstoned-librewolf-fix-bin.html")
	ordinary := readFixture(t, "log-present-yay.html")
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if strings.Contains(r.URL.RawQuery, "librewolf-fix-bin") {
			io.WriteString(w, tombstone)
			return
		}
		io.WriteString(w, ordinary)
	}))
	defer srv.Close()
	c := NewHTTP(srv.URL, srv.Client())
	found, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !found {
		t.Fatal("tombstone not detected")
	}
	if !strings.Contains(msg, "malware") {
		t.Errorf("msg = %q", msg)
	}
	found, _, err = c.Tombstone(context.Background(), "brave-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if found {
		t.Error("false tombstone on an ordinary package")
	}
}

// TestTombstonePresentForAdministrativeRemoval pins that Tombstone reports
// presence of any removal commit — administrative or malware — while
// IsMalwareRemoval alone decides the malware/administrative split. Tombstone
// must not collapse the two responsibilities.
//
// Rewritten onto the captured fixture markup for the same reason as
// TestTombstoneDetectsMalwareRemoval: its former hand-written body had no cgit
// log table and is now an error, not a match.
//
// N1 changed the wording from `removed due to rename` to the history-bearing
// form. The contract's requirement is unchanged and is what this still pins —
// Tombstone reports PRESENCE for an administrative removal and IsMalwareRemoval
// alone decides the severity split. But a bare `removed due to rename` as a sole
// commit is no longer presence: it is indistinguishable from a one-commit repo
// whose only commit removed a file, so branch 1 declines it and it comes back
// clean. That narrowing is the documented cost of the N1 fix, and it is the same
// predicate that makes `reset pkgrel to 1` clean.
func TestTombstonePresentForAdministrativeRemoval(t *testing.T) {
	c := serveBody(t, http.StatusOK,
		tombstoneFixtureWithSubject(t, "history removed due to rename to some-pkg-bin"))
	found, msg, err := c.Tombstone(context.Background(), "some-pkg")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !found {
		t.Fatal("administrative removal must still be reported as present")
	}
	if IsMalwareRemoval(msg) {
		t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
	}
}

// TestTombstonePrefersMalwareBearingCandidate pins F4's surviving intent: when a
// truncated history holds more than one removal notice, the malware-bearing
// subject is returned so an administrative one cannot shadow it.
//
// Rebuilt onto a two-commit removal-only log, because the shape it used to use —
// the newest and oldest rows of a complete 50-commit log — no longer produces
// two candidates: a 50-commit history is not a truncated one, so branch 1 cannot
// fire on it at all.
func TestTombstonePrefersMalwareBearingCandidate(t *testing.T) {
	body := tombstoneFixtureWithSubjects(t, "removed due to rename", realTombstoneSubject)

	subjects, err := parseCgitLog(body)
	if err != nil {
		t.Fatalf("parseCgitLog: %v", err)
	}
	if len(subjects) != 2 {
		t.Fatalf("got %d subjects, want 2", len(subjects))
	}
	for i, s := range subjects {
		if !anchoredRemoval(s) {
			t.Fatalf("subjects[%d] = %q must read as a removal, else branch 1 cannot fire", i, s)
		}
	}
	if IsMalwareRemoval(subjects[0]) {
		t.Fatalf("the newest subject %q must be the administrative one", subjects[0])
	}

	c := serveBody(t, http.StatusOK, body)
	present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if !present {
		t.Fatal("removal not detected")
	}
	if msg != realTombstoneSubject {
		t.Errorf("msg = %q, want the malware-bearing %q", msg, realTombstoneSubject)
	}
}

// TestIsMalwareRemovalDistinguishesAdministrativeRemovals pins both
// directions of contract rule 3: a false malware accusation and a missed
// malware removal are both defects.
func TestIsMalwareRemovalDistinguishesAdministrativeRemovals(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"history removed due to malware", true},
		{"removed due to rename", false},
		{"removed due to merge into another package", false},
		{"history removed due to malicious code in the PKGBUILD", true},
	}
	for _, c := range cases {
		if got := IsMalwareRemoval(c.msg); got != c.want {
			t.Errorf("IsMalwareRemoval(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
}

// TestIsMalwareRemovalHyphenCompounds pins R1 in both directions.
//
// The hyphen-strict term guard DISCARDED every hyphen-compounded malware
// wording: these nine were each verified in isolation, with no other term
// present, and each classified as not-malware. The guard existed for exactly two
// measured cases and both are package names — so the fix demotes a
// hyphen-adjacent strong term into the vetoable tier instead of dropping it, and
// the two package names stay false on their `rename`/`merge` token.
func TestIsMalwareRemovalHyphenCompounds(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"removed: trojan-dropper in the prebuilt binary", true},
		{"history removed due to a malware-laden prebuilt binary", true},
		{"removed: trojan-infected upstream tarball", true},
		{"removed the backdoor-laced install hook", true},
		{"removed: rootkit-style LD_PRELOAD shim in the package", true},
		{"removed a keylogger-like input grabber", true},
		{"removed: info-stealer in the vendored binary", true},
		{"removed infostealer blob from the tarball", true},
		{"history removed due to a backdoor-dropper in the sources", true},
		// The two measured cases the hyphen guard existed for: a strong term
		// inside a package NAME. Both carry a load-bearing veto token.
		{"removed due to rename to malware-analysis-toolkit", false},
		{"history removed due to merge into clamav-unofficial-sigs-malware-expert", false},
	}
	for _, c := range cases {
		if got := IsMalwareRemoval(c.msg); got != c.want {
			t.Errorf("IsMalwareRemoval(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
	// And a bare strong term stays unvetoable no matter what else is present.
	if !IsMalwareRemoval("history removed due to malware") {
		t.Error("a bare strong term must remain unvetoable")
	}
}

// TestIsMalwareRemovalStemsInIsolation pins the stem terms against regression.
// Every string below carries exactly ONE malware term, so a co-occurring term
// cannot rescue the row — which is how the R1 re-attack measured them.
func TestIsMalwareRemovalStemsInIsolation(t *testing.T) {
	for _, msg := range []string{
		// exfiltrat
		"removed for exfiltrating ~/.ssh to a remote host",
		"removed: exfiltration of browser cookies at build time",
		"removed, the install hook exfiltrated the ssh directory",
		// obfuscat
		"removed obfuscated install hook",
		"removed: heavy obfuscation in the vendored blob",
		// typosquat
		"removed typosquatting base",
		"removed typosquatted base of a distro package",
		// hijack
		"removed upload from a hijacked account",
		"removed after account hijacking",
		// stealer, as a suffix stem: `infostealer` is one word
		"removed infostealer blob from the tarball",
	} {
		if !IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
		}
	}
	// The word-boundary semantics the stems must not cost: a term may not match
	// inside an unrelated word.
	for _, msg := range []string{
		"removed the generate step from the PKGBUILD",
		"removed corporate mirror from the sources",
		"removed wormhole support, upstream dropped it",
		"removed the determiner cache, examiner output is enough",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
		}
	}
}

// TestIsMalwareRemovalDroppedVetoTokens pins R5. Nine of the eleven veto tokens
// carried zero measured weight while each opened a suppression path; dropping
// them turns these malware removals from false-assurance into true.
//
// N2 flipped the last three rows from false to true. They were the residual R5
// documented and deferred: a veto token appearing AFTER the reason clause still
// suppressed. The veto is now reason-positional, so `merged from a forked
// repository`, `sources moved to a new mirror` and `; base renamed` no longer
// veto — in each the reason is the compromise, not the rename. `merge`/`rename`
// remain load-bearing where they ARE the reason, which is what still keeps
// `removed due to rename to malware-analysis-toolkit` and `history removed due to
// merge into clamav-...-malware-expert` false (pinned in
// TestIsMalwareRemovalHyphenCompounds and the F6 corpus).
func TestIsMalwareRemovalDroppedVetoTokens(t *testing.T) {
	cases := []struct {
		msg  string
		want bool
	}{
		{"removed due to policy violation: obfuscated payload in the install hook", true}, // policy
		{"removed duplicate base carrying the same compromised tarball", true},            // duplicate
		{"removed dupe of the hijacked upstream mirror", true},                            // dupe
		{"removed orphaned base after an unauthorized upload", true},                      // orphan
		{"removed compromised prebuilt binary, replaced by a source build", true},         // replaced by
		{"removed unauthorized upload with a forged license header", true},                // license
		{"removed compromised release at upstream request", true},                         // upstream request
		// N2: the veto token is present but NOT in a reason position, so it no
		// longer suppresses. In each of these the stated reason is the compromise.
		{"removed compromised sources merged from a forked repository", true},           // merged, not the reason
		{"removed compromised tarball; sources moved to a new mirror", true},            // moved to, not the reason
		{"history removed due to a compromised maintainer account; base renamed", true}, // was the TODO(P1-B) residual
	}
	for _, c := range cases {
		if got := IsMalwareRemoval(c.msg); got != c.want {
			t.Errorf("IsMalwareRemoval(%q) = %v, want %v", c.msg, got, c.want)
		}
	}
	// The deliberate, documented cost of dropping `co-maintainer`: a compromised
	// maintainer account is THE AUR malware vector, so the token correlates with
	// genuine compromise and vetoing on it suppressed the notices that matter
	// most. This string was removed from the false-accusation corpus for it.
	if !IsMalwareRemoval("removed unauthorized upload of a stale sdist by a co-maintainer") {
		t.Error("dropping the co-maintainer veto must let this read as malware")
	}
}

// TestIsMalwareRemovalFalseAccusationCorpus is the F6 corpus: administrative
// removals that the previous `security` term turned into malware criticals,
// plus the hyphen-guard and weak-tier-veto cases.
//
// R5 removed exactly one entry — `removed unauthorized upload of a stale sdist
// by a co-maintainer` — because the `co-maintainer` veto that kept it false was
// dropped on purpose. It was a lead-invented entry, not one of the original
// reviewer's eight, and the accepted cost is pinned in
// TestIsMalwareRemovalDroppedVetoTokens. All eight original F6 strings remain:
// six are false on term absence alone (`security` is not a term) and two rest on
// `rename`/`merge`.
func TestIsMalwareRemovalFalseAccusationCorpus(t *testing.T) {
	for _, msg := range []string{
		// `security` is not a malware indicator: eight measured false criticals.
		"history removed due to merge into security-misc",
		"removed due to rename to arch-security-tools",
		"removed due to a security policy update requiring https sources",
		"history removed due to duplicate of the security-hardening meta package",
		"removed for security policy: PKGBUILD used sudo at build time",
		"removed due to orphan cleanup; see the security tracker entry for context",
		// The hyphen guard: a strong term inside a package name is a name.
		"removed due to rename to malware-analysis-toolkit",
		"history removed due to merge into clamav-unofficial-sigs-malware-expert",
		// The administrative veto over the weak tier.
		"removed due to rename; payload moved to the -bin package",
		// `c2` is not a malware indicator either.
		"reset to c2 branch after a bad force-push",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
		}
	}
}

// TestIsMalwareRemovalFalseAssuranceCorpus is the F3 corpus: malware removals
// the six-term list missed entirely, plus the two cases proving the
// administrative veto cannot suppress a strong term.
func TestIsMalwareRemovalFalseAssuranceCorpus(t *testing.T) {
	for _, msg := range []string{
		"history removed due to a cryptominer in the prebuilt binary",
		"removed: credential stealer in the install script",
		"history removed after a supply chain attack on the upstream tarball",
		"removed for exfiltrating ~/.ssh to a remote host",
		"removed due to a keylogger in the vendored blob",
		"history removed due to a RAT in the AppImage",
		"removed obfuscated payload from the PKGBUILD",
		"removed a rogue postinstall script phoning home",
		"removed typosquatting package shipping a stager",
		"removed unauthorized upload by a hijacked account",
		// The veto gates the weak tier only, so neither of these is suppressed.
		"removed due to policy violation: backdoor stager in PKGBUILD",
		"history removed due to malware; base renamed to librewolf-bin",
	} {
		if !IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
		}
	}
}

// tombstoneFixtureWithRows builds a log of one row per (subject, author) pair
// from the captured tombstone fixture's real commit row, so the author cell —
// maintainer-controlled git metadata — can be varied while every other byte of
// captured cgit markup stays intact. authors may be shorter than subjects; the
// fixture's own author is used for the remainder.
func tombstoneFixtureWithRows(t *testing.T, subjects []string, authors []string) string {
	t.Helper()
	body, row := tombstoneFixtureRow(t)
	const fixtureAuthor = ">Bert Peters</td>"
	if !strings.Contains(row, fixtureAuthor) {
		t.Fatalf("tombstone fixture row has no author cell: %q", row)
	}
	oldSubject := ">" + realTombstoneSubject + "</a>"
	var rows strings.Builder
	for i, s := range subjects {
		r := strings.Replace(row, oldSubject, ">"+s+"</a>", 1)
		if i < len(authors) {
			r = strings.Replace(r, fixtureAuthor, ">"+authors[i]+"</td>", 1)
		}
		rows.WriteString(r)
	}
	return strings.Replace(body, row, rows.String(), 1)
}

// TestTombstoneShortLogOrdinaryCommitsAreNotCriticals is the N1 regression pin
// and the most important test in this round.
//
// Round two replaced a row-POSITION gate with a STRUCTURAL one — every commit in
// the log must be a removal notice — and pinned it against the captured
// 50-commit yay page, where a 50-row history makes that condition unsatisfiable.
// The condition is satisfied trivially by a SHORT history, and the suite never
// exercised one, so the defect was relocated rather than removed: all twelve
// r4OrdinarySubjects — the very corpus round two was written to protect —
// produced present=true with IsMalwareRemoval=true, a false SevCritical against
// a live base, when presented as the sole commit of a log, and again when paired
// with one more removal-verb commit.
//
// Both shapes are pinned here, because a one-commit repo and a two-commit repo
// are both ordinary things (a fresh AUR submission, a submission plus a fixup),
// and neither is evidence that a history was truncated.
func TestTombstoneShortLogOrdinaryCommitsAreNotCriticals(t *testing.T) {
	// A second removal-verb commit, so "every subject is an anchored removal"
	// still holds for the paired shape and only the history-removal predicate
	// stands between these subjects and a critical.
	const secondRemoval = "drop the EICAR test file"
	if !anchoredRemoval(secondRemoval) {
		t.Fatalf("%q must read as a removal, else the paired shape is untested", secondRemoval)
	}

	for _, subject := range r4OrdinarySubjects {
		// Pin the premise: each subject really is an anchored removal and really
		// is malware-word-bearing, so branch 1 is the only thing being tested.
		if !anchoredRemoval(subject) {
			t.Fatalf("%q must read as a removal, else the gate is untested", subject)
		}
		if !IsMalwareRemoval(subject) {
			t.Fatalf("%q must be malware-bearing, else the gate is untested", subject)
		}

		for _, shape := range []struct {
			name string
			log  []string
		}{
			{"sole commit", []string{subject}},
			{"paired with one more removal", []string{subject, secondRemoval}},
		} {
			t.Run(shape.name+": "+subject, func(t *testing.T) {
				body := tombstoneFixtureWithRows(t, shape.log, nil)

				// Pin the setup: the log really has the intended shape, and every
				// subject in it really is an anchored removal.
				subjects, err := parseCgitLog(body)
				if err != nil {
					t.Fatalf("parseCgitLog: %v", err)
				}
				if len(subjects) != len(shape.log) {
					t.Fatalf("got %d subjects, want %d", len(subjects), len(shape.log))
				}
				for i, s := range subjects {
					if s != shape.log[i] {
						t.Fatalf("subjects[%d] = %q, want %q", i, s, shape.log[i])
					}
					if !anchoredRemoval(s) {
						t.Fatalf("subjects[%d] = %q must read as a removal", i, s)
					}
				}

				c := serveBody(t, http.StatusOK, body)
				present, msg, err := c.Tombstone(context.Background(), "some-pkg")
				if present && IsMalwareRemoval(msg) {
					t.Fatalf("FALSE CRITICAL: a %d-commit ordinary log became a malware tombstone: msg = %q",
						len(shape.log), msg)
				}
				// Stronger, and what the fix actually delivers: not a tombstone at
				// all, because no subject claims the HISTORY was removed.
				if present {
					t.Errorf("ordinary short log became a tombstone: msg = %q", msg)
				}
				// The answer is a Gap for every subject branch 2 can see, and a
				// clean silence for the two whose only removal word is a bare
				// `drop`/`drops` inflection that removalAnywhereRe omits. Either
				// is acceptable; a critical is not.
				if wantGap := removalAnywhereRe.MatchString(subject); wantGap && err == nil {
					t.Errorf("want the ambiguity gap, got a clean (%v, %q, nil)", present, msg)
				} else if !wantGap && err != nil {
					t.Errorf("no removal word for branch 2 to see, so want silence, got %v", err)
				}
			})
		}
	}
}

// TestTombstoneSquashedForcePushIsNotARemoval pins N3. A squashed or force-pushed
// AUR repo legitimately has ONE commit, and `reset`/`drop`/`clear` are ordinary
// words for what that commit did. Round two admitted `reset` as an anchored
// removal verb on the argument that branch 1 needs every subject to be a removal
// and branch 2 needs the subject to be malware-bearing — which is exactly true of
// a one-commit log and exactly why each of these returned present=true, a
// SevSuspicious `aur-absent` against a live base.
//
// These carry no malware word, so the honest answer is silence, not a Gap:
// nothing about them is undecidable.
func TestTombstoneSquashedForcePushIsNotARemoval(t *testing.T) {
	for _, subject := range []string{
		"reset pkgrel to 1",
		"reset PKGBUILD to the working version",
		"reset to upstream tag v1.2.3",
		"drop the unused patch",
		"clear stale .SRCINFO",
	} {
		t.Run(subject, func(t *testing.T) {
			// Pin the premise: it IS an anchored removal, so only the
			// history-removal predicate rejects it.
			if !anchoredRemoval(subject) {
				t.Fatalf("%q must read as an anchored removal, else N3 is untested", subject)
			}
			if historyRemoval(subject) {
				t.Fatalf("%q must not read as a history removal", subject)
			}

			c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, subject))
			present, msg, err := c.Tombstone(context.Background(), "some-pkg")
			if present || msg != "" || err != nil {
				t.Errorf("got (%v, %q, %v), want a clean (false, \"\", nil)", present, msg, err)
			}
		})
	}
}

// TestTombstoneBracketedListPrefix pins N4's first half. The code already
// anticipated an `aur-general` list prefix, but stripped the anchored
// `^aur-general:` form BEFORE trimming a leading `[`, so the bracketed mailman
// form — the standard form of that prefix — was never stripped and
// `[aur-general] history removed due to malware` as a sole commit returned a
// clean (false, "", nil): the real tombstone wording, reported as clean.
func TestTombstoneBracketedListPrefix(t *testing.T) {
	for _, subject := range []string{
		"[aur-general] history removed due to malware",
		"[aur-general]: history removed due to malware",
		"[aur-general: history removed due to malware",
		"[AUR-general] history removed due to malware",
		"[TU] history removed due to malware",
		"[aur] history removed due to malware",
	} {
		t.Run(subject, func(t *testing.T) {
			c := serveBody(t, http.StatusOK, tombstoneFixtureWithSubject(t, subject))
			present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
			if err != nil {
				t.Fatalf("Tombstone: %v", err)
			}
			if !present {
				t.Fatalf("a bracketed list prefix must not hide the tombstone in %q", subject)
			}
			if msg != subject {
				t.Errorf("msg = %q, want the whole subject %q", msg, subject)
			}
			if !IsMalwareRemoval(msg) {
				t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
			}
		})
	}
}

// TestTombstoneUnanchoredMalwareRemovalIsAGap pins N4's second half. Branch 2
// used to require `anchoredRemoval(s) && IsMalwareRemoval(s)` on the same
// subject, so any tombstone wording that failed only the ANCHORED form was
// answered with silence rather than a Gap. All three of these are real ways to
// write the verified notice and all three returned (false, "", nil).
//
// Served in a MULTI-commit log so branch 1 cannot fire and branch 2 is what is
// under test.
func TestTombstoneUnanchoredMalwareRemovalIsAGap(t *testing.T) {
	const ordinary = "upgpkg: 1.2.3-1"
	if anchoredRemoval(ordinary) {
		t.Fatalf("%q must not read as a removal, else branch 1 could fire", ordinary)
	}

	for _, subject := range []string{
		"package history was removed due to malware",
		"history has been removed due to malware",
		"base removed: malware in the PKGBUILD",
	} {
		t.Run(subject, func(t *testing.T) {
			// Pin the premise: the anchored predicate really does decline it, so
			// the old condition really was unreachable.
			if anchoredRemoval(subject) {
				t.Fatalf("%q reads as an anchored removal; it is not the N4 case", subject)
			}
			c := serveBody(t, http.StatusOK, tombstoneFixtureWithRows(t, []string{subject, ordinary}, nil))
			present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
			if err == nil {
				t.Fatalf("%q must be a Gap, not a clean (%v, %q, nil)", subject, present, msg)
			}
			// Explicitly NOT the old (false, "", nil).
			if present || msg != "" {
				t.Errorf("got (%v, %q), want the zero result alongside the error", present, msg)
			}
			if !strings.Contains(err.Error(), subject) {
				t.Errorf("the gap reason must name the wording, got %v", err)
			}
		})
	}

	// And the removal word is still REQUIRED: a subject that mentions malware
	// while claiming no removal buys no gap. Dropping that requirement would gap
	// on every clamav-adjacent packaging commit.
	t.Run("no removal word, no gap", func(t *testing.T) {
		const subject = "upgpkg: 1.2-1: add clamav malware signatures"
		if !IsMalwareRemoval(subject) {
			t.Fatalf("%q must be malware-word-bearing, else this case is untested", subject)
		}
		c := serveBody(t, http.StatusOK, tombstoneFixtureWithRows(t, []string{subject, ordinary}, nil))
		present, msg, err := c.Tombstone(context.Background(), "clamav-unofficial-sigs")
		if present || msg != "" || err != nil {
			t.Errorf("got (%v, %q, %v), want a clean (false, \"\", nil)", present, msg, err)
		}
	})
}

// r1HyphenCompounds are the nine measured hyphen-compounded malware wordings from
// R1, each verified in isolation with no other term present.
var r1HyphenCompounds = []string{
	"removed: trojan-dropper in the prebuilt binary",
	"history removed due to a malware-laden prebuilt binary",
	"removed: trojan-infected upstream tarball",
	"removed the backdoor-laced install hook",
	"removed: rootkit-style LD_PRELOAD shim in the package",
	"removed a keylogger-like input grabber",
	"removed: info-stealer in the vendored binary",
	"removed infostealer blob from the tarball",
	"history removed due to a backdoor-dropper in the sources",
}

// TestIsMalwareRemovalVetoIsReasonPositional pins N2 in both directions.
//
// R1 demoted a hyphen-adjacent strong term into the VETOABLE tier, which made its
// fix conditional on the notice naming no replacement base — and an AUR malware
// removal routinely names one, because the removed base is usually a typosquat.
// Every one of the nine R1 compounds went back to IsMalwareRemoval=false with
// either `; base renamed to foo-bin` or `; merged into foo` appended, i.e. R1 was
// undone by the most common real trailing clause. The unhyphenated control
// `history removed due to malware; base renamed to librewolf-bin` stayed true only
// because a BARE strong term outranks the veto entirely.
//
// The veto now requires its token in a reason position, which is what an
// administrative removal looks like and what a trailing housekeeping clause is not.
func TestIsMalwareRemovalVetoIsReasonPositional(t *testing.T) {
	// The veto must keep vetoing where the token IS the reason. These three are
	// the load-bearing cases the token list exists for.
	for _, msg := range []string{
		"removed due to rename to malware-analysis-toolkit",
		"history removed due to merge into clamav-unofficial-sigs-malware-expert",
		"removed due to rename; payload moved to the -bin package",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false: the token IS the reason", msg)
		}
	}

	// And it must stop vetoing where the token merely follows the reason.
	flip := []string{
		"history removed due to trojan-dropper in the prebuilt binary; base renamed to foo-bin",
		// The residual R5 documented and deferred as TODO(P1-B).
		"history removed due to a compromised maintainer account; base renamed",
	}
	for _, c := range r1HyphenCompounds {
		flip = append(flip, c+"; base renamed to foo-bin", c+"; merged into foo")
	}
	for _, msg := range flip {
		if !IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = false, want true: the token is not the reason", msg)
		}
	}
}

// TestParseCgitLogNohoverOnlyMatchesTheTag pins N5. The header-row test was
// `strings.Contains(row, "nohover")` over the WHOLE row, so the author cell —
// maintainer-controlled git metadata — or the subject text deleted a row from BOTH
// sides of the row-count check, leaving the counts consistent and no error. A
// three-row log whose first two rows carried the author `nohover dev` parsed to a
// single subject with err == nil, and a single subject reading `history removed due
// to malware` is branch 1: a critical against a live base.
func TestParseCgitLogNohoverOnlyMatchesTheTag(t *testing.T) {
	t.Run("author cell", func(t *testing.T) {
		body := tombstoneFixtureWithRows(t,
			[]string{"upgpkg: 1.2.3-1", "upgpkg: 1.2.2-1", realTombstoneSubject},
			[]string{"nohover dev", "nohover dev"})
		subjects, err := parseCgitLog(body)
		if err != nil {
			t.Fatalf("parseCgitLog: %v", err)
		}
		if len(subjects) != 3 {
			t.Fatalf("got %d subjects, want 3: an author cell must not delete a commit row (%q)", len(subjects), subjects)
		}

		// And the collapsed log must not have been a tombstone.
		c := serveBody(t, http.StatusOK, body)
		present, msg, err := c.Tombstone(context.Background(), "librewolf-fix-bin")
		if present {
			t.Fatalf("FALSE CRITICAL: `nohover` in an author cell collapsed a 3-commit log into a tombstone: msg = %q", msg)
		}
		// The real wording in a live 3-commit history is honest ambiguity.
		if err == nil {
			t.Errorf("want the ambiguity gap, got a clean (%v, %q, nil)", present, msg)
		}
	})

	t.Run("subject text", func(t *testing.T) {
		body := tombstoneFixtureWithRows(t,
			[]string{"fix nohover css in the theme", "upgpkg: 1.2.2-1", "upgpkg: 1.2.1-1"}, nil)
		subjects, err := parseCgitLog(body)
		if err != nil {
			t.Fatalf("parseCgitLog: %v", err)
		}
		if len(subjects) != 3 {
			t.Fatalf("got %d subjects, want 3: a subject must not delete its own row (%q)", len(subjects), subjects)
		}
		if subjects[0] != "fix nohover css in the theme" {
			t.Errorf("subjects[0] = %q, want the nohover-bearing subject", subjects[0])
		}
	})

	// Uppercase `NOHOVER` on the tag itself still misses, and that is deliberate:
	// it makes cgit's header row count as a commit row with no extractable
	// subject, which is the 1:1 count mismatch — a Gap, the safe direction.
	// "Fixing" it into a case-insensitive silent skip would trade a Gap for a
	// silent row deletion.
	t.Run("uppercase tag still yields the count mismatch", func(t *testing.T) {
		body := readFixture(t, "log-tombstoned-librewolf-fix-bin.html")
		const header = "<tr class='nohover'>"
		if !strings.Contains(body, header) {
			t.Fatalf("fixture is expected to contain %q", header)
		}
		body = strings.Replace(body, header, "<tr class='NOHOVER'>", 1)

		subjects, err := parseCgitLog(body)
		if err == nil {
			t.Fatalf("an unrecognised header row must error, got %d subjects", len(subjects))
		}
		if !strings.Contains(err.Error(), "2 commit rows but 1") {
			t.Errorf("error must name the mismatch, got %v", err)
		}
	})
}

// TestIsMalwareRemovalNegationPrefixes pins the negation/defence guard. R1's
// hyphen-tolerant term guard admits a term with a hyphen on its left, so every
// one of these — each the OPPOSITE of a malware notice — classified as malware.
func TestIsMalwareRemovalNegationPrefixes(t *testing.T) {
	for _, msg := range []string{
		"removed non-malware test cases from the corpus",
		"removed the anti-malware hook",
		"drop anti-rootkit scanning from the install hook",
		"removed pseudo-trojan sample used by the test suite",
		"removed de-obfuscation helper",
		"removed the anti-virus scan step",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
		}
	}
	// Suppression is per-OCCURRENCE, not per-term: an unprefixed occurrence of
	// the same term in the same subject still counts.
	for _, msg := range []string{
		"removed the anti-malware hook and the malware sample it fed",
		"removed the anti-virus scan step after finding a trojan in the tarball",
	} {
		if !IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = false, want true: the unprefixed term must still count", msg)
		}
	}
}

// TestIsMalwareRemovalStealerPlural pins N7: the stem was singular-only, so
// `removed stealers from the tarball` and `removed infostealers` classified as
// not-malware. `stealership` must stay false — the plural `s` is still followed by
// a word boundary.
func TestIsMalwareRemovalStealerPlural(t *testing.T) {
	for _, msg := range []string{
		"removed stealers from the tarball",
		"removed infostealers",
	} {
		if !IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = false, want true", msg)
		}
	}
	for _, msg := range []string{
		"removed the stealership dealer-locator dataset",
		"dropped stealership branding assets",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
		}
	}
}

// TestIsMalwareRemovalBeaconIsWeak pins the `beacon` tier move. As a bare strong
// term it made `removed beacon chain support` — ordinary Ethereum packaging — an
// UNVETOABLE malware verdict. In the weak tier it is vetoable, and the specific
// `beacon chain` compound is suppressed outright, because RE2 has no lookahead
// and the exclusion cannot live inside the term alternation.
//
// A beacon string that SHOULD still read as malware does exist, so the term is
// not dead weight: `removed the c2 beacon in the install hook` has no veto and no
// suppressed compound. (`c2` itself is deliberately not a term — `reset to c2
// branch after a bad force-push` classified as malware when it was.)
func TestIsMalwareRemovalBeaconIsWeak(t *testing.T) {
	for _, msg := range []string{
		"removed beacon chain support",
		"drop beacon chain validator support, upstream split the package",
	} {
		if IsMalwareRemoval(msg) {
			t.Errorf("IsMalwareRemoval(%q) = true, want false", msg)
		}
	}
	if !IsMalwareRemoval("removed the c2 beacon in the install hook") {
		t.Error("a beacon with no veto and no ordinary compound must still read as malware")
	}
	// And it must be VETOABLE now, which a strong bare term is not.
	if IsMalwareRemoval("removed due to rename; the beacon module moved to the -bin package") {
		t.Error("a weak-tier beacon must be vetoable by a reason-position rename")
	}
}
