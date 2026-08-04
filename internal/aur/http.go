package aur

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"html"
	"io"
	"net/http"
	"net/url"
	"regexp"
	"strings"
)

const (
	maxBody       = 8 << 20 // hard cap; a bundle/response bomb must not exhaust memory
	userAgentName = "aurvet"

	// infoChunkSize bounds how many bases go into a single Info request's
	// arg[] list. The v5 RPC's practical arg[] ceiling is documented at
	// roughly 250 entries before a request risks a 413/414; 200 keeps a
	// margin below that so longer package names pushing the query string
	// length up do not close the gap, while still batching efficiently for
	// the reference system's population (39 foreign packages, one request).
	// A const, not a parameter (E-7): the caller has no reason to tune this,
	// and a tunable knob here is scope neither the escalation nor the frozen
	// Client interface asked for.
	infoChunkSize = 200
)

type HTTP struct {
	base string
	hc   *http.Client
	// bodyCap is the response-size cap in bytes, seeded from maxBody by
	// NewHTTP. It exists so an in-package test can exercise the cap without
	// allocating 8 MiB. Unexported on purpose: the frozen NewHTTP signature
	// does not change.
	bodyCap int64
}

var _ Client = (*HTTP)(nil)

func NewHTTP(baseURL string, hc *http.Client) *HTTP {
	if hc == nil {
		hc = http.DefaultClient
	}
	return &HTTP{base: strings.TrimRight(baseURL, "/"), hc: hc, bodyCap: maxBody}
}

type rpcResponse struct {
	Type        string `json:"type"`
	Error       string `json:"error"`
	ResultCount int    `json:"resultcount"`
	Results     []Pkg  `json:"results"`
}

// rpcSuccessTypes are the response types that mean "the RPC answered the
// question I asked". Anything else — including the empty string from a `{}`
// body — is a failed lookup, not an empty one (F10).
var rpcSuccessTypes = map[string]bool{"multiinfo": true, "info": true}

// httpStatusError carries a non-200 status together with its body, so a caller
// can inspect the body before deciding whether the status means "failure" or
// "answer".
type httpStatusError struct {
	code int
	body []byte
}

func (e *httpStatusError) Error() string { return fmt.Sprintf("http %d", e.code) }

// cgitInvalidBranchRe matches cgit's own not-a-branch error page, captured
// verbatim in testdata/aur/cgit/log-404-nonexistent-branch.html.
var cgitInvalidBranchRe = regexp.MustCompile(`(?i)cgit v[\d.]+|<div id='cgit'>`)

// isNoSuchBranch reports whether err is cgit answering "this branch does not
// exist" -- a definitive absence of any removal record, not a failed lookup.
//
// This distinction is load-bearing and rests on a measurement: librewolf-fix-bin,
// the verified 2025 malware removal, STILL answers 200 with a populated log
// table. cgit retains logs after package deletion, so a 404 cannot conceal a
// tombstone. Treating it as "could not tell" made every legitimately-absent
// package gap forever, which pinned a healthy system at exit 3 permanently and
// suppressed the aur-absent rule entirely -- spec §5.1's cheapest, highest-signal
// check fired on 0 of the 1 package it targets on the reference system.
//
// It is deliberately narrow: BOTH a 404 status AND a cgit-generated body. A
// captive portal or proxy answering 404 with its own page is still an error, and
// a 200 carrying this same body remains an error (F7) -- only cgit's own 404
// counts as an answer.
func isNoSuchBranch(err error) bool {
	var se *httpStatusError
	if !errors.As(err, &se) || se.code != http.StatusNotFound {
		return false
	}
	return cgitInvalidBranchRe.Match(se.body)
}

// get fetches u and returns its body.
//
// F8: the size cap is enforced by reading one byte PAST it and erroring when
// that byte arrives, instead of silently truncating. io.ReadAll over a
// LimitReader returns a short read with err == nil, so 8 MiB of padding
// followed by the real tombstone used to drop the tombstone and report a clean
// page. A resource guard must not double as a detection bypass (INV-9).
func (h *HTTP) get(ctx context.Context, u string) ([]byte, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("User-Agent", userAgentName)
	resp, err := h.hc.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		// A 404 is reported with its body so Tombstone can tell cgit saying
		// "no such branch" -- which is an ANSWER -- from any other 404, which
		// is a failure. See errNoSuchBranch.
		if resp.StatusCode == http.StatusNotFound {
			b, _ := io.ReadAll(io.LimitReader(resp.Body, 64<<10))
			return nil, &httpStatusError{code: resp.StatusCode, body: b}
		}
		return nil, fmt.Errorf("http %d", resp.StatusCode)
	}
	limit := h.bodyCap
	if limit <= 0 {
		limit = maxBody
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(body)) > limit {
		return nil, fmt.Errorf("response exceeded cap of %d bytes", limit)
	}
	return body, nil
}

// Info fetches AUR metadata for bases, splitting the request into
// infoChunkSize-sized chunks so one over-long arg[] list cannot turn into a
// single 413/414 (E-7). Names are not deduplicated across the input — see the
// chunking loop below.
func (h *HTTP) Info(ctx context.Context, bases []string) (map[string]Pkg, error) {
	if len(bases) == 0 {
		return map[string]Pkg{}, nil
	}

	// Every chunk's Results accumulate into one slice before any keying pass
	// runs. Per contract rule 1, a failing chunk fails the WHOLE call — a
	// partial map with a nil error would be a silent absence for every name in
	// the failed chunk, so any error here returns immediately with a nil map.
	var allResults []Pkg
	for start := 0; start < len(bases); start += infoChunkSize {
		end := start + infoChunkSize
		if end > len(bases) {
			end = len(bases)
		}
		// Not deduplicated: check.Provenance already dedups names via a set
		// before calling Info (its nameSet), so a duplicate reaching here is
		// the caller's to avoid, not Info's to filter. A duplicate straddling
		// a chunk boundary is simply asked about twice; that does not disturb
		// the per-chunk resultcount check below, which compares a response's
		// own count to its own results length, not to the request's arg[]
		// count.
		chunk := bases[start:end]

		q := url.Values{"v": {"5"}, "type": {"info"}}
		for _, b := range chunk {
			q.Add("arg[]", b)
		}
		body, err := h.get(ctx, h.base+"/rpc/?"+q.Encode())
		if err != nil {
			return nil, err
		}
		var r rpcResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, err
		}
		// F10: three RPC failure shapes used to read as "these packages are not
		// in the AUR". Per contract rule 1 a failure is a gap, never an
		// absence, so each becomes an error and the caller records a
		// finding.Gap. Validated per chunk (E-7 requirement 4): a chunk whose
		// response is malformed must not be waved through because another
		// chunk was fine.
		//
		//  1. a non-empty "error" field with no type:"error"
		//     ({"resultcount":0,"results":[],"error":"Too many package results."})
		//  2. an unrecognised or absent type (a bare `{}`)
		//  3. resultcount disagreeing with the results array
		if r.Error != "" {
			return nil, fmt.Errorf("aur rpc: %s", r.Error)
		}
		if !rpcSuccessTypes[r.Type] {
			return nil, fmt.Errorf("aur rpc: unrecognised response type %q", r.Type)
		}
		if r.ResultCount != len(r.Results) {
			return nil, fmt.Errorf("aur rpc: resultcount %d but %d results", r.ResultCount, len(r.Results))
		}
		for i, p := range r.Results {
			// R8: a result with neither identity indexes nowhere, yet it
			// satisfies the resultcount check — so every requested base read
			// as absent from a response that was actually broken. Per
			// contract rule 1 that is a gap. Checked per chunk, same reason
			// as the three checks above.
			if p.Name == "" && p.PackageBase == "" {
				return nil, fmt.Errorf("aur rpc: result %d has neither Name nor PackageBase", i)
			}
		}
		allResults = append(allResults, r.Results...)
	}

	// Keying happens in TWO passes over the GLOBAL union of every chunk's
	// Results, and the order is the fix for R6 — now enforced across chunk
	// boundaries too, not only within one response.
	//
	// F15 requires cross-keying on both Name and PackageBase: the v5 endpoint
	// matches package NAMES — `by=pkgbase` is rejected outright
	// ({"error":"Incorrect by field specified."}) — so a caller that asks for a
	// base and only finds it keyed by base would report a live package as absent
	// whenever the base name differs from every package name it builds.
	//
	// R6: a single-pass loop that wrote both keys put names and bases in one
	// namespace, so one result's PackageBase key could overwrite another
	// result's Name key. `{"Name":"librewolf","PackageBase":"librewolf-other"}`
	// followed by `{"Name":"librewolf-bin","PackageBase":"librewolf"}` left
	// out["librewolf"] holding librewolf-bin — and Maintainer/Submitter is
	// exactly the field a takeover check compares, so the caller was handed
	// another package's provenance under a name it did not belong to.
	//
	// Running this per chunk instead of once over the union would reopen R6 at
	// the chunk boundary: a chunk 2 PackageBase key could claim a key that a
	// later chunk's own Name result would have claimed, because chunk 2 never
	// sees chunk 3's results. Accumulating first and running both passes once
	// is what keeps the invariant global.
	//
	// Invariant: a package's own Name always wins its key. Pass one claims
	// every Name; pass two adds PackageBase keys only where nothing claimed
	// them. Nothing is ever overwritten with a different Pkg.
	out := make(map[string]Pkg, 2*len(allResults))
	for _, p := range allResults {
		if p.Name != "" {
			// Package names are unique in the AUR, so two results cannot
			// legitimately claim the same Name key.
			out[p.Name] = p
		}
	}
	for _, p := range allResults {
		if p.PackageBase == "" {
			continue
		}
		if _, taken := out[p.PackageBase]; taken {
			continue
		}
		out[p.PackageBase] = p
	}
	return out, nil
}

// logTableOpen is the opening tag of cgit's commit log table. Extraction is
// bounded to this element's byte range (F5): the same page carries a search
// form and six tab links that mention the base, and the yay fixture's tab bar
// holds a 51st /commit/ link that is not a commit row at all.
const logTableOpen = `<table class='list nowrap'>`

// commitAnchorRe extracts one log row's subject: the anchor text of its commit
// link. Written against captured cgit markup (testdata/aur/cgit/PROVENANCE.md);
// the matcher this replaces targeted class='logsubject' and a message-body
// cell, neither of which cgit emits without showmsg=1. Addresses F1/F2/F5/F9 at
// the root by yielding the subject alone instead of a 60-character window over
// raw page HTML.
var commitAnchorRe = regexp.MustCompile(`<a href='[^']*/commit/\?[^']*'>(.*?)</a>`)

// tagRe strips any markup left inside an extracted subject, so classification
// never sees angle brackets (F9: markup and entities must not reach the
// classifier, where they cost matching budget and flip verdicts).
var tagRe = regexp.MustCompile(`<[^>]*>`)

// parseCgitLog extracts the commit subjects of a cgit log page, newest first.
//
// It deliberately does NOT report whether the log is complete, and pagination is
// deliberately NOT a coverage gap. R3 dissolves rather than being fixed, and
// this is the key insight: SEEING TWO OR MORE COMMITS IS ALREADY CONCLUSIVE
// PROOF THAT THE HISTORY IS NOT TRUNCATED, which is the only thing Tombstone's
// gate needs from the page. So reading only the newest 50 of N commits is
// sufficient to rule out a tombstone, and a `[next]` pager needs no gap. The
// `pagerIsEmpty` helper that used to feed the deleted oldest-row branch has no
// remaining consumer — which also dissolves R10, where an unclosed
// `<ul class='pager'>` read as a complete log and armed that branch.
//
// F7: a body with no log table is NOT an absence of tombstones. A captive
// portal, a proxy interception page, a cgit error page served with 200 and a
// maintenance page all answer 200 with no log table, and the old matcher turned
// every one of them into a clean bill of health. Per contract rule 1 that must
// become an error so the caller records a finding.Gap.
//
// N6, documented and NOT fixed: a `</table>` landing cleanly BETWEEN two rows
// truncates the row count and the subject list consistently, so the counts agree
// and a truncated log can read as a short one — which after N1 still needs a
// history-removal wording to reach branch 1, but could then read as a tombstone.
// Its reachability is bounded: network-level truncation cannot produce it. A
// short body contradicts `Content-Length` and a chunked response closed
// mid-stream both surface as `unexpected EOF` from h.get, before any parsing. The
// only remaining vectors are an HTML-rewriting intermediary and future cgit
// markup drift.
//
// N8, documented and NOT fixed: two structural first-wins assumptions.
// `strings.Index(body, logTableOpen)` takes the FIRST `<table class='list
// nowrap'>` on the page, so a second such element (cgit emits one today) would be
// ignored entirely; and `commitAnchorRe.FindStringSubmatch(row)` takes the FIRST
// commit anchor in a row, so a row carrying two would contribute one subject for
// one counted row — the 1:1 count check stays satisfied and the second anchor is
// dropped in silence.
func parseCgitLog(body string) (subjects []string, err error) {
	start := strings.Index(body, logTableOpen)
	if start < 0 {
		return nil, errors.New("no cgit log table in response")
	}
	rest := body[start+len(logTableOpen):]
	end := strings.Index(rest, "</table>")
	if end < 0 {
		return nil, errors.New("unterminated cgit log table in response")
	}
	// R7: count commit rows STRUCTURALLY and require one extracted subject per
	// row. A row whose commit anchor does not match used to be dropped in
	// silence, which turned a markup change — or a `</table>` appearing
	// mid-row, truncating the last row — into a shorter log rather than a
	// coverage gap. Row indices no longer matter under the structural gate, but
	// the row COUNT does: it is what distinguishes a truncated history from a
	// live one, so a miscount is exactly the input the gate must not be fed.
	chunks := strings.Split(rest[:end], "<tr")
	// chunks[0] is whatever precedes the first `<tr`; it is not a row.
	var commitRows int
	for _, row := range chunks[1:] {
		// N5: the header-row test must look at the `<tr` element's OWN
		// attributes, not at the row body. `strings.Contains(row, "nohover")`
		// tested the whole row, so the author cell — maintainer-controlled git
		// metadata — or the subject text could delete a row from BOTH sides of
		// the count check below, leaving the counts consistent and no error. A
		// three-row log whose first two rows carried the author `nohover dev`
		// parsed to one subject with err == nil, and if that subject was
		// `history removed due to malware` the result was a critical against a
		// live base; `fix nohover css in the theme` as a subject did the same.
		//
		// Uppercase `NOHOVER` deliberately still misses: it makes the header row
		// count as a commit row with no extractable subject, which is the count
		// mismatch below — a Gap, the safe direction. Making it a silent skip
		// would be the unsafe "fix".
		tag := row
		if i := strings.Index(tag, ">"); i >= 0 {
			tag = tag[:i]
		}
		if strings.Contains(tag, "nohover") {
			continue // cgit's column-header row, not a commit
		}
		commitRows++
		m := commitAnchorRe.FindStringSubmatch(row)
		if m == nil {
			continue
		}
		subjects = append(subjects, normalizeSubject(m[1]))
	}
	if commitRows == 0 {
		// A branch with zero commits does not exist in git, so a log table
		// with no commit rows means the markup changed under us. Erroring is
		// the safe direction: a coverage gap, never a false absence.
		return nil, errors.New("cgit log table has no commit rows")
	}
	if len(subjects) != commitRows {
		return nil, fmt.Errorf("cgit log table has %d commit rows but %d extractable subjects",
			commitRows, len(subjects))
	}
	return subjects, nil
}

// normalizeSubject turns raw anchor text into the string that gets classified:
// markup stripped, HTML entities decoded, whitespace runs collapsed, trimmed.
// F9: cgit escapes subjects, so `'` arrives as `&#39;`. Classifying the escaped
// form made the same subject land on different verdicts depending only on
// whether it happened to contain an apostrophe.
func normalizeSubject(raw string) string {
	s := tagRe.ReplaceAllString(raw, "")
	s = html.UnescapeString(s)
	return strings.Join(strings.Fields(s), " ")
}

// strongTerms are malware indicators that no administrative wording may veto —
// provided they appear as a bare token, with no hyphen on either side. A
// hyphen-adjacent occurrence is demoted to the vetoable weak tier instead of
// being discarded (R1); see termGuardHyphenTolerant.
//
// F3: the list this replaces held six terms and missed ten measured malware
// removals. `security` is deliberately ABSENT — it is not a malware indicator,
// it appears in policy, tracker and package-name contexts, and `security-misc`
// and `security-hardening-*` are real AUR packages; it produced eight measured
// false malware accusations. `c2` is absent for the same reason: `reset to c2
// branch after a bad force-push` classified as malware.
//
// Whole-word terms carry their own trailing `\b`; stem terms deliberately do
// not, so `exfiltrat` still matches `exfiltrating`.
//
// R1: `stealer` is a SUFFIX stem (`\w*stealer\b`) because `infostealer` is one
// word — as a whole token, `removed infostealer blob from the tarball` matched
// nothing. `miner\b` in weakTerms stays word-bounded on purpose: as a stem it
// would fire on `determiner` and `examiner`.
//
// N7: the stem is `\w*stealers?\b`, not `\w*stealer\b` — `removed stealers from
// the tarball` and `removed infostealers` both classified as not-malware on the
// singular-only form. `stealership` still does not match: `s?` is followed by
// `\b`, and `stealership` continues into a word character either way.
//
// The residual over-match class is a term used as the SUBJECT MATTER of tooling
// rather than as a finding: `removed backdoor-detection heuristics`, `removed
// keylogger-detection docs`, `removed the malware-analysis-toolkit dependency`,
// `drop clamav-unofficial-sigs-malware-expert from optdepends`, `removed the rat
// race benchmark`, `updated the stager module docs`, `removed the dropper
// directory`, `remove the worm-gear model files`. A `-detection` / `-analysis`
// suffix is the canonical shape. These are DOCUMENTED RESIDUALS, left unfixed:
// after N1 none of them can reach Tombstone's branch 1 in a multi-commit log
// (they carry no `history` qualifier, so they are not a historyRemoval), so the
// worst they cost is a Gap — honest uncertainty — never a false critical.
var strongTerms = []string{
	`malware\b`, `malicious\b`, `trojan\b`, `backdoor\b`, `rootkit\b`,
	`\w*stealers?\b`, `cryptominer\b`, `coinminer\b`, `keylogger\b`, `rat\b`,
	`dropper\b`, `stager\b`, `phishing\b`, `worm\b`,
	`exfiltrat`, `typosquat`, `rogue\s+\w+\s+script`, `phon(?:e|es|ing)\s+home`,
}

// weakTerms are suggestive but also ordinary packaging words, so an
// administrative veto may overrule them (F6).
//
// `beacon` sits here rather than in strongTerms: `removed beacon chain support`
// is ordinary Ethereum packaging, and as a bare strong term it produced an
// unvetoable critical. In the weak tier it is vetoable, and the specific
// `beacon chain` compound is suppressed outright by nonIndicatorRe.
var weakTerms = []string{
	`compromised\b`, `payload\b`, `unauthorized\b`, `miner\b`, `virus\b`,
	`beacon\b`, `hijack`, `obfuscat`, `supply.?chain`,
}

// termGuard wraps a term alternation so a term counts only as its own token AND
// only when no hyphen touches it — the "bare" tier.
//
// The right side is `[^-]`, NOT `[^\w-]`: RE2 has no lookahead, so `(?!-)`
// does not compile and the guard must consume a character instead. Consuming a
// non-word character would block ordinary suffix continuation and silently kill
// every stem term — `exfiltrat` would never match `exfiltrating`.
func termGuard(terms []string) string {
	return `(?i)(?:^|[^\w-])(?:` + strings.Join(terms, "|") + `)(?:[^-]|$)`
}

// termGuardHyphenTolerant is termGuard with the hyphen restriction lifted on
// both sides. A term must still be its own token — no word character may run
// into it on the left, and whole-word terms keep their own trailing `\b`, so
// `rat\b` still cannot fire on `generate` or `corporate` and `worm\b` still
// cannot fire on `wormhole` — but a hyphen on either side is allowed. It is a
// strict superset of termGuard.
//
// R1: the hyphen-strict guard DISCARDED every hyphen-compounded malware
// wording, nine measured removals among them `trojan-dropper in the prebuilt
// binary`, `malware-laden prebuilt binary` and `backdoor-laced install hook`,
// each of which classified as not-malware with no other term present. The
// hyphen guard exists for exactly two measured cases and both are package names
// (`malware-analysis-toolkit`, `clamav-unofficial-sigs-malware-expert`) — and
// both carry an administrative veto token. So the fix changes the TIER, not the
// verdict: a hyphen-adjacent strong term is demoted into the vetoable weak
// tier. The two package-name cases stay false because `rename`/`merge` fires;
// the nine compounds become true because nothing vetoes them.
func termGuardHyphenTolerant(terms []string) string {
	return `(?i)(?:^|[^\w])(?:` + strings.Join(terms, "|") + `)`
}

// strongBareRe matches an unvetoable malware indicator: a strong term as a
// standalone token with no hyphen on either side (F3).
var strongBareRe = regexp.MustCompile(termGuard(strongTerms))

// strongHyphenAdjRe matches a strong term that is present but may be
// hyphen-adjacent (R1). Being a superset of strongBareRe it is only ever
// consulted after strongBareRe has already declined.
var strongHyphenAdjRe = regexp.MustCompile(termGuardHyphenTolerant(strongTerms))

// weakAnyRe matches a suggestive-but-ambiguous indicator as a token,
// hyphen-adjacent or not (F6); adminVetoRe may overrule it.
var weakAnyRe = regexp.MustCompile(termGuardHyphenTolerant(weakTerms))

// nonIndicatorRe matches term occurrences that are the OPPOSITE of a malware
// notice, so they must contribute to neither tier.
//
// A negation or defence prefix inverts the term's meaning: `removed non-malware
// test cases from the corpus`, `removed the anti-malware hook`, `drop
// anti-rootkit scanning from the install hook`, `removed pseudo-trojan sample
// used by the test suite`, `removed de-obfuscation helper` and `removed the
// anti-virus scan step` all classified as malware, because R1's hyphen-tolerant
// guard admits a term with a hyphen on its left. Suppression is done by blanking
// the whole prefixed compound out of the subject BEFORE any term matches, so an
// UNPREFIXED occurrence of the same term elsewhere in the same subject still
// counts — that is the difference between suppressing an occurrence and dropping
// a term.
//
// `beacon chain` rides the same mechanism for a different reason: RE2 has no
// lookahead, so `beacon` cannot exclude its ordinary Ethereum compound inside
// the term alternation itself.
var nonIndicatorRe = regexp.MustCompile(`(?i)\b(?:non|anti|pseudo|counter|de)-\w+|\bbeacon\s+chain\b`)

// suppressNonIndicators blanks every nonIndicatorRe occurrence, replacing it
// with a space so neighbouring tokens cannot be fused into a new word.
func suppressNonIndicators(msg string) string {
	return nonIndicatorRe.ReplaceAllString(msg, " ")
}

// adminVetoRe matches wording that explains a removal administratively.
//
// F6: it gates the WEAK tier only. A flat veto that outranked any term hit
// would suppress genuine malware — `removed due to policy violation: backdoor
// stager in PKGBUILD` and `history removed due to malware; base renamed to
// librewolf-bin` both go malware=false under a flat veto. Tiering makes the
// veto structurally incapable of hiding a bare strong term.
//
// R5: nine of the eleven tokens this list used to carry had ZERO measured
// weight while each opened a suppression path — eleven measured malware
// removals classified as administrative. Only the load-bearing tokens survive:
//   - `rename`/`renamed`/`merge`/`merged` are what keep
//     `removed due to rename to malware-analysis-toolkit` and
//     `history removed due to merge into clamav-unofficial-sigs-malware-expert`
//     false now that a hyphen-adjacent strong term is demoted into this tier.
//   - `moved to` is what keeps
//     `removed due to rename; payload moved to the -bin package` false.
//
// Dropped: duplicate, dupe, orphan, replaced by, licen[cs]e, upstream request,
// policy, co-maintainer.
//
// `co-maintainer` is dropped DELIBERATELY at a known cost: `removed
// unauthorized upload of a stale sdist by a co-maintainer` now reads as
// malware. A compromised maintainer or co-maintainer account is THE AUR malware
// vector, so the token is positively correlated with genuine compromise and
// vetoing on it suppresses precisely the notices that matter most. `policy` is
// dropped for the same shape of reason: `removed due to policy violation:` is
// standard admin phrasing for a malware removal.
//
// N2: the veto is REASON-POSITIONAL. A token anywhere in the subject used to
// veto, and an AUR malware removal routinely names a replacement base — the
// removed base is usually a typosquat — so `history removed due to
// trojan-dropper in the prebuilt binary; base renamed to foo-bin` read as
// administrative. All nine R1 hyphen compounds behaved that way with either
// `; base renamed to foo-bin` or `; merged into foo`, while the unhyphenated
// control `history removed due to malware; base renamed to librewolf-bin` stayed
// true only because a bare strong term outranks the veto entirely. R1's fix was
// therefore conditional on the notice naming no replacement base.
//
// The token must now occupy a reason position — subject-initial, or introduced by
// `due to` / `because of` / `for` — which is what a genuine administrative
// removal looks like (`removed due to rename to …`) and what a malware notice's
// trailing housekeeping clause (`; base renamed to foo-bin`) is not. This also
// closes the residual the previous round deferred as TODO(P1-B): `history removed
// due to a compromised maintainer account; base renamed` now reads as malware,
// because `renamed` is not the reason.
var adminVetoRe = regexp.MustCompile(
	`(?i)(?:^|due\s+to\s+|because\s+of\s+|for\s+)(?:a\s+|an\s+|the\s+)?(?:rename|renamed|merge|merged|moved\s+to)\b`)

// IsMalwareRemoval reports whether a removal message indicates malicious
// content rather than an administrative removal such as a rename or merge.
// This is the difference between a critical verdict and a suspicious one:
// "removed due to rename" must not be reported as malware (L2 defect D2).
//
// It is the ONLY place the malware/administrative judgement lives. Tombstone
// never calls it to decide presence.
//
// Three tiers, per R1: a bare strong term is unvetoable; a hyphen-adjacent
// strong term and a weak term share the vetoable tier. Every tier sees the same
// negation-suppressed subject, so `anti-malware` contributes nowhere while a bare
// `malware` in the same subject still does.
func IsMalwareRemoval(msg string) bool {
	s := suppressNonIndicators(msg)
	if strongBareRe.MatchString(s) {
		return true
	}
	if adminVetoRe.MatchString(s) {
		return false
	}
	return strongHyphenAdjRe.MatchString(s) || weakAnyRe.MatchString(s)
}

// leadingNoiseRe strips the mailing-list decoration a removal notice may carry
// before its verb: an optional `[`, an optional list tag (`aur-general`, `aur`,
// `TU`) closed by `]`, `]:` or `:`, and the whitespace after it. The tag list is
// FIXED literals, deliberately not an arbitrary `<token>:` prefix: stripping a
// leading `<base>:` buys a base-prefixed tombstone that has never been observed
// (the one real tombstone is bare) and pays with false criticals on
// security-tooling bases — `pev: removed the malware test corpus` and `yara:
// dropped the backdoor ruleset` both became present+malware. These three tags are
// safe because none of them is a package base.
//
// N4: this replaces a two-step that applied an anchored `^aur-general:\s*` regex
// and only THEN trimmed a leading `[`, so the bracketed mailman form — the
// standard form of the very prefix the code already anticipated — was never
// stripped at all and `[aur-general] history removed due to malware` as a sole
// commit returned a clean (false, "", nil). One strip handles `[aur-general] `,
// `[aur-general]: `, `[aur-general: `, `aur-general: `, `[TU] `, `[aur] ` and a
// bare `[removed]` in either order.
var leadingNoiseRe = regexp.MustCompile(`(?i)^\[?\s*(?:(?:aur-general|aur|tu)\s*(?:\]\s*:?|:)\s*)?`)

// stripLeadingNoise removes that decoration. Both removal predicates below run
// on its output, so a bracketed prefix cannot hide either one.
func stripLeadingNoise(subject string) string {
	return leadingNoiseRe.ReplaceAllString(subject, "")
}

// removalHeadRe matches a removal verb at the START of a subject.
//
// F1: the matcher this replaces gated detection on the literal prepositions
// `history removed` / `removed due to` / `removed for`, so `removed: malware in
// the sources` and nine other phrasings matched nothing at all. Anchoring on
// the verb instead of the preposition catches the phrasings; anchoring at
// position 0 is what rejects the mid-subject false accusation
// `upgpkg: 2.1.0-1: patch removed for security reasons upstream`.
//
// R9: `reset` used to be excluded outright because `reset pkgrel to 1` is
// ordinary AUR wording, which missed `history reset due to malware`,
// `reset history: malware in the PKGBUILD` and `reset: malware in the sources`.
// Admitting it in the anchored forms only — exactly like every other verb — is
// safe for a reason that has nothing to do with history length: `reset` is
// admitted as an anchoredRemoval verb but `reset pkgrel to 1` is not a
// historyRemoval form, so it cannot fire branch 1 on its own, at any log length.
//
// N3 is why that distinction had to be drawn. The claim this comment used to make
// — that branch 1 needs EVERY subject to be a removal, so ordinary wording is
// safe — is false for a SHORT log: a squashed single-commit log whose only subject
// is `reset pkgrel to 1` satisfied "every subject is a removal" trivially and
// returned present=true against a live base.
var removalHeadRe = regexp.MustCompile(`(?i)^(?:history\s+)?(?:remov(?:e|es|ed|ing|al)|delet(?:e|es|ed|ing|ion)|purg(?:e|es|ed|ing)|drop(?:s|ped|ping)?|clear(?:s|ed|ing)?|reset(?:s|ting)?)\b`)

// malwareLedRemovalRe matches the other observed word order, where the
// indicator leads and the removal noun follows ("malware removal"). Anchored at
// position 0 for the same reason as removalHeadRe.
var malwareLedRemovalRe = regexp.MustCompile(`(?i)^(?:` + strings.Join(strongTerms, "|") + `)\s+(?:removal|removed)\b`)

// anchoredRemoval reports whether a normalized subject is a removal notice.
// It says nothing about WHY the removal happened — that is IsMalwareRemoval's
// sole responsibility.
func anchoredRemoval(subject string) bool {
	s := stripLeadingNoise(subject)
	return removalHeadRe.MatchString(s) || malwareLedRemovalRe.MatchString(s)
}

// historyRemovalRe matches the distinctive "the history itself was removed"
// shape, anchored. The one verified real tombstone is `history removed due to
// malware` — it carries the `history` qualifier. A bare removal verb does not.
//
// N1: `anchoredRemoval` alone is far too broad to gate branch 1. It is satisfied
// by short ORDINARY histories, not only truncated ones — all twelve of the repo's
// own measured `r4OrdinarySubjects` (`removed the malware test corpus`, `dropped
// the backdoor ruleset`, …) produced present=true with IsMalwareRemoval=true, a
// false SevCritical against a live base, when presented as the sole commit of a
// log, and again when paired with one more removal-verb commit. Round two's
// structural gate did not eliminate that defect, it relocated it from "row 0 of a
// long log" to "every row of a short log".
//
// The three alternations are the same claim in different word orders:
//
//  1. history-first — `history removed`, `the package history was removed`,
//     `history has been removed`;
//  2. verb-first — `remove history:`, `delete history due to`, `reset history:`;
//  3. base-first — `package removed`, `base removed:`.
//
// Alternation 2 is NOT in the finding's literal regex list, but the finding
// requires `reset history: malware in the PKGBUILD` and `remove history: malware
// in the PKGBUILD` to remain tombstones, and neither matches any of the listed
// forms. It is the same `history` qualifier, read left to right.
var historyRemovalRe = regexp.MustCompile(
	`(?i)^(?:the\s+)?(?:package\s+|base\s+)?history\s+(?:has\s+been\s+|had\s+been\s+|was\s+|been\s+)?(?:removed|reset|deleted|purged|cleared|wiped)\b` +
		`|(?i)^(?:remov(?:e|es|ed|ing|al)|delet(?:e|es|ed|ing|ion)|purg(?:e|es|ed|ing)|drop(?:s|ped|ping)?|clear(?:s|ed|ing)?|reset(?:s|ting)?|wip(?:e|es|ed|ing))\s+(?:the\s+)?(?:package\s+|base\s+)?history\b` +
		`|(?i)^(?:package|base)\s+(?:has\s+been\s+|was\s+)?(?:removed|deleted)\b`)

// reasonPositionStrongRe is the FOURTH historyRemoval alternative (F1): a removal
// verb whose stated REASON is a strong malware term, given immediately after the
// verb or after a short delimiter.
//
// F1 (round 4): the `history` conjunct that N1 added to branch 1 cost six of F1's
// nine measured phrasings their critical, because none of them carries a `history`
// qualifier — `removed: malware in the sources`, `removed (malware)`, `deleted due
// to malware`, `removed - malware`, `removed  due to malware` and `[removed]
// malware in the prebuilt binary` all became Gaps as sole commits. A Gap is not
// silence, so F1's original defect had not returned, but these are malware removal
// NOTICES and "could not decide" is the wrong answer for them.
//
// The discriminating signal is REASON POSITION, not the verb. A removal notice
// states its reason immediately after the verb or a delimiter; an ordinary commit
// removes a THING, and a noun phrase intervenes — `removed the malware test
// corpus`, `purge stale payload fixtures`, `remove the vendored miner binary`. So
// the connector set is deliberately tiny (`:` `-` `(` `[` `]`, or `due to` / `for`
// / `because of`) and the only article allowed on the term is `a`/`an`, never
// `the`: `due to a trojan` is a reason, `the malware test corpus` is an object.
// That article restriction is what rejects nine of the twelve measured
// `r4OrdinarySubjects`; the connector requirement rejects the other three.
//
// `reset` is deliberately ABSENT from this verb set even though removalHeadRe
// admits it (R9). `reset: malware in the sources` is pinned as a Gap rather than a
// critical — a tombstone verdict resting on nothing but the verb `reset` is
// exactly what R9 traded away — and admitting `reset` here would turn it into
// branch 1. Otherwise the verb set is removalHeadRe's.
//
// The term alternation is `strongTerms` itself, so this predicate and
// IsMalwareRemoval cannot drift apart. It is hyphen-TOLERANT on the right, like
// termGuardHyphenTolerant: `removed: trojan-dropper in the prebuilt binary` is one
// of R1's nine measured real wordings and must reach branch 1. The documented cost
// is in strongTerms' residual list — a hyphen-compounded strong term used as
// SUBJECT MATTER right after a connector (`removed: backdoor-detection
// heuristics`) is admitted here, where before it could only ever cost a Gap.
var reasonPositionStrongRe = regexp.MustCompile(
	`(?i)^(?:remov(?:e|es|ed|ing|al)|delet(?:e|es|ed|ing|ion)|purg(?:e|es|ed|ing)|drop(?:s|ped|ping)?|clear(?:s|ed|ing)?)` +
		`(?:\s*[:\-(\[\]]+\s*|\s+(?:due\s+to|because\s+of|for)\s+)` +
		`(?:an?\s+)?(?:` + strings.Join(strongTerms, "|") + `)`)

// historyRemoval reports whether a subject claims the HISTORY was removed, as
// opposed to merely carrying a removal verb. `malwareLedRemovalRe` counts too:
// `<strong term> removal` is the same claim with the indicator leading, and
// `reasonPositionStrongRe` counts because a removal whose stated reason IS malware
// is a removal notice rather than a commit that removed something (F1).
func historyRemoval(subject string) bool {
	s := stripLeadingNoise(subject)
	return historyRemovalRe.MatchString(s) ||
		malwareLedRemovalRe.MatchString(s) ||
		reasonPositionStrongRe.MatchString(s)
}

// removalAnywhereRe matches a removal word ANYWHERE in a subject, unanchored.
// It exists only for Tombstone's branch 2 (N4); the anchored predicates above are
// what decide a tombstone.
//
// ITS VERB SET MUST STAY IN SYNC WITH removalHeadRe's. The two differ only in
// anchoring — one asks "does this subject OPEN with a removal verb", the other
// "does it contain one at all" — so a verb either regex recognises must be
// recognised by both. It carried `dropped` and `cleared` but not
// `drop`/`drops`/`dropping` or `clear`/`clears`/`clearing`, which removalHeadRe
// admits, and the asymmetry was load-bearing in the wrong direction: `drop miner
// support, use the upstream release` and `drops the beacon example config` fell
// past branch 2 into a clean (false, "", nil) instead of a Gap, and a real
// tombstone worded `drop the history` or `clear history: malware` would have been
// missed by branch 2 entirely. `wip(?:e|es|ed|ing)` has no removalHeadRe
// counterpart on purpose — it is a historyRemovalRe verb, and branch 2 must see
// every wording branch 1 can.
var removalAnywhereRe = regexp.MustCompile(
	`(?i)\b(?:remov(?:e|es|ed|ing|al)|delet(?:e|es|ed|ing|ion)|purg(?:e|es|ed|ing)|drop(?:s|ped|ping)?|clear(?:s|ed|ing)?|reset(?:s|ting)?|wip(?:e|es|ed|ing))\b`)

func (h *HTTP) Tombstone(ctx context.Context, base string) (bool, string, error) {
	q := url.Values{"h": {base}}
	body, err := h.get(ctx, h.base+"/cgit/aur.git/log/?"+q.Encode())
	if err != nil {
		// cgit answering "no such branch" is a definitive absence of any
		// removal record, not a lookup failure. See isNoSuchBranch.
		if isNoSuchBranch(err) {
			return false, "", nil
		}
		return false, "", err
	}
	subjects, err := parseCgitLog(string(body))
	if err != nil {
		return false, "", fmt.Errorf("cgit log for %s: %w", base, err)
	}
	// The gate is STRUCTURAL, not positional.
	//
	// R4: the row-position gate this replaces admitted row 0 UNCONDITIONALLY,
	// and row 0 is where every ordinary commit lives. Twelve measured ordinary
	// subjects substituted into the newest row of the captured 50-commit yay
	// page all produced present=true, malware=true — twelve false criticals
	// against a live package: `remove the vendored miner binary, upstream ships
	// it now`, `removed the malware test corpus`, `dropped the backdoor
	// ruleset`, `purge stale payload fixtures` and eight more. The same twelve
	// at row 13 were correctly rejected, so the protection was temporal, not
	// structural: every deep row was row 0 once.
	//
	// The structural fact to build on is that A HISTORY REMOVAL TRUNCATES THE
	// PARENT CHAIN. That is WHY the one verified real tombstone
	// (log-tombstoned-librewolf-fix-bin.html) is a single-commit log with an
	// empty pager. A base with 50 commits is not a tombstoned base, whatever
	// any individual subject says.
	//
	// 1. A tombstone is a truncated history: EVERY commit in the log is a
	//    removal notice, AND at least one of them claims THE HISTORY was removed.
	//
	//    N1/N3: the second conjunct is not decoration. "Every commit is a removal
	//    notice" is satisfied trivially by a SHORT ORDINARY history — a squashed
	//    force-push whose sole subject is `reset pkgrel to 1`, or a one-commit
	//    repo whose sole subject is `removed the malware test corpus`. All twelve
	//    measured ordinary subjects, and five measured squashed-force-push
	//    subjects, produced present=true against live bases that way; the twelve
	//    also produced IsMalwareRemoval=true, i.e. a false SevCritical. Round
	//    two's structural gate moved that defect from "row 0 of a long log" to
	//    "every row of a short log" rather than removing it. Requiring a
	//    DISTINCTIVE history-removal form is what removes it: `history removed due
	//    to malware` carries the `history` qualifier and the ordinary wordings do
	//    not.
	//
	//    F1 (round 4): the `history` qualifier is not the only distinctive form.
	//    `historyRemoval` also admits a removal whose stated REASON is a strong
	//    malware term (`removed: malware in the sources`, `deleted due to
	//    malware`) — a removal NOTICE. The ordinary wordings name an OBJECT
	//    instead (`removed the malware test corpus`) and stay out; see
	//    reasonPositionStrongRe.
	everyCommitIsARemoval := true
	anyHistoryRemoval := false
	for _, s := range subjects {
		if !anchoredRemoval(s) {
			everyCommitIsARemoval = false
			break
		}
		if historyRemoval(s) {
			anyHistoryRemoval = true
		}
	}
	if everyCommitIsARemoval && anyHistoryRemoval { // parseCgitLog guarantees len(subjects) > 0
		// Prefer a malware-bearing subject so an administrative-sounding one
		// can never shadow it (F4). Otherwise report the newest qualifying
		// subject; subjects are newest-first.
		for _, s := range subjects {
			if IsMalwareRemoval(s) {
				return true, s, nil
			}
		}
		return true, subjects[0], nil
	}
	// 2. Otherwise this is not a tombstone. But if some subject is malware-bearing
	//    AND carries a removal word anywhere, we cannot tell a
	//    tombstone-plus-later-commits (a resurrected base) — or a tombstone whose
	//    wording branch 1's anchored predicates do not recognise — from an
	//    ordinary commit that happens to mention malware. Per contract rule 1 that
	//    ambiguity is a coverage gap, never a clean pass and never a critical — a
	//    gap says "I could not decide", which is true.
	//
	//    N4: the condition used to be `anchoredRemoval(s) && IsMalwareRemoval(s)`,
	//    which meant ANY tombstone wording failing only the anchored form was
	//    answered with silence rather than a Gap: `package history was removed due
	//    to malware`, `history has been removed due to malware` and `base removed:
	//    malware in the PKGBUILD` all returned a clean (false, "", nil). Requiring
	//    the removal word ANYWHERE instead of at position 0 catches them.
	//
	//    The removal word is still REQUIRED. Gapping on IsMalwareRemoval alone
	//    would gap on `upgpkg: 1.2-1: add clamav malware signatures`, which
	//    mentions malware while claiming no removal at all. Branch 2 is
	//    deliberately noisier than branch 1 is permissive, because a Gap is honest
	//    uncertainty and a critical is an accusation.
	//
	//    This is what rejects all twelve R4 strings: yay has 50 commits so
	//    branch 1 cannot fire, and being malware-bearing they land here and
	//    become a Gap instead of a false critical. It is also what catches R2,
	//    a real `history removed due to malware` at an interior row of a
	//    complete log, which the position gate answered with silence.
	//
	//    The noise is bounded to malware-word-bearing removal subjects only:
	//    `drop python2 support` at HEAD is not malware-bearing, so it falls
	//    through to branch 3 and ordinary packages get no gap spam. And the
	//    resurrected-base case that the deleted oldest-row branch guessed at
	//    becomes an honest Gap instead of a guess in either direction.
	for _, s := range subjects {
		if IsMalwareRemoval(s) && removalAnywhereRe.MatchString(s) {
			return false, "", fmt.Errorf(
				"cgit log for %s: removal wording %q in a %d-commit history; "+
					"cannot distinguish a tombstone from an ordinary commit", base, s, len(subjects))
		}
	}
	// 3. A multi-commit history with no malware-bearing removal notice. Not a
	//    tombstone. Genuinely clean.
	return false, "", nil
}
