// internal/bundle/fetch.go
//
// Bounded retrieval. This file fetches bytes and does nothing else with them.
//
// It deliberately has no reference to Bundle, Delegation or any parser. The
// verification order -- authenticate raw bytes, then parse -- is only real if
// the code that obtains the bytes cannot be tempted into interpreting them, so
// the separation is structural rather than a convention.
//
// The three limits, and what each is for:
//
//	timeout     a hung connection must not hang a scan. It is a context
//	            deadline covering the whole exchange including the body read,
//	            not a per-read timeout that a slow drip resets forever.
//	size cap    enforced by reading ONE BYTE PAST the limit and erroring when
//	            that byte arrives. io.ReadAll over a LimitReader returns a short
//	            read with a nil error, so a truncating cap would silently hand a
//	            prefix of a bundle to a verifier -- and a resource guard that
//	            doubles as a detection bypass is worse than no guard.
//	redirects   no CROSS-HOST redirect, ever. A redirect to another host moves
//	            the fetch to a server the operator never configured; the
//	            signature would still be checked, but the request -- and any
//	            future one that learns the new location -- would not be going
//	            where they think. Same-host redirects are allowed up to a small
//	            bound so a publisher can reorganise paths.
package bundle

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// DefaultFetchTimeout bounds one retrieval end to end.
const DefaultFetchTimeout = 30 * time.Second

// maxRedirects bounds same-host redirects.
const maxRedirects = 5

var (
	// ErrFetch reports a retrieval that did not produce bytes.
	ErrFetch = errors.New("bundle: fetch failed")

	// ErrCrossHostRedirect reports a redirect that leaves the configured host.
	ErrCrossHostRedirect = errors.New("bundle: refusing a cross-host redirect")
)

// Fetcher retrieves bundle and delegation bytes over HTTPS.
//
// The zero value is not usable; use NewFetcher.
type Fetcher struct {
	client  *http.Client
	timeout time.Duration
	cap     int64
}

// NewFetcher builds a fetcher.
//
// A nil client gets one whose redirect policy refuses cross-host hops. Passing a
// client is how tests point at a local server; a caller that passes its own
// client is responsible for its redirect policy, and NewFetcher does not
// silently rewrite it -- so production wiring should pass nil.
func NewFetcher(client *http.Client, timeout time.Duration, sizeCap int64) *Fetcher {
	if timeout <= 0 {
		timeout = DefaultFetchTimeout
	}
	if sizeCap <= 0 {
		sizeCap = MaxBundleBytes
	}
	if client == nil {
		client = &http.Client{CheckRedirect: refuseCrossHost}
	}
	return &Fetcher{client: client, timeout: timeout, cap: sizeCap}
}

// RefuseCrossHost is the redirect policy, exported so a caller supplying its own
// http.Client can install the same one rather than reimplementing it.
func RefuseCrossHost(req *http.Request, via []*http.Request) error {
	return refuseCrossHost(req, via)
}

func refuseCrossHost(req *http.Request, via []*http.Request) error {
	if len(via) >= maxRedirects {
		return fmt.Errorf("%w: more than %d redirects", ErrFetch, maxRedirects)
	}
	if len(via) == 0 {
		return nil
	}
	from := via[0].URL
	if !strings.EqualFold(req.URL.Host, from.Host) {
		return fmt.Errorf("%w: %s redirected to %s", ErrCrossHostRedirect, from.Host, req.URL.Host)
	}
	if !strings.EqualFold(req.URL.Scheme, from.Scheme) {
		return fmt.Errorf("%w: %s downgraded from %s to %s", ErrFetch, from.Host,
			from.Scheme, req.URL.Scheme)
	}
	return nil
}

// Get retrieves rawURL and returns the body.
//
// It returns bytes, never a parsed document. requireTLS is a parameter rather
// than a constant only so a test can point at a local http server; production
// callers pass true and the default in Fetch is true.
func (f *Fetcher) Get(ctx context.Context, rawURL string, requireTLS bool) ([]byte, error) {
	u, err := url.Parse(rawURL)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if requireTLS && !strings.EqualFold(u.Scheme, "https") {
		return nil, fmt.Errorf("%w: %s is not https; a bundle fetched in the clear can be "+
			"withheld or swapped by anyone on the path, and the signature only tells you "+
			"afterwards", ErrFetch, rawURL)
	}
	if u.Host == "" {
		return nil, fmt.Errorf("%w: %s names no host", ErrFetch, rawURL)
	}

	ctx, cancel := context.WithTimeout(ctx, f.timeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u.String(), nil)
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	req.Header.Set("User-Agent", "aurvet")

	resp, err := f.client.Do(req)
	if err != nil {
		// Two %w verbs: the redirect policy's own error must stay reachable
		// through errors.Is, or a caller cannot tell "refused a cross-host
		// redirect" -- which is an attack -- from "the server was down".
		return nil, fmt.Errorf("%w: %w", ErrFetch, err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("%w: http %d", ErrFetch, resp.StatusCode)
	}
	body, err := io.ReadAll(io.LimitReader(resp.Body, f.cap+1))
	if err != nil {
		return nil, fmt.Errorf("%w: %v", ErrFetch, err)
	}
	if int64(len(body)) > f.cap {
		return nil, fmt.Errorf("%w: response exceeded the %d byte cap", ErrFetch, f.cap)
	}
	return body, nil
}
