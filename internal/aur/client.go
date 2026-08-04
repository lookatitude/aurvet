package aur

import "context"

// Pkg is the subset of AUR metadata this tool uses. Submitter is retained
// because submitter != maintainer is an observable takeover signal.
type Pkg struct {
	Name           string
	PackageBase    string
	Maintainer     string
	Submitter      string
	FirstSubmitted int64
	LastModified   int64
}

// Client is the network seam. Tests use Fake so no test touches the network.
type Client interface {
	// Info looks up every base in ONE request. A missing key means the AUR
	// does not have that package; an error means the lookup failed. These are
	// never conflated.
	Info(ctx context.Context, bases []string) (map[string]Pkg, error)
	// Tombstone reports whether the package's cgit log records a REMOVAL
	// commit, and the matching message.
	//
	// present == true means A REMOVAL WAS DETECTED. It does NOT mean malware:
	// an administrative removal ("removed due to rename") is present too.
	// Severity comes solely from passing the returned message to
	// IsMalwareRemoval — callers must not escalate on present alone, or every
	// administrative removal becomes a critical.
	//
	// A non-nil error means the check could not be completed (transport
	// failure, size cap, or a 200 response that is not a cgit log page). The
	// caller must record a finding.Gap and must never read it as "no removal"
	// (contract rule 1: a failure is a gap, never an absence).
	Tombstone(ctx context.Context, base string) (bool, string, error)
}
