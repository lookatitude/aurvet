// internal/pkgmeta/buildinfo.go
package pkgmeta

import (
	"archive/tar"
	"compress/gzip"
	"errors"
	"fmt"
	"io"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/lookatitude/aurvet/internal/finding"
	"github.com/lookatitude/aurvet/internal/fsx"
)

// buildInfoMember is the exact archive member name. The match is exact rather
// than by suffix or basename: an archive can contain "../.BUILDINFO" or
// "usr/share/doc/.BUILDINFO", and neither is the file makepkg wrote.
const buildInfoMember = ".BUILDINFO"

// BuildInfo is one build's own record of itself.
//
// The three fields P2 task 3 names -- PkgBuildSHA256, BuildDir, StartDir -- are
// the reason this reader exists. The digest is the only local evidence that the
// recipe built matches the recipe published; the two directories say WHERE it
// was built, which is how the checked-in fixture reveals that a -bin package's
// archive was produced in a CI workspace (/github/workspace/res) rather than on
// the user's machine -- so its pkgbuild_sha256sum is over a PKGBUILD nobody
// local ever saw.
type BuildInfo struct {
	Format         string
	PkgName        string
	PkgBase        string
	PkgVer         string
	PkgArch        string
	PkgBuildSHA256 string
	Packager       string

	// BuildDate is the builddate field as an instant in UTC. Zero when the
	// field is absent or unparsable; BuildDateRaw keeps what was written.
	BuildDate    time.Time
	BuildDateRaw string

	BuildDir     string
	StartDir     string
	BuildTool    string
	BuildToolVer string

	BuildEnv []string
	Options  []string

	// Installed is the build environment's package set, "name-ver-rel-arch"
	// per entry. It is the largest part of the file (278 entries in the
	// checked-in fixture) and the reason MaxValuesPerKey exists.
	Installed []string

	// Other retains keys this reader does not model. The format has grown
	// before (format 1 -> 2 added buildtool/buildtoolver), and dropping an
	// unrecognised key would mean a future rule cannot see a field that was
	// sitting right there.
	Other map[string][]string
}

// ParseBuildInfo parses .BUILDINFO content from any source.
//
// Taking an io.Reader rather than a path is the decision that makes the zstd
// problem tractable: the same parser serves an unpacked file, a member of an
// archive this package can decompress, a snapshot, and anything a caller
// decompressed by other means.
func ParseBuildInfo(r io.Reader, lim Limits) (BuildInfo, error) {
	lim = lim.withDefaults()
	fields, _, err := scanFields(r, lim)
	if err != nil {
		return BuildInfo{}, err
	}

	b := BuildInfo{Other: map[string][]string{}}
	for _, f := range fields {
		switch f.key {
		case "format":
			b.Format = f.value
		case "pkgname":
			b.PkgName = f.value
		case "pkgbase":
			b.PkgBase = f.value
		case "pkgver":
			b.PkgVer = f.value
		case "pkgarch":
			b.PkgArch = f.value
		case "pkgbuild_sha256sum":
			b.PkgBuildSHA256 = f.value
		case "packager":
			b.Packager = f.value
		case "builddate":
			b.BuildDateRaw = f.value
			// An unparsable builddate leaves BuildDate zero rather than
			// failing the whole file: the digest is still evidence.
			if secs, err := strconv.ParseInt(f.value, 10, 64); err == nil {
				b.BuildDate = time.Unix(secs, 0).UTC()
			}
		case "builddir":
			b.BuildDir = f.value
		case "startdir":
			b.StartDir = f.value
		case "buildtool":
			b.BuildTool = f.value
		case "buildtoolver":
			b.BuildToolVer = f.value
		case "buildenv":
			b.BuildEnv = append(b.BuildEnv, f.value)
		case "options":
			b.Options = append(b.Options, f.value)
		case "installed":
			b.Installed = append(b.Installed, f.value)
		default:
			b.Other[f.key] = append(b.Other[f.key], f.value)
		}
	}
	return b, nil
}

// buildInfoRequired are the fields a provenance check cannot proceed without.
// Named in one place so Missing and Gaps cannot drift apart.
var buildInfoRequired = []string{"pkgbase", "pkgbuild_sha256sum", "builddir", "startdir"}

// Missing names the provenance-critical fields that are absent, in a fixed
// order, and returns nil when none are.
//
// pkgbase is on the list and is never inferred from pkgname. Substituting the
// package name would file 432 of 1410 packages on the reference system under the
// wrong key, and the failure would be invisible: a snapshot filed under
// "flutter-tool" simply never matches a lookup for "flutter".
func (b BuildInfo) Missing() []string {
	var out []string
	for _, name := range buildInfoRequired {
		var v string
		switch name {
		case "pkgbase":
			v = b.PkgBase
		case "pkgbuild_sha256sum":
			v = b.PkgBuildSHA256
		case "builddir":
			v = b.BuildDir
		case "startdir":
			v = b.StartDir
		}
		if v == "" {
			out = append(out, name)
		}
	}
	return out
}

// Gaps turns Missing into coverage gaps for subject (a pkgbase).
//
// Each gap says which check is now unanswerable, per INV-10: a check whose
// evidence precondition is not met reports unavailable, and "unavailable" only
// means something if it names what it needed.
func (b BuildInfo) Gaps(subject string) []finding.Gap {
	var gaps []finding.Gap
	for _, name := range b.Missing() {
		reason := fmt.Sprintf(".BUILDINFO has no %s", name)
		switch name {
		case "pkgbuild_sha256sum":
			reason += "; the recipe that was built cannot be compared with the one the AUR published"
		case "pkgbase":
			reason += "; provenance is keyed on pkgbase, so this record cannot be filed or looked up"
		case "builddir", "startdir":
			reason += "; where the build ran cannot be established"
		}
		gaps = append(gaps, finding.Gap{RuleID: RuleBuildInfo, Subject: subject, Reason: reason})
	}
	return gaps
}

// BuildInfoFromFile reads an unpacked .BUILDINFO under root.
//
// This is the recommended path on Arch, because the archive is almost always
// zstd (see CompressionOf): makepkg leaves .BUILDINFO in the build directory,
// and `snapshot` copies it into the tool's own state before the cache is
// cleaned. The read is confined and refuses a symlink leaf unresolved -- a
// build directory lives under a user's home and is not a trusted path.
func BuildInfoFromFile(root *os.Root, rel string, lim Limits) (BuildInfo, error) {
	lim = lim.withDefaults()
	f, st, err := fsx.OpenConfined(root, rel)
	if err != nil {
		return BuildInfo{}, err
	}
	defer f.Close()
	if st.Size > lim.MaxFileBytes {
		return BuildInfo{}, fmt.Errorf("%w: %s is %d bytes", ErrLimit, rel, st.Size)
	}
	return ParseBuildInfo(f, lim)
}

// BuildInfoFromArchive extracts and parses .BUILDINFO from a package archive.
//
// name selects the decompressor (see CompressionOf) and r supplies the bytes,
// so a caller that already has the archive open -- or that only has a stream --
// does not have to hand over a path.
func BuildInfoFromArchive(name string, r io.Reader, lim Limits) (BuildInfo, error) {
	lim = lim.withDefaults()

	algo, supported := CompressionOf(name)
	if !supported {
		return BuildInfo{}, compressionError(name, algo)
	}

	var tr *tar.Reader
	switch algo {
	case "none":
		tr = tar.NewReader(&cappedReader{r: r, max: lim.MaxArchiveBytes})
	case "gzip":
		zr, err := gzip.NewReader(&cappedReader{r: r, max: lim.MaxArchiveBytes})
		if err != nil {
			if errors.Is(err, ErrLimit) {
				return BuildInfo{}, err
			}
			return BuildInfo{}, fmt.Errorf("%w: %s is not a readable gzip stream: %v", ErrFormat, name, err)
		}
		defer zr.Close()
		// The cap is applied to the INFLATED stream as well, not just the
		// compressed one: the ratio is what makes a small archive expensive,
		// and a bound on the bytes an attacker had to ship does not bound what
		// they inflate to.
		tr = tar.NewReader(&cappedReader{r: zr, max: lim.MaxArchiveBytes})
	default:
		return BuildInfo{}, compressionError(name, algo)
	}

	members := 0
	for {
		h, err := tr.Next()
		if errors.Is(err, io.EOF) {
			return BuildInfo{}, fmt.Errorf("%w: %s", ErrNoBuildInfo, name)
		}
		if err != nil {
			// A cap hit reaches here as ErrLimit from cappedReader, and must
			// stay ErrLimit: "I stopped reading" and "the archive is malformed"
			// are different facts about the package.
			if errors.Is(err, ErrLimit) {
				return BuildInfo{}, err
			}
			return BuildInfo{}, fmt.Errorf("%w: %s: %v", ErrFormat, name, err)
		}
		if members++; members > lim.MaxTarMembers {
			return BuildInfo{}, fmt.Errorf("%w: %s holds more than %d members and no .BUILDINFO was found in them",
				ErrLimit, name, lim.MaxTarMembers)
		}
		// Exact name, and only a regular file. The member name is never used as
		// a filesystem path here -- nothing is extracted -- but matching
		// loosely would let "../.BUILDINFO" impersonate the real one.
		if h.Name != buildInfoMember || h.Typeflag != tar.TypeReg {
			continue
		}
		if h.Size > lim.MaxFileBytes {
			return BuildInfo{}, fmt.Errorf("%w: .BUILDINFO in %s claims %d bytes, over the %d cap",
				ErrLimit, name, h.Size, lim.MaxFileBytes)
		}
		return ParseBuildInfo(tr, lim)
	}
}

// cappedReader bounds a stream and reports the bound as ErrLimit at the point
// it is hit.
//
// A plain io.LimitReader would instead hand the tar or zlib reader a truncated
// stream, which surfaces as io.ErrUnexpectedEOF -- indistinguishable from a
// genuinely corrupt archive. The distinction matters: one is aurvet declining to
// read further, the other is a fact about the package.
type cappedReader struct {
	r   io.Reader
	n   int64
	max int64
}

func (c *cappedReader) Read(p []byte) (int, error) {
	if c.n >= c.max {
		return 0, fmt.Errorf("%w: archive exceeds the %d byte cap", ErrLimit, c.max)
	}
	if int64(len(p)) > c.max-c.n {
		p = p[:c.max-c.n]
	}
	n, err := c.r.Read(p)
	c.n += int64(n)
	return n, err
}

// compressionError explains the refusal and, crucially, says where the fact can
// still be read. A gap that does not tell its reader what to do instead is a
// dead end.
func compressionError(name, algo string) error {
	if algo == "" {
		return fmt.Errorf("%w: %s is not a package archive name; read the unpacked .BUILDINFO from the "+
			"build directory or from a snapshot instead", ErrCompression, name)
	}
	return fmt.Errorf("%w: %s is %s-compressed, which is not in the Go standard library and this module "+
		"takes no third-party decompressor; read the unpacked .BUILDINFO from the build directory, or the "+
		"copy a snapshot captured, instead", ErrCompression, name, algo)
}

// CompressionOf reports the compression a package archive name implies and
// whether this package can read it.
//
// This is the .BUILDINFO decompression decision, as data a caller can consult
// BEFORE opening a 200 MB file it cannot read:
//
//	.pkg.tar      none    readable (archive/tar)
//	.pkg.tar.gz   gzip    readable (compress/gzip)
//	.pkg.tar.zst  zstd    NOT readable -- coverage gap
//	.pkg.tar.xz   xz      NOT readable -- coverage gap
//	.pkg.tar.bz2  bzip2   NOT readable -- see below
//	.pkg.tar.lz4  lz4     NOT readable -- coverage gap
//
// Arch's default is zstd and 229 of the 233 archives in the reference system's
// yay cache are .pkg.tar.zst (the other 4 are .xz), so the unreadable case is
// the COMMON one. That is not a gap in this reader so much as the reason
// `snapshot` exists (spec §7): .BUILDINFO is archive-only, the archive is
// compressed with something outside the standard library, and this module takes
// no third-party decompressor -- golang.org/x/sys is the only sanctioned
// dependency and it is not a decompressor. The options were (a) add a module,
// (b) shell out to bsdtar, (c) read what is reachable and report the rest as a
// coverage gap. (a) is refused by the dependency policy, (b) is refused by
// INV-2, so (c) it is, and the refusal names the algorithm and says where the
// same fact can still be found.
//
// bzip2 is a deliberate exception to "readable if the stdlib can": compress/bzip2
// could decompress it, but no makepkg has defaulted to bzip2 for over a decade,
// so there is no population to support and an untested decompression path in a
// security tool is a liability rather than a feature. It is reported as a named
// gap like the rest.
func CompressionOf(name string) (algo string, supported bool) {
	// Trim a directory prefix without treating the value as a path: this is a
	// name-shaped string from an archive or a listing, not something to open.
	if i := strings.LastIndexByte(name, '/'); i >= 0 {
		name = name[i+1:]
	}
	switch {
	case strings.HasSuffix(name, ".pkg.tar"):
		return "none", true
	case strings.HasSuffix(name, ".pkg.tar.gz"):
		return "gzip", true
	case strings.HasSuffix(name, ".pkg.tar.zst"), strings.HasSuffix(name, ".pkg.tar.zstd"):
		return "zstd", false
	case strings.HasSuffix(name, ".pkg.tar.xz"):
		return "xz", false
	case strings.HasSuffix(name, ".pkg.tar.bz2"):
		return "bzip2", false
	case strings.HasSuffix(name, ".pkg.tar.lz4"):
		return "lz4", false
	case strings.HasSuffix(name, ".pkg.tar.lzo"):
		return "lzop", false
	case strings.HasSuffix(name, ".pkg.tar.Z"):
		return "compress", false
	default:
		return "", false
	}
}
