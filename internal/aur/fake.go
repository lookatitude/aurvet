package aur

import "context"

// Fake is the recorded-fixture Client used by every test outside http_test.go.
type Fake struct {
	Known      map[string]Pkg
	Tombstones map[string]string
	// TombstoneErr fails Tombstone for one specific base, so a test can
	// express "the index answered, but the cgit lookup for this base failed"
	// without also failing Info or every other base's Tombstone call — which
	// is the only thing Err can express. Checked after Err, so Err still
	// fails every call unconditionally.
	TombstoneErr map[string]error
	Err          error
}

var _ Client = Fake{}

func (f Fake) Info(_ context.Context, bases []string) (map[string]Pkg, error) {
	if f.Err != nil {
		return nil, f.Err
	}
	out := make(map[string]Pkg)
	for _, b := range bases {
		if p, ok := f.Known[b]; ok {
			out[b] = p
		}
	}
	return out, nil
}

func (f Fake) Tombstone(_ context.Context, base string) (bool, string, error) {
	if f.Err != nil {
		return false, "", f.Err
	}
	// Presence is not enough: a nil VALUE must not answer. `TombstoneErr[base]
	// = nil` used to return (false, "", nil) — byte-identical to the answer for
	// a base the Fake has never heard of — which silently shadowed a real
	// Tombstones entry. A table-driven test threading a possibly-nil error
	// through this map lost its tombstone on the nil row and still passed a
	// "must not be critical" assertion vacuously, so the footgun could let an
	// INV-A regression ship green.
	if err := f.TombstoneErr[base]; err != nil {
		return false, "", err
	}
	msg, ok := f.Tombstones[base]
	return ok, msg, nil
}
