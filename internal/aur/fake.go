package aur

import "context"

// Fake is the recorded-fixture Client used by every test outside http_test.go.
type Fake struct {
	Known      map[string]Pkg
	Tombstones map[string]string
	Err        error
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
	msg, ok := f.Tombstones[base]
	return ok, msg, nil
}
