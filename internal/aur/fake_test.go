package aur

import (
	"context"
	"errors"
	"testing"
)

// These four tests are the executable statement of contract rule 1: a
// failure is a coverage gap, never an absence, and genuine absence is not a
// failure. See docs/interface-contracts-p1a.md, cross-cutting rule 1.

func TestFakeInfoErrorIsNotAbsence(t *testing.T) {
	wantErr := errors.New("aur unreachable")
	f := Fake{Err: wantErr}
	got, err := f.Info(context.Background(), []string{"foo-bin"})
	if err == nil {
		t.Fatal("Info with Err set must return a non-nil error")
	}
	if got != nil {
		t.Errorf("Info with Err set must not return a usable map, got %v", got)
	}
}

func TestFakeTombstoneErrorIsNotAbsence(t *testing.T) {
	wantErr := errors.New("aur unreachable")
	f := Fake{Err: wantErr}
	found, _, err := f.Tombstone(context.Background(), "foo-bin")
	if err == nil {
		t.Fatal("Tombstone with Err set must return a non-nil error")
	}
	if found {
		t.Error("found must be false when Err is set, so a caller checking err first never sees a false positive")
	}
}

func TestFakeInfoAbsenceIsNotAnError(t *testing.T) {
	f := Fake{Known: map[string]Pkg{"foo-bin": {Name: "foo-bin"}}}
	got, err := f.Info(context.Background(), []string{"not-there"})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if _, ok := got["not-there"]; ok {
		t.Errorf("got entry for absent base: %v", got)
	}
}

func TestFakeTombstoneAbsenceIsNotAnError(t *testing.T) {
	f := Fake{Tombstones: map[string]string{"known-removed": "history removed due to malware"}}
	found, msg, err := f.Tombstone(context.Background(), "not-there")
	if err != nil {
		t.Fatalf("Tombstone: %v", err)
	}
	if found {
		t.Error("found = true for a base with no tombstone entry")
	}
	if msg != "" {
		t.Errorf("msg = %q, want empty", msg)
	}
}

// These three tests are the executable statement of the third Tombstone
// outcome (docs/interface-contracts-p1a.md rule 1, sharpened by task 8): the
// index can answer Info while the cgit lookup for one specific base fails.
// TombstoneErr is what lets a test express that split without also failing
// every other call, which is what f.Err already does.

func TestFakeTombstoneErrPerBaseIsNotAbsence(t *testing.T) {
	wantErr := errors.New("cgit unreachable")
	f := Fake{TombstoneErr: map[string]error{"foo-bin": wantErr}}
	found, _, err := f.Tombstone(context.Background(), "foo-bin")
	if err == nil {
		t.Fatal("Tombstone with a per-base TombstoneErr entry must return a non-nil error")
	}
	if found {
		t.Error("found must be false when the per-base error fires, so a caller checking err first never sees a false positive")
	}
}

func TestFakeTombstoneErrDoesNotAffectOtherBases(t *testing.T) {
	f := Fake{
		Tombstones:   map[string]string{"other-bin": "history removed due to malware"},
		TombstoneErr: map[string]error{"foo-bin": errors.New("cgit unreachable")},
	}
	found, msg, err := f.Tombstone(context.Background(), "other-bin")
	if err != nil {
		t.Fatalf("Tombstone(other-bin): %v", err)
	}
	if !found || msg != "history removed due to malware" {
		t.Errorf("found=%v msg=%q, want the unaffected base's own tombstone", found, msg)
	}
}

func TestFakeTombstoneErrDoesNotAffectInfo(t *testing.T) {
	f := Fake{
		Known:        map[string]Pkg{"foo-bin": {Name: "foo-bin"}},
		TombstoneErr: map[string]error{"foo-bin": errors.New("cgit unreachable")},
	}
	got, err := f.Info(context.Background(), []string{"foo-bin"})
	if err != nil {
		t.Fatalf("Info: %v", err)
	}
	if _, ok := got["foo-bin"]; !ok {
		t.Errorf("Info missing entry for foo-bin: %v", got)
	}
}
