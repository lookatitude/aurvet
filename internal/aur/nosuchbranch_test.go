package aur

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// cgit answering 404 "Invalid branch" is a definitive absence of any removal
// record, not a failed lookup. The measurement this rests on: librewolf-fix-bin,
// the verified malware removal, still answers 200 with a populated log table, so
// cgit retains logs after deletion and a 404 cannot conceal a tombstone.
func TestTombstoneCgit404IsNoTombstoneNotAGap(t *testing.T) {
	body, err := os.ReadFile("../../testdata/aur/cgit/log-404-nonexistent-branch.html")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write(body)
	}))
	defer srv.Close()
	present, msg, err := NewHTTP(srv.URL, srv.Client()).Tombstone(context.Background(), "python-pkg_resources")
	if err != nil {
		t.Errorf("cgit 404 returned err=%v; want a definitive no-tombstone answer", err)
	}
	if present || msg != "" {
		t.Errorf("present=%v msg=%q; want (false, \"\")", present, msg)
	}
}

// Narrowness: only cgit's OWN 404 is an answer. A captive portal or proxy
// answering 404 with its own page is still a failure, or it becomes a blanket
// false-assurance path for every package at once.
func TestTombstoneNonCgit404IsStillAnError(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusNotFound)
		w.Write([]byte("<html><head><title>Sign in to the network</title></head><body>404</body></html>"))
	}))
	defer srv.Close()
	_, _, err := NewHTTP(srv.URL, srv.Client()).Tombstone(context.Background(), "yay")
	if err == nil {
		t.Error("non-cgit 404 returned err=nil; a portal 404 must not read as 'no tombstone'")
	}
}

// A 200 carrying that same cgit error body stays an error (F7): only the 404
// status plus a cgit body is an answer.
func TestTombstoneCgitErrorBodyWith200IsStillAnError(t *testing.T) {
	body, err := os.ReadFile("../../testdata/aur/cgit/log-404-nonexistent-branch.html")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Write(body)
	}))
	defer srv.Close()
	if _, _, err := NewHTTP(srv.URL, srv.Client()).Tombstone(context.Background(), "yay"); err == nil {
		t.Error("200 with a cgit error body returned err=nil; F7 requires an error")
	}
}
