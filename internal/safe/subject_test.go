// internal/safe/subject_test.go
package safe

import (
	"context"
	"errors"
	"fmt"
	"runtime"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestRunPassesSuccessThrough(t *testing.T) {
	err, panicked := Run("pkg-a", func() error { return nil })
	if err != nil || panicked {
		t.Fatalf("Run = (%v, %v), want (nil, false)", err, panicked)
	}
}

// An ordinary error is not a panic. Conflating the two would make every
// unreadable file look like a coverage gap caused by our own code.
func TestRunPreservesOrdinaryErrorIdentity(t *testing.T) {
	sentinel := errors.New("boom")
	err, panicked := Run("pkg-a", func() error { return fmt.Errorf("wrapped: %w", sentinel) })
	if panicked {
		t.Error("panicked = true for a returned error")
	}
	if !errors.Is(err, sentinel) {
		t.Fatalf("err = %v, want it to wrap the sentinel", err)
	}
	if errors.Is(err, ErrPanic) {
		t.Error("a returned error must not be reported as a panic")
	}
}

func TestRunContainsPanicAndNamesTheSubject(t *testing.T) {
	err, panicked := Run("pkg-b", func() error { panic("crafted metadata") })
	if !panicked {
		t.Error("panicked = false for a panicking subject")
	}
	if !errors.Is(err, ErrPanic) {
		t.Fatalf("err = %v, want it to wrap ErrPanic", err)
	}
	for _, want := range []string{"pkg-b", "crafted metadata"} {
		if !strings.Contains(err.Error(), want) {
			t.Errorf("err = %q, missing %q", err.Error(), want)
		}
	}
}

// The panics a parser actually raises are runtime errors, not string panics,
// and panic(nil) is a *runtime.PanicNilError since Go 1.21. Neither may escape.
func TestRunContainsRuntimePanics(t *testing.T) {
	cases := map[string]func() error{
		"nil-map-write":  func() error { var m map[string]int; m["x"] = 1; return nil },
		"index-range":    func() error { s := []byte{}; _ = s[3]; return nil },
		"nil-deref":      func() error { var p *int; _ = *p; return nil },
		"panic-nil":      func() error { panic(nil) },
		"slice-negative": func() error { s := []byte("ab"); n := -1; _ = s[:n]; return nil },
	}
	for name, fn := range cases {
		t.Run(name, func(t *testing.T) {
			err, panicked := Run(name, fn)
			if !panicked || !errors.Is(err, ErrPanic) {
				t.Fatalf("Run = (%v, %v), want a contained panic", err, panicked)
			}
		})
	}
}

// runtime.Goexit is NOT a panic: recover() returns nil for it, and after the
// deferred handlers run the goroutine is terminated -- so Run's return statement
// never executes and no return value can report it. This test pins that
// documented limit rather than pretending otherwise: the caller sees NO verdict,
// which is why collect accounts for dispatched-versus-answered subjects and gaps
// the difference. A test asserting an error here would be asserting something
// the language cannot deliver.
func TestGoexitLeavesNoVerdictWhichIsWhyCallersMustCount(t *testing.T) {
	var (
		answered bool
		done     = make(chan struct{})
	)
	go func() {
		defer close(done)
		_, _ = Run("pkg-goexit", func() error { runtime.Goexit(); return nil })
		answered = true // unreachable: Goexit terminates the goroutine.
	}()
	<-done
	if answered {
		t.Fatal("Run returned through a runtime.Goexit; the documented limit no longer holds and collect's dispatched-versus-answered accounting can be reconsidered")
	}
}

// The case that kills processes. Each worker goroutine wraps its own body in
// Run; the panic must not reach the runtime, and every subject must produce a
// verdict. If Run's recover were in the parent instead, this test would not
// fail -- the whole test binary would die.
func TestRunContainsAPanicRaisedInsideAWorkerGoroutine(t *testing.T) {
	const workers = 16

	type verdict struct {
		subject  string
		err      error
		panicked bool
	}
	var (
		mu  sync.Mutex
		got []verdict
		wg  sync.WaitGroup
	)
	for i := range workers {
		wg.Add(1)
		go func() {
			defer wg.Done()
			subject := fmt.Sprintf("pkg-%02d", i)
			err, panicked := Run(subject, func() error {
				if i%2 == 0 {
					panic(fmt.Sprintf("panic from worker %d", i))
				}
				return nil
			})
			mu.Lock()
			got = append(got, verdict{subject, err, panicked})
			mu.Unlock()
		}()
	}
	wg.Wait()

	if len(got) != workers {
		t.Fatalf("got %d verdicts, want %d: a worker died instead of reporting", len(got), workers)
	}
	panics := 0
	for _, v := range got {
		if v.panicked {
			panics++
			if !errors.Is(v.err, ErrPanic) {
				t.Errorf("%s: err = %v, want ErrPanic", v.subject, v.err)
			}
		}
	}
	if panics != workers/2 {
		t.Errorf("contained %d panics, want %d", panics, workers/2)
	}
}

func TestRunTimeoutBoundsAHang(t *testing.T) {
	release := make(chan struct{})
	defer close(release)

	start := time.Now()
	err, panicked := RunTimeout(context.Background(), "pkg-hang", 50*time.Millisecond,
		func(context.Context) error { <-release; return nil })
	elapsed := time.Since(start)

	if !errors.Is(err, ErrTimeout) {
		t.Fatalf("err = %v, want ErrTimeout", err)
	}
	if panicked {
		t.Error("panicked = true for a timeout; a hang is not a panic")
	}
	if elapsed > 5*time.Second {
		t.Errorf("RunTimeout took %v: the deadline did not bound the subject", elapsed)
	}
	if !strings.Contains(err.Error(), "pkg-hang") {
		t.Errorf("err = %q does not name its subject", err.Error())
	}
}

// The deadline is handed to fn, so a cooperative subject stops early instead of
// being abandoned. A subject that ignores it still gets bounded by the case
// above; both have to hold.
func TestRunTimeoutCancelsTheSubjectsContext(t *testing.T) {
	err, panicked := RunTimeout(context.Background(), "pkg-coop", 20*time.Millisecond,
		func(ctx context.Context) error { <-ctx.Done(); return ctx.Err() })
	if panicked {
		t.Error("panicked = true for a cooperative cancellation")
	}
	if !errors.Is(err, context.DeadlineExceeded) {
		t.Fatalf("err = %v, want the subject's own DeadlineExceeded", err)
	}
}

func TestRunTimeoutContainsAPanicInItsOwnGoroutine(t *testing.T) {
	err, panicked := RunTimeout(context.Background(), "pkg-b", time.Minute,
		func(context.Context) error { panic("crafted metadata") })
	if !panicked || !errors.Is(err, ErrPanic) {
		t.Fatalf("RunTimeout = (%v, %v), want a contained panic", err, panicked)
	}
}

func TestRunTimeoutHonoursAnAlreadyCancelledParent(t *testing.T) {
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	ran := false
	err, _ := RunTimeout(ctx, "pkg-cancelled", time.Minute,
		func(context.Context) error { ran = true; return nil })
	if err == nil {
		t.Fatalf("err = nil, want a refusal; ran=%v", ran)
	}
	if !errors.Is(err, context.Canceled) && !errors.Is(err, ErrTimeout) {
		t.Errorf("err = %v, want a cancellation", err)
	}
}

func TestRunTimeoutZeroLimitMeansUnbounded(t *testing.T) {
	err, panicked := RunTimeout(context.Background(), "pkg-a", 0,
		func(context.Context) error { time.Sleep(10 * time.Millisecond); return nil })
	if err != nil || panicked {
		t.Fatalf("RunTimeout = (%v, %v), want (nil, false)", err, panicked)
	}
}
