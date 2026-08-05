// internal/safe/subject.go
//
// Package safe is the containment boundary between one subject's analysis and
// the rest of the scan. It exists because of INV-9: a panic or a hang while
// examining one package is a coverage gap attributable to that package, never a
// global abort and never silence. A tool that dies on the first crafted input
// tells an attacker exactly how to become invisible -- every subject after the
// crash goes unexamined, and a process that never wrote a report also never
// reported that it had not.
//
// Nothing here interprets a byte. It contains stdlib only, on purpose: this is
// the code that has to keep working when everything it wraps does not.
package safe

import (
	"context"
	"errors"
	"fmt"
	"time"
)

// The two containment outcomes, exported so callers can classify a gap rather
// than string-matching a message.
var (
	// ErrPanic reports that the subject's analysis panicked and the panic was
	// contained. It is deliberately distinct from an error the subject
	// returned: a returned error is usually a fact about the subject (a file
	// could not be opened), while a panic is a fact about OUR code failing on
	// that subject. Both are gaps; only one is a bug report.
	ErrPanic = errors.New("panicked during analysis")

	// ErrTimeout reports that the subject exceeded its per-subject deadline.
	// A hang is bounded rather than terminal -- without this, one fifo or one
	// pathological input is denial of tool for the whole scan.
	ErrTimeout = errors.New("timed out during analysis")
)

// cooperativeGrace is how long RunTimeout waits, after the deadline fires, for a
// subject that honours the context to report its own error. See RunTimeout.
const cooperativeGrace = 100 * time.Millisecond

// Run calls fn, containing any panic it raises, and reports whether it panicked.
//
// The recover lives HERE, at the top of the function that calls fn, and callers
// must place Run at the top of every worker goroutine's body. A goroutine's
// panic cannot be recovered by the goroutine that started it: a recover in the
// parent, however carefully written, does not run and the process dies. That is
// the single easiest thing in this phase to get wrong and the most fatal, which
// is why there is exactly one implementation of it in the tree.
//
// The returned error is non-nil in both failure modes and callers turn it into
// one finding.Gap. Run itself does not build the Gap: deciding what a failure
// means for a report is the reporting layer's job, and keeping this package free
// of that decision keeps it free of dependencies.
//
// Documented limit (INV-6): runtime.Goexit is not a panic. recover() returns nil
// for it and the goroutine is terminated once the deferred handlers finish, so
// Run's return statement never executes and NO verdict reaches the caller. A
// caller that dispatches subjects concurrently must therefore count answers, not
// assume them -- collect does, and gaps the difference.
func Run(subject string, fn func() error) (err error, panicked bool) {
	defer func() {
		if r := recover(); r != nil {
			// The stack is deliberately not captured into the error: the
			// message ends up in a report an operator reads, and a goroutine
			// dump there is noise. The panic value names the failure; the
			// subject names where to look.
			err = fmt.Errorf("%s: %w: %v", subject, ErrPanic, r)
			panicked = true
		}
	}()
	return fn(), false
}

// RunTimeout is Run with a per-subject deadline. limit <= 0 means unbounded, so
// a caller that has not configured a timeout gets Run's behaviour rather than an
// accidental instant expiry.
//
// fn receives the bounded context so a cooperative subject can stop early and
// return its own error -- that is the good case, and the error it returns is
// passed through unchanged (it will wrap context.DeadlineExceeded, not
// ErrTimeout, because the subject, not us, decided to stop).
//
// A subject that ignores the context is ABANDONED, not killed: Go cannot
// interrupt a goroutine, and pretending otherwise would be a lie in a comment
// rather than a bug in the code. The goroutine keeps running and its result is
// discarded, so the send below is on a buffered channel and never blocks
// forever. The cost is bounded -- one leaked goroutine per hung subject, and the
// syscalls it holds are already O_NONBLOCK by fsx's construction. The
// alternative, waiting for it, is the hang this function exists to prevent.
func RunTimeout(parent context.Context, subject string, limit time.Duration, fn func(context.Context) error) (err error, panicked bool) {
	// A subject dispatched after the scan was already cancelled must not be
	// started, and must not report success either: not-started is a gap. Without
	// this, a cancelled scan with a queue of pending subjects marks all of them
	// clean because each fn happened to finish before the first select ran.
	if err := parent.Err(); err != nil {
		return fmt.Errorf("%s: not analysed: %w", subject, err), false
	}

	ctx := parent
	if limit > 0 {
		var cancel context.CancelFunc
		ctx, cancel = context.WithTimeout(parent, limit)
		defer cancel()
	}

	type outcome struct {
		err      error
		panicked bool
	}
	// Buffered: the abandoned goroutine must be able to finish its send.
	done := make(chan outcome, 1)

	go func() {
		// Every worker goroutine has its own recover. This one included --
		// RunTimeout's caller is in a different goroutine and cannot help.
		e, p := Run(subject, func() error { return fn(ctx) })
		done <- outcome{e, p}
	}()

	select {
	case o := <-done:
		return o.err, o.panicked
	case <-ctx.Done():
		// A cooperative subject is woken by the cancellation and is, at this
		// instant, racing us to report its own error. Without this grace window
		// the outcome depends on scheduler luck: the same subject reports
		// context.DeadlineExceeded on one run and ErrTimeout on the next, and a
		// flaky classification of a gap is worse than either answer. The window
		// keeps the bound (limit + cooperativeGrace) and buys a deterministic
		// verdict for the subjects that behave.
		select {
		case o := <-done:
			return o.err, o.panicked
		case <-time.After(cooperativeGrace):
		}
		if parent.Err() != nil && !errors.Is(ctx.Err(), context.DeadlineExceeded) {
			// The whole scan was cancelled, not this subject's budget spent.
			return fmt.Errorf("%s: %w", subject, parent.Err()), false
		}
		return fmt.Errorf("%s: %w after %s", subject, ErrTimeout, limit), false
	}
}
