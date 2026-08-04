// Command arch-drift detects compromised AUR packages and verifies that a
// system has not been tampered with.
package main

import (
	"flag"
	"fmt"
	"io"
	"os"

	"github.com/lookatitude/arch-drift/internal/config"
)

// Exit codes are contractual (spec §14). They are the machine-readable result
// of a scan, so they must never drift: automation branches on them.
const (
	exitClean      = 0 // analysis completed, nothing at or above the floor
	exitFindings   = 1 // analysis completed, findings reported
	exitUsage      = 2 // the invocation itself was wrong
	exitIncomplete = 3 // analysis could not cover what it was asked to cover
)

func main() {
	os.Exit(run(os.Args[1:], os.Stdout, os.Stderr))
}

// run is main's testable body: everything it touches arrives as a parameter,
// and it returns the exit code rather than calling os.Exit.
func run(args []string, stdout, stderr io.Writer) int {
	fs := flag.NewFlagSet("arch-drift", flag.ContinueOnError)
	fs.SetOutput(stderr)
	offlineRoot := fs.String("offline-root", "", "examine a mounted filesystem instead of the running system")

	if err := fs.Parse(args); err != nil {
		return exitUsage
	}

	rest := fs.Args()
	if len(rest) == 0 {
		fmt.Fprintln(stderr, "usage: arch-drift [flags] <command>")
		fmt.Fprintln(stderr, "commands: doctor")
		return exitUsage
	}

	switch rest[0] {
	case "doctor":
		cfg, err := config.Resolve(*offlineRoot, os.Geteuid())
		if err != nil {
			fmt.Fprintf(stderr, "arch-drift: %v\n", err)
			return exitIncomplete
		}
		for _, l := range cfg.Doctor() {
			fmt.Fprintf(stdout, "%-14s %-46s (%s)\n", l.Key, l.Value, l.Source)
		}
		return exitClean

	default:
		fmt.Fprintf(stderr, "arch-drift: unknown command %q\n", rest[0])
		return exitUsage
	}
}
