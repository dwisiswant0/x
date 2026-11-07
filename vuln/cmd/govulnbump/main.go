package main

import (
	"context"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"os/signal"

	"go.dw1.io/x/vuln/internal/bump"
	"go.dw1.io/x/vuln/internal/govulncheck"
)

// Exit codes. exitVulns matches govulncheck's exit code for vulnerabilities.
const (
	exitOK    = 0
	exitError = 1
	exitUsage = 2
	exitVulns = 3
)

const usageHeader = `usage: govulnbump [flags] [patterns]

govulnbump upgrades dependencies that have known vulnerabilities to versions that fix them.

`

func main() {
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt)
	code := run(ctx, os.Args[1:], os.Stdout, os.Stderr)

	stop()
	os.Exit(code)
}

// run runs govulnbump with the command-line arguments args and returns its
// exit code. With -C, it changes the process's working directory.
func run(ctx context.Context, args []string, stdout, stderr io.Writer) int {
	opts, dir, err := parseFlags(args, stderr)
	if errors.Is(err, flag.ErrHelp) {
		return exitOK
	}

	if err != nil {
		return exitUsage
	}
	// The scanner runs "go env" in the working directory, so -C changes it
	// for the whole process, as "go -C" does.
	if dir != "" {
		if err := os.Chdir(dir); err != nil {
			printError(stderr, err)

			return exitError
		}
	}

	res, err := bump.Run(ctx, opts, stderr)

	return finish(stdout, stderr, res, err)
}

// finish reports the results of bump.Run and returns the exit code. It
// reports a failed run's changes to go.mod before its error.
func finish(stdout, stderr io.Writer, res *bump.Result, err error) int {
	var werr error

	if res != nil {
		if e := printReport(stdout, res, err != nil); e != nil {
			if res.Updated() {
				werr = fmt.Errorf("go.mod was updated, but writing the report failed: %w", e)
			} else {
				werr = fmt.Errorf("writing report: %w", e)
			}
		}
	}

	// Print the errors separately, so that each one starts with the
	// command's name.
	for _, e := range []error{err, werr} {
		if e != nil {
			printError(stderr, e)
		}
	}

	if err == nil {
		err = werr
	}

	return exitCode(res, err)
}

// exitCode returns the exit code for the results of bump.Run, which returns
// a Result whenever it succeeds.
func exitCode(res *bump.Result, err error) int {
	switch {
	case errors.Is(err, bump.ErrUsage):
		return exitUsage
	case err != nil:
		return exitError
	case res.Vulnerable():
		return exitVulns
	}

	return exitOK
}

// printError writes err to stderr, followed by a pointer to the usage
// message for usage errors.
func printError(stderr io.Writer, err error) {
	msg := "govulnbump: " + err.Error() + "\n"
	if errors.Is(err, bump.ErrUsage) {
		msg += "Run 'govulnbump -h' for usage.\n"
	}
	// There is nowhere left to report a failed write to stderr.
	_, _ = io.WriteString(stderr, msg)
}

// parseFlags parses the command line into options for bump.Run and the -C
// directory.
func parseFlags(args []string, stderr io.Writer) (opts bump.Options, dir string, err error) {
	var level string

	fs := flag.NewFlagSet("govulnbump", flag.ContinueOnError)
	fs.SetOutput(stderr)
	fs.Usage = func() {
		_, _ = io.WriteString(fs.Output(), usageHeader)
		fs.PrintDefaults()
	}
	fs.StringVar(&dir, "C", "", "change to `dir` before running")
	fs.StringVar(&opts.DB, "db", "", "vulnerability database `url` (default https://vuln.go.dev)")
	fs.StringVar(&level, "scan", string(govulncheck.ScanLevelSymbol), "scan `level`: module, package, or symbol")
	fs.StringVar(&opts.Tags, "tags", "", "comma-separated `list` of build tags")
	fs.BoolVar(&opts.Test, "test", false, "also scan test files")
	fs.BoolVar(&opts.DryRun, "n", false, "report the upgrades without making them")
	fs.BoolVar(&opts.Toolchain, "toolchain", false,
		"raise the go.mod toolchain line to fix standard library vulnerabilities")

	if err := fs.Parse(args); err != nil {
		return opts, "", fmt.Errorf("parsing flags: %w", err)
	}

	opts.Level = govulncheck.ScanLevel(level)
	opts.Patterns = fs.Args()

	return opts, dir, nil
}
