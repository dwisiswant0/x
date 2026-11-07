// Package bump upgrades the vulnerable dependencies of a module to versions
// that fix them. It implements the govulnbump command.
package bump

import (
	"context"
	"errors"
	"fmt"
	"go/build"
	"io"
	"path/filepath"
	"strings"

	"golang.org/x/mod/modfile"

	"go.dw1.io/x/vuln/internal/govulncheck"
)

// Options configures Run.
type Options struct {
	DB        string                // vulnerability database URL; "" means the scanner's default
	Level     govulncheck.ScanLevel // scan level; "" means symbol
	Tags      string                // comma-separated build tags
	Test      bool                  // also scan test files
	DryRun    bool                  // report the upgrades without making them
	Toolchain bool                  // raise the toolchain line to fix standard library vulnerabilities

	// Patterns are directory patterns, such as ./..., that name the
	// packages to scan. They default to ./... at symbol and package level,
	// and must be empty at module level.
	Patterns []string
}

// ErrUsage is wrapped by the errors that Run returns for options it can't
// use, such as an unknown scan level.
var ErrUsage = errors.New("invalid usage")

type usageError struct{ msg string }

func (e *usageError) Error() string { return e.msg }
func (e *usageError) Unwrap() error { return ErrUsage }

func usagef(format string, args ...any) error {
	return &usageError{fmt.Sprintf(format, args...)}
}

// A Result describes what Run did and what remains.
type Result struct {
	DryRun bool

	// Upgrades are the modules that were vulnerable at the start, with the
	// advisories that affected them then, from their versions before the
	// run to their versions after it. With DryRun, they are the planned
	// upgrades, which Run didn't make.
	//
	// A later round can upgrade other modules too, for advisories that the
	// earlier upgrades introduced. Those modules are in Changes.
	Upgrades []Upgrade

	// Changes are the other version changes in go.mod, such as
	// requirements that the upgrades raised and a raised go line.
	Changes []Change

	// Unfixed are the vulnerabilities that remain at Level.
	Unfixed []Unfixed

	// GoGet, with DryRun, holds the go command arguments that make
	// Upgrades.
	GoGet []string

	// Uncalled, at symbol level, counts the advisories that affect packages
	// the code imports but whose vulnerable functions it doesn't call, and
	// that a package-level run could fix. Standard library advisories count
	// only with Options.Toolchain.
	Uncalled int

	// Summaries maps the advisory IDs in Upgrades and Unfixed to one-line
	// descriptions.
	Summaries map[string]string
}

// Vulnerable reports whether vulnerabilities remain at r.Level. After a dry
// run, they include the ones that the upgrades would fix.
func (r *Result) Vulnerable() bool {
	return len(r.Unfixed) > 0 || (r.DryRun && len(r.Upgrades) > 0)
}

// Updated reports whether Run changed go.mod.
func (r *Result) Updated() bool {
	return !r.DryRun && (len(r.Upgrades) > 0 || len(r.Changes) > 0)
}

// Run upgrades the vulnerable dependencies of the module in the working
// directory. It scans the module, upgrades the modules that the scan reports
// at opts.Level, and rescans until a scan plans no upgrades. It writes
// progress and go command output to stderr.
//
// If Run fails after it has upgraded modules, it also returns a Result with
// only Upgrades, Changes, and Summaries set, so that the caller can still
// report them. If it fails before, it returns a nil Result.
func Run(ctx context.Context, opts Options, stderr io.Writer) (*Result, error) {
	if err := opts.normalize(); err != nil {
		return nil, err
	}

	env, err := readGoEnv(ctx)
	if err != nil {
		return nil, err
	}

	if err := env.check(); err != nil {
		return nil, err
	}

	if opts.Toolchain && !switchesToolchains(env.GOTOOLCHAIN) {
		return nil, usagef("-toolchain has no effect with GOTOOLCHAIN=%s; use auto or path", env.GOTOOLCHAIN)
	}

	return run(ctx, &opts, env.GOMOD, stderr)
}

// normalize checks o and fills in its defaults.
func (o *Options) normalize() error {
	switch o.Level {
	case "":
		o.Level = govulncheck.ScanLevelSymbol

		fallthrough
	case govulncheck.ScanLevelSymbol, govulncheck.ScanLevelPackage:
		if len(o.Patterns) == 0 {
			o.Patterns = []string{"./..."}
		}
	case govulncheck.ScanLevelModule:
		// The scanner rejects patterns at module level.
		if len(o.Patterns) > 0 {
			return usagef("patterns are not accepted with -scan=module")
		}
	default:
		return usagef("invalid -scan level %q: want module, package, or symbol", o.Level)
	}
	// The patterns are also go get arguments. go get upgrades the module of
	// an import path pattern such as "all" to its latest version, so allow
	// only directory patterns, which name packages in the main module.
	for _, p := range o.Patterns {
		if !build.IsLocalImport(p) && !filepath.IsAbs(p) {
			return usagef("pattern %q is not a directory pattern; use one such as ./... or ./cmd/app", p)
		}
	}

	return nil
}

// run scans the module whose go.mod is at gomod, upgrades the vulnerable
// modules it finds, and rescans until a scan plans no upgrades.
func run(ctx context.Context, opts *Options, gomod string, stderr io.Writer) (*Result, error) {
	initial, err := readModFile(gomod)
	if err != nil {
		return nil, err
	}

	acc := newAccumulator(opts)

	progressf(stderr, "scanning %s (%s level)", scanTarget(opts), opts.Level)

	for {
		before, err := readModFile(gomod)
		if err != nil {
			return acc.partial(initial, nil), err
		}

		res, err := scanModule(ctx, opts, stderr)
		if err != nil {
			return acc.partial(initial, before), err
		}

		ups, left := plan(res, before, opts.Level, opts.Toolchain)
		acc.scanned(res, before, ups, left)

		if len(ups) == 0 {
			return acc.result(initial, before), nil
		}

		getArgs := goGetArgs(ups, opts)

		if opts.DryRun {
			acc.upgraded(res, ups)
			acc.goGet = getArgs

			return acc.result(initial, before), nil
		}

		after, done, err := apply(ctx, acc, res, ups, getArgs, before, gomod, stderr)
		if done {
			return acc.result(initial, after), nil
		}

		if err != nil {
			return acc.partial(initial, after), err
		}

		progressf(stderr, "rescanning")
	}
}

// apply makes the upgrades ups of a round, which go get runs with getArgs,
// and records them in acc. before is go.mod at the start of the round. It
// returns go.mod afterward, or nil if it can't be read, and done if go get
// left go.mod unchanged, in which case another round would plan the same
// upgrades.
func apply(ctx context.Context, acc *accumulator, res *scanResult, ups []Upgrade, getArgs []string,
	before *modfile.File, gomod string, stderr io.Writer,
) (after *modfile.File, done bool, err error) {
	if err := runGo(ctx, stderr, getArgs...); err != nil {
		return before, false, err
	}

	after, err = readModFile(gomod)
	if err != nil {
		// go get succeeded, so it made the upgrades.
		acc.upgraded(res, ups)

		return nil, false, err
	}

	if len(modChanges(before, after)) == 0 {
		acc.notApplied(res, ups)

		return after, true, nil
	}

	acc.upgraded(res, ups)

	if hasVendor(gomod) {
		progressf(stderr, "running go mod vendor")

		if err := runGo(ctx, stderr, "mod", "vendor"); err != nil {
			return after, false, err
		}
	}

	return after, false, nil
}

// progressf writes a progress line to stderr. Progress is best effort.
func progressf(stderr io.Writer, format string, args ...any) {
	_, _ = fmt.Fprintf(stderr, "govulnbump: "+format+"\n", args...)
}

// scanTarget describes what the scan covers, for progress output.
func scanTarget(opts *Options) string {
	return strings.Join(opts.packages(), " ")
}

// packages returns the patterns of the packages that the scan loads. A
// module-level scan has no patterns and loads the package in the working
// directory.
func (o *Options) packages() []string {
	if len(o.Patterns) == 0 {
		return []string{"."}
	}

	return o.Patterns
}

// goGetArgs returns the go command arguments that make the upgrades ups.
// The scan patterns make go get load the scanned packages, so that it
// records go.sum entries for any modules they now need. Without them, go
// get adds go.sum entries only for modules that already had them.
func goGetArgs(ups []Upgrade, opts *Options) []string {
	args := []string{"get"}
	if opts.Test {
		args = append(args, "-t")
	}

	if opts.Tags != "" {
		args = append(args, "-tags="+opts.Tags)
	}

	for _, u := range ups {
		args = append(args, u.arg())
	}

	return append(args, opts.packages()...)
}
