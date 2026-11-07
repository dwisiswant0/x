package bump

import (
	"maps"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"

	"go.dw1.io/x/vuln/internal/govulncheck"
	"go.dw1.io/x/vuln/internal/osv"
	isem "go.dw1.io/x/vuln/internal/semver"
)

// An accumulator collects the results of Run's rounds into a Result, which
// compares the module before the run with the module after it.
type accumulator struct {
	level     govulncheck.ScanLevel
	dryRun    bool
	toolchain bool
	rounds    int                 // rounds with upgrades
	upgrades  map[string]*Upgrade // the first round's upgrades, by module path
	unfixed   []Unfixed           // after the last scan
	uncalled  int                 // in the last scan
	goGet     []string
	summaries map[string]string // of every advisory seen
}

func newAccumulator(opts *Options) *accumulator {
	return &accumulator{
		level:     opts.Level,
		dryRun:    opts.DryRun,
		toolchain: opts.Toolchain,
		upgrades:  map[string]*Upgrade{},
		summaries: map[string]string{},
	}
}

// scanned records a scan of the module whose go.mod is mf, and the plan
// that it led to.
func (a *accumulator) scanned(res *scanResult, mf *modfile.File, ups []Upgrade, left []Unfixed) {
	a.unfixed = left
	a.uncalled = 0

	if a.level == govulncheck.ScanLevelSymbol {
		a.uncalled = uncalled(res, mf, a.toolchain, ups, left)
	}

	for _, u := range left {
		a.summarize(res, u.OSVs)
	}
}

// upgraded records the upgrades of a round: made, or planned with DryRun.
// Upgrades in later rounds only raise the first round's To. Their advisories
// didn't affect the module at the start, and other modules that they upgrade
// show up as go.mod changes.
func (a *accumulator) upgraded(res *scanResult, ups []Upgrade) {
	first := a.rounds == 0
	a.rounds++

	for _, u := range ups {
		a.summarize(res, u.OSVs)

		if prev := a.upgrades[u.Module]; prev != nil {
			prev.To = u.To
		} else if first {
			u.OSVs = slices.Clone(u.OSVs)
			a.upgrades[u.Module] = &u
		}
	}
}

// notApplied records the upgrades of a round that go get didn't make.
func (a *accumulator) notApplied(res *scanResult, ups []Upgrade) {
	for _, u := range ups {
		a.summarize(res, u.OSVs)
		a.unfixed = append(a.unfixed, Unfixed{u.Module, u.From, u.OSVs, "go get did not upgrade it"})
	}

	slices.SortFunc(a.unfixed, func(x, y Unfixed) int { return strings.Compare(x.Module, y.Module) })
}

func (a *accumulator) summarize(res *scanResult, ids []string) {
	for _, id := range ids {
		if e := res.osvs[id]; e != nil {
			a.summaries[id] = summary(e)
		}
	}
}

// result returns the Result of a finished run. initial and final are the
// go.mod files before the first round and after the last.
func (a *accumulator) result(initial, final *modfile.File) *Result {
	r := a.changed(initial, final)
	if r == nil {
		r = &Result{}
	}

	r.DryRun = a.dryRun
	r.Unfixed = a.unfixed
	r.GoGet = a.goGet
	r.Uncalled = a.uncalled
	r.Summaries = a.summariesOf(r)

	return r
}

// partial returns the Result of a failed run: only the upgrades and go.mod
// changes so far, and their summaries, or nil if there are none. final is
// nil if go.mod can't be read.
func (a *accumulator) partial(initial, final *modfile.File) *Result {
	r := a.changed(initial, final)
	if r != nil {
		r.Summaries = a.summariesOf(r)
	}

	return r
}

// changed returns a Result with only the upgrades and go.mod changes so far,
// or nil if there are none.
func (a *accumulator) changed(initial, final *modfile.File) *Result {
	if len(a.upgrades) == 0 {
		return nil
	}

	var reqs map[string]string
	if !a.dryRun && final != nil {
		reqs = requirements(final)
	}

	r := &Result{}

	for _, path := range slices.Sorted(maps.Keys(a.upgrades)) {
		u := *a.upgrades[path]
		// A later round can raise the module further, directly or as a
		// requirement of another upgrade.
		if v := reqs[path]; v != "" {
			u.To = v
		}

		r.Upgrades = append(r.Upgrades, u)
	}

	if reqs != nil {
		r.Changes = otherChanges(modChanges(initial, final), r.Upgrades)
	}

	return r
}

// summariesOf returns the summaries of the advisories in r.
func (a *accumulator) summariesOf(r *Result) map[string]string {
	sums := map[string]string{}

	add := func(ids []string) {
		for _, id := range ids {
			if s, ok := a.summaries[id]; ok {
				sums[id] = s
			}
		}
	}

	for _, u := range r.Upgrades {
		add(u.OSVs)
	}

	for _, u := range r.Unfixed {
		add(u.OSVs)
	}

	return sums
}

// otherChanges returns the changes that the upgrades don't already describe.
func otherChanges(changes []Change, ups []Upgrade) []Change {
	return slices.DeleteFunc(changes, func(c Change) bool {
		return slices.ContainsFunc(ups, func(u Upgrade) bool {
			if u.Module == osv.GoStdModulePath {
				return c.Name == "toolchain" && c.To == isem.SemverToGoTag(u.To)
			}

			return c.Name == u.Module && c.To == u.To
		})
	})
}

// uncalled counts the advisories that a package-level plan of the scan res
// would fix, but that the symbol-level plan, which made ups and left, doesn't
// report. Those affect imported packages whose vulnerable functions aren't
// called.
func uncalled(res *scanResult, mf *modfile.File, toolchain bool, ups []Upgrade, left []Unfixed) int {
	reported := map[string]bool{}

	for _, u := range ups {
		for _, id := range u.OSVs {
			reported[id] = true
		}
	}

	for _, u := range left {
		for _, id := range u.OSVs {
			reported[id] = true
		}
	}

	pkgUps, _ := plan(res, mf, govulncheck.ScanLevelPackage, toolchain)
	more := map[string]bool{}

	for _, u := range pkgUps {
		for _, id := range u.OSVs {
			if !reported[id] {
				more[id] = true
			}
		}
	}

	return len(more)
}

// summary returns a one-line description of e: its summary or, as
// govulncheck falls back to its details, the first sentence of those.
func summary(e *osv.Entry) string {
	if e.Summary != "" {
		return e.Summary
	}

	details := strings.Join(strings.Fields(e.Details), " ")
	if i := strings.Index(details, ". "); i >= 0 {
		details = details[:i+1]
	}

	return details
}
