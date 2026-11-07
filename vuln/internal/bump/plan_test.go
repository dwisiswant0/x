package bump

import (
	"reflect"
	"testing"

	"golang.org/x/mod/modfile"

	"go.dw1.io/x/vuln/internal/govulncheck"
	"go.dw1.io/x/vuln/internal/osv"
)

const (
	lib     = "example.com/lib"
	std     = osv.GoStdModulePath
	idA     = "GO-0000-0001"
	idB     = "GO-0000-0002"
	baseMod = "module example.com/main\n\ngo 1.26.0\n"
)

// called returns a symbol-level finding: id's vulnerable function in
// module mod at version v is called.
func called(id, mod, v string) *govulncheck.Finding {
	return &govulncheck.Finding{OSV: id, Trace: []*govulncheck.Frame{
		{Module: mod, Version: v, Package: mod + "/vuln", Function: "Bad"},
		{Module: "example.com/main", Package: "example.com/main", Function: "main"},
	}}
}

// imported returns a package-level finding.
func imported(id, mod, v string) *govulncheck.Finding {
	return &govulncheck.Finding{OSV: id, Trace: []*govulncheck.Frame{{Module: mod, Version: v, Package: mod + "/vuln"}}}
}

// required returns a module-level finding.
func required(id, mod, v string) *govulncheck.Finding {
	return &govulncheck.Finding{OSV: id, Trace: []*govulncheck.Frame{{Module: mod, Version: v}}}
}

// entry returns an advisory for mod with one SEMVER range per events list.
func entry(id, mod string, ranges ...[]osv.RangeEvent) *osv.Entry {
	a := osv.Affected{Module: osv.Module{Path: mod, Ecosystem: osv.GoEcosystem}}
	for _, evs := range ranges {
		a.Ranges = append(a.Ranges, osv.Range{Type: osv.RangeTypeSemver, Events: evs})
	}

	return &osv.Entry{ID: id, Affected: []osv.Affected{a}}
}

// span returns the events for the range [introduced, fixed).
// An empty fixed means no fix.
func span(introduced, fixed string) []osv.RangeEvent {
	evs := []osv.RangeEvent{{Introduced: introduced}}
	if fixed != "" {
		evs = append(evs, osv.RangeEvent{Fixed: fixed})
	}

	return evs
}

func parseModFile(t *testing.T, s string) *modfile.File {
	t.Helper()

	mf, err := modfile.Parse("go.mod", []byte(s), nil)
	if err != nil {
		t.Fatal(err)
	}

	return mf
}

type planTest struct {
	name      string
	level     govulncheck.ScanLevel // default symbol
	toolchain bool
	gomod     string // default baseMod
	findings  []*govulncheck.Finding
	entries   []*osv.Entry
	wantUps   []Upgrade
	wantLeft  []Unfixed
}

func runPlanTests(t *testing.T, tests []planTest) {
	t.Helper()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			level := tc.level
			if level == "" {
				level = govulncheck.ScanLevelSymbol
			}

			gomod := tc.gomod
			if gomod == "" {
				gomod = baseMod
			}

			ups, left := plan(scanOf(tc.findings, tc.entries...), parseModFile(t, gomod), level, tc.toolchain)
			if !reflect.DeepEqual(ups, tc.wantUps) {
				t.Errorf("upgrades:\n got %+v\nwant %+v", ups, tc.wantUps)
			}

			if !reflect.DeepEqual(left, tc.wantLeft) {
				t.Errorf("unfixed:\n got %+v\nwant %+v", left, tc.wantLeft)
			}
		})
	}
}

func TestPlanLevels(t *testing.T) {
	t.Parallel()
	runPlanTests(t, []planTest{
		{
			name:     "symbol level ignores imported-only findings",
			findings: []*govulncheck.Finding{required(idA, lib, "v1.0.0"), imported(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
		},
		{
			name:     "package level counts imported findings",
			level:    govulncheck.ScanLevelPackage,
			findings: []*govulncheck.Finding{required(idA, lib, "v1.0.0"), imported(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
			wantUps:  []Upgrade{{lib, "v1.0.0", "v1.1.0", []string{idA}}},
		},
		{
			name:     "module level counts required findings, sorted by module",
			level:    govulncheck.ScanLevelModule,
			findings: []*govulncheck.Finding{required(idB, "example.com/zzz", "v0.1.0"), required(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0")), entry(idB, "example.com/zzz", span("0", "0.2.0"))},
			wantUps: []Upgrade{
				{lib, "v1.0.0", "v1.1.0", []string{idA}},
				{"example.com/zzz", "v0.1.0", "v0.2.0", []string{idB}},
			},
		},
		{
			name: "repeated findings make one upgrade",
			findings: []*govulncheck.Finding{
				required(idB, lib, "v1.0.0"), imported(idB, lib, "v1.0.0"), called(idB, lib, "v1.0.0"),
				called(idA, lib, "v1.0.0"), called(idA, lib, "v1.0.0"),
			},
			entries: []*osv.Entry{entry(idA, lib, span("0", "1.1.0")), entry(idB, lib, span("0", "1.1.0"))},
			wantUps: []Upgrade{{lib, "v1.0.0", "v1.1.0", []string{idA, idB}}},
		},
	})
}

func TestPlanTargets(t *testing.T) {
	t.Parallel()

	const (
		pseudoFrom = "v0.0.0-20210101000000-abcdefabcdef"
		pseudoTo   = "v0.0.0-20220906165146-f3363e06e74c"
	)

	runPlanTests(t, []planTest{
		{
			name:     "pseudo-version fix",
			findings: []*govulncheck.Finding{called(idA, lib, pseudoFrom)},
			entries:  []*osv.Entry{entry(idA, lib, span("0", pseudoTo[1:]))},
			wantUps:  []Upgrade{{lib, pseudoFrom, pseudoTo, []string{idA}}},
		},
		{
			name:     "incompatible fix keeps its suffix",
			findings: []*govulncheck.Finding{called(idA, lib, "v2.0.0+incompatible")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "2.1.0+incompatible"))},
			wantUps:  []Upgrade{{lib, "v2.0.0+incompatible", "v2.1.0+incompatible", []string{idA}}},
		},
		{
			name:     "ranges for other modules are ignored",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries: []*osv.Entry{{ID: idA, Affected: []osv.Affected{
				entry(idA, lib+"/v2", span("0", "1.0.5")).Affected[0],
				entry(idA, lib, span("0", "1.1.0")).Affected[0],
			}}},
			wantUps: []Upgrade{{lib, "v1.0.0", "v1.1.0", []string{idA}}},
		},
		{
			name:     "two advisories need the larger fix",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0"), called(idB, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0")), entry(idB, lib, span("0", "1.2.0"))},
			wantUps:  []Upgrade{{lib, "v1.0.0", "v1.2.0", []string{idA, idB}}},
		},
		{
			// v1.1.0 is affected by B and v1.2.0 by A's second range.
			name:     "affected candidates are skipped",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0"), called(idB, lib, "v1.0.0")},
			entries: []*osv.Entry{
				entry(idA, lib, span("0", "1.1.0"), span("1.1.1", "1.3.0")),
				entry(idB, lib, span("0", "1.2.0")),
			},
			wantUps: []Upgrade{{lib, "v1.0.0", "v1.3.0", []string{idA, idB}}},
		},
		{
			name:     "excluded candidate is skipped",
			gomod:    baseMod + "exclude example.com/lib v1.1.0\n",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"), span("1.5.0", "1.5.1"))},
			wantUps:  []Upgrade{{lib, "v1.0.0", "v1.5.1", []string{idA}}},
		},
	})
}

func TestPlanUnfixed(t *testing.T) {
	t.Parallel()

	const replaced = "replaced in go.mod; update the replace directive"

	runPlanTests(t, []planTest{
		{
			name:     "every fix excluded",
			gomod:    baseMod + "exclude example.com/lib v1.1.0\n",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
			wantLeft: []Unfixed{{lib, "v1.0.0", []string{idA}, "fixed in v1.1.0, which go.mod excludes"}},
		},
		{
			name:     "no fix",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", ""))},
			wantLeft: []Unfixed{{lib, "v1.0.0", []string{idA}, "no fixed version"}},
		},
		{
			name:     "advisory missing from the stream",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			wantLeft: []Unfixed{{lib, "v1.0.0", []string{idA}, "no fixed version"}},
		},
		{
			name:     "replaced module, same path",
			gomod:    baseMod + "replace example.com/lib => example.com/lib v1.0.0\n",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
			wantLeft: []Unfixed{{lib, "v1.0.0", []string{idA}, replaced}},
		},
		{
			name:     "replaced module, finding names the replacement",
			gomod:    baseMod + "replace example.com/orig => example.com/lib v1.0.0\n",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
			wantLeft: []Unfixed{{lib, "v1.0.0", []string{idA}, replaced}},
		},
		{
			name:     "main module",
			gomod:    "module example.com/lib\n",
			findings: []*govulncheck.Finding{called(idA, lib, "")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0"))},
			wantLeft: []Unfixed{{lib, "", []string{idA}, "the vulnerable code is in the main module"}},
		},
	})
}

func TestPlanStdlib(t *testing.T) {
	t.Parallel()

	const notAbove = "fixed in go1.26.2, which is not above the go.mod go and toolchain lines"

	runPlanTests(t, []planTest{
		{
			name:     "without -toolchain",
			findings: []*govulncheck.Finding{called(idA, std, "v1.26.0")},
			entries:  []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			wantLeft: []Unfixed{{
				std, "v1.26.0", []string{idA},
				"fixed in go1.26.2; rerun with -toolchain to raise the toolchain line",
			}},
		},
		{
			name:      "with -toolchain",
			toolchain: true,
			findings:  []*govulncheck.Finding{called(idA, std, "v1.26.0")},
			entries:   []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			wantUps:   []Upgrade{{std, "v1.26.0", "v1.26.2", []string{idA}}},
		},
		{
			name:      "prerelease fix is skipped",
			toolchain: true,
			findings:  []*govulncheck.Finding{called(idA, std, "v1.26.4")},
			entries:   []*osv.Entry{entry(idA, std, span("0", "1.27.0-rc.2"), span("1.27.0", "1.27.1"))},
			wantUps:   []Upgrade{{std, "v1.26.4", "v1.27.1", []string{idA}}},
		},
		{
			name:      "fix not above the toolchain line",
			toolchain: true,
			gomod:     baseMod + "toolchain go1.26.5\n",
			findings:  []*govulncheck.Finding{called(idA, std, "v1.26.0")},
			entries:   []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			wantLeft:  []Unfixed{{std, "v1.26.0", []string{idA}, notAbove}},
		},
		{
			name:      "fix not above the go line",
			toolchain: true,
			gomod:     "module example.com/main\n\ngo 1.26.2\n",
			findings:  []*govulncheck.Finding{called(idA, std, "v1.26.0")},
			entries:   []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			wantLeft:  []Unfixed{{std, "v1.26.0", []string{idA}, notAbove}},
		},
	})
}

func TestUpgradeArg(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		u    Upgrade
		want string
	}{
		{Upgrade{Module: lib, To: "v1.1.0"}, "example.com/lib@v1.1.0"},
		{Upgrade{Module: std, To: "v1.26.2"}, "toolchain@go1.26.2"},
		{Upgrade{Module: std, To: "v1.27.0"}, "toolchain@go1.27.0"},
	} {
		if got := tc.u.arg(); got != tc.want {
			t.Errorf("%+v.arg() = %q, want %q", tc.u, got, tc.want)
		}
	}
}
