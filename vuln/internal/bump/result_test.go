package bump

import (
	"reflect"
	"testing"

	"go.dw1.io/x/vuln/internal/govulncheck"
	"go.dw1.io/x/vuln/internal/osv"
)

const other = "example.com/other"

// scanOf returns a scan result with the findings and the advisories.
func scanOf(findings []*govulncheck.Finding, entries ...*osv.Entry) *scanResult {
	res := &scanResult{osvs: map[string]*osv.Entry{}, findings: findings}
	for _, e := range entries {
		res.osvs[e.ID] = e
	}

	return res
}

// withSummary sets the summary of e.
func withSummary(e *osv.Entry, s string) *osv.Entry {
	e.Summary = s

	return e
}

// TestAccumulatorRounds checks that the Result compares the module before
// the run with the module after it, across rounds.
func TestAccumulatorRounds(t *testing.T) {
	t.Parallel()

	initial := parseModFile(t, baseMod+"require (\n\texample.com/lib v1.0.0\n\texample.com/other v0.2.0\n)\n")
	final := parseModFile(t, baseMod+
		"require (\n\texample.com/dep v1.0.0\n\texample.com/lib v1.3.0\n\texample.com/other v0.3.0\n)\n")

	acc := newAccumulator(&Options{Level: govulncheck.ScanLevelPackage})

	// Round 1 fixes A. The new version of lib has B, and it raises other to
	// a version with C.
	res1 := scanOf(nil, withSummary(entry(idA, lib, span("0", "1.1.0")), "a"))
	ups1 := []Upgrade{{lib, "v1.0.0", "v1.1.0", []string{idA}}}
	acc.scanned(res1, initial, ups1, nil)
	acc.upgraded(res1, ups1)

	// Round 2 fixes B and C, which didn't affect the module at the start.
	res2 := scanOf(nil,
		withSummary(entry(idB, lib, span("1.1.0", "1.2.0")), "b"),
		withSummary(entry("GO-0000-0003", other, span("0.2.5", "0.3.0")), "c"))
	ups2 := []Upgrade{{lib, "v1.1.0", "v1.2.0", []string{idB}}, {other, "v0.2.5", "v0.3.0", []string{"GO-0000-0003"}}}
	acc.scanned(res2, initial, ups2, nil)
	acc.upgraded(res2, ups2)

	acc.scanned(scanOf(nil), final, nil, nil)

	want := &Result{
		// go.mod has lib v1.3.0, which another requirement raised it to.
		Upgrades:  []Upgrade{{lib, "v1.0.0", "v1.3.0", []string{idA}}},
		Changes:   []Change{{"example.com/dep", "", "v1.0.0"}, {other, "v0.2.0", "v0.3.0"}},
		Summaries: map[string]string{idA: "a"},
	}

	if got := acc.result(initial, final); !reflect.DeepEqual(got, want) {
		t.Errorf("result:\n got %+v\nwant %+v", got, want)
	}
}

func TestAccumulatorNotApplied(t *testing.T) {
	t.Parallel()

	mf := parseModFile(t, baseMod+"require example.com/lib v1.0.0\n")
	acc := newAccumulator(&Options{Level: govulncheck.ScanLevelSymbol})
	res := scanOf(nil, withSummary(entry(idA, lib, span("0", "1.1.0")), "a"))
	ups := []Upgrade{{lib, "v1.0.0", "v1.1.0", []string{idA}}}

	acc.scanned(res, mf, ups, nil)
	acc.notApplied(res, ups)

	want := &Result{
		Unfixed:   []Unfixed{{lib, "v1.0.0", []string{idA}, "go get did not upgrade it"}},
		Summaries: map[string]string{idA: "a"},
	}

	if got := acc.result(mf, mf); !reflect.DeepEqual(got, want) {
		t.Errorf("result:\n got %+v\nwant %+v", got, want)
	}

	if got := acc.partial(mf, mf); got != nil {
		t.Errorf("partial = %+v, want nil when nothing was upgraded", got)
	}
}

func TestUncalled(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		name      string
		toolchain bool
		findings  []*govulncheck.Finding
		entries   []*osv.Entry
		want      int
	}{
		{
			name:     "imported advisory with a fix",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0"), imported(idB, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0")), entry(idB, lib, span("0", "1.2.0"))},
			want:     1,
		},
		{
			// A package-level run couldn't upgrade lib at all.
			name:     "imported advisory without a fix",
			findings: []*govulncheck.Finding{called(idA, lib, "v1.0.0"), imported(idB, lib, "v1.0.0")},
			entries:  []*osv.Entry{entry(idA, lib, span("0", "1.1.0")), entry(idB, lib, span("0", ""))},
			want:     0,
		},
		{
			name:     "stdlib advisory without -toolchain",
			findings: []*govulncheck.Finding{imported(idA, std, "v1.26.0")},
			entries:  []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			want:     0,
		},
		{
			name:      "stdlib advisory with -toolchain",
			toolchain: true,
			findings:  []*govulncheck.Finding{imported(idA, std, "v1.26.0")},
			entries:   []*osv.Entry{entry(idA, std, span("0", "1.26.2"))},
			want:      1,
		},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			res := scanOf(tc.findings, tc.entries...)
			mf := parseModFile(t, baseMod)
			ups, left := plan(res, mf, govulncheck.ScanLevelSymbol, tc.toolchain)

			if got := uncalled(res, mf, tc.toolchain, ups, left); got != tc.want {
				t.Errorf("uncalled = %d, want %d", got, tc.want)
			}
		})
	}
}

func TestOtherChanges(t *testing.T) {
	t.Parallel()

	ups := []Upgrade{
		{lib, "v1.0.0", "v1.2.0", []string{idA}},
		{std, "v1.26.0", "v1.26.2", []string{idB}},
	}
	changes := []Change{
		{"go", "1.26.0", "1.26.1"},
		{"toolchain", "", "go1.26.2"},
		{"example.com/dep", "", "v1.0.0"},
		{lib, "v1.0.0", "v1.2.0"},
	}
	want := []Change{{"go", "1.26.0", "1.26.1"}, {"example.com/dep", "", "v1.0.0"}}

	if got := otherChanges(changes, ups); !reflect.DeepEqual(got, want) {
		t.Errorf("otherChanges:\n got %+v\nwant %+v", got, want)
	}
}

func TestSummary(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		entry osv.Entry
		want  string
	}{
		{osv.Entry{Summary: "Short summary", Details: "Long details. More."}, "Short summary"},
		{osv.Entry{Details: "First sentence\nwraps. Second sentence."}, "First sentence wraps."},
		{osv.Entry{Details: "Only sentence."}, "Only sentence."},
	} {
		if got := summary(&tc.entry); got != tc.want {
			t.Errorf("summary(%+v) = %q, want %q", tc.entry, got, tc.want)
		}
	}
}
