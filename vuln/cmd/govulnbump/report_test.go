package main

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"strings"
	"testing"

	"go.dw1.io/x/vuln/internal/bump"
)

const (
	lib      = "example.com/lib"
	idA      = "GO-0000-0001"
	idB      = "GO-0000-0002"
	summaryA = "Bad is vulnerable."
)

// upgradeA is the upgrade that fixes GO-0000-0001.
func upgradeA() bump.Upgrade {
	return bump.Upgrade{Module: lib, From: "v1.0.0", To: "v1.1.0", OSVs: []string{idA}}
}

func depAdded() bump.Change { return bump.Change{Name: "example.com/dep", To: "v1.0.0"} }

type reportTest struct {
	name   string
	res    *bump.Result
	failed bool
	want   string
}

func runReportTests(t *testing.T, tests []reportTest) {
	t.Helper()

	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var out strings.Builder
			if err := printReport(&out, tc.res, tc.failed); err != nil {
				t.Fatal(err)
			}

			if got := out.String(); got != tc.want {
				t.Errorf("report:\n%s\nwant:\n%s", got, tc.want)
			}
		})
	}
}

func TestPrintReportUpgrades(t *testing.T) {
	t.Parallel()
	runReportTests(t, []reportTest{
		{
			name: "fixed",
			res: &bump.Result{
				Upgrades:  []bump.Upgrade{upgradeA()},
				Changes:   []bump.Change{{Name: "go", From: "1.26.0", To: "1.27.0"}, depAdded()},
				Uncalled:  1,
				Summaries: map[string]string{idA: summaryA},
			},
			want: `Fixed 1 vulnerability by upgrading 1 module:
  example.com/lib v1.0.0 => v1.1.0
    GO-0000-0001  Bad is vulnerable.

Also changed in go.mod:
  go               1.26.0 => 1.27.0
  example.com/dep  v1.0.0 (added)

Also found 1 vulnerability in packages you import, but your code doesn't appear to call it.
To fix it too, run with -scan=package.
`,
		},
		{
			name: "failed run",
			res: &bump.Result{
				Upgrades:  []bump.Upgrade{upgradeA()},
				Changes:   []bump.Change{depAdded()},
				Summaries: map[string]string{idA: summaryA},
			},
			failed: true,
			want: `Upgraded 1 module before the error:
  example.com/lib v1.0.0 => v1.1.0
    GO-0000-0001  Bad is vulnerable.

Also changed in go.mod:
  example.com/dep  v1.0.0 (added)
`,
		},
	})
}

func TestPrintReportUnfixed(t *testing.T) {
	t.Parallel()
	runReportTests(t, []reportTest{
		{
			name: "dry run with an unfixed vulnerability",
			res: &bump.Result{
				DryRun:   true,
				Upgrades: []bump.Upgrade{upgradeA()},
				GoGet:    []string{"get", "example.com/lib@v1.1.0", "./..."},
				Unfixed: []bump.Unfixed{{
					Module:  "stdlib",
					Version: "v1.26.0",
					OSVs:    []string{idB},
					Reason:  "fixed in go1.26.1; rerun with -toolchain to raise the toolchain line",
				}},
				Summaries: map[string]string{idA: summaryA},
			},
			want: `Would fix 1 vulnerability by upgrading 1 module:
  example.com/lib v1.0.0 => v1.1.0
    GO-0000-0001  Bad is vulnerable.

To make these upgrades, run:
  go get example.com/lib@v1.1.0 ./...

Not fixed:
  stdlib go1.26.0: fixed in go1.26.1; rerun with -toolchain to raise the toolchain line
    GO-0000-0002
`,
		},
		{
			name: "vulnerability in the main module",
			res: &bump.Result{
				Unfixed:   []bump.Unfixed{{Module: "example.com/main", OSVs: []string{idA}, Reason: "it is the main module"}},
				Summaries: map[string]string{},
			},
			want: "Not fixed:\n  example.com/main: it is the main module\n    GO-0000-0001\n",
		},
	})
}

func TestPrintReportNothingToUpgrade(t *testing.T) {
	t.Parallel()
	runReportTests(t, []reportTest{
		{
			name: "nothing found",
			res:  &bump.Result{},
			want: "Nothing to upgrade.\n",
		},
		{
			name: "dry run with nothing found",
			res:  &bump.Result{DryRun: true},
			want: "Nothing to upgrade.\n",
		},
		{
			name: "nothing called",
			res:  &bump.Result{Uncalled: 2},
			want: `Nothing to upgrade.

Also found 2 vulnerabilities in packages you import, but your code doesn't appear to call them.
To fix them too, run with -scan=package.
`,
		},
	})
}

func TestFinish(t *testing.T) {
	t.Parallel()

	updated := &bump.Result{Upgrades: []bump.Upgrade{upgradeA()}}
	unchanged := &bump.Result{}
	goGetErr := fmt.Errorf("go get example.com/lib@v1.2.0 ./...: %w", io.ErrUnexpectedEOF)
	updatedErr := "govulnbump: go.mod was updated, but writing the report failed: " + io.ErrClosedPipe.Error()

	for _, tc := range []struct {
		name       string
		stdout     io.Writer
		res        *bump.Result
		err        error
		want       int
		wantStdout string   // prefix
		wantStderr []string // lines
	}{
		{"report write fails after an update", &failingWriter{}, updated, nil,
			exitError, "", []string{updatedErr}},
		{"report write fails without an update", &failingWriter{}, unchanged, nil,
			exitError, "", []string{"govulnbump: writing report: " + io.ErrClosedPipe.Error()}},
		{"run fails after an update", &bytes.Buffer{}, updated, goGetErr,
			exitError, "Upgraded 1 module before the error:\n", []string{"govulnbump: " + goGetErr.Error()}},
		{"run and report write fail", &failingWriter{}, updated, goGetErr,
			exitError, "", []string{
				"govulnbump: " + goGetErr.Error(),
				updatedErr,
			}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Parallel()

			var stderr bytes.Buffer
			if got := finish(tc.stdout, &stderr, tc.res, tc.err); got != tc.want {
				t.Errorf("exit %d, want %d", got, tc.want)
			}

			if buf, ok := tc.stdout.(*bytes.Buffer); ok && !strings.HasPrefix(buf.String(), tc.wantStdout) {
				t.Errorf("stdout does not start with %q:\n%s", tc.wantStdout, buf)
			}

			if want := strings.Join(tc.wantStderr, "\n") + "\n"; stderr.String() != want {
				t.Errorf("stderr:\n%s\nwant:\n%s", stderr.String(), want)
			}
		})
	}
}

// failingWriter fails every write and counts the attempts.
type failingWriter struct{ writes int }

func (w *failingWriter) Write([]byte) (int, error) {
	w.writes++

	return 0, io.ErrClosedPipe
}

func TestPrinterKeepsFirstError(t *testing.T) {
	t.Parallel()

	w := &failingWriter{}
	p := &printer{w: w}
	p.printf("one\n")
	p.table([]string{"a\tb"})
	p.sectionf("two")

	if !errors.Is(p.err, io.ErrClosedPipe) || w.writes != 1 {
		t.Errorf("after a failed write: err = %v and %d writes, want %v and 1 write", p.err, w.writes, io.ErrClosedPipe)
	}
}
