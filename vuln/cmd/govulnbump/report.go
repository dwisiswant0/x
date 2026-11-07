package main

import (
	"fmt"
	"io"
	"strings"
	"text/tabwriter"

	"go.dw1.io/x/vuln/internal/bump"
)

// printReport writes the report of a run to w. If the run failed, res holds
// only the changes it made, and the report lists only those.
func printReport(w io.Writer, res *bump.Result, failed bool) error {
	p := &printer{w: w}

	if failed {
		p.upgrades(fmt.Sprintf("Upgraded %s before the error:", count(len(res.Upgrades), "module", "modules")), res)
		p.changes(res.Changes)

		return p.err
	}

	if len(res.Upgrades) > 0 {
		verb := "Fixed"
		if res.DryRun {
			verb = "Would fix"
		}

		p.upgrades(fmt.Sprintf("%s %s by upgrading %s:", verb,
			count(fixedCount(res), "vulnerability", "vulnerabilities"),
			count(len(res.Upgrades), "module", "modules")), res)
	}

	p.changes(res.Changes)

	if len(res.GoGet) > 0 {
		p.sectionf("To make these upgrades, run:")
		p.printf("  go %s\n", strings.Join(res.GoGet, " "))
	}

	p.unfixed(res)

	// Otherwise a run with nothing to do would print nothing. The report
	// doesn't claim that no vulnerabilities remain: the uncalled hint below
	// can name some.
	if len(res.Upgrades) == 0 && len(res.Unfixed) == 0 {
		p.sectionf("Nothing to upgrade.")
	}

	p.uncalled(res)

	return p.err
}

func (p *printer) upgrades(header string, res *bump.Result) {
	p.sectionf(header)

	for _, u := range res.Upgrades {
		p.printf("  %s %s => %s\n", u.Module,
			bump.DisplayVersion(u.Module, u.From), bump.DisplayVersion(u.Module, u.To))
		p.advisories(res, u.OSVs)
	}
}

func (p *printer) changes(changes []bump.Change) {
	if len(changes) == 0 {
		return
	}

	rows := make([]string, 0, len(changes))
	for _, c := range changes {
		rows = append(rows, changeRow(c))
	}

	p.sectionf("Also changed in go.mod:")
	p.table(rows)
}

// changeRow formats c as a table row.
func changeRow(c bump.Change) string {
	switch {
	case c.From == "":
		return c.Name + "\t" + c.To + " (added)"
	case c.To == "":
		return c.Name + "\t" + c.From + " (removed)"
	}

	return c.Name + "\t" + c.From + " => " + c.To
}

func (p *printer) unfixed(res *bump.Result) {
	if len(res.Unfixed) == 0 {
		return
	}

	p.sectionf("Not fixed:")

	for _, u := range res.Unfixed {
		name := u.Module
		if u.Version != "" {
			name += " " + bump.DisplayVersion(u.Module, u.Version)
		}

		p.printf("  %s: %s\n", name, u.Reason)
		p.advisories(res, u.OSVs)
	}
}

// uncalled points out the vulnerabilities in imported packages that the code
// doesn't call, which -scan=package would also fix. bump.Run counts them only
// at symbol level.
func (p *printer) uncalled(res *bump.Result) {
	if res.Uncalled == 0 {
		return
	}

	pronoun := "it"
	if res.Uncalled > 1 {
		pronoun = "them"
	}

	p.sectionf("Also found %s in packages you import, but your code doesn't appear to call %s.",
		count(res.Uncalled, "vulnerability", "vulnerabilities"), pronoun)
	p.printf("To fix %s too, run with -scan=package.\n", pronoun)
}

func (p *printer) advisories(res *bump.Result, ids []string) {
	for _, id := range ids {
		if s := res.Summaries[id]; s != "" {
			p.printf("    %s  %s\n", id, s)
		} else {
			p.printf("    %s\n", id)
		}
	}
}

// fixedCount returns the number of advisories that res's upgrades fix.
func fixedCount(res *bump.Result) int {
	ids := map[string]bool{}

	for _, u := range res.Upgrades {
		for _, id := range u.OSVs {
			ids[id] = true
		}
	}

	return len(ids)
}

func count(n int, one, many string) string {
	if n == 1 {
		return "1 " + one
	}

	return fmt.Sprintf("%d %s", n, many)
}

// A printer writes the report. It keeps the first write error, so that a
// failed write is checked once rather than after every line.
type printer struct {
	w       io.Writer
	err     error
	started bool // whether a section has been written
}

func (p *printer) printf(format string, args ...any) {
	if p.err == nil {
		_, p.err = fmt.Fprintf(p.w, format, args...)
	}
}

// sectionf starts a section with a header line, after a blank line that
// separates it from the previous section.
func (p *printer) sectionf(format string, args ...any) {
	if p.started {
		p.printf("\n")
	}

	p.started = true
	p.printf(format+"\n", args...)
}

// columnGap is the number of spaces between table columns.
const columnGap = 2

// table writes rows, whose cells are separated by tabs, as indented and
// aligned columns.
func (p *printer) table(rows []string) {
	if p.err != nil {
		return
	}

	tw := tabwriter.NewWriter(p.w, 0, 0, columnGap, ' ', 0)
	for _, row := range rows {
		_, p.err = fmt.Fprintf(tw, "  %s\n", row)
		if p.err != nil {
			return
		}
	}

	p.err = tw.Flush()
}
