package bump

import (
	"fmt"
	"go/version"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
	"golang.org/x/mod/semver"

	"go.dw1.io/x/vuln/internal/govulncheck"
	"go.dw1.io/x/vuln/internal/osv"
	isem "go.dw1.io/x/vuln/internal/semver"
)

// An Upgrade raises a module to a version that fixes its vulnerabilities.
// For the standard library, it raises the go.mod toolchain line instead.
type Upgrade struct {
	Module   string   // module path, or "stdlib"
	From, To string   // semantic versions with a "v" prefix
	OSVs     []string // IDs of the advisories it fixes, sorted
}

// arg returns the go get argument that makes the upgrade.
func (u Upgrade) arg() string {
	if u.Module == osv.GoStdModulePath {
		return "toolchain@" + isem.SemverToGoTag(u.To)
	}

	return u.Module + "@" + u.To
}

// Unfixed is a vulnerable module that Run does not upgrade.
type Unfixed struct {
	Module  string   // module path, or "stdlib"
	Version string   // semantic version with a "v" prefix
	OSVs    []string // IDs of the advisories that affect it, sorted
	Reason  string   // why it is not upgraded, such as "no fixed version"
}

// plan decides how to fix the vulnerabilities that res reports at level.
// mf is the main module's go.mod file. If bumpToolchain is set, plan fixes
// standard library vulnerabilities by raising the toolchain line.
//
// Only the advisories reported at level constrain an upgrade. Otherwise an
// unreachable advisory with no fix would block every upgrade of its module.
// The rescan after the upgrade catches advisories that the new version
// introduces.
func plan(res *scanResult, mf *modfile.File, level govulncheck.ScanLevel, bumpToolchain bool) ([]Upgrade, []Unfixed) {
	var (
		ups  []Upgrade
		left []Unfixed
	)

	for _, m := range vulnModules(res.findings, level) {
		var entries []*osv.Entry

		for _, id := range m.osvs {
			if e := res.osvs[id]; e != nil {
				entries = append(entries, e)
			}
		}

		to, reason := target(m, entries, mf, bumpToolchain)
		if reason != "" {
			left = append(left, Unfixed{m.path, m.version, m.osvs, reason})

			continue
		}

		ups = append(ups, Upgrade{m.path, m.version, to, m.osvs})
	}

	return ups, left
}

// vulnModule is a module with vulnerabilities at the selected scan level.
type vulnModule struct {
	path    string
	version string
	osvs    []string // advisory IDs, sorted
}

// vulnModules groups the findings at level by module, sorted by path.
// The same advisory and module repeat, because the scanner reports each
// advisory at every level up to the scan level, once per call path.
func vulnModules(findings []*govulncheck.Finding, level govulncheck.ScanLevel) []vulnModule {
	byPath := map[string]*vulnModule{}

	for _, f := range findings {
		if len(f.Trace) == 0 || !atLevel(f.Trace[0], level) {
			continue
		}

		fr := f.Trace[0]

		m := byPath[fr.Module]
		if m == nil {
			m = &vulnModule{path: fr.Module, version: fr.Version}
			byPath[fr.Module] = m
		}

		if !slices.Contains(m.osvs, f.OSV) {
			m.osvs = append(m.osvs, f.OSV)
		}
	}

	mods := make([]vulnModule, 0, len(byPath))

	for _, m := range byPath {
		slices.Sort(m.osvs)
		mods = append(mods, *m)
	}

	slices.SortFunc(mods, func(a, b vulnModule) int { return strings.Compare(a.path, b.path) })

	return mods
}

// atLevel reports whether a finding whose innermost frame is fr counts at
// level. It matches how govulncheck's text output counts findings: a called
// function at symbol level, an imported package at package level, and a
// required module at module level.
func atLevel(fr *govulncheck.Frame, level govulncheck.ScanLevel) bool {
	switch level {
	case govulncheck.ScanLevelSymbol:
		return fr.Function != ""
	case govulncheck.ScanLevelPackage:
		return fr.Package != ""
	}

	return true
}

// target returns the version to upgrade m to, given the advisories that
// affect it, or the reason not to upgrade it.
func target(m vulnModule, entries []*osv.Entry, mf *modfile.File, bumpToolchain bool) (to, reason string) {
	if reason := skipReason(mf, m.path); reason != "" {
		return "", reason
	}

	usable, allowed := versionFilters(mf, m.path)

	fix := lowestFix(m.path, m.version, entries, allowed)
	if fix == "" {
		return "", noFixReason(m.path, lowestFix(m.path, m.version, entries, usable))
	}

	if m.path == osv.GoStdModulePath && !bumpToolchain {
		return "", fmt.Sprintf("fixed in %s; rerun with -toolchain to raise the toolchain line", isem.SemverToGoTag(fix))
	}

	return fix, ""
}

// skipReason returns the reason not to upgrade the module path at all, or ""
// if there is none.
func skipReason(mf *modfile.File, path string) string {
	switch {
	case mf.Module != nil && path == mf.Module.Mod.Path:
		return "the vulnerable code is in the main module"
	case isReplaced(mf, path):
		// Findings name the replacement module, so go get would change the
		// wrong requirement.
		return "replaced in go.mod; update the replace directive"
	}

	return ""
}

// versionFilters returns two tests for fixed versions of the module path:
// usable accepts the versions that govulnbump can upgrade to, and allowed
// accepts the usable versions that go.mod also permits.
func versionFilters(mf *modfile.File, path string) (usable, allowed func(string) bool) {
	if path != osv.GoStdModulePath {
		usable = func(string) bool { return true }
		allowed = func(v string) bool { return !isExcluded(mf, path, v) }

		return usable, allowed
	}
	// Go toolchain names spell prereleases differently from SemverToGoTag,
	// for example go1.20rc1 and go1.20-rc1.
	usable = func(v string) bool { return semver.Prerelease(v) == "" }
	// go get toolchain@ treats the toolchain line like a module requirement,
	// so a lower version would downgrade it.
	allowed = func(v string) bool { return usable(v) && raisesToolchain(mf, isem.SemverToGoTag(v)) }

	return usable, allowed
}

// noFixReason explains why the module path has no allowed fixed version.
// blocked is its lowest usable fixed version, or "" if it has none.
func noFixReason(path, blocked string) string {
	switch {
	case blocked == "":
		return "no fixed version"
	case path == osv.GoStdModulePath:
		return fmt.Sprintf("fixed in %s, which is not above the go.mod go and toolchain lines",
			isem.SemverToGoTag(blocked))
	}

	return fmt.Sprintf("fixed in %s, which go.mod excludes", blocked)
}

// lowestFix returns the lowest version of the module path above current
// that keep accepts and that none of the entries affects, or "" if there is
// none. The candidates are the fixed versions that the entries list for path.
func lowestFix(path, current string, entries []*osv.Entry, keep func(string) bool) string {
	var (
		ranges [][]osv.Range
		fixes  []string
	)

	for _, e := range entries {
		for _, a := range e.Affected {
			// An advisory can also list related modules, such as other
			// major versions. The scanner ignores those, and so does this.
			if a.Module.Path != path {
				continue
			}

			ranges = append(ranges, a.Ranges)

			for _, v := range fixedVersions(a.Ranges) {
				if semver.Compare(current, v) < 0 && keep(v) {
					fixes = append(fixes, v)
				}
			}
		}
	}

	slices.SortFunc(fixes, semver.Compare)

	for _, v := range fixes {
		affected := slices.ContainsFunc(ranges, func(rs []osv.Range) bool { return isem.Affects(rs, v) })
		if !affected {
			return v
		}
	}

	return ""
}

// fixedVersions returns the fixed versions in the SEMVER ranges, with a "v"
// prefix.
func fixedVersions(ranges []osv.Range) []string {
	var vs []string

	for _, r := range ranges {
		if r.Type != osv.RangeTypeSemver {
			continue
		}

		for _, ev := range r.Events {
			if ev.Fixed != "" {
				// OSV versions have no "v" prefix. Don't canonicalize: that
				// would drop "+incompatible".
				vs = append(vs, "v"+strings.TrimPrefix(ev.Fixed, "v"))
			}
		}
	}

	return vs
}

func isReplaced(mf *modfile.File, path string) bool {
	for _, r := range mf.Replace {
		if r.Old.Path == path || r.New.Path == path {
			return true
		}
	}

	return false
}

func isExcluded(mf *modfile.File, path, v string) bool {
	for _, e := range mf.Exclude {
		if e.Mod.Path == path && e.Mod.Version == v {
			return true
		}
	}

	return false
}

// raisesToolchain reports whether the Go toolchain tag is newer than both
// the go and toolchain lines of mf.
func raisesToolchain(mf *modfile.File, tag string) bool {
	if mf.Go != nil && version.Compare(tag, "go"+mf.Go.Version) <= 0 {
		return false
	}

	if mf.Toolchain != nil && version.Compare(tag, mf.Toolchain.Name) <= 0 {
		return false
	}

	return true
}

// DisplayVersion returns version v of module as users know it: a Go release
// name such as go1.26.2 for the standard library, and v itself otherwise.
func DisplayVersion(module, v string) string {
	if module == osv.GoStdModulePath {
		return isem.SemverToGoTag(v)
	}

	return v
}
