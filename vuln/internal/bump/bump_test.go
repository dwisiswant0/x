package bump

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"slices"
	"strings"
	"testing"

	"golang.org/x/mod/module"
	modzip "golang.org/x/mod/zip"

	"go.dw1.io/x/vuln/internal/govulncheck"
)

func TestOptions(t *testing.T) {
	t.Parallel()

	// A literal such as "/abs/dir" has no volume name, so it isn't absolute
	// on Windows.
	dirs := []string{"./cmd/app", t.TempDir()}

	for _, tc := range []struct {
		opts         Options
		wantLevel    govulncheck.ScanLevel
		wantPatterns []string
		wantErr      bool
	}{
		{Options{}, govulncheck.ScanLevelSymbol, []string{"./..."}, false},
		{Options{Level: govulncheck.ScanLevelPackage, Patterns: dirs}, govulncheck.ScanLevelPackage, dirs, false},
		{Options{Level: govulncheck.ScanLevelModule}, govulncheck.ScanLevelModule, nil, false},
		{Options{Level: govulncheck.ScanLevelModule, Patterns: []string{"./..."}}, "", nil, true},
		{Options{Level: "bogus"}, "", nil, true},
		{Options{Patterns: []string{"all"}}, "", nil, true},
		{Options{Patterns: []string{"./...", "golang.org/x/net/http2"}}, "", nil, true},
	} {
		opts := tc.opts

		err := opts.normalize()
		if tc.wantErr {
			if !errors.Is(err, ErrUsage) {
				t.Errorf("%+v.normalize() = %v, want a usage error", tc.opts, err)
			}

			continue
		}

		if err != nil || opts.Level != tc.wantLevel || !slices.Equal(opts.Patterns, tc.wantPatterns) {
			t.Errorf("%+v.normalize() = %v, giving level %q and patterns %q; want nil, %q, %q",
				tc.opts, err, opts.Level, opts.Patterns, tc.wantLevel, tc.wantPatterns)
		}
	}
}

func TestGoGetArgs(t *testing.T) {
	t.Parallel()

	ups := []Upgrade{{Module: "example.com/lib", To: "v1.1.0"}, {Module: std, To: "v1.26.2"}}
	for _, tc := range []struct {
		opts Options
		want string
	}{
		{Options{Patterns: []string{"./..."}}, "get example.com/lib@v1.1.0 toolchain@go1.26.2 ./..."},
		{
			Options{Test: true, Tags: "a,b", Patterns: []string{"./cmd/app"}},
			"get -t -tags=a,b example.com/lib@v1.1.0 toolchain@go1.26.2 ./cmd/app",
		},
		{Options{}, "get example.com/lib@v1.1.0 toolchain@go1.26.2 ."},
	} {
		if got := strings.Join(goGetArgs(ups, &tc.opts), " "); got != tc.want {
			t.Errorf("goGetArgs(%+v) = %q, want %q", tc.opts, got, tc.want)
		}
	}
}

// summaryA is the summary of GO-0000-0001. Its details are one sentence,
// which Run uses as the summary.
const summaryA = "Bad in example.com/lib/vuln is vulnerable."

// upgradeA is the upgrade that fixes GO-0000-0001.
func upgradeA() Upgrade { return Upgrade{lib, "v1.0.0", "v1.1.0", []string{idA}} }

// depAdded is the go.mod change from example.com/lib v1.1.0, which adds a
// dependency.
func depAdded() []Change { return []Change{{"example.com/dep", "", "v1.0.0"}} }

func TestCalledVulnerabilityIsUpgraded(t *testing.T) {
	db := setup(t, "vuln.Bad()", "")

	res, errOut, err := runBump(t, Options{DB: db})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}
	// GO-0000-0002 affects v1.1.0, but main doesn't call it, so it doesn't
	// count at symbol level. Uncalled counts it.
	wantResult(t, res, &Result{
		Upgrades:  []Upgrade{upgradeA()},
		Changes:   depAdded(),
		Uncalled:  1,
		Summaries: map[string]string{idA: summaryA},
	})
	wantRequires(t, "example.com/lib v1.1.0")
	// v1.1.0 adds example.com/dep. The rescan loads its package, so go.sum
	// needs the module's hash, not just its go.mod hash.
	if sum := readFile(t, "go.sum"); !strings.Contains(sum, "example.com/dep v1.0.0 h1:") {
		t.Errorf("go.sum has no hash for example.com/dep v1.0.0:\n%s", sum)
	}

	if want := "govulnbump: scanning ./... (symbol level)\n"; !strings.HasPrefix(errOut, want) {
		t.Errorf("stderr does not start with %q:\n%s", want, errOut)
	}
}

func TestDryRun(t *testing.T) {
	db := setup(t, "vuln.Bad()", "")
	before := readFile(t, "go.mod")

	res, errOut, err := runBump(t, Options{DB: db, DryRun: true})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		DryRun:    true,
		Upgrades:  []Upgrade{upgradeA()},
		GoGet:     []string{"get", "example.com/lib@v1.1.0", "./..."},
		Summaries: map[string]string{idA: summaryA},
	})

	if after := readFile(t, "go.mod"); after != before {
		t.Errorf("DryRun changed go.mod:\n%s", after)
	}
}

func TestImportedVulnerability(t *testing.T) {
	db := setup(t, "vuln.Good()", "")
	before := readFile(t, "go.mod")

	// govulncheck reports only called vulnerabilities at symbol level.
	res, errOut, err := runBump(t, Options{DB: db})
	if err != nil {
		t.Fatalf("symbol level: Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{Uncalled: 1, Summaries: map[string]string{}})

	if after := readFile(t, "go.mod"); after != before {
		t.Fatalf("symbol level changed go.mod:\n%s", after)
	}

	// v1.1.0 fixes GO-0000-0001 but introduces GO-0000-0002, so the rescan
	// plans a second round. The result compares the start with the end, so
	// it reports v1.0.0 => v1.2.0 for GO-0000-0001 only.
	res, errOut, err = runBump(t, Options{DB: db, Level: govulncheck.ScanLevelPackage})
	if err != nil {
		t.Fatalf("package level: Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		Upgrades:  []Upgrade{{lib, "v1.0.0", "v1.2.0", []string{idA}}},
		Changes:   depAdded(),
		Summaries: map[string]string{idA: summaryA},
	})
	wantRequires(t, "example.com/lib v1.2.0")

	if n := strings.Count(errOut, "govulnbump: rescanning\n"); n != 2 {
		t.Errorf("Run rescanned %d times, want 2:\n%s", n, errOut)
	}
}

func TestModuleLevel(t *testing.T) {
	db := setup(t, "vuln.Good()", "")

	res, errOut, err := runBump(t, Options{DB: db, Level: govulncheck.ScanLevelModule})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		Upgrades:  []Upgrade{{lib, "v1.0.0", "v1.2.0", []string{idA}}},
		Changes:   depAdded(),
		Summaries: map[string]string{idA: summaryA},
	})
	wantRequires(t, "example.com/lib v1.2.0")

	if sum := readFile(t, "go.sum"); !strings.Contains(sum, "example.com/dep v1.0.0 h1:") {
		t.Errorf("go.sum has no hash for example.com/dep v1.0.0:\n%s", sum)
	}
}

func TestVendoredModule(t *testing.T) {
	db := setup(t, "vuln.Bad()", "")
	goCommand(t, "mod", "vendor")

	res, errOut, err := runBump(t, Options{DB: db})
	if err != nil || len(res.Upgrades) != 1 {
		t.Fatalf("Run = %+v, %v; want one upgrade\nstderr:\n%s", res, err, errOut)
	}

	if !strings.Contains(errOut, "govulnbump: running go mod vendor\n") {
		t.Errorf("stderr is missing go mod vendor:\n%s", errOut)
	}

	if mods := readFile(t, filepath.Join("vendor", "modules.txt")); !strings.Contains(mods, "# example.com/lib v1.1.0\n") {
		t.Errorf("vendor/modules.txt does not have example.com/lib v1.1.0:\n%s", mods)
	}
}

func TestReplacedModule(t *testing.T) {
	db := setup(t, "vuln.Bad()", "\nreplace example.com/lib => example.com/lib v1.0.0\n")
	before := readFile(t, "go.mod")

	res, errOut, err := runBump(t, Options{DB: db})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		Unfixed:   []Unfixed{{lib, "v1.0.0", []string{idA}, "replaced in go.mod; update the replace directive"}},
		Summaries: map[string]string{idA: summaryA},
	})

	if after := readFile(t, "go.mod"); after != before {
		t.Errorf("go.mod changed:\n%s", after)
	}
}

// TestUpgradeRaisesAnother checks a round in which one upgrade raises another
// module above that module's own fix. example.com/dep v0.2.0 fixes
// GO-0000-0003, but example.com/lib v1.1.0, which fixes GO-0000-0001,
// requires example.com/dep v1.0.0.
func TestUpgradeRaisesAnother(t *testing.T) {
	db := setupModule(t, "require (\n\texample.com/dep v0.1.0\n\texample.com/lib v1.0.0\n)\n",
		"import (\n\t\"example.com/dep\"\n\t\"example.com/lib/vuln\"\n)\n\nfunc main() {\n\tdep.Check()\n\tvuln.Bad()\n}\n")

	const idC = "GO-0000-0003"

	ups := []Upgrade{{"example.com/dep", "v0.1.0", "v1.0.0", []string{idC}}, upgradeA()}
	sums := map[string]string{idA: summaryA, idC: "Check in example.com/dep is vulnerable."}

	res, errOut, err := runBump(t, Options{DB: db, DryRun: true})
	if err != nil {
		t.Fatalf("DryRun: Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		DryRun:    true,
		Upgrades:  ups,
		GoGet:     []string{"get", "example.com/dep@v1.0.0", "example.com/lib@v1.1.0", "./..."},
		Summaries: sums,
	})

	res, errOut, err = runBump(t, Options{DB: db})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		Upgrades:  ups,
		Changes:   []Change{}, // the upgrades are the only go.mod changes
		Uncalled:  1,
		Summaries: sums,
	})
	wantRequires(t, "example.com/dep v1.0.0")
	wantRequires(t, "example.com/lib v1.1.0")
}

// TestUpgradeRaisesIndirect is like TestUpgradeRaisesAnother, but in a go
// 1.16 module that requires example.com/dep only indirectly. In such a
// module, go get drops an indirect requirement whose version it raises.
func TestUpgradeRaisesIndirect(t *testing.T) {
	db := setupModule(t, "require example.com/legacy v1.0.0\n",
		"import \"example.com/legacy\"\n\nfunc main() { legacy.Bad() }\n")

	writeFile(t, "go.mod", strings.Replace(readFile(t, "go.mod"), "go 1.26.0", "go 1.16", 1))
	wantRequires(t, "example.com/dep v0.1.0 // indirect")

	const idC, idD = "GO-0000-0003", "GO-0000-0004"

	ups := []Upgrade{
		{"example.com/dep", "v0.1.0", "v1.0.0", []string{idC}},
		{"example.com/legacy", "v1.0.0", "v1.1.0", []string{idD}},
	}
	sums := map[string]string{
		idC: "Check in example.com/dep is vulnerable.",
		idD: "Bad in example.com/legacy is vulnerable.",
	}

	res, errOut, err := runBump(t, Options{DB: db, DryRun: true})
	if err != nil {
		t.Fatalf("DryRun: Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{
		DryRun:    true,
		Upgrades:  ups,
		GoGet:     []string{"get", "example.com/dep@v1.0.0", "example.com/legacy@v1.1.0", "./..."},
		Summaries: sums,
	})

	res, errOut, err = runBump(t, Options{DB: db})
	if err != nil {
		t.Fatalf("Run: %v\nstderr:\n%s", err, errOut)
	}

	wantResult(t, res, &Result{Upgrades: ups, Changes: []Change{}, Summaries: sums})
	wantRequires(t, "example.com/dep v1.0.0 // indirect")
	wantRequires(t, "example.com/legacy v1.1.0")
}

func TestGoGetFails(t *testing.T) {
	db := setup(t, "vuln.Bad()", "")
	// The module cache has v1.0.0, which the scan needs, but not v1.1.0.
	t.Setenv("GOPROXY", "off")

	// go get fails on the copy of go.mod that selects versions, and Run
	// shows what go get printed.
	res, errOut, err := runBump(t, Options{DB: db})
	if err == nil || errors.Is(err, ErrUsage) ||
		!strings.HasPrefix(err.Error(), "selecting versions for example.com/lib@v1.1.0: go get ") ||
		!strings.Contains(errOut, "GOPROXY=off") || res != nil {
		t.Fatalf("Run = %+v, %v; want nil and a go get failure with its output\nstderr:\n%s", res, err, errOut)
	}
}

// TestGoGetFailsAfterSelection checks a go get failure after version
// selection, whose go get writes only a copy of go.mod, succeeds.
func TestGoGetFailsAfterSelection(t *testing.T) {
	db := setup(t, "vuln.Bad()", "")

	if os.Geteuid() == 0 {
		t.Skip("root can write a read-only go.mod")
	}

	if err := os.Chmod("go.mod", 0o400); err != nil {
		t.Fatal(err)
	}
	// Windows can't remove a read-only file.
	t.Cleanup(func() { _ = os.Chmod("go.mod", 0o600) })

	res, errOut, err := runBump(t, Options{DB: db})
	if err == nil || !strings.HasPrefix(err.Error(), "go get example.com/lib@v1.1.0 ./...: ") || res != nil {
		t.Fatalf("Run = %+v, %v; want nil and a go get failure\nstderr:\n%s", res, err, errOut)
	}
}

// TestFailureAfterUpgrade checks that when a later round fails, Run still
// returns the upgrades that earlier rounds made.
func TestFailureAfterUpgrade(t *testing.T) {
	db := setup(t, "vuln.Good()", "")
	// Round 1 upgrades to v1.1.0 from the module cache. Round 2 needs
	// v1.2.0, which isn't there.
	goCommand(t, "mod", "download", "example.com/lib@v1.1.0", "example.com/dep@v1.0.0")
	t.Setenv("GOPROXY", "off")

	res, errOut, err := runBump(t, Options{DB: db, Level: govulncheck.ScanLevelPackage})
	if err == nil || !strings.HasPrefix(err.Error(), "selecting versions for example.com/lib@v1.2.0: go get ") {
		t.Fatalf("Run error = %v, want a go get failure in round 2\nstderr:\n%s", err, errOut)
	}

	// The failed round's advisory, GO-0000-0002, is in neither Upgrades nor
	// Unfixed, so it has no summary.
	wantResult(t, res, &Result{
		Upgrades:  []Upgrade{upgradeA()},
		Changes:   depAdded(),
		Summaries: map[string]string{idA: summaryA},
	})
	wantRequires(t, "example.com/lib v1.1.0")
}

func TestToolchainNeedsSwitching(t *testing.T) {
	setup(t, "vuln.Bad()", "") // sets GOTOOLCHAIN=local

	if _, _, err := runBump(t, Options{Toolchain: true}); !errors.Is(err, ErrUsage) {
		t.Fatalf("Run error = %v, want a usage error", err)
	}
}

func TestNoModule(t *testing.T) {
	t.Setenv("GOWORK", "off")
	t.Chdir(t.TempDir())

	if _, _, err := runBump(t, Options{DryRun: true}); !errors.Is(err, errNoModule) {
		t.Fatalf("Run error = %v, want %v", err, errNoModule)
	}
}

// setup creates a module in a temporary directory, changes to it, and
// returns the URL of the test vulnerability database. The module requires
// example.com/lib v1.0.0, and its main function runs body. gomodExtra is
// appended to go.mod.
//
// setup points the go command at a local module proxy and module cache, so
// the test needs no network.
func setup(t *testing.T, body, gomodExtra string) (db string) {
	t.Helper()

	return setupModule(t, "require example.com/lib v1.0.0\n"+gomodExtra,
		"import \"example.com/lib/vuln\"\n\nfunc main() { "+body+" }\n")
}

// setupModule is like setup, but go.mod has reqs after its go line, and
// main.go has src after its package clause.
func setupModule(t *testing.T, reqs, src string) (db string) {
	t.Helper()

	if testing.Short() {
		t.Skip("scans a module")
	}
	// Resolve testdata before changing to the new module.
	testdata, err := filepath.Abs("testdata")
	if err != nil {
		t.Fatal(err)
	}

	proxy := t.TempDir()
	buildProxy(t, filepath.Join(testdata, "proxy"), proxy)
	t.Setenv("GOPROXY", fileURL(proxy))
	t.Setenv("GOSUMDB", "off")
	t.Setenv("GOPRIVATE", "")
	t.Setenv("GONOPROXY", "")
	t.Setenv("GOTOOLCHAIN", "local")
	t.Setenv("GOWORK", "off")
	t.Setenv("GOMODCACHE", t.TempDir())
	// The module cache is read-only by default, which breaks TempDir cleanup.
	t.Setenv("GOFLAGS", "-modcacherw")

	dir := t.TempDir()
	writeFile(t, filepath.Join(dir, "go.mod"), "module example.com/main\n\ngo 1.26.0\n\n"+reqs)
	writeFile(t, filepath.Join(dir, "main.go"), "package main\n\n"+src)
	t.Chdir(dir)
	goCommand(t, "mod", "tidy")

	return fileURL(filepath.Join(testdata, "vulndb-v1"))
}

// buildProxy writes a file-based module proxy to dst from the module
// directories in src, which are named path@version.
func buildProxy(t *testing.T, src, dst string) {
	t.Helper()

	versions := map[string][]string{}
	walk := func(dir string, d fs.DirEntry, err error) error {
		if err != nil {
			t.Fatal(err)
		}

		if !d.IsDir() || !strings.Contains(d.Name(), "@") {
			return nil
		}

		rel, err := filepath.Rel(src, dir)
		if err != nil {
			t.Fatal(err)
		}

		path, v, _ := strings.Cut(filepath.ToSlash(rel), "@")

		at := filepath.Join(dst, filepath.FromSlash(path), "@v")
		if err := os.MkdirAll(at, 0o750); err != nil {
			t.Fatal(err)
		}

		writeFile(t, filepath.Join(at, v+".mod"), readFile(t, filepath.Join(dir, "go.mod")))
		writeFile(t, filepath.Join(at, v+".info"), fmt.Sprintf(`{"Version":%q,"Time":"2024-01-01T00:00:00Z"}`, v))

		var zip bytes.Buffer
		if err := modzip.CreateFromDir(&zip, module.Version{Path: path, Version: v}, dir); err != nil {
			t.Fatal(err)
		}

		writeFile(t, filepath.Join(at, v+".zip"), zip.String())
		versions[path] = append(versions[path], v)

		return filepath.SkipDir
	}

	if err := filepath.WalkDir(src, walk); err != nil {
		t.Fatal(err)
	}

	for path, vs := range versions {
		writeFile(t, filepath.Join(dst, filepath.FromSlash(path), "@v", "list"), strings.Join(vs, "\n")+"\n")
	}
}

func runBump(t *testing.T, opts Options) (res *Result, stderr string, err error) {
	t.Helper()

	var errOut bytes.Buffer

	res, err = Run(context.Background(), opts, &errOut)

	return res, errOut.String(), err
}

func wantResult(t *testing.T, got, want *Result) {
	t.Helper()

	if !reflect.DeepEqual(got, want) {
		t.Errorf("Run result:\n got %+v\nwant %+v", got, want)
	}
}

// wantRequires checks that go.mod in the working directory has the
// requirement req, such as "example.com/lib v1.1.0".
func wantRequires(t *testing.T, req string) {
	t.Helper()

	gomod := readFile(t, "go.mod")
	if !strings.Contains(gomod, "require "+req+"\n") && !strings.Contains(gomod, "\t"+req+"\n") {
		t.Errorf("go.mod does not require %s:\n%s", req, gomod)
	}
}

func goCommand(t *testing.T, args ...string) {
	t.Helper()

	out, err := exec.CommandContext(t.Context(), "go", args...).CombinedOutput() //nolint:gosec // fixed arguments
	if err != nil {
		t.Fatalf("go %s: %v\n%s", strings.Join(args, " "), err, out)
	}
}

// fileURL returns the file URL of the absolute path. A Windows path gets a
// slash before its drive letter, as in file:///C:/dir; in file://C:/dir,
// C: is the host, which the go command rejects.
func fileURL(path string) string {
	path = filepath.ToSlash(path)
	if !strings.HasPrefix(path, "/") {
		path = "/" + path
	}

	return "file://" + path
}

func readFile(t *testing.T, name string) string {
	t.Helper()

	data, err := os.ReadFile(name) //nolint:gosec // tests read their own fixtures
	if err != nil {
		t.Fatal(err)
	}

	return string(data)
}

func writeFile(t *testing.T, name, data string) {
	t.Helper()

	if err := os.WriteFile(name, []byte(data), 0o600); err != nil {
		t.Fatal(err)
	}
}
