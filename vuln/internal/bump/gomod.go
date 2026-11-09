package bump

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"

	"go.dw1.io/x/vuln/internal/osv"
)

var (
	errNoModule  = errors.New("no go.mod file found; run govulnbump in a module or use -C")
	errWorkspace = errors.New("workspaces are not supported")
	errDropped   = errors.New("go get dropped the requirement")
)

// goEnv holds the go command settings that govulnbump depends on.
type goEnv struct {
	GOMOD       string `json:"GOMOD"`
	GOWORK      string `json:"GOWORK"`
	GOTOOLCHAIN string `json:"GOTOOLCHAIN"`
}

func readGoEnv(ctx context.Context) (*goEnv, error) {
	out, err := exec.CommandContext(ctx, "go", "env", "-json", "GOMOD", "GOWORK", "GOTOOLCHAIN").Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) && len(ee.Stderr) > 0 {
			return nil, fmt.Errorf("go env: %s: %w", bytes.TrimSpace(ee.Stderr), err)
		}

		return nil, fmt.Errorf("go env: %w", err)
	}

	var env goEnv
	if err := json.Unmarshal(out, &env); err != nil {
		return nil, fmt.Errorf("go env: %w", err)
	}

	return &env, nil
}

// check reports whether govulnbump can work on the module that env
// describes.
func (env *goEnv) check() error {
	if env.GOMOD == "" || env.GOMOD == os.DevNull {
		return errNoModule
	}

	if env.GOWORK != "" && env.GOWORK != "off" {
		return fmt.Errorf("%w (using %s); run with GOWORK=off", errWorkspace, env.GOWORK)
	}

	return nil
}

// switchesToolchains reports whether the GOTOOLCHAIN setting lets the go
// command switch to the toolchain that go.mod names.
func switchesToolchains(gotoolchain string) bool {
	return gotoolchain == "auto" || gotoolchain == "path" ||
		strings.HasSuffix(gotoolchain, "+auto") || strings.HasSuffix(gotoolchain, "+path")
}

func readModFile(path string) (*modfile.File, error) {
	data, err := os.ReadFile(path) //nolint:gosec // path is GOMOD from go env, not user input
	if err != nil {
		return nil, fmt.Errorf("reading go.mod: %w", err)
	}

	mf, err := modfile.Parse(path, data, nil)
	if err != nil {
		return nil, fmt.Errorf("parsing go.mod: %w", err)
	}

	return mf, nil
}

// hasVendor reports whether the module whose go.mod is at gomod vendors its
// dependencies.
func hasVendor(gomod string) bool {
	_, err := os.Stat(filepath.Join(filepath.Dir(gomod), "vendor", "modules.txt"))

	return err == nil
}

// runGo runs the go command with args, writing its output to w.
func runGo(ctx context.Context, w io.Writer, args ...string) error {
	// The arguments are flags that govulnbump sets itself (-t, and -tags=
	// and -modfile=, which carry their values in the same argument),
	// module@version pairs from the plan, whose versions are valid semver,
	// and directory patterns, which start with "." or are absolute paths. So
	// none becomes another flag.
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // see above
	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}

	return nil
}

// selectVersions raises the To of each module upgrade in ups to the version
// that go get selects when go.mod, at gomod, requires at least To. The
// selected version is higher if another upgrade requires a newer version.
// go get must select each module@version argument exactly, so with the lower
// To it would fail.
//
// selectVersions finds them by running the round's go get, without its
// module arguments, on a temporary copy of go.mod that requires each To: a
// requirement, unlike a go get argument, is a minimum. Running go get itself,
// rather than go list, also switches to a newer toolchain when a new version
// needs one.
func selectVersions(ctx context.Context, gomod string, ups []Upgrade, opts *Options, stderr io.Writer) error {
	mf, err := readModFile(gomod)
	if err != nil {
		return err
	}

	var (
		std     []Upgrade
		planned []string // the module@version arguments that the copy replaces
	)

	for _, u := range ups {
		if u.Module == osv.GoStdModulePath {
			std = append(std, u)

			continue
		}
		// Require it directly: below go 1.17, go get drops an indirect
		// requirement whose version it raises.
		if err := mf.DropRequire(u.Module); err != nil {
			return fmt.Errorf("selecting versions: %w", err)
		}

		mf.AddNewRequire(u.Module, u.To, false)
		planned = append(planned, u.arg())
	}

	if len(planned) == 0 {
		return nil
	}

	reqs, err := getOnCopy(ctx, mf, gomod, goGetArgs(std, opts), stderr)
	if err != nil {
		return fmt.Errorf("selecting versions for %s: %w", strings.Join(planned, " "), err)
	}

	for i, u := range ups {
		if u.Module == osv.GoStdModulePath {
			continue
		}

		v := reqs[u.Module]
		if v == "" {
			return fmt.Errorf("selecting versions: %w on %s", errDropped, u.Module)
		}

		ups[i].To = v
	}

	return nil
}

// getOnCopy runs the go command with getArgs, which start with "get", on a
// temporary copy of mf, which replaces the go.mod file at gomod. It returns
// the requirements in the copy afterward. It writes go get's output to stderr
// only if go get fails.
func getOnCopy(ctx context.Context, mf *modfile.File, gomod string, getArgs []string, stderr io.Writer,
) (map[string]string, error) {
	dir, err := os.MkdirTemp("", "govulnbump-")
	if err != nil {
		return nil, fmt.Errorf("copying go.mod: %w", err)
	}

	defer func() { _ = os.RemoveAll(dir) }()

	modCopy, err := writeModCopy(dir, mf, gomod)
	if err != nil {
		return nil, err
	}

	// Insert -modfile after "get".
	args := slices.Insert(getArgs, 1, "-modfile="+modCopy)

	var out bytes.Buffer
	if err := runGo(ctx, &out, args...); err != nil {
		_, _ = stderr.Write(out.Bytes())

		return nil, err
	}

	after, err := readModFile(modCopy)
	if err != nil {
		return nil, err
	}

	return requirements(after), nil
}

// copyPerm is the permission of the files that writeModCopy writes.
const copyPerm = 0o600

// writeModCopy writes mf, which replaces the go.mod file at gomod, to dir,
// and returns its path. It also copies the go.sum file beside gomod, because
// -modfile makes the go command use the go.sum file in dir, and without the
// copy it would verify every checksum again.
func writeModCopy(dir string, mf *modfile.File, gomod string) (string, error) {
	sumPath := filepath.Join(filepath.Dir(gomod), "go.sum")

	sum, err := os.ReadFile(sumPath) //nolint:gosec // gomod is GOMOD from go env, not user input
	if err != nil && !errors.Is(err, fs.ErrNotExist) {
		return "", fmt.Errorf("reading go.sum: %w", err)
	}

	data, err := mf.Format()
	if err != nil {
		return "", fmt.Errorf("formatting go.mod: %w", err)
	}

	modCopy := filepath.Join(dir, "go.mod")
	if err := os.WriteFile(modCopy, data, copyPerm); err != nil {
		return "", fmt.Errorf("copying go.mod: %w", err)
	}

	sumCopy := filepath.Join(dir, "go.sum")
	if err := os.WriteFile(sumCopy, sum, copyPerm); err != nil { //nolint:gosec // dir is from os.MkdirTemp
		return "", fmt.Errorf("copying go.sum: %w", err)
	}

	return modCopy, nil
}

// A Change is a go.mod line whose version changed: the go line, the
// toolchain line, or a requirement.
type Change struct {
	Name     string // "go", "toolchain", or a module path
	From, To string // "" if the line is absent
}

// modChanges returns the version changes from before to after: the go
// line, then the toolchain line, then requirements sorted by module path.
func modChanges(before, after *modfile.File) []Change {
	var cs []Change

	add := func(name, from, to string) {
		if from != to {
			cs = append(cs, Change{name, from, to})
		}
	}
	add("go", goLine(before), goLine(after))
	add("toolchain", toolchainLine(before), toolchainLine(after))

	fromReqs, toReqs := requirements(before), requirements(after)
	paths := make([]string, 0, len(fromReqs)+len(toReqs))

	for p := range fromReqs {
		paths = append(paths, p)
	}

	for p := range toReqs {
		if _, ok := fromReqs[p]; !ok {
			paths = append(paths, p)
		}
	}

	slices.Sort(paths)

	for _, p := range paths {
		add(p, fromReqs[p], toReqs[p])
	}

	return cs
}

func goLine(mf *modfile.File) string {
	if mf.Go == nil {
		return ""
	}

	return mf.Go.Version
}

func toolchainLine(mf *modfile.File) string {
	if mf.Toolchain == nil {
		return ""
	}

	return mf.Toolchain.Name
}

// requirements maps each required module path to its version.
func requirements(mf *modfile.File) map[string]string {
	reqs := make(map[string]string, len(mf.Require))
	for _, r := range mf.Require {
		reqs[r.Mod.Path] = r.Mod.Version
	}

	return reqs
}
