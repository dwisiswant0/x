package bump

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"

	"golang.org/x/mod/modfile"
)

var (
	errNoModule  = errors.New("no go.mod file found; run govulnbump in a module or use -C")
	errWorkspace = errors.New("workspaces are not supported")
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
	// The arguments are flags that govulnbump sets itself (-t and -tags=,
	// which carries the user's list in the same argument), module@version
	// pairs from the plan, whose versions are valid semver, and directory
	// patterns, which start with "." or are absolute paths. So none becomes
	// another flag.
	cmd := exec.CommandContext(ctx, "go", args...) //nolint:gosec // see above
	cmd.Stdout = w
	cmd.Stderr = w

	if err := cmd.Run(); err != nil {
		return fmt.Errorf("go %s: %w", strings.Join(args, " "), err)
	}

	return nil
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
