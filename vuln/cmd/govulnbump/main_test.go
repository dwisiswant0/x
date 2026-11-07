package main

import (
	"bytes"
	"context"
	"fmt"
	"io"
	"path/filepath"
	"strings"
	"testing"

	"go.dw1.io/x/vuln/internal/bump"
)

func TestFlags(t *testing.T) {
	t.Parallel()

	for _, tc := range []struct {
		args []string
		want int
	}{
		{[]string{"-h"}, exitOK},
		{[]string{"-nosuchflag"}, exitUsage},
		// bump.Run rejects these before it runs the go command.
		{[]string{"-scan=bogus"}, exitUsage},
		{[]string{"-scan=module", "./..."}, exitUsage},
		{[]string{"all"}, exitUsage},
	} {
		if code, _ := runCommand(t, tc.args...); code != tc.want {
			t.Errorf("govulnbump %s: exit %d, want %d", strings.Join(tc.args, " "), code, tc.want)
		}
	}
}

func TestExitCode(t *testing.T) {
	t.Parallel()

	unfixed := []bump.Unfixed{{Module: "example.com/lib", Reason: "no fixed version"}}

	for _, tc := range []struct {
		res  *bump.Result
		err  error
		want int
	}{
		{&bump.Result{}, nil, exitOK},
		{&bump.Result{Upgrades: []bump.Upgrade{{Module: "example.com/lib"}}}, nil, exitOK},
		{&bump.Result{Unfixed: unfixed}, nil, exitVulns},
		{&bump.Result{DryRun: true, Upgrades: []bump.Upgrade{{Module: "example.com/lib"}}}, nil, exitVulns},
		{nil, io.ErrClosedPipe, exitError},
		{nil, fmt.Errorf("bad pattern: %w", bump.ErrUsage), exitUsage},
	} {
		if got := exitCode(tc.res, tc.err); got != tc.want {
			t.Errorf("exitCode(%+v, %v) = %d, want %d", tc.res, tc.err, got, tc.want)
		}
	}
}

func TestChdir(t *testing.T) {
	t.Setenv("GOWORK", "off")
	// Cleanups run last-in, first-out, so calling t.TempDir before t.Chdir
	// restores the working directory before dir is removed. Windows can't
	// remove a process's working directory.
	dir := t.TempDir()
	t.Chdir(".") // restore the working directory that -C changes

	if code, _ := runCommand(t, "-C", filepath.Join(dir, "missing")); code != exitError {
		t.Errorf("-C to a missing directory: exit %d, want %d", code, exitError)
	}
	// The test runs inside this module, so "no go.mod" shows that -C
	// changed the directory before the go command ran.
	code, stderr := runCommand(t, "-n", "-C", dir)
	if code != exitError || !strings.Contains(stderr, "no go.mod") {
		t.Errorf("-C to a directory without go.mod: exit %d, want %d\nstderr:\n%s", code, exitError, stderr)
	}
}

func runCommand(t *testing.T, args ...string) (code int, stderr string) {
	t.Helper()

	var out, errOut bytes.Buffer

	code = run(context.Background(), args, &out, &errOut)

	return code, errOut.String()
}
