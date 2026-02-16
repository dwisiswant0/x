//go:build freebsd || linux

package ldd

import (
	"os"
	"path/filepath"
	"testing"
)

func pickDynamicExecutable(t *testing.T) string {
	t.Helper()

	candidates := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, exe)
	}
	candidates = append(candidates, "/bin/sh", "/usr/bin/env", "/bin/ls")

	for _, candidate := range candidates {
		interp, err := GetInterp(candidate)
		if err != nil {
			continue
		}
		if interp != "" {
			return candidate
		}
	}

	t.Skip("no dynamic executable candidate found on this host")
	return ""
}

func TestListSkipsBadEntries(t *testing.T) {
	good := pickDynamicExecutable(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	deps, err := List(missing, good)
	if err != nil {
		t.Fatalf("List returned unexpected error: %v", err)
	}

	if len(deps) == 0 {
		t.Fatalf("expected dependencies from %q, got empty result", good)
	}
}

func TestFListSkipsBadEntries(t *testing.T) {
	good := pickDynamicExecutable(t)
	missing := filepath.Join(t.TempDir(), "does-not-exist")

	deps, err := FList(missing, good)
	if err != nil {
		t.Fatalf("FList returned unexpected error: %v", err)
	}

	if len(deps) == 0 {
		t.Fatalf("expected followed dependencies from %q, got empty result", good)
	}
}
