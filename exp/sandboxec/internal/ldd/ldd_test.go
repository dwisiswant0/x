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

func TestFollowSkipsMissingPaths(t *testing.T) {
	dir := t.TempDir()
	missing := filepath.Join(dir, "missing")
	dangling := filepath.Join(dir, "dangling")
	if err := os.Symlink(missing, dangling); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	// A link to the dangling link ends at the same missing file.
	hop := filepath.Join(dir, "hop")
	if err := os.Symlink(dangling, hop); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	got, err := follow(hop, dangling)
	if err != nil {
		t.Fatalf("follow returned error for a dangling symlink: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("follow(hop, dangling) = %q, want none", got)
	}

	got, err = follow(missing)
	if err != nil {
		t.Fatalf("follow returned error for a missing path: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("follow(missing) = %q, want none", got)
	}
}

func TestParseinterpLine(t *testing.T) {
	tests := []struct {
		line string
		want string
		ok   bool
	}{
		{line: "\tlibc.so.6 => /lib/x86_64-linux-gnu/libc.so.6 (0x00007f0000000000)", want: "/lib/x86_64-linux-gnu/libc.so.6", ok: true},
		{line: "\tlinux-vdso.so.1 => (0x00007ffe4972d000)"},
		{line: "\tlibfoo.so.1 => not found"},
		{line: "\t/lib64/ld-linux-x86-64.so.2 => /lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)"},
		{line: "\tnot a dynamic executable"},
	}

	for _, tt := range tests {
		got, ok := parseinterpLine(tt.line)
		if got != tt.want || ok != tt.ok {
			t.Errorf("parseinterpLine(%q) = %q, %v, want %q, %v", tt.line, got, ok, tt.want, tt.ok)
		}
	}
}
