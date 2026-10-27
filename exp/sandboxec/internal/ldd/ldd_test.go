//go:build freebsd || linux

package ldd

import (
	"fmt"
	"os"
	"path/filepath"
	"slices"
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

// The kernel fails to open a looping chain, or one of more than 40 links, with
// ELOOP, so neither may become a rule.
func TestFollowDropsUnopenableChains(t *testing.T) {
	dir := t.TempDir()

	a, b := filepath.Join(dir, "a"), filepath.Join(dir, "b")
	if err := os.Symlink(b, a); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	if err := os.Symlink(a, b); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	// A link into the loop is dropped with it.
	into := filepath.Join(dir, "into")
	if err := os.Symlink(a, into); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	got, err := follow(a, into)
	if err != nil {
		t.Fatalf("follow returned error for a symlink loop: %v", err)
	}
	if len(got) != 0 {
		t.Fatalf("follow(a, into) = %q, want none", got)
	}

	// l1 -> file, l2 -> l1, ..., l41 -> l40
	file := filepath.Join(dir, "file")
	if err := os.WriteFile(file, nil, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	target := file
	for i := 1; i <= maxSymlinks+1; i++ {
		link := filepath.Join(dir, fmt.Sprintf("l%d", i))
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink returned error: %v", err)
		}
		target = link
	}

	got, err = follow(filepath.Join(dir, fmt.Sprintf("l%d", maxSymlinks)))
	if err != nil {
		t.Fatalf("follow returned error for %d links: %v", maxSymlinks, err)
	}
	if len(got) != maxSymlinks+1 {
		t.Fatalf("follow of %d links returned %d paths, want %d", maxSymlinks, len(got), maxSymlinks+1)
	}

	got, err = follow(filepath.Join(dir, fmt.Sprintf("l%d", maxSymlinks+1)))
	if err != nil {
		t.Fatalf("follow returned error for %d links: %v", maxSymlinks+1, err)
	}
	if len(got) != 0 {
		t.Fatalf("follow of %d links = %q, want none", maxSymlinks+1, got)
	}

	// Following the shorter chain first must not let the longer one through.
	longest := filepath.Join(dir, fmt.Sprintf("l%d", maxSymlinks+1))
	shorter := filepath.Join(dir, fmt.Sprintf("l%d", maxSymlinks))
	for _, paths := range [][]string{{shorter, longest}, {longest, shorter}} {
		got, err := follow(paths...)
		if err != nil {
			t.Fatalf("follow(%q) returned error: %v", paths, err)
		}
		if len(got) != maxSymlinks+1 || slices.Contains(got, longest) {
			t.Fatalf("follow(%q) returned %d paths (with %q: %v), want %d without it", paths, len(got), longest, slices.Contains(got, longest), maxSymlinks+1)
		}
	}
}

// A cached dependency list is stale once the loader's cache or environment
// changes, as after a library moves and ldconfig runs.
func TestDepCacheKeyTracksLoaderState(t *testing.T) {
	dir := t.TempDir()

	file := filepath.Join(dir, "bin")
	if err := os.WriteFile(file, []byte("bin"), 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	loaderCache := filepath.Join(dir, "ld.so.cache")
	if err := os.WriteFile(loaderCache, []byte("v1"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	preload := filepath.Join(dir, "ld.so.preload")
	oldLdSoCache, oldLdSoPreload := ldSoCache, ldSoPreload
	ldSoCache, ldSoPreload = loaderCache, preload
	t.Cleanup(func() {
		ldSoCache, ldSoPreload = oldLdSoCache, oldLdSoPreload
	})
	t.Setenv("LD_LIBRARY_PATH", "")
	t.Setenv("LD_PRELOAD", "")
	t.Setenv("GLIBC_TUNABLES", "")

	key := func() string {
		t.Helper()

		k, ok := depCacheKey(file)
		if !ok {
			t.Fatalf("depCacheKey(%q) returned no key", file)
		}

		return k
	}

	prev := key()
	if again := key(); again != prev {
		t.Fatalf("depCacheKey changed without a change: %q, then %q", prev, again)
	}

	for _, change := range []struct {
		name  string
		apply func() error
	}{
		{name: "ld.so.cache", apply: func() error { return os.WriteFile(loaderCache, []byte("v2 longer"), 0o644) }},
		{name: "LD_LIBRARY_PATH", apply: func() error { return os.Setenv("LD_LIBRARY_PATH", dir) }},
		{name: "LD_PRELOAD", apply: func() error { return os.Setenv("LD_PRELOAD", file) }},
		{name: "ld.so.preload", apply: func() error { return os.WriteFile(preload, []byte(file), 0o644) }},
		{name: "GLIBC_TUNABLES", apply: func() error { return os.Setenv("GLIBC_TUNABLES", "glibc.cpu.hwcaps=-AVX2") }},
	} {
		if err := change.apply(); err != nil {
			t.Fatalf("changing %s: %v", change.name, err)
		}

		next := key()
		if next == prev {
			t.Errorf("depCacheKey did not change with %s", change.name)
		}
		prev = next
	}
}

// A cached entry that names a library that no longer exists is looked up
// again rather than served.
func TestListRefreshesEntryWithMissingLibrary(t *testing.T) {
	exe := pickDynamicExecutable(t)

	interp, err := GetInterp(exe)
	if err != nil {
		t.Fatalf("GetInterp returned error: %v", err)
	}
	key, ok := depCacheKey(exe)
	if !ok {
		t.Fatalf("depCacheKey(%q) returned no key", exe)
	}

	missing := filepath.Join(t.TempDir(), "libmoved.so.1")
	getDepCache().Set(key, depCacheEntry{Interp: interp, SONames: []string{missing}})

	got, err := List(exe)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	for _, path := range got {
		if path == missing {
			t.Fatalf("List(%q) served the cached missing library %q", exe, missing)
		}
	}
	if len(got) == 0 {
		t.Fatalf("List(%q) returned no libraries", exe)
	}
}
