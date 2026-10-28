//go:build freebsd || linux

package ldd

import (
	"bytes"
	"debug/elf"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

func candidateExecutables() []string {
	candidates := make([]string, 0, 4)
	if exe, err := os.Executable(); err == nil {
		candidates = append(candidates, exe)
	}

	return append(candidates, "/bin/sh", "/usr/bin/env", "/bin/ls")
}

func pickDynamicExecutable(t *testing.T) string {
	t.Helper()

	for _, candidate := range candidateExecutables() {
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
		{line: "\tlibfoo.so.1 => /opt/My App/lib/libfoo.so.1 (0x00007f0000000000)", want: "/opt/My App/lib/libfoo.so.1", ok: true},
		{line: "\tlibbar.so.1 => /opt/lib/libbar.so.1", want: "/opt/lib/libbar.so.1", ok: true},
		{line: "\tlinux-vdso.so.1 (0x00007ffe4972d000)"},
		{line: "\t/lib64/ld-linux-x86-64.so.2 (0x00007f0000000000)"},
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

// The kernel applies ".." in a link's target to the directory the link is in
// after resolving it, so a walk that joins the two as written can reach a
// different file.
func TestFollowKeepsOnlyPathsToTheSameFile(t *testing.T) {
	dir := t.TempDir()

	// dir/w/a -> dir/w/x/y, and dir/w/x/y/libq.so -> ../../lib/libq.so, which
	// the kernel opens as dir/w/lib/libq.so. Joined as written, it is
	// dir/lib/libq.so.
	w := filepath.Join(dir, "w")
	for _, d := range []string{filepath.Join(w, "x", "y"), filepath.Join(w, "lib"), filepath.Join(dir, "lib")} {
		if err := os.MkdirAll(d, 0o755); err != nil {
			t.Fatalf("MkdirAll returned error: %v", err)
		}
	}
	library, other := filepath.Join(w, "lib", "libq.so"), filepath.Join(dir, "lib", "libq.so")
	for _, file := range []string{library, other} {
		if err := os.WriteFile(file, []byte(file), 0o644); err != nil {
			t.Fatalf("WriteFile returned error: %v", err)
		}
	}
	if err := os.Symlink(filepath.Join(w, "x", "y"), filepath.Join(w, "a")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	if err := os.Symlink("../../lib/libq.so", filepath.Join(w, "x", "y", "libq.so")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	start := filepath.Join(w, "a", "libq.so")
	got, err := follow(start)
	if err != nil {
		t.Fatalf("follow returned error: %v", err)
	}
	if slices.Contains(got, other) {
		t.Errorf("follow(%q) = %q, includes %q, which it does not open", start, got, other)
	}
	if !slices.Contains(got, start) {
		t.Errorf("follow(%q) = %q, missing %q", start, got, start)
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

func TestListSkipsFilesThatAreNotLibraries(t *testing.T) {
	exe := pickDynamicExecutable(t)

	interp, err := GetInterp(exe)
	if err != nil {
		t.Fatalf("GetInterp returned error: %v", err)
	}
	libs, err := runinterp(interp, exe)
	if err != nil || len(libs) == 0 {
		t.Fatalf("runinterp(%q, %q) = %q, %v, want libraries", interp, exe, libs, err)
	}
	key, ok := depCacheKey(exe)
	if !ok {
		t.Fatalf("depCacheKey(%q) returned no key", exe)
	}

	// The loader's report names whatever the inspected files ask for, so
	// stand in for a report that names a file, a directory and a program,
	// none of which is a library. A program is commonly a position-independent
	// executable, which is an ELF shared object too.
	dir := t.TempDir()
	notLibraries := []string{filepath.Join(dir, "libnotes.so.1"), filepath.Join(dir, "libdir.so.1"), exe}
	if err := os.WriteFile(notLibraries[0], []byte("not a library\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.Mkdir(notLibraries[1], 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	cache := getDepCache()
	cache.Set(key, depCacheEntry{Interp: interp, SONames: append([]string{libs[0]}, notLibraries...)})
	t.Cleanup(func() { cache.Delete(key) })

	got, err := List(exe)
	if err != nil {
		t.Fatalf("List returned error: %v", err)
	}
	for _, path := range notLibraries {
		if slices.Contains(got, path) {
			t.Errorf("List(%q) = %q, includes %q, which is not a library", exe, got, path)
		}
	}
	if !slices.Contains(got, libs[0]) {
		t.Errorf("List(%q) = %q, missing library %q", exe, got, libs[0])
	}
}

// The loader finds the dynamic table through the program headers, so removing
// the section headers, as sstrip does, leaves a program a program and a
// library a library, while a shared object without a dynamic table is no
// library at all.
func TestIsLibraryReadsTheDynamicSegment(t *testing.T) {
	exe := pickPIE(t)

	interp, err := GetInterp(exe)
	if err != nil {
		t.Fatalf("GetInterp returned error: %v", err)
	}
	libs, err := runinterp(interp, exe)
	if err != nil || len(libs) == 0 {
		t.Fatalf("runinterp(%q, %q) = %q, %v, want libraries", interp, exe, libs, err)
	}

	dir := t.TempDir()
	tests := []struct {
		name string
		path string
		want bool
	}{
		{name: "program", path: exe},
		{name: "program without section headers", path: withoutSectionHeaders(t, exe, filepath.Join(dir, "program"))},
		{name: "library", path: libs[0], want: true},
		{name: "library without section headers", path: withoutSectionHeaders(t, libs[0], filepath.Join(dir, "library")), want: true},
		{name: "library without a dynamic segment", path: withoutDynamicSegment(t, libs[0], filepath.Join(dir, "nodynamic"))},
	}
	for _, tt := range tests {
		if got := isLibrary(tt.path); got != tt.want {
			t.Errorf("isLibrary(%s) = %v, want %v", tt.name, got, tt.want)
		}
	}
}

// pickPIE returns a dynamically linked executable whose section headers mark
// it as position-independent. The test binary is not one under -race.
func pickPIE(t *testing.T) string {
	t.Helper()

	for _, candidate := range candidateExecutables() {
		if interp, err := GetInterp(candidate); err != nil || interp == "" {
			continue
		}

		f, err := elf.Open(candidate)
		if err != nil {
			continue
		}
		flags, err := f.DynValue(elf.DT_FLAGS_1)
		_ = f.Close()
		if err == nil && slices.ContainsFunc(flags, func(flag uint64) bool { return elf.DynFlag1(flag)&elf.DF_1_PIE != 0 }) {
			return candidate
		}
	}

	t.Skip("no position-independent executable found on this host")
	return ""
}

// withoutSectionHeaders writes a copy of the ELF file at path to copyPath with
// its section header table removed, as sstrip does, and returns copyPath.
func withoutSectionHeaders(t *testing.T, path, copyPath string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}

	// Clear e_shoff, and e_shnum and e_shstrndx, which follow e_shentsize.
	shoff, shoffSize, shnum := 0x28, 8, 0x3c
	if elf.Class(data[elf.EI_CLASS]) == elf.ELFCLASS32 {
		shoff, shoffSize, shnum = 0x20, 4, 0x30
	}
	clear(data[shoff : shoff+shoffSize])
	clear(data[shnum : shnum+4])
	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	f, err := elf.Open(copyPath)
	if err != nil {
		t.Fatalf("elf.Open(%q) returned error: %v", copyPath, err)
	}
	defer func() {
		_ = f.Close()
	}()
	if len(f.Sections) != 0 {
		t.Fatalf("%s still has %d sections", copyPath, len(f.Sections))
	}

	return copyPath
}

// withoutDynamicSegment writes a copy of the ELF file at path to copyPath with
// its PT_DYNAMIC program header turned into PT_NULL, and returns copyPath.
func withoutDynamicSegment(t *testing.T, path, copyPath string) string {
	t.Helper()

	data, err := os.ReadFile(path)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(data))
	if err != nil {
		t.Fatalf("elf.NewFile returned error: %v", err)
	}

	// Find the program headers from e_phoff, e_phentsize and e_phnum.
	order := f.ByteOrder
	phoff, entsize, num := order.Uint64(data[0x20:]), int(order.Uint16(data[0x36:])), int(order.Uint16(data[0x38:]))
	if f.Class == elf.ELFCLASS32 {
		phoff, entsize, num = uint64(order.Uint32(data[0x1c:])), int(order.Uint16(data[0x2a:])), int(order.Uint16(data[0x2c:]))
	}
	found := false
	for i := range num {
		header := data[int(phoff)+i*entsize:]
		if elf.ProgType(order.Uint32(header)) == elf.PT_DYNAMIC {
			order.PutUint32(header, uint32(elf.PT_NULL))
			found = true
		}
	}
	if !found {
		t.Fatalf("%s has no PT_DYNAMIC program header", path)
	}

	if err := os.WriteFile(copyPath, data, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return copyPath
}
