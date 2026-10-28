// nolint
//go:build darwin
// +build darwin

package macho

import (
	"debug/macho"
	"encoding/binary"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"testing"
)

func TestResolveRPath(t *testing.T) {
	loaderDir := "/tmp/loader"
	execDir := "/tmp/executable"

	tests := []struct {
		name  string
		rpath string
		want  string
	}{
		{name: "absolute", rpath: "/usr/lib", want: "/usr/lib"},
		{name: "loader path", rpath: "@loader_path/Frameworks", want: "/tmp/loader/Frameworks"},
		{name: "executable path", rpath: "@executable_path/Frameworks", want: "/tmp/executable/Frameworks"},
		{name: "relative", rpath: "Frameworks", want: "/tmp/loader/Frameworks"},
		{name: "unknown token", rpath: "@unknown/path", want: ""},
		{name: "empty", rpath: "", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveRPath(tt.rpath, loaderDir, execDir)
			if got != tt.want {
				t.Fatalf("resolveRPath(%q) = %q, want %q", tt.rpath, got, tt.want)
			}
		})
	}
}

func TestResolveMachOLibraryPathBasic(t *testing.T) {
	loaderPath := "/tmp/loader/app"
	execDir := "/tmp/executable"
	rpaths := []string{"/tmp/rpaths"}

	tests := []struct {
		name string
		lib  string
		want string
	}{
		{name: "absolute", lib: "/usr/lib/libSystem.B.dylib", want: "/usr/lib/libSystem.B.dylib"},
		{name: "loader path", lib: "@loader_path/libX.dylib", want: "/tmp/loader/libX.dylib"},
		{name: "executable path", lib: "@executable_path/libY.dylib", want: "/tmp/executable/libY.dylib"},
		{name: "relative", lib: "libZ.dylib", want: "/tmp/loader/libZ.dylib"},
		{name: "unknown token", lib: "@unknown/libW.dylib", want: ""},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := resolveLibraryPath(tt.lib, loaderPath, execDir, rpaths)
			if got != tt.want {
				t.Fatalf("resolveLibraryPath(%q) = %q, want %q", tt.lib, got, tt.want)
			}
		})
	}
}

func TestResolveMachOLibraryPathRPathLookup(t *testing.T) {
	tempDir := t.TempDir()
	loaderDir := filepath.Join(tempDir, "loader")
	execDir := filepath.Join(tempDir, "exec")
	rpathDir := filepath.Join(tempDir, "rpath")

	if err := os.MkdirAll(loaderDir, 0o755); err != nil {
		t.Fatalf("mkdir loader dir: %v", err)
	}
	if err := os.MkdirAll(execDir, 0o755); err != nil {
		t.Fatalf("mkdir exec dir: %v", err)
	}
	if err := os.MkdirAll(rpathDir, 0o755); err != nil {
		t.Fatalf("mkdir rpath dir: %v", err)
	}

	libFile := filepath.Join(rpathDir, "libA.dylib")
	if err := os.WriteFile(libFile, []byte("test"), 0o644); err != nil {
		t.Fatalf("write test dylib: %v", err)
	}

	loaderPath := filepath.Join(loaderDir, "app")
	if err := os.WriteFile(loaderPath, []byte("bin"), 0o755); err != nil {
		t.Fatalf("write loader file: %v", err)
	}

	got := resolveLibraryPath("@rpath/libA.dylib", loaderPath, execDir, []string{rpathDir})
	if got != libFile {
		t.Fatalf("resolveLibraryPath(@rpath/...) = %q, want %q", got, libFile)
	}

	missing := resolveLibraryPath("@rpath/missing.dylib", loaderPath, execDir, []string{rpathDir})
	if missing != "" {
		t.Fatalf("expected empty result for missing @rpath target, got %q", missing)
	}
}

func TestGetDependenciesSkipsNonMachO(t *testing.T) {
	dir := t.TempDir()

	tests := []struct {
		name    string
		content []byte
	}{
		{name: "script", content: []byte("#!/bin/sh\nexit 0\n")},
		{name: "truncated", content: []byte{0xcf, 0xfa, 0xed, 0xfe}},
		{name: "empty", content: nil},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, tt.name)
			if err := os.WriteFile(file, tt.content, 0o755); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}

			// A repeated call returns the same, whether or not the first was
			// cached.
			for range 2 {
				deps, err := GetDependencies(file)
				if err != nil {
					t.Fatalf("GetDependencies returned error: %v", err)
				}
				if len(deps) != 0 {
					t.Fatalf("GetDependencies = %q, want none", deps)
				}
			}
		})
	}
}

func TestGetDependenciesUniversalBinary(t *testing.T) {
	const file = "/usr/bin/true"

	ff, err := macho.OpenFat(file)
	if err != nil {
		t.Skipf("%s is not a universal binary: %v", file, err)
	}
	_ = ff.Close()

	if _, err := GetDependencies(file); err != nil {
		t.Fatalf("GetDependencies returned error: %v", err)
	}

	// The dylibs of the shared cache may not exist on disk, so GetDependencies
	// can be empty here. The imports still show that the slice was read.
	libraries, _, _, err := readMachO(file, hostCPU())
	if err != nil {
		t.Fatalf("readMachO returned error: %v", err)
	}
	if len(libraries) == 0 {
		t.Fatalf("readMachO(%q) returned no imported libraries", file)
	}
}

// A dylib loads as the CPU of the image that loads it, which under Rosetta is
// not the host's, and as every CPU when no slice matched.
func TestReadMachOSliceCPU(t *testing.T) {
	const file = "/usr/bin/true"

	ff, err := macho.OpenFat(file)
	if err != nil {
		t.Skipf("%s is not a universal binary: %v", file, err)
	}
	cpus := make(map[macho.Cpu]bool)
	for _, arch := range ff.Arches {
		cpus[arch.Cpu] = true
	}
	_ = ff.Close()

	for _, cpu := range []macho.Cpu{macho.CpuAmd64, macho.CpuArm64, macho.CpuPpc, 0} {
		want := cpu
		if !cpus[cpu] {
			want = 0
		}

		_, _, libCPU, err := readMachO(file, cpu)
		if err != nil {
			t.Fatalf("readMachO(%q, %v) returned error: %v", file, cpu, err)
		}
		if libCPU != want {
			t.Errorf("readMachO(%q, %v) dylib CPU = %v, want %v", file, cpu, libCPU, want)
		}
	}
}

// Only a result that cannot change while the root stays the same is complete,
// and so cached.
func TestGetDepsComplete(t *testing.T) {
	dir := t.TempDir()

	script := filepath.Join(dir, "script")
	if err := os.WriteFile(script, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, complete := getDeps(script); !complete {
		t.Error("getDeps(script) is incomplete, want complete")
	}

	empty := filepath.Join(dir, "empty")
	if err := os.WriteFile(empty, nil, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, complete := getDeps(empty); !complete {
		t.Error("getDeps(empty) is incomplete, want complete")
	}

	// A file with a Mach-O magic number that fails to parse may still be
	// being written.
	truncated := filepath.Join(dir, "truncated")
	if err := os.WriteFile(truncated, []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if _, complete := getDeps(truncated); complete {
		t.Error("getDeps(truncated) is complete, want incomplete")
	}

	unreadable := filepath.Join(dir, "unreadable")
	if err := os.WriteFile(unreadable, []byte("#!/bin/sh\nexit 0\n"), 0o000); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if f, err := os.Open(unreadable); err == nil {
		_ = f.Close()
		t.Skip("running with privileges that ignore file modes")
	}
	if _, complete := getDeps(unreadable); complete {
		t.Error("getDeps(unreadable) is complete, want incomplete")
	}
}

// A file names its dylibs by path, so the file a path names may be any file,
// and it may change after its walk was cached.
func TestGetDependenciesSkipsFilesThatAreNotDylibs(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("no C compiler: %v", err)
	}

	dir := t.TempDir()
	lib := filepath.Join(dir, "libdep.dylib")
	main := filepath.Join(dir, "main")
	for name, src := range map[string]string{
		"dep.c":  "int dep(void) { return 1; }\n",
		"main.c": "int dep(void);\nint main(void) { return dep(); }\n",
	} {
		if err := os.WriteFile(filepath.Join(dir, name), []byte(src), 0o644); err != nil {
			t.Fatalf("WriteFile returned error: %v", err)
		}
	}
	for _, args := range [][]string{
		{"-dynamiclib", "-install_name", lib, "-o", lib, filepath.Join(dir, "dep.c")},
		{"-o", main, filepath.Join(dir, "main.c"), lib},
	} {
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Skipf("cc %q failed: %v\n%s", args, err, out)
		}
	}

	key, ok := depCacheKey(main)
	if !ok {
		t.Fatalf("depCacheKey(%q) returned no key", main)
	}
	cache := getDepCache()
	t.Cleanup(func() { cache.Delete(key) })

	dylib, err := os.ReadFile(lib)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	executable, err := os.ReadFile(main)
	if err != nil {
		t.Fatalf("ReadFile returned error: %v", err)
	}
	for _, tt := range []struct {
		name    string
		content []byte
	}{
		{name: "text", content: []byte("not a library\n")},
		{name: "executable", content: executable},
	} {
		t.Run(tt.name, func(t *testing.T) {
			if err := os.WriteFile(lib, dylib, 0o755); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}
			deps, err := GetDependencies(main)
			if err != nil {
				t.Fatalf("GetDependencies returned error: %v", err)
			}
			if !slices.Contains(deps, lib) {
				t.Fatalf("GetDependencies(%q) = %q, missing dylib %q", main, deps, lib)
			}
			if !cache.Has(key) {
				t.Fatalf("GetDependencies(%q) did not cache its walk", main)
			}

			if err := os.WriteFile(lib, tt.content, 0o755); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}

			// The first call is served from the cache, the second walks again.
			for _, walk := range []string{"cached", "fresh"} {
				deps, err := GetDependencies(main)
				if err != nil {
					t.Fatalf("GetDependencies returned error: %v", err)
				}
				if slices.Contains(deps, lib) {
					t.Errorf("%s GetDependencies(%q) = %q, includes %q, which is not a dylib", walk, main, deps, lib)
				}
				cache.Delete(key)
			}
		})
	}
}

func TestIsDylib(t *testing.T) {
	cc, err := exec.LookPath("cc")
	if err != nil {
		t.Skipf("no C compiler: %v", err)
	}

	dir := t.TempDir()
	src := filepath.Join(dir, "main.c")
	if err := os.WriteFile(src, []byte("int main(void) { return 0; }\n"), 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	build := func(name string, args ...string) []byte {
		t.Helper()

		file := filepath.Join(dir, name)
		args = append(args, "-o", file, src)
		if out, err := exec.Command(cc, args...).CombinedOutput(); err != nil {
			t.Skipf("cc %q failed: %v\n%s", args, err, out)
		}
		data, err := os.ReadFile(file)
		if err != nil {
			t.Fatalf("ReadFile returned error: %v", err)
		}

		return data
	}
	universal := []string{"-arch", "arm64", "-arch", "x86_64"}
	dylib := build("dylib", "-dynamiclib")
	executable := build("executable")

	oversized := fat(false, dylib)
	binary.BigEndian.PutUint32(oversized[4:], (4096-8)/20+1)

	tests := []struct {
		name string
		data []byte
		want bool
	}{
		{name: "dylib", data: dylib, want: true},
		{name: "universal dylib", data: build("universal dylib", append([]string{"-dynamiclib"}, universal...)...), want: true},
		{name: "64-bit universal dylib", data: fat(true, dylib), want: true},
		{name: "universal with a dylib image", data: fat(false, executable, dylib), want: true},
		{name: "executable", data: executable},
		{name: "universal executable", data: build("universal executable", universal...)},
		{name: "universal with more entries than dyld reads", data: oversized},
		{name: "text", data: []byte("not a library\n")},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			file := filepath.Join(dir, "check")
			if err := os.WriteFile(file, tt.data, 0o644); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}

			if got := isDylib(file); got != tt.want {
				t.Errorf("isDylib(%s) = %v, want %v", tt.name, got, tt.want)
			}
		})
	}
}

// fat returns a universal binary of images, each at a page boundary, with
// fat_arch entries, or fat_arch_64 ones if wide.
func fat(wide bool, images ...[]byte) []byte {
	magic, entrySize := uint32(macho.MagicFat), 20
	if wide {
		magic, entrySize = magicFat64, 32
	}

	out := binary.BigEndian.AppendUint32(nil, magic)
	out = binary.BigEndian.AppendUint32(out, uint32(len(images)))
	offset := 4096
	for _, image := range images {
		entry := make([]byte, entrySize)
		if wide {
			binary.BigEndian.PutUint64(entry[8:], uint64(offset))
		} else {
			binary.BigEndian.PutUint32(entry[8:], uint32(offset))
		}
		out = append(out, entry...)
		offset += (len(image) + 4095) / 4096 * 4096
	}
	for _, image := range images {
		out = append(out, make([]byte, (4096-len(out)%4096)%4096)...)
		out = append(out, image...)
	}

	return out
}
