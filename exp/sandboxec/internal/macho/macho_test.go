// nolint
//go:build darwin
// +build darwin

package macho

import (
	"debug/macho"
	"os"
	"path/filepath"
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
