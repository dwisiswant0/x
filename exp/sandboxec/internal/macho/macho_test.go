// nolint
//go:build darwin
// +build darwin

package macho

import (
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
