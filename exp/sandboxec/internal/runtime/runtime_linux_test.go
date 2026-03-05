// nolint
//go:build linux
// +build linux

package runtime

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
)

func TestPATHToSOFiles(t *testing.T) {
	dirs := GetPATHDirs()
	if len(dirs) == 0 {
		return
	}

	soFiles, err := GetLinkersFilesFromDirs(dirs...)
	if err != nil {
		t.Fatalf("GetLinkersFilesFromDirs failed: %v", err)
	}

	t.Logf("discovered %d unique shared-library paths", len(soFiles))
}

func TestGetLinkersFiles(t *testing.T) {
	t.Run("returns dependencies for dynamic executable", func(t *testing.T) {
		candidates := []string{"/bin/sh", "/usr/bin/env", "/bin/ls"}

		var target string
		for _, candidate := range candidates {
			if _, err := os.Stat(candidate); err == nil {
				target = candidate
				break
			}
		}

		if target == "" {
			t.Skip("no executable candidate found on this host")
		}

		deps, err := GetLinkersFiles(target)
		if err != nil {
			t.Fatalf("GetLinkersFiles returned error: %v", err)
		}

		if len(deps) == 0 {
			t.Fatalf("expected at least one dependency for %q", target)
		}
	})

	t.Run("returns empty for empty input", func(t *testing.T) {
		deps, err := GetLinkersFiles("")
		if err != nil {
			t.Fatalf("GetLinkersFiles returned error: %v", err)
		}
		if len(deps) != 0 {
			t.Fatalf("expected empty dependencies, got: %#v", deps)
		}
	})
}

func TestGetLinkersFilesFromDirs(t *testing.T) {
	t.Run("returns dependencies from executable files in provided dirs", func(t *testing.T) {
		dir := t.TempDir()

		targetCandidates := []string{"/bin/sh", "/usr/bin/env", "/bin/ls"}

		var src string
		for _, candidate := range targetCandidates {
			if _, err := os.Stat(candidate); err == nil {
				src = candidate
				break
			}
		}

		if src == "" {
			t.Skip("no executable candidate found on this host")
		}

		symlinkA := filepath.Join(dir, "tool-a")
		symlinkB := filepath.Join(dir, "tool-b")
		if err := os.Symlink(src, symlinkA); err != nil {
			t.Fatalf("create symlinkA: %v", err)
		}
		if err := os.Symlink(src, symlinkB); err != nil {
			t.Fatalf("create symlinkB: %v", err)
		}

		nonExec := filepath.Join(dir, "README.txt")
		if err := os.WriteFile(nonExec, []byte("hello"), 0o644); err != nil {
			t.Fatalf("write nonExec: %v", err)
		}

		deps, err := GetLinkersFilesFromDirs(dir)
		if err != nil {
			t.Fatalf("GetLinkersFilesFromDirs returned error: %v", err)
		}

		if len(deps) == 0 {
			t.Fatalf("expected at least one dependency from dir %q", dir)
		}
	})

	t.Run("returns empty when directories are unreadable or missing", func(t *testing.T) {
		deps, err := GetLinkersFilesFromDirs(filepath.Join(t.TempDir(), "missing"))
		if err != nil {
			t.Fatalf("GetLinkersFilesFromDirs returned error: %v", err)
		}
		if len(deps) != 0 {
			t.Fatalf("expected empty dependencies, got: %#v", deps)
		}
	})
}

func TestGetPATHDirs(t *testing.T) {
	t.Run("returns empty slice when PATH is unset", func(t *testing.T) {
		t.Setenv("PATH", "")

		dirs := GetPATHDirs()
		if len(dirs) != 0 {
			t.Fatalf("expected empty slice, got: %#v", dirs)
		}
	})

	t.Run("splits PATH by colon", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()
		t.Setenv("PATH", dirA+":"+dirB)

		got := GetPATHDirs()
		want := []string{dirA, dirB}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected PATH dirs: got %#v, want %#v", got, want)
		}
	})

	t.Run("includes resolved executable symlink target directory", func(t *testing.T) {
		binDir := t.TempDir()
		targetDir := t.TempDir()
		targetExe := filepath.Join(targetDir, "tool-bin")

		if err := os.WriteFile(targetExe, []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
			t.Fatalf("write target exe: %v", err)
		}

		linkPath := filepath.Join(binDir, "tool")
		if err := os.Symlink(targetExe, linkPath); err != nil {
			t.Fatalf("create symlink: %v", err)
		}

		t.Setenv("PATH", binDir)

		got := GetPATHDirs()
		want := []string{binDir, targetDir}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected PATH dirs: got %#v, want %#v", got, want)
		}
	})
}

func TestGetLinkerDirs(t *testing.T) {
	t.Run("includes LD_LIBRARY_PATH entries in order without duplicates", func(t *testing.T) {
		dirA := t.TempDir()
		dirB := t.TempDir()
		nonExistent := dirA + "/does-not-exist"

		t.Setenv("LD_LIBRARY_PATH", dirA+":"+dirB+":"+dirA+":"+nonExistent)

		dirs, err := GetLinkerDirs()
		if err != nil {
			t.Fatalf("GetLinkerDirs returned error: %v", err)
		}

		idxA := -1
		idxB := -1
		for i, d := range dirs {
			if d == dirA && idxA == -1 {
				idxA = i
			}
			if d == dirB && idxB == -1 {
				idxB = i
			}
			if d == nonExistent {
				t.Fatalf("unexpected non-existent LD_LIBRARY_PATH dir in result: %q", d)
			}
		}

		if idxA == -1 || idxB == -1 {
			t.Fatalf("expected LD_LIBRARY_PATH dirs to be included: got %#v", dirs)
		}

		if idxA >= idxB {
			t.Fatalf("expected LD_LIBRARY_PATH order to be preserved, got idxA=%d idxB=%d", idxA, idxB)
		}

		countA := 0
		for _, d := range dirs {
			if d == dirA {
				countA++
			}
		}

		if countA != 1 {
			t.Fatalf("expected deduplicated dir %q once, got %d occurrences", dirA, countA)
		}
	})

	dirs, err := GetLinkerDirs()
	if err != nil {
		t.Fatalf("GetLinkerDirs returned error: %v", err)
	}

	if len(dirs) == 0 {
		t.Fatalf("expected at least one linker dir")
	}

	seen := make(map[string]struct{}, len(dirs))
	for i, d := range dirs {
		if d == "" {
			t.Fatalf("found empty linker dir at index %d", i)
		}
		if _, ok := seen[d]; ok {
			t.Fatalf("found duplicate linker dir %q", d)
		}
		seen[d] = struct{}{}
	}

	stdDefaults := []string{
		"/lib",
		"/usr/lib",
		"/lib64",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
	}

	expectedPrefix := make([]string, 0, len(stdDefaults))
	for _, d := range stdDefaults {
		if _, err := os.Stat(d); err == nil {
			expectedPrefix = append(expectedPrefix, d)
		}
	}

	if len(dirs) < len(expectedPrefix) {
		t.Fatalf("insufficient dirs length: got %d, want at least %d", len(dirs), len(expectedPrefix))
	}

	for i, want := range expectedPrefix {
		if dirs[i] != want {
			t.Fatalf("unexpected default linker dir order at index %d: got %q, want %q", i, dirs[i], want)
		}
	}
}
