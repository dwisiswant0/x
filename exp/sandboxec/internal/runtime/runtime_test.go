// nolint
//go:build linux
// +build linux

package runtime

import (
	"os"
	"reflect"
	"testing"
)

func TestGetPATHDirs(t *testing.T) {
	t.Run("returns empty slice when PATH is unset", func(t *testing.T) {
		t.Setenv("PATH", "")

		dirs := GetPATHDirs()
		if len(dirs) != 0 {
			t.Fatalf("expected empty slice, got: %#v", dirs)
		}
	})

	t.Run("splits PATH by colon", func(t *testing.T) {
		t.Setenv("PATH", "/usr/local/bin:/usr/bin:/bin")

		got := GetPATHDirs()
		want := []string{"/usr/local/bin", "/usr/bin", "/bin"}
		if !reflect.DeepEqual(got, want) {
			t.Fatalf("unexpected PATH dirs: got %#v, want %#v", got, want)
		}
	})
}

func TestGetLinkerDirs(t *testing.T) {
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
