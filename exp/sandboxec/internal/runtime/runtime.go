// nolint
//go:build linux
// +build linux

package runtime

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"
)

// GetPATHDirs returns the entries from the PATH environment variable.
//
// It splits PATH using ':' and returns an empty slice when PATH is unset
// or empty.
func GetPATHDirs() []string {
	var dirs []string

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return dirs
	}

	for dir := range strings.SplitSeq(pathEnv, ":") {
		if _, err := os.Stat(dir); err == nil {
			dirs = appendUniq(dirs, dir)
		}
	}

	return dirs
}

// GetLinkerDirs returns dynamic linker search directories for the host.
//
// It starts with existing common system defaults, then appends directories
// defined in /etc/ld.so.conf (including nested include directives), while
// preserving order and removing duplicates.
func GetLinkerDirs() ([]string, error) {
	var dirs []string

	stdDefaults := []string{
		"/lib",
		"/usr/lib",
		"/lib64",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
	}

	for _, d := range stdDefaults {
		if _, err := os.Stat(d); err == nil {
			dirs = append(dirs, d)
		}
	}

	ldConfDirs, err := parseLdConf("/etc/ld.so.conf")
	if err != nil {
		return nil, err
	}

	dirs = appendUniq(dirs, ldConfDirs...)

	return dirs, nil
}

// parseLdConf reads an ld.so.conf-style file and returns linker directories.
//
// It ignores empty lines and comments, resolves include directives recursively,
// and deduplicates directory entries while preserving discovery order.
func parseLdConf(filename string) ([]string, error) {
	file, err := os.Open(filename)
	if err != nil {
		return nil, err
	}
	defer file.Close()

	var dirs []string
	scanner := bufio.NewScanner(file)

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())

		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}

		if after, ok := strings.CutPrefix(line, "include "); ok {
			pattern := strings.TrimSpace(after)

			matches, err := filepath.Glob(pattern)
			if err != nil {
				continue
			}

			for _, match := range matches {
				subDirs, err := parseLdConf(match)
				if err != nil {
					continue
				}

				for _, d := range subDirs {
					if _, err := os.Stat(d); err == nil {
						dirs = appendUniq(dirs, d)
					}
				}
			}

			continue
		}

		dirs = appendUniq(dirs, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dirs, nil
}

// appendUniq appends elems to slice while preserving order and skipping values
// that already exist in slice.
//
// NOTE(dwisiswant0): Might be separated into a utility package if needed.
func appendUniq[T comparable](slice []T, elems ...T) []T {
	seen := make(map[T]struct{}, len(slice)+len(elems))

	for _, v := range slice {
		seen[v] = struct{}{}
	}

	for _, v := range elems {
		if _, ok := seen[v]; !ok {
			seen[v] = struct{}{}
			slice = append(slice, v)
		}
	}

	return slice
}
