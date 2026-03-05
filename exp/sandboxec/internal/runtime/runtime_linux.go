// nolint
//go:build linux
// +build linux

package runtime

import (
	"bufio"
	"os"
	"path/filepath"
	"strings"

	"go.dw1.io/x/exp/sandboxec/internal/ldd"
)

// GetLinkerDirs returns dynamic linker search directories for the host.
//
// It starts with existing common system defaults, then appends directories
// from LD_LIBRARY_PATH and /etc/ld.so.conf (including nested include
// directives), while preserving discovery order and removing duplicates.
func GetLinkerDirs() ([]string, error) {
	var dirs []string
	seen := make(map[string]struct{})

	stdDefaults := []string{
		"/lib",
		"/usr/lib",
		"/lib64",
		"/usr/lib64",
		"/lib/x86_64-linux-gnu",
		"/usr/lib/x86_64-linux-gnu",
	}

	for _, d := range stdDefaults {
		dirs = appendExistingDirUniq(dirs, seen, d)
	}

	for _, d := range splitEnvDirs("LD_LIBRARY_PATH") {
		dirs = appendExistingDirUniq(dirs, seen, d)
	}

	ldConfDirs, err := parseLdConf("/etc/ld.so.conf")
	if err != nil {
		return nil, err
	}

	dirs = appendUniqWithSeen(dirs, seen, ldConfDirs...)

	return dirs, nil
}

// GetLinkersFiles returns dynamic-linker dependency files for one file path.
//
// The input path is expected to point to an executable or shared object.
// It returns an empty slice for an empty input path.
func GetLinkersFiles(f string) ([]string, error) {
	if f == "" {
		return nil, nil
	}

	return ldd.FList(f)
}

// GetLinkersFilesFromDirs returns dynamic-linker dependency files for
// executable-like files discovered in the provided directories.
//
// Candidate executables are de-duplicated by resolved target path before
// dependency expansion.
func GetLinkersFilesFromDirs(d ...string) ([]string, error) {
	files := make([]string, 0)
	seenTargets := make(map[string]struct{})

	for _, dir := range d {
		for file := range getExecFiles(dir) {
			target := file.resolved
			if target == "" {
				target = file.candidate
			}

			if _, ok := seenTargets[target]; ok {
				continue
			}
			seenTargets[target] = struct{}{}
			files = append(files, file.candidate)
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	return ldd.FList(files...)
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
	defer func() {
		_ = file.Close()
	}()

	var dirs []string
	seen := make(map[string]struct{})

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
						dirs = appendUniqWithSeen(dirs, seen, d)
					}
				}
			}

			continue
		}

		dirs = appendUniqWithSeen(dirs, seen, line)
	}

	if err := scanner.Err(); err != nil {
		return nil, err
	}

	return dirs, nil
}
