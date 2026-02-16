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

// GetPATHDirs returns runtime-relevant directories discovered from PATH.
//
// It includes existing PATH entries and resolved target directories for
// executable files found inside those entries (e.g., symlinked launchers).
// It returns an empty slice when PATH is unset or empty.
func GetPATHDirs() []string {
	var dirs []string
	seen := make(map[string]struct{})

	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return dirs
	}

	for dir := range strings.SplitSeq(pathEnv, ":") {
		info, err := os.Stat(dir)
		if err != nil || !info.IsDir() {
			continue
		}

		dirs = appendUniqWithSeen(dirs, seen, dir)
		targetDirs := getExecTargetDirs(dir)
		dirs = appendUniqWithSeen(dirs, seen, targetDirs...)

		resolvedDir, err := filepath.EvalSymlinks(dir)
		if err == nil {
			resolvedInfo, statErr := os.Stat(resolvedDir)
			if statErr == nil && resolvedInfo.IsDir() {
				dirs = appendUniqWithSeen(dirs, seen, resolvedDir)
			}
		}
	}

	return dirs
}

// GetLinkerDirs returns dynamic linker search directories for the host.
//
// It starts with existing common system defaults, then appends directories
// from LD_LIBRARY_PATH and /etc/ld.so.conf (including nested include
// directives), while preserving order and removing duplicates.
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
		if _, err := os.Stat(d); err == nil {
			dirs = appendUniqWithSeen(dirs, seen, d)
		}
	}

	for d := range strings.SplitSeq(os.Getenv("LD_LIBRARY_PATH"), ":") {
		if d == "" {
			continue
		}

		if _, err := os.Stat(d); err == nil {
			dirs = appendUniqWithSeen(dirs, seen, d)
		}
	}

	ldConfDirs, err := parseLdConf("/etc/ld.so.conf")
	if err != nil {
		return nil, err
	}

	dirs = appendUniqWithSeen(dirs, seen, ldConfDirs...)

	return dirs, nil
}

// GetLinkersFiles returns linker dependency files for one executable/library path.
func GetLinkersFiles(f string) ([]string, error) {
	if f == "" {
		return nil, nil
	}

	return ldd.FList(f)
}

// GetLinkersFilesFromDirs returns linker dependency files for executable-like
// files discovered in the provided directories.
func GetLinkersFilesFromDirs(d ...string) ([]string, error) {
	files := make([]string, 0)
	seenTargets := make(map[string]struct{})

	for _, dir := range d {
		entries, err := os.ReadDir(dir)
		if err != nil {
			continue
		}

		for _, entry := range entries {
			if entry.IsDir() {
				continue
			}

			candidate := filepath.Join(dir, entry.Name())
			info, err := os.Stat(candidate)
			if err != nil {
				continue
			}

			if !info.Mode().IsRegular() || info.Mode()&0o111 == 0 {
				continue
			}

			resolved := candidate
			entryType := entry.Type()
			isSymlink := entryType&os.ModeSymlink != 0
			if !isSymlink && entryType == 0 {
				if linfo, lerr := os.Lstat(candidate); lerr == nil {
					isSymlink = linfo.Mode()&os.ModeSymlink != 0
				}
			}

			if isSymlink {
				if target, err := filepath.EvalSymlinks(candidate); err == nil {
					resolved = target
				}
			}

			if _, ok := seenTargets[resolved]; ok {
				continue
			}
			seenTargets[resolved] = struct{}{}

			files = append(files, candidate)
		}
	}

	if len(files) == 0 {
		return nil, nil
	}

	return ldd.FList(files...)
}

func getExecTargetDirs(pathDir string) []string {
	entries, err := os.ReadDir(pathDir)
	if err != nil {
		return nil
	}

	var dirs []string
	seen := make(map[string]struct{})

	for _, entry := range entries {
		info, err := entry.Info()
		if err != nil {
			continue
		}

		if info.IsDir() || info.Mode()&0o111 == 0 {
			continue
		}

		entryPath := filepath.Join(pathDir, entry.Name())

		resolvedPath := entryPath
		entryType := entry.Type()
		isSymlink := entryType&os.ModeSymlink != 0
		if !isSymlink && entryType == 0 {
			if linfo, lerr := os.Lstat(entryPath); lerr == nil {
				isSymlink = linfo.Mode()&os.ModeSymlink != 0
			}
		}

		if isSymlink {
			resolvedPath, err = filepath.EvalSymlinks(entryPath)
			if err != nil {
				continue
			}
		}

		targetDir := filepath.Dir(resolvedPath)
		targetInfo, err := os.Stat(targetDir)
		if err != nil || !targetInfo.IsDir() {
			continue
		}

		dirs = appendUniqWithSeen(dirs, seen, targetDir)
	}

	return dirs
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

// appendUniq appends elems to slice while preserving order and skipping values
// that already exist in slice.
//
// NOTE(dwisiswant0): Might be separated into a utility package if needed.
func appendUniq[T comparable](slice []T, elems ...T) []T { // nolint
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

// appendUniqWithSeen appends non-empty elems that are not in seen.
//
// The caller owns seen and should reuse it across calls to avoid repeated
// allocations and re-scanning of the destination slice.
//
// NOTE(dwisiswant0): Might be separated into a utility package if needed.
func appendUniqWithSeen[T1 comparable, T2 map[T1]struct{}](slice []T1, seen T2, elems ...T1) []T1 {
	for _, v := range elems {
		if _, ok := seen[v]; ok {
			continue
		}

		seen[v] = struct{}{}
		slice = append(slice, v)
	}

	return slice
}
