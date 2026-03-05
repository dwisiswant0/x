// nolint
//go:build linux || darwin
// +build linux darwin

package runtime

import (
	"iter"
	"os"
	"path/filepath"
	"strings"
)

type execFile struct {
	candidate string
	isSymlink bool
	resolved  string
}

// GetPATHDirs returns runtime-relevant directories discovered from PATH.
//
// It includes existing PATH entries and resolved target directories for
// executable files found inside those entries (e.g., symlinked launchers).
// Returned paths are de-duplicated while preserving discovery order.
// It returns an empty slice when PATH is unset or empty.
func GetPATHDirs() []string {
	var dirs []string
	seen := make(map[string]struct{})

	for _, dir := range splitEnvDirs("PATH") {
		dirs = appendExistingDirUniq(dirs, seen, dir)
		targetDirs := getExecTargetDirs(dir)
		dirs = appendUniqWithSeen(dirs, seen, targetDirs...)

		linfo, lerr := os.Lstat(dir)
		if lerr == nil && linfo.Mode()&os.ModeSymlink != 0 {
			resolvedDir, err := filepath.EvalSymlinks(dir)
			if err == nil {
				if resolvedInfo, statErr := os.Stat(resolvedDir); statErr == nil && resolvedInfo.IsDir() {
					dirs = appendUniqWithSeen(dirs, seen, resolvedDir)
				}
			}
		}
	}

	return dirs
}

func splitEnvDirs(envKey string) []string {
	value := os.Getenv(envKey)
	if value == "" {
		return nil
	}

	dirs := make([]string, 0)
	for dir := range strings.SplitSeq(value, ":") {
		if dir == "" {
			continue
		}
		dirs = append(dirs, dir)
	}

	return dirs
}

func getExecTargetDirs(pathDir string) []string {
	var dirs []string
	seen := make(map[string]struct{})

	for file := range getExecFiles(pathDir) {
		if !file.isSymlink {
			dirs = appendUniqWithSeen(dirs, seen, pathDir)
			continue
		}

		if file.resolved == "" {
			continue
		}

		targetDir := filepath.Dir(file.resolved)
		dirs = appendExistingDirUniq(dirs, seen, targetDir)
	}

	return dirs
}

func getExecFiles(dir string) iter.Seq[execFile] {
	return func(yield func(execFile) bool) {
		entries, err := os.ReadDir(dir)
		if err != nil {
			return
		}

		for _, entry := range entries {
			entryType := entry.Type()
			if entryType.IsDir() {
				continue
			}
			if entryType&os.ModeType != 0 && entryType&os.ModeSymlink == 0 && !entryType.IsRegular() {
				continue
			}

			candidate := filepath.Join(dir, entry.Name())

			isSymlink := entryType&os.ModeSymlink != 0
			if !isSymlink && entryType == 0 {
				if linfo, err := os.Lstat(candidate); err == nil {
					isSymlink = linfo.Mode()&os.ModeSymlink != 0
				}
			}

			var mode os.FileMode
			if !isSymlink && entryType.IsRegular() {
				info, err := entry.Info()
				if err != nil {
					continue
				}
				mode = info.Mode()
			} else {
				info, err := os.Stat(candidate)
				if err != nil {
					continue
				}
				mode = info.Mode()
			}

			if !mode.IsRegular() || mode&0o111 == 0 {
				continue
			}

			resolved := candidate
			if isSymlink {
				if target, err := filepath.EvalSymlinks(candidate); err == nil {
					resolved = target
				} else {
					resolved = ""
				}
			}

			if !yield(execFile{
				candidate: candidate,
				isSymlink: isSymlink,
				resolved:  resolved,
			}) {
				return
			}
		}
	}
}

// appendUniqWithSeen appends elements that are not already present in seen.
//
// The caller owns seen and should reuse it across calls to avoid repeated
// allocations and re-scanning of the destination slice.
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

func appendExistingDirUniq(dirs []string, seen map[string]struct{}, dir string) []string {
	if dir == "" {
		return dirs
	}

	info, err := os.Stat(dir)
	if err != nil || !info.IsDir() {
		return dirs
	}

	return appendUniqWithSeen(dirs, seen, dir)
}
