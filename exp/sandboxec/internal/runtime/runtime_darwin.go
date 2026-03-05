// nolint
//go:build darwin
// +build darwin

package runtime

import "go.dw1.io/x/exp/sandboxec/internal/macho"

// GetLinkersFiles returns dynamic-linker dependency files for one file path.
//
// It parses Mach-O load commands and returns absolute dependency paths that
// currently exist on disk. It returns an empty slice for an empty input path.
func GetLinkersFiles(f string) ([]string, error) {
	if f == "" {
		return nil, nil
	}

	return macho.GetDependencies(f)
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

	deps := make([]string, 0)
	seenDeps := make(map[string]struct{})

	for _, f := range files {
		itemDeps, err := macho.GetDependencies(f)
		if err != nil {
			return nil, err
		}

		for _, dep := range itemDeps {
			deps = appendUniqWithSeen(deps, seenDeps, dep)
		}
	}

	return deps, nil
}
