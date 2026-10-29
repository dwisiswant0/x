//go:build linux || darwin
// +build linux darwin

package sandboxec

import (
	"fmt"
	"path/filepath"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
	"go.dw1.io/x/exp/sandboxec/internal/runtime"
)

// Option configures a Sandboxec instance.
//
// Returning an error records the first failure and exposes it through Cmd Err
// on the first Command or CommandContext call.
//
// Options that only one platform supports are in platform packages, such as
// sandboxec/landlock.
type Option func(*config.Config) error

// WithBestEffort enables best-effort enforcement.
//
// On Linux, unsupported Landlock ABIs or missing kernel support are ignored
// instead of causing enforcement to fail. On Darwin, Seatbelt enforcement
// failures are ignored and commands are still created. This may weaken
// least-privilege guarantees, including network restrictions. It is a
// compatibility fallback and not a security boundary.
func WithBestEffort() Option {
	return func(cfg *config.Config) error {
		cfg.BestEffort = true

		return nil
	}
}

// WithFSRule adds a filesystem rule for the given path and access rights.
//
// The path must be non-empty and rights must be non-zero. On Linux, the rights
// apply according to Landlock's file and directory access distinctions.
func WithFSRule(path string, rights access.FS) Option {
	return func(cfg *config.Config) error {
		if path == "" {
			return fmt.Errorf("%w: FSRule requires a path", ErrInvalidOption)
		}

		if rights == 0 {
			return fmt.Errorf("%w: FSRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: path, Rights: rights})

		return nil
	}
}

// WithNetworkRule adds a network rule for the given port.
//
// Rights control TCP bind and connect access for the port. On Darwin and on
// Landlock ABI V4+, TCP bind and connect are denied by default, and
// WithNetworkRule allowlists ports. On Linux, network rules require Landlock
// ABI V4+.
func WithNetworkRule(port uint16, rights access.Network) Option {
	return func(cfg *config.Config) error {
		if rights == 0 {
			return fmt.Errorf("%w: NetworkRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.NetRules = append(cfg.NetRules, config.NetRule{Port: port, Rights: rights})

		return nil
	}
}

// WithUnsafeHostRuntime allows [access.FS_READ_EXEC] access to host runtime paths.
//
// It grants read/execute rights to PATH-derived runtime targets and to
// resolved shared-library dependency files discovered from executable entries.
// Use it for compatibility with host-provided runtimes and shared libraries.
// It may broaden sandbox access.
//
// Files it cannot use, such as scripts or libraries that no longer exist or
// cannot be read, are skipped. So is a dependency path that is not a shared
// library, even if a program names it as one. On Linux, the option fails with
// [ErrInvalidOption] if the path of a library it found cannot be inspected.
func WithUnsafeHostRuntime() Option {
	return func(cfg *config.Config) error {
		pathTargets := runtime.GetPATHDirs()

		soFiles, err := runtime.GetLinkersFilesFromDirs(pathTargets...)
		if err != nil {
			return fmt.Errorf("%w: failed to resolve runtime dependency files: %v", ErrInvalidOption, err)
		}
		pathTargets = append(pathTargets, soFiles...)

		// Paths are cleaned as exec.LookPath cleans PATH entries, so that one
		// directory listed twice yields one rule.
		seen := make(map[string]struct{})
		for _, pathTarget := range pathTargets {
			if pathTarget == "" {
				continue
			}

			cleaned := filepath.Clean(pathTarget)
			if _, ok := seen[cleaned]; ok {
				continue
			}

			seen[cleaned] = struct{}{}
			cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: cleaned, Rights: access.FS_READ_EXEC})
		}

		return nil
	}
}
