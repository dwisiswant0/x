// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"fmt"
	"path/filepath"
	"strings"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/runtime"
)

// Option configures a Sandboxec instance.
type Option func(*config) error

type config struct {
	bestEffort bool
	flags      uint64

	fsRules  []fsRule
	netRules []netRule
}

func defaultConfig() config {
	return config{}
}

// WithBestEffort enables best-effort Seatbelt enforcement.
//
// When enabled, enforcement failures are ignored and commands are still
// created. This is a compatibility fallback and not a security boundary.
func WithBestEffort() Option {
	return func(cfg *config) error {
		cfg.bestEffort = true

		return nil
	}
}

// WithABI is unsupported on Darwin.
func WithABI(version int) Option {
	return func(cfg *config) error {
		_ = cfg
		_ = version

		return fmt.Errorf("%w: WithABI is unsupported on darwin", ErrInvalidOption)
	}
}

// WithIgnoreIfMissing is unsupported on Darwin.
func WithIgnoreIfMissing() Option {
	return func(cfg *config) error {
		_ = cfg

		return fmt.Errorf("%w: WithIgnoreIfMissing is unsupported on darwin", ErrInvalidOption)
	}
}

// WithFSRule adds a filesystem rule used to build a Seatbelt policy.
func WithFSRule(path string, rights access.FS) Option {
	return func(cfg *config) error {
		if path == "" {
			return fmt.Errorf("%w: FSRule requires a path", ErrInvalidOption)
		}

		if rights == 0 {
			return fmt.Errorf("%w: FSRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.fsRules = append(cfg.fsRules, fsRule{path: filepath.Clean(path), rights: rights})

		return nil
	}
}

// WithNetworkRule adds a network rule used to build a Seatbelt policy.
func WithNetworkRule(port uint16, rights access.Network) Option {
	return func(cfg *config) error {
		if rights == 0 {
			return fmt.Errorf("%w: NetworkRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.netRules = append(cfg.netRules, netRule{port: port, rights: rights})

		return nil
	}
}

// WithRestrictScoped is unsupported on Darwin.
func WithRestrictScoped() Option {
	return func(cfg *config) error {
		_ = cfg

		return fmt.Errorf("%w: WithRestrictScoped is unsupported on darwin", ErrInvalidOption)
	}
}

// WithUnsafeHostRuntime allows [access.FS_READ_EXEC] access to host runtime paths.
//
// It grants read/execute rights to PATH-derived runtime targets and to
// resolved shared-library dependency files discovered from executable entries.
// Use it for compatibility with host-provided runtimes and shared libraries.
// It may broaden sandbox access.
func WithUnsafeHostRuntime() Option {
	return func(cfg *config) error {
		pathTargets := runtime.GetPATHDirs()

		soFiles, err := runtime.GetLinkersFilesFromDirs(pathTargets...)
		if err != nil {
			return fmt.Errorf("%w: failed to resolve runtime dependency files: %v", ErrSeatbeltUnavailable, err)
		}
		pathTargets = append(pathTargets, soFiles...)

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
			cfg.fsRules = append(cfg.fsRules, fsRule{path: cleaned, rights: access.FS_READ_EXEC})
		}

		return nil
	}
}

func (c config) seatbeltPolicy() string {
	lines := []string{"(version 1)", "(allow default)"}

	if len(c.fsRules) > 0 {
		lines = append(lines, "(deny file-read*)", "(deny file-write*)", "(deny file-map-executable)")
	}

	for _, rule := range c.fsRules {
		safePath := strings.ReplaceAll(rule.path, `"`, `\\"`)

		if rule.rights&access.FS_READ != 0 || rule.rights&access.FS_READ_EXEC != 0 || rule.rights&access.FS_READ_WRITE != 0 || rule.rights&access.FS_READ_WRITE_EXEC != 0 {
			lines = append(lines, `(allow file-read* (subpath "`+safePath+`"))`)
		}

		if rule.rights&access.FS_WRITE != 0 || rule.rights&access.FS_READ_WRITE != 0 || rule.rights&access.FS_READ_WRITE_EXEC != 0 {
			lines = append(lines, `(allow file-write* (subpath "`+safePath+`"))`)
		}

		if rule.rights&access.FS_READ_EXEC != 0 || rule.rights&access.FS_READ_WRITE_EXEC != 0 {
			lines = append(lines, `(allow file-map-executable (subpath "`+safePath+`"))`)
		}
	}

	allowInbound := false
	allowOutbound := false
	inboundPorts := make([]uint16, 0)
	outboundPorts := make([]uint16, 0)
	seenInbound := make(map[uint16]struct{})
	seenOutbound := make(map[uint16]struct{})

	for _, rule := range c.netRules {
		if rule.rights&access.NETWORK_BIND_TCP != 0 {
			allowInbound = true
			if _, ok := seenInbound[rule.port]; !ok {
				seenInbound[rule.port] = struct{}{}
				inboundPorts = append(inboundPorts, rule.port)
			}
		}

		if rule.rights&access.NETWORK_CONNECT_TCP != 0 {
			allowOutbound = true
			if _, ok := seenOutbound[rule.port]; !ok {
				seenOutbound[rule.port] = struct{}{}
				outboundPorts = append(outboundPorts, rule.port)
			}
		}
	}

	lines = append(lines, "(deny network-inbound)", "(deny network-outbound)")

	if allowInbound {
		for _, port := range inboundPorts {
			lines = append(lines, `(allow network-inbound (local tcp "*:`+fmt.Sprintf("%d", port)+`"))`)
		}
	}

	if allowOutbound {
		for _, port := range outboundPorts {
			lines = append(lines, `(allow network-outbound (remote tcp "*:`+fmt.Sprintf("%d", port)+`"))`)
		}
	}

	return strings.Join(lines, "\n")
}

type fsRule struct {
	path   string
	rights access.FS
}

type netRule struct {
	port   uint16
	rights access.Network
}
