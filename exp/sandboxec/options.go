// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"fmt"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.dw1.io/x/exp/sandboxec/access"
)

// Option configures a Sandboxec instance.
//
// Returning an error records the first failure and exposes it through Cmd Err
// on the first Command or CommandContext call.
type Option func(*config) error

type config struct {
	abi             int
	bestEffort      bool
	ignoreIfMissing bool
	restrictScoped  bool
	fsRules         []fsRule
	netRules        []netRule
}

const maxABIVersion = 6

func defaultConfig() config {
	return config{abi: maxABIVersion}
}

func toLandlockConfig(version int) (landlock.Config, error) {
	switch version {
	case 1:
		return landlock.V1, nil
	case 2:
		return landlock.V2, nil
	case 3:
		return landlock.V3, nil
	case 4:
		return landlock.V4, nil
	case 5:
		return landlock.V5, nil
	case 6:
		return landlock.V6, nil
	default:
		return landlock.Config{}, fmt.Errorf("%w: unsupported ABI version %d", ErrInvalidOption, version)
	}
}

func (c *config) validateCompatibility() error {
	if c.abi < 4 && len(c.netRules) > 0 {
		return fmt.Errorf("%w: network rules require ABI V4+", ErrABINotSupported)
	}

	if c.abi < 6 && c.restrictScoped {
		return fmt.Errorf("%w: scoped IPC restrictions require ABI V6", ErrABINotSupported)
	}

	if c.bestEffort {
		return nil
	}

	supported, err := syscall.LandlockGetABIVersion()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLandlockUnavailable, err)
	}

	if supported < c.abi {
		return fmt.Errorf("%w: requested ABI %d, supported %d", ErrABINotSupported, c.abi, supported)
	}

	return nil
}

// WithABI selects the Landlock ABI version (1-6).
//
// The selected version is validated at enforcement time unless best-effort
// enforcement is enabled.
func WithABI(version int) Option {
	return func(cfg *config) error {
		if _, err := toLandlockConfig(version); err != nil {
			return err
		}

		cfg.abi = version

		return nil
	}
}

// WithBestEffort enables best-effort Landlock enforcement.
//
// When enabled, unsupported Landlock ABIs or missing kernel support are ignored
// instead of causing enforcement to fail. This may weaken least-privilege
// guarantees (including network restrictions) on unsupported kernels.
func WithBestEffort() Option {
	return func(cfg *config) error {
		cfg.bestEffort = true

		return nil
	}
}

// WithIgnoreIfMissing ignores missing paths in filesystem rules.
//
// This allows rules to be declared for optional paths without failing
// enforcement.
func WithIgnoreIfMissing() Option {
	return func(cfg *config) error {
		cfg.ignoreIfMissing = true

		return nil
	}
}

// WithFSRule adds a filesystem rule for the given path and access rights.
//
// The supplied rights apply to the path according to Landlock's file and
// directory access distinctions. The path must be non-empty and rights must be
// non-zero.
func WithFSRule(path string, rights access.FS) Option {
	return func(cfg *config) error {
		if path == "" {
			return fmt.Errorf("%w: FSRule requires a path", ErrInvalidOption)
		}

		if rights == 0 {
			return fmt.Errorf("%w: FSRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.fsRules = append(cfg.fsRules, fsRule{path: path, rights: rights})

		return nil
	}
}

// WithNetworkRule adds a network rule for the given port.
//
// Rights control TCP bind and connect access for the specified port. Network
// rules require Landlock ABI V4+.
//
// On ABI V4+, network policy is deny-by-default for TCP bind/connect;
// WithNetworkRule explicitly allowlists ports.
func WithNetworkRule(port uint16, rights access.Network) Option {
	return func(cfg *config) error {
		if rights == 0 {
			return fmt.Errorf("%w: NetworkRule requires non-zero access rights", ErrInvalidOption)
		}

		cfg.netRules = append(cfg.netRules, netRule{port: port, rights: rights})

		return nil
	}
}

// WithRestrictScoped enables scoped IPC restrictions (Landlock V6+).
//
// This further limits the process to scoped IPC operations when supported.
func WithRestrictScoped() Option {
	return func(cfg *config) error {
		cfg.restrictScoped = true

		return nil
	}
}

type fsRule struct {
	path   string
	rights access.FS
}

type netRule struct {
	port   uint16
	rights access.Network
}
