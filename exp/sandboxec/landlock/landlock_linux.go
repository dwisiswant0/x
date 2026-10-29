//go:build linux
// +build linux

package landlock

import (
	"fmt"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

// WithABI selects the Landlock ABI version.
//
// Use 0 to auto-select the highest supported ABI on the running kernel, clamped
// to the maximum ABI supported by sandboxec.
//
// The selected version is validated at enforcement time unless best-effort
// enforcement is enabled.
func WithABI(version int) sandboxec.Option {
	return func(cfg *config.Config) error {
		if version < 0 || version > config.MaxABI {
			return fmt.Errorf("%w: unsupported ABI version %d", sandboxec.ErrInvalidOption, version)
		}

		cfg.ABI = version

		return nil
	}
}

// WithIgnoreIfMissing ignores missing paths in filesystem rules.
//
// This allows rules to be declared for optional paths without failing
// enforcement.
func WithIgnoreIfMissing() sandboxec.Option {
	return func(cfg *config.Config) error {
		cfg.IgnoreIfMissing = true

		return nil
	}
}

// WithRestrictScoped enables scoped IPC restrictions (Landlock V6+).
//
// This further limits the process to scoped IPC operations when supported.
func WithRestrictScoped() sandboxec.Option {
	return func(cfg *config.Config) error {
		cfg.RestrictScoped = true

		return nil
	}
}
