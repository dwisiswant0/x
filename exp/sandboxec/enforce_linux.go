// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"fmt"
	"os"
	"sync"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

var (
	landlockABIOnce    sync.Once
	landlockABIVersion int
	landlockABIError   error
)

func getLandlockABIVersion() (int, error) {
	landlockABIOnce.Do(func() {
		landlockABIVersion, landlockABIError = syscall.LandlockGetABIVersion()
	})

	return landlockABIVersion, landlockABIError
}

func defaultABIVersion() int {
	supported, err := getLandlockABIVersion()
	if err != nil {
		return config.MaxABI
	}

	if supported < 1 {
		return 1
	}

	if supported > config.MaxABI {
		return config.MaxABI
	}

	return supported
}

// landlockABI returns the configured ABI, or the default ABI when cfg leaves
// it at 0.
func landlockABI(cfg *config.Config) int {
	if cfg.ABI == 0 {
		return defaultABIVersion()
	}

	return cfg.ABI
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
	case 7:
		return landlock.V7, nil
	default:
		return landlock.Config{}, fmt.Errorf("%w: unsupported ABI version %d", ErrInvalidOption, version)
	}
}

func validateCompatibility(cfg *config.Config, abi int) error {
	if abi < 4 && len(cfg.NetRules) > 0 {
		return fmt.Errorf("%w: network rules require ABI V4+", ErrABINotSupported)
	}

	if abi < 6 && cfg.RestrictScoped {
		return fmt.Errorf("%w: scoped IPC restrictions require ABI V6", ErrABINotSupported)
	}

	if cfg.BestEffort {
		return nil
	}

	supported, err := getLandlockABIVersion()
	if err != nil {
		return fmt.Errorf("%w: %v", ErrLandlockUnavailable, err)
	}

	if supported < abi {
		return fmt.Errorf("%w: requested ABI %d, supported %d", ErrABINotSupported, abi, supported)
	}

	return nil
}

func (s *Sandboxec) enforce() error {
	abi := landlockABI(&s.cfg)

	cfg, err := toLandlockConfig(abi)
	if err != nil {
		return err
	}

	if s.cfg.BestEffort {
		cfg = cfg.BestEffort()
	}

	if err := validateCompatibility(&s.cfg, abi); err != nil {
		return err
	}

	hasFSRules := len(s.cfg.FSRules) > 0
	hasNetRules := len(s.cfg.NetRules) > 0

	if !hasFSRules && !hasNetRules && !s.cfg.RestrictScoped {
		if err := cfg.Restrict(devNullRule(abi)); err != nil {
			return fmt.Errorf("landlock default restrict failed: %w", err)
		}

		return nil
	}

	// The filesystem is deny-by-default: without FS rules, deny all of it,
	// even when only network or scoped restrictions are set. The one
	// exception is /dev/null, which every sandbox allows.
	rules, err := s.buildFSRules()
	if err != nil {
		return err
	}

	rules = append(rules, devNullRule(abi))

	if err := cfg.RestrictPaths(rules...); err != nil {
		return fmt.Errorf("landlock restrict paths failed: %w", err)
	}

	// Landlock ABI V1-V3 do not support network rules, so only attempt to apply
	// them if the configured ABI is V4+.
	if abi >= 4 {
		var rules []landlock.Rule

		if hasNetRules {
			for _, rule := range s.cfg.NetRules {
				if rule.Rights&access.NETWORK_BIND_TCP != 0 {
					rules = append(rules, landlock.BindTCP(rule.Port))
				}

				if rule.Rights&access.NETWORK_CONNECT_TCP != 0 {
					rules = append(rules, landlock.ConnectTCP(rule.Port))
				}
			}
		}

		if err := cfg.RestrictNet(rules...); err != nil {
			return fmt.Errorf("landlock restrict net failed: %w", err)
		}
	}

	if s.cfg.RestrictScoped {
		if err := cfg.RestrictScoped(); err != nil {
			return fmt.Errorf("landlock scoped restrict failed: %w", err)
		}
	}

	return nil
}

// devNullRule returns the rule that lets every sandbox use /dev/null, which
// os/exec opens in the sandboxed process for a nil standard stream. Only
// /dev/null is allowed: /dev/stdin, /dev/stdout and /dev/stderr link to
// /proc/self/fd/N, so a rule for them would grant whatever file the process's
// standard streams point at.
//
// It grants what a read-write file rule would, limited to the rights that abi
// handles. go-landlock checks a rule's rights against the handled set before
// any best-effort downgrade, so a right that abi does not handle, such as
// ioctl_dev below ABI 5, would make enforcement fail.
func devNullRule(abi int) landlock.Rule {
	rights := landlock.AccessFSSet(syscall.AccessFSReadFile | syscall.AccessFSWriteFile)

	if abi >= 3 {
		rights |= landlock.AccessFSSet(syscall.AccessFSTruncate)
	}

	if abi >= 5 {
		rights |= landlock.AccessFSSet(syscall.AccessFSIoctlDev)
	}

	// A system without /dev/null, such as a minimal container, still enforces.
	return landlock.PathAccess(rights, "/dev/null").IgnoreIfMissing()
}

func (s *Sandboxec) buildFSRules() ([]landlock.Rule, error) {
	var rules []landlock.Rule

	for _, rule := range s.cfg.FSRules {
		info, err := os.Stat(rule.Path)
		if err != nil {
			if os.IsNotExist(err) && s.cfg.IgnoreIfMissing {
				fileAccess := filterAccess(rule.Rights, false)
				dirAccess := filterAccess(rule.Rights, true)

				if fileAccess != 0 {
					fsRule := landlock.PathAccess(fileAccess, rule.Path).IgnoreIfMissing()
					rules = append(rules, fsRule)
				}

				if dirAccess != 0 {
					fsRule := landlock.PathAccess(dirAccess, rule.Path).IgnoreIfMissing()
					rules = append(rules, fsRule)
				}

				continue
			}

			return nil, fmt.Errorf("filesystem path %q: %w", rule.Path, err)
		}

		fsRule := landlock.PathAccess(filterAccess(rule.Rights, info.IsDir()), rule.Path)

		if s.cfg.IgnoreIfMissing {
			fsRule = fsRule.IgnoreIfMissing()
		}

		rules = append(rules, fsRule)
	}

	return rules, nil
}

func filterAccess(rights access.FS, isDir bool) landlock.AccessFSSet {
	accessSet := landlock.AccessFSSet(rights)
	if isDir {
		return accessSet
	}

	dirOnly := landlock.AccessFSSet(
		syscall.AccessFSReadDir |
			syscall.AccessFSRemoveDir |
			syscall.AccessFSRemoveFile |
			syscall.AccessFSMakeChar |
			syscall.AccessFSMakeDir |
			syscall.AccessFSMakeReg |
			syscall.AccessFSMakeSock |
			syscall.AccessFSMakeFifo |
			syscall.AccessFSMakeBlock |
			syscall.AccessFSMakeSym |
			syscall.AccessFSRefer,
	)

	return accessSet &^ dirOnly
}
