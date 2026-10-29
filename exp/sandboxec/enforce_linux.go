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

// ruleABI returns the ABI that filesystem rules must fit, which is the
// selected ABI abi unless best-effort mode runs on a kernel with an older ABI.
// go-landlock then enforces the kernel's ABI, and if a rule holds refer that
// the kernel's ABI does not handle, it enforces nothing at all.
func ruleABI(cfg *config.Config, abi int) int {
	if !cfg.BestEffort {
		return abi
	}

	supported, err := getLandlockABIVersion()
	if err != nil || supported >= abi {
		return abi
	}

	return supported
}

// toLandlockConfig returns the configuration that restricts everything that
// Landlock ABI version can restrict. It restricts scoped IPC only if scoped is
// set.
func toLandlockConfig(version int, scoped bool) (landlock.Config, error) {
	if version < 1 || version > config.MaxABI {
		return landlock.Config{}, fmt.Errorf("%w: unsupported ABI version %d", ErrInvalidOption, version)
	}

	// FS_READ_WRITE_EXEC holds every filesystem right up to MaxABI.
	fsRights := filterAccess(access.FS_READ_WRITE_EXEC, true, version)

	var netRights landlock.AccessNetSet
	if version >= 4 {
		netRights = landlock.AccessNetSet(access.NETWORK_BIND_TCP | access.NETWORK_CONNECT_TCP)
	}

	var scopes landlock.ScopedSet
	if scoped && version >= 6 {
		scopes = syscall.ScopeAbstractUnixSocket | syscall.ScopeSignal
	}

	cfg, err := landlock.NewConfig(fsRights, netRights, scopes)
	if err != nil {
		return landlock.Config{}, err
	}

	return *cfg, nil
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

	// A sandbox without rules restricts everything its ABI supports, including
	// scoped IPC.
	noRules := len(s.cfg.FSRules) == 0 && len(s.cfg.NetRules) == 0

	cfg, err := toLandlockConfig(abi, s.cfg.RestrictScoped || noRules)
	if err != nil {
		return err
	}

	if s.cfg.BestEffort {
		cfg = cfg.BestEffort()
	}

	if err := validateCompatibility(&s.cfg, abi); err != nil {
		return err
	}

	// The filesystem is deny-by-default: without FS rules, deny all of it,
	// even when only network or scoped restrictions are set. The one
	// exception is /dev/null, which every sandbox allows.
	fsABI := ruleABI(&s.cfg, abi)

	rules, err := s.buildFSRules(fsABI)
	if err != nil {
		return err
	}

	rules = append(rules, devNullRule(fsABI))
	rules = append(rules, s.buildNetRules()...)

	// Enforce a single ruleset. Every ruleset denies Landlock's refer right,
	// which covers moving and linking files between directories, unless one of
	// its own rules grants it. That includes a ruleset that handles only
	// network or scoped access, so a second ruleset would block the moves and
	// links that the FS rules allow.
	if err := cfg.Restrict(rules...); err != nil {
		return fmt.Errorf("landlock restrict failed: %w", err)
	}

	return nil
}

// devNullRule returns the rule that lets every sandbox use /dev/null, which
// os/exec opens in the sandboxed process for a nil standard stream. Only
// /dev/null is allowed: /dev/stdin, /dev/stdout and /dev/stderr link to
// /proc/self/fd/N, so a rule for them would grant whatever file the process's
// standard streams point at.
//
// It grants what a read-write file rule would.
func devNullRule(abi int) landlock.Rule {
	rights := filterAccess(access.FS_READ_WRITE, false, abi)

	// A system without /dev/null, such as a minimal container, still enforces.
	return landlock.PathAccess(rights, "/dev/null").IgnoreIfMissing()
}

func (s *Sandboxec) buildFSRules(abi int) ([]landlock.Rule, error) {
	var rules []landlock.Rule

	for _, rule := range s.cfg.FSRules {
		info, err := os.Stat(rule.Path)
		if err != nil {
			if os.IsNotExist(err) && s.cfg.IgnoreIfMissing {
				fileAccess := filterAccess(rule.Rights, false, abi)
				dirAccess := filterAccess(rule.Rights, true, abi)

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

		fsRule := landlock.PathAccess(filterAccess(rule.Rights, info.IsDir(), abi), rule.Path)

		if s.cfg.IgnoreIfMissing {
			fsRule = fsRule.IgnoreIfMissing()
		}

		rules = append(rules, fsRule)
	}

	return rules, nil
}

func (s *Sandboxec) buildNetRules() []landlock.Rule {
	var rules []landlock.Rule

	for _, rule := range s.cfg.NetRules {
		if rule.Rights&access.NETWORK_BIND_TCP != 0 {
			rules = append(rules, landlock.BindTCP(rule.Port))
		}

		if rule.Rights&access.NETWORK_CONNECT_TCP != 0 {
			rules = append(rules, landlock.ConnectTCP(rule.Port))
		}
	}

	return rules
}

// filterAccess returns the Landlock rights that rights grant on a file, or on
// a directory if isDir, at Landlock ABI abi.
//
// It drops the rights that Landlock added after abi, such as ioctl_dev below
// ABI 5, because go-landlock rejects a rule that holds one, even in
// best-effort mode.
// A ruleset at abi does not restrict those rights anyway, except refer, which
// ABI 1 always denies.
func filterAccess(rights access.FS, isDir bool, abi int) landlock.AccessFSSet {
	accessSet := landlock.AccessFSSet(rights)

	if abi < 2 {
		accessSet &^= syscall.AccessFSRefer
	}

	if abi < 3 {
		accessSet &^= syscall.AccessFSTruncate
	}

	if abi < 5 {
		accessSet &^= syscall.AccessFSIoctlDev
	}

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
