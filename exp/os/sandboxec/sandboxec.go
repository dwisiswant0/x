// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"sync"

	"github.com/landlock-lsm/go-landlock/landlock"
	"github.com/landlock-lsm/go-landlock/landlock/syscall"
	"go.dw1.io/x/exp/os/sandboxec/access"
)

// Sandboxec configures Landlock restrictions for the current process and
// produces Cmd values that run under those restrictions.
//
// Landlock restrictions apply to the current process and all goroutines. Once
// enforced, they cannot be removed for the lifetime of the process.
type Sandboxec struct {
	cfg       config
	optErr    error
	applyOnce sync.Once
	applyErr  error
}

// Cmd is an alias for [exec.Cmd] to preserve os/exec-style documentation links.
type Cmd = exec.Cmd

// New creates a Sandboxec configured by the provided options.
//
// Option errors are recorded and surfaced on the first call to Command or
// CommandContext via the returned Cmd Err field.
func New(opts ...Option) *Sandboxec {
	var optErr error

	cfg := defaultConfig()
	for _, opt := range opts {
		if opt == nil {
			continue
		}

		if err := opt(&cfg); err != nil && optErr == nil {
			optErr = err
		}
	}

	return &Sandboxec{
		cfg:    cfg,
		optErr: optErr,
	}
}

// Command returns a Cmd configured like [exec.Command], after enforcing
// Landlock for the current process.
//
// If enforcement fails, the returned Cmd has Err set to that failure.
func (s *Sandboxec) Command(name string, arg ...string) *Cmd {
	s.enforceOnce()

	cmd := exec.Command(name, arg...)
	if s.applyErr != nil {
		cmd.Err = s.applyErr
	}

	return cmd
}

// CommandContext returns a Cmd configured like [exec.CommandContext], after
// enforcing Landlock for the current process.
//
// If enforcement fails, the returned Cmd has Err set to that failure.
func (s *Sandboxec) CommandContext(ctx context.Context, name string, arg ...string) *Cmd {
	s.enforceOnce()

	cmd := exec.CommandContext(ctx, name, arg...)
	if s.applyErr != nil {
		cmd.Err = s.applyErr
	}

	return cmd
}

// LookPath returns the path to an executable like [exec.LookPath].
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

func (s *Sandboxec) enforceOnce() {
	s.applyOnce.Do(func() {
		s.applyErr = s.enforce()
	})
}

func (s *Sandboxec) enforce() error {
	if s.optErr != nil {
		return s.optErr
	}

	cfg, err := toLandlockConfig(s.cfg.abi)
	if err != nil {
		return err
	}

	if s.cfg.bestEffort {
		cfg = cfg.BestEffort()
	}

	if err := s.cfg.validateCompatibility(); err != nil {
		return err
	}

	hasFSRules := len(s.cfg.fsRules) > 0
	hasNetRules := len(s.cfg.netRules) > 0

	if !hasFSRules && !hasNetRules && !s.cfg.restrictScoped {
		if err := cfg.Restrict(); err != nil {
			return fmt.Errorf("landlock default restrict failed: %w", err)
		}

		return nil
	}

	if hasFSRules {
		rules, err := s.buildFSRules()
		if err != nil {
			return err
		}

		if len(rules) > 0 {
			if err := cfg.RestrictPaths(rules...); err != nil {
				return fmt.Errorf("landlock restrict paths failed: %w", err)
			}
		}
	}

	if hasNetRules {
		var rules []landlock.Rule

		for _, rule := range s.cfg.netRules {
			if rule.rights&access.NETWORK_BIND_TCP != 0 {
				rules = append(rules, landlock.BindTCP(rule.port))
			}

			if rule.rights&access.NETWORK_CONNECT_TCP != 0 {
				rules = append(rules, landlock.ConnectTCP(rule.port))
			}
		}

		if err := cfg.RestrictNet(rules...); err != nil {
			return fmt.Errorf("landlock restrict net failed: %w", err)
		}
	}

	if s.cfg.restrictScoped {
		if err := cfg.RestrictScoped(); err != nil {
			return fmt.Errorf("landlock scoped restrict failed: %w", err)
		}
	}

	return nil
}

func (s *Sandboxec) buildFSRules() ([]landlock.Rule, error) {
	var rules []landlock.Rule

	for _, rule := range s.cfg.fsRules {
		info, err := os.Stat(rule.path)
		if err != nil {
			if os.IsNotExist(err) && s.cfg.ignoreIfMissing {
				fileAccess := filterAccess(rule.rights, false)
				dirAccess := filterAccess(rule.rights, true)

				if fileAccess != 0 {
					fsRule := landlock.PathAccess(fileAccess, rule.path).IgnoreIfMissing()
					rules = append(rules, fsRule)
				}

				if dirAccess != 0 {
					fsRule := landlock.PathAccess(dirAccess, rule.path).IgnoreIfMissing()
					rules = append(rules, fsRule)
				}

				continue
			}

			return nil, fmt.Errorf("filesystem path %q: %w", rule.path, err)
		}

		fsRule := landlock.PathAccess(filterAccess(rule.rights, info.IsDir()), rule.path)

		if s.cfg.ignoreIfMissing {
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
