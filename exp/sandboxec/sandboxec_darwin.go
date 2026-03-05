// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"context"
	"os/exec"
	"sync"
)

// Sandboxec configures Seatbelt restrictions for the current process and
// produces Cmd values that run under those restrictions.
//
// Seatbelt restrictions apply to the current process and all goroutines. Once
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
// Seatbelt for the current process.
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
// enforcing Seatbelt for the current process.
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

	policy := s.cfg.seatbeltPolicy()

	if err := applySeatbelt(policy, s.cfg.flags); err != nil {
		if s.cfg.bestEffort {
			return nil
		}

		return err
	}

	return nil
}
