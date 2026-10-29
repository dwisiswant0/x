//go:build linux || darwin
// +build linux darwin

package sandboxec

import (
	"context"
	"os/exec"
	"sync"

	"go.dw1.io/x/exp/sandboxec/internal/config"
)

// Sandboxec configures sandbox restrictions for the current process and
// produces Cmd values that run under those restrictions. It uses Landlock on
// Linux and Seatbelt on Darwin.
//
// The restrictions apply to the current process and all goroutines. Once
// enforced, they cannot be removed for the lifetime of the process.
type Sandboxec struct {
	cfg       config.Config
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
	var cfg config.Config
	var optErr error

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

// Command returns a Cmd configured like [exec.Command], after enforcing the
// sandbox for the current process.
//
// If enforcement fails, the returned Cmd has Err set to that failure.
func (s *Sandboxec) Command(name string, arg ...string) *Cmd {
	s.enforceOnce()

	cmd := exec.Command(name, arg...)
	s.attach(cmd)

	return cmd
}

// CommandContext returns a Cmd configured like [exec.CommandContext], after
// enforcing the sandbox for the current process.
//
// If enforcement fails, the returned Cmd has Err set to that failure.
func (s *Sandboxec) CommandContext(ctx context.Context, name string, arg ...string) *Cmd {
	s.enforceOnce()

	cmd := exec.CommandContext(ctx, name, arg...)
	s.attach(cmd)

	return cmd
}

// LookPath returns the path to an executable like [exec.LookPath].
func LookPath(file string) (string, error) {
	return exec.LookPath(file)
}

// enforceOnce runs before each command is created, so that the command's PATH
// lookup sees the same restrictions on every call, including the first.
func (s *Sandboxec) enforceOnce() {
	s.applyOnce.Do(func() {
		if s.optErr != nil {
			s.applyErr = s.optErr

			return
		}

		s.applyErr = s.enforce()
	})
}

// attach applies the enforcement result to a newly created command.
func (s *Sandboxec) attach(cmd *Cmd) {
	if s.applyErr != nil {
		cmd.Err = s.applyErr
	}
}
