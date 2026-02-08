// nolint
//go:build linux
// +build linux

package sandboxec

import "os/exec"

var (
	// ErrDot is an alias for [exec.ErrDot] to preserve os/exec-style
	// documentation links.
	ErrDot = exec.ErrDot

	// ErrNotFound is an alias for [exec.ErrNotFound] to preserve os/exec-style
	// documentation links.
	ErrNotFound = exec.ErrNotFound

	// ErrWaitDelay is an alias for [exec.ErrWaitDelay] to preserve os/exec-style
	// documentation links.
	ErrWaitDelay = exec.ErrWaitDelay
)
