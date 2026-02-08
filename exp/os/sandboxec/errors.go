// nolint
//go:build linux
// +build linux

package sandboxec

import "errors"

// ErrLandlockUnavailable indicates that Landlock is not supported by the kernel
// or cannot be queried.
//
// It can be wrapped in option or enforcement errors.
var ErrLandlockUnavailable = errors.New("landlock is unavailable")

// ErrABINotSupported indicates that the requested ABI is not available on the
// running kernel.
//
// It can be wrapped when a requested ABI exceeds kernel support.
var ErrABINotSupported = errors.New("requested landlock ABI is not supported")

// ErrInvalidOption indicates that an option was malformed or incomplete.
//
// It can be wrapped by option validation failures.
var ErrInvalidOption = errors.New("invalid sandbox option")
