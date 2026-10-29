//go:build linux || darwin
// +build linux darwin

package sandboxec

import "errors"

// ErrUnavailable indicates that the platform sandbox is unavailable or failed
// to initialize.
//
// [ErrLandlockUnavailable] and [ErrSeatbeltUnavailable] match it with
// [errors.Is], so callers can check for an unavailable sandbox on any platform.
var ErrUnavailable = errors.New("sandbox is unavailable")

// ErrLandlockUnavailable indicates that Landlock is not supported by the kernel
// or cannot be queried. It matches [ErrUnavailable].
//
// It can be wrapped in enforcement errors.
var ErrLandlockUnavailable error = unavailableError("landlock is unavailable")

// ErrSeatbeltUnavailable indicates that macOS Seatbelt sandboxing is unavailable
// or failed to initialize, including when the process already has a different
// Seatbelt policy. It matches [ErrUnavailable].
//
// It can be wrapped in enforcement errors.
var ErrSeatbeltUnavailable error = unavailableError("seatbelt is unavailable")

// ErrABINotSupported indicates that the requested ABI is not available on the
// running kernel.
//
// It can be wrapped when a requested ABI exceeds kernel support.
var ErrABINotSupported = errors.New("requested landlock ABI is not supported")

// ErrInvalidOption indicates that an option was malformed or incomplete, or
// could not be applied.
//
// It can be wrapped by option validation failures.
var ErrInvalidOption = errors.New("invalid sandbox option")

// unavailableError is a platform-specific error that matches ErrUnavailable.
type unavailableError string

func (e unavailableError) Error() string {
	return string(e)
}

func (unavailableError) Is(target error) bool {
	return target == ErrUnavailable
}
