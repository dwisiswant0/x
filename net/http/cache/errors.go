package cache

import "errors"

// ErrInvalidOption indicates that an [Option] passed to [New] has an invalid
// value. Errors returned by [New] wrap it.
var ErrInvalidOption = errors.New("cache: invalid option")

// ErrInvalidSnapshot indicates that [Transport.Load] couldn't read a complete
// snapshot written by [Transport.Save]: reading failed, or it read something
// else. Errors returned by Load wrap it.
var ErrInvalidSnapshot = errors.New("cache: invalid snapshot")
