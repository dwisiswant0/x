// nolint
//go:build linux || darwin
// +build linux darwin

package sandboxec

import (
	"errors"
	"os"
)

// isExecDenied reports whether err comes from the sandbox refusing to start a
// program, rather than from another permission failure such as opening a
// file for the command's standard streams.
func isExecDenied(err error) bool {
	var pathErr *os.PathError

	return errors.As(err, &pathErr) && pathErr.Op == "fork/exec" && errors.Is(err, os.ErrPermission)
}
