// nolint
//go:build linux
// +build linux

// Package sandboxec wraps os/exec with Landlock policy enforcement.
//
// The package enforces Landlock rules once per process; all subsequently
// created commands run under the same restrictions. Enforcement errors (such as
// unsupported ABI versions) are surfaced through Cmd Err on the first command
// creation.
//
// Example:
//
//	sb := sandboxec.New(
//		sandboxec.WithBestEffort(),
//		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
//		sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
//	)
//	cmd := sb.Command("/usr/bin/printf", "hello")
//	if cmd.Err != nil {
//		// handle enforcement error
//	}
//	_ = cmd.Run()
//
// Note: Landlock support is Linux-only and depends on the running kernel.
package sandboxec
