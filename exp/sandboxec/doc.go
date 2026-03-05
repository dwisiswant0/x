// Package sandboxec wraps os/exec with process-wide sandbox policy enforcement.
//
// On Linux, sandboxec is backed by Landlock. On Darwin, sandboxec is backed by
// Seatbelt.
//
// The package enforces sandbox rules once per process. Commands created after
// enforcement run under the same restrictions. Enforcement errors are exposed
// through Cmd Err on the first command creation.
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
// Platform notes:
//
//   - Linux support depends on Landlock availability in the running kernel.
//   - On Linux, the default ABI is auto-selected to the highest ABI supported
//     by both kernel and package.
//   - WithUnsafeHostRuntime expands host runtime access from PATH-derived
//     targets and dynamic-linker dependency files.
//   - Darwin support requires CGO_ENABLED=0.
package sandboxec
