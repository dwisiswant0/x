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
//   - Linux-only options, such as the Landlock ABI selection, are in package
//     sandboxec/landlock.
//   - [ErrUnavailable] matches the unavailable-sandbox error of either
//     platform.
//   - WithUnsafeHostRuntime expands host runtime access from PATH-derived
//     targets and dynamic-linker dependency files.
//   - On Darwin, a process holds one Seatbelt policy. A Sandboxec whose rules
//     differ from the policy already enforced fails with
//     [ErrSeatbeltUnavailable]. With [WithBestEffort], that failure is ignored,
//     and that Sandboxec's commands run under the first policy.
package sandboxec
