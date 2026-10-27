// Package landlock provides sandboxec options that only Linux Landlock
// supports.
//
// The options exist only on Linux, so code that uses them must be built for
// Linux only.
//
// Example:
//
//	sb := sandboxec.New(
//		landlock.WithABI(7),
//		landlock.WithIgnoreIfMissing(),
//		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
//	)
package landlock
