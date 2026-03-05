// nolint
//go:build darwin
// +build darwin

package access

// FS represents placeholder filesystem access rights for Darwin sandbox options.
//
// Seatbelt policy on Darwin is expressed as a policy string; these constants
// are kept for API compatibility with Linux call sites.
type FS uint64

const (
	FS_READ FS = 1 << iota
	fsExec
	FS_WRITE

	FS_READ_EXEC       = FS_READ | fsExec
	FS_READ_WRITE      = FS_READ | FS_WRITE
	FS_READ_WRITE_EXEC = FS_READ | FS_WRITE | fsExec
)

// Network represents placeholder network access rights for Darwin sandbox options.
//
// Seatbelt policy on Darwin is expressed as a policy string; these constants
// are kept for API compatibility with Linux call sites.
type Network uint64

const (
	NETWORK_BIND_TCP Network = 1 << iota
	NETWORK_CONNECT_TCP
)
