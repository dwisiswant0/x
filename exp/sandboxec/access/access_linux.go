// nolint
//go:build linux
// +build linux

package access

import "github.com/landlock-lsm/go-landlock/landlock/syscall"

// FS represents filesystem access rights for Landlock rules.
type FS uint64

const (
	// FS_READ allows reading file contents and directory entries.
	FS_READ FS = syscall.AccessFSReadFile | syscall.AccessFSReadDir

	// FS_READ_EXEC allows reading and executing files plus reading directories.
	FS_READ_EXEC FS = FS_READ | syscall.AccessFSExecute

	// FS_WRITE allows creating, modifying, and removing filesystem entries.
	FS_WRITE FS = syscall.AccessFSWriteFile | syscall.AccessFSTruncate | syscall.AccessFSIoctlDev |
		syscall.AccessFSReadDir | syscall.AccessFSRemoveDir | syscall.AccessFSRemoveFile |
		syscall.AccessFSMakeChar | syscall.AccessFSMakeDir | syscall.AccessFSMakeReg | syscall.AccessFSMakeSock |
		syscall.AccessFSMakeFifo | syscall.AccessFSMakeBlock | syscall.AccessFSMakeSym |
		syscall.AccessFSRefer

	// FS_READ_WRITE allows read and write access without execute.
	FS_READ_WRITE FS = FS_READ | FS_WRITE

	// FS_READ_WRITE_EXEC allows read, write, and execute access.
	FS_READ_WRITE_EXEC FS = FS_READ_WRITE | syscall.AccessFSExecute
)

// Network represents network access rights for Landlock rules.
type Network uint64

const (
	// NETWORK_BIND_TCP allows binding TCP sockets on a port.
	NETWORK_BIND_TCP Network = syscall.AccessNetBindTCP

	// NETWORK_CONNECT_TCP allows connecting TCP sockets to a port.
	NETWORK_CONNECT_TCP Network = syscall.AccessNetConnectTCP
)
