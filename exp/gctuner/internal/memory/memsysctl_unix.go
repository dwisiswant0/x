// nolint
//go:build darwin || freebsd || openbsd || dragonfly || netbsd
// +build darwin freebsd openbsd dragonfly netbsd

package memory

import (
	"syscall"
	"unsafe"
)

func sysctlUint64(name string) (uint64, bool) {
	value, err := syscall.Sysctl(name)
	if err != nil {
		return 0, false
	}

	// Sysctl returns a string; convert to bytes and decode uint64.
	b := []byte(value)
	if len(b) < 8 {
		b = append(b, 0)
	}

	return *(*uint64)(unsafe.Pointer(&b[0])), true
}
