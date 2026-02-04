// nolint
//go:build windows
// +build windows

package memory

import (
	"unsafe"

	"syscall"
)

type memoryStatusEx struct {
	Length               uint32
	MemoryLoad           uint32
	TotalPhys            uint64
	AvailPhys            uint64
	TotalPageFile        uint64
	AvailPageFile        uint64
	TotalVirtual         uint64
	AvailVirtual         uint64
	AvailExtendedVirtual uint64
}

var (
	modKernel32              = syscall.NewLazyDLL("kernel32.dll")
	procGlobalMemoryStatusEx = modKernel32.NewProc("GlobalMemoryStatusEx")
)

func globalMemoryStatusEx(mem *memoryStatusEx) bool {
	r1, _, _ := procGlobalMemoryStatusEx.Call(uintptr(unsafe.Pointer(mem)))
	return r1 != 0
}

func sysTotalMemory() uint64 {
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	if !globalMemoryStatusEx(&mem) {
		return 0
	}

	return mem.TotalPhys
}

func sysFreeMemory() uint64 {
	var mem memoryStatusEx
	mem.Length = uint32(unsafe.Sizeof(mem))
	if !globalMemoryStatusEx(&mem) {
		return 0
	}

	return mem.AvailPhys
}
