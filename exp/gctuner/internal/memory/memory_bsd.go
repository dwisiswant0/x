// nolint
//go:build freebsd || openbsd || dragonfly || netbsd
// +build freebsd openbsd dragonfly netbsd

package memory

func sysTotalMemory() uint64 {
	mem, ok := sysctlUint64("hw.physmem")
	if !ok {
		return 0
	}

	return mem
}

func sysFreeMemory() uint64 {
	mem, ok := sysctlUint64("hw.usermem")
	if !ok {
		return 0
	}

	return mem
}
