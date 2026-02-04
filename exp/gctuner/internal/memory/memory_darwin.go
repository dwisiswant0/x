// nolint
//go:build darwin
// +build darwin

package memory

import (
	"os/exec"
	"regexp"
	"strconv"
)

func sysTotalMemory() uint64 {
	mem, ok := sysctlUint64("hw.memsize")
	if !ok {
		return 0
	}

	return mem
}

func sysFreeMemory() uint64 {
	cmd := exec.Command("vm_stat")
	outBytes, err := cmd.Output()
	if err != nil {
		return 0
	}

	rePageSize := regexp.MustCompile(`page size of ([0-9]*) bytes`)
	reFreePages := regexp.MustCompile(`Pages free: *([0-9]*)\.`)
	reInactivePages := regexp.MustCompile(`Pages inactive: *([0-9]*)\.`)

	matches := rePageSize.FindSubmatchIndex(outBytes)
	pageSize := uint64(4096)
	if len(matches) == 4 {
		pageSize, err = strconv.ParseUint(string(outBytes[matches[2]:matches[3]]), 10, 64)
		if err != nil {
			return 0
		}
	}

	matches = reFreePages.FindSubmatchIndex(outBytes)
	freePages := uint64(0)
	if len(matches) == 4 {
		freePages, err = strconv.ParseUint(string(outBytes[matches[2]:matches[3]]), 10, 64)
		if err != nil {
			return 0
		}
	}

	matches = reInactivePages.FindSubmatchIndex(outBytes)
	inactivePages := uint64(0)
	if len(matches) == 4 {
		inactivePages, err = strconv.ParseUint(string(outBytes[matches[2]:matches[3]]), 10, 64)
		if err != nil {
			return 0
		}
	}

	return (freePages + inactivePages) * pageSize
}
