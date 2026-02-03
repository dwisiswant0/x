//go:build linux
// +build linux

package memory

import (
	"bufio"
	"os"
	"strconv"
	"strings"

	"go.dw1.io/x/exp/gctuner/internal/cgroup"
)

func sysTotalMemory() uint64 {
	totalMem := readMemInfoValue("MemTotal")
	if totalMem == 0 {
		return 0
	}

	mem := cgroup.GetMemoryLimit()
	if mem <= 0 || int64(int(mem)) != mem || uint64(mem) > totalMem {
		// Try reading hierarchical memory limit.
		mem = cgroup.GetHierarchicalMemoryLimit()
		if mem <= 0 || int64(int(mem)) != mem || uint64(mem) > totalMem {
			return totalMem
		}
	}

	return uint64(mem)
}

func sysFreeMemory() uint64 {
	total := sysTotalMemory()
	usage := cgroup.GetMemoryUsage()

	if usage > 0 && int64(int(usage)) == usage && uint64(usage) <= total {
		return total - uint64(usage)
	}

	freeMem := readMemInfoValue("MemAvailable")
	if freeMem == 0 {
		freeMem = readMemInfoValue("MemFree")
	}

	return freeMem
}

func readMemInfoValue(key string) uint64 {
	file, err := os.Open("/proc/meminfo")
	if err != nil {
		return 0
	}
	defer func() { _ = file.Close() }()

	scanner := bufio.NewScanner(file)
	prefix := key + ":"

	for scanner.Scan() {
		line := strings.TrimSpace(scanner.Text())
		if !strings.HasPrefix(line, prefix) {
			continue
		}

		fields := strings.Fields(line)
		if len(fields) < 2 {
			return 0
		}

		value, err := strconv.ParseUint(fields[1], 10, 64)
		if err != nil {
			return 0
		}

		// meminfo values are in kB
		return value * 1024
	}

	return 0
}
