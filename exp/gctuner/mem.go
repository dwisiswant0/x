package gctuner

import (
	"runtime"

	"go.dw1.io/x/exp/gctuner/internal/memory"
)

var memStats runtime.MemStats

func readMemoryInuse() uint64 {
	runtime.ReadMemStats(&memStats)

	return memStats.HeapInuse
}

func getMemoryLimit() uint64 {
	if limit := readGOMEMLIMIT(); limit > 0 {
		return uint64(limit)
	}

	return memory.GetMemoryLimit()
}
