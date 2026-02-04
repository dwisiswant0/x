// nolint
//go:build !go1.19
// +build !go1.19

package gctuner

func readGOMEMLIMIT() int64 {
	return 0
}

func setMemoryLimit(limit uint64) uint64 {
	return 0
}
