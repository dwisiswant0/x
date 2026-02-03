// nolint
//go:build !linux
// +build !linux

package memory

// sysTotalMemory returns total system memory. Unknown on non-linux.
func sysTotalMemory() uint64 {
	return 0
}

// sysFreeMemory returns free system memory. Unknown on non-linux.
func sysFreeMemory() uint64 {
	return 0
}
