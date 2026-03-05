// nolint
//go:build darwin && cgo
// +build darwin,cgo

package sandboxec

import "fmt"

func applySeatbelt(policy string, flags uint64) error {
	_ = policy
	_ = flags

	return fmt.Errorf("%w: goffi requires CGO_ENABLED=0 on darwin", ErrSeatbeltUnavailable)
}
