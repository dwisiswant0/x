// nolint
//go:build darwin && !cgo
// +build darwin,!cgo

package sandboxec

import (
	"testing"
)

func TestDarwinNoCGOSeatbeltProbeDoesNotCrash(t *testing.T) {
	runHelperDarwin(t, "seatbelt-probe", nil)
}
