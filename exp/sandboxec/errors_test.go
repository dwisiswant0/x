// nolint
//go:build linux || darwin
// +build linux darwin

package sandboxec

import (
	"errors"
	"fmt"
	"testing"
)

func TestUnavailableErrorsMatchErrUnavailable(t *testing.T) {
	for _, sentinel := range []error{ErrLandlockUnavailable, ErrSeatbeltUnavailable} {
		err := fmt.Errorf("%w: detail", sentinel)

		if !errors.Is(err, ErrUnavailable) {
			t.Errorf("%v does not match ErrUnavailable", err)
		}

		if !errors.Is(err, sentinel) {
			t.Errorf("%v does not match %v", err, sentinel)
		}
	}

	if errors.Is(ErrLandlockUnavailable, ErrSeatbeltUnavailable) {
		t.Error("ErrLandlockUnavailable matches ErrSeatbeltUnavailable")
	}

	for _, other := range []error{ErrABINotSupported, ErrInvalidOption} {
		if errors.Is(other, ErrUnavailable) {
			t.Errorf("%v matches ErrUnavailable", other)
		}
	}
}
