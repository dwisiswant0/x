// nolint
//go:build darwin && cgo
// +build darwin,cgo

package sandboxec

/*
#cgo CFLAGS: -Wno-deprecated-declarations

#include <sandbox.h>
#include <stdlib.h>
*/
import "C"

import (
	"fmt"
	"strings"
	"unsafe"
)

func applySeatbelt(policy string, flags uint64) error {
	policyPtr := C.CString(policy)
	defer C.free(unsafe.Pointer(policyPtr))

	var errBuf *C.char
	result := C.sandbox_init(policyPtr, C.uint64_t(flags), &errBuf)
	if errBuf != nil {
		defer C.sandbox_free_error(errBuf)
	}

	if result != 0 {
		if errBuf != nil {
			return fmt.Errorf("%w: sandbox_init returned %d: %s", ErrSeatbeltUnavailable, result, strings.TrimSpace(C.GoString(errBuf)))
		}

		return fmt.Errorf("%w: sandbox_init returned %d", ErrSeatbeltUnavailable, result)
	}

	return nil
}
