// nolint
//go:build darwin && cgo
// +build darwin,cgo

package seatbelt

/*
#cgo CFLAGS: -Wno-deprecated-declarations

#include <sandbox.h>
#include <stdlib.h>
*/
import "C"

import "unsafe"

func sandboxInit(profile string) error {
	profilePtr := C.CString(profile)
	defer C.free(unsafe.Pointer(profilePtr))

	var errBuf *C.char
	result := C.sandbox_init(profilePtr, sbplFlags, &errBuf)
	if errBuf != nil {
		defer C.sandbox_free_error(errBuf)
	}

	if result != 0 {
		return initError(int32(result), C.GoString(errBuf))
	}

	return nil
}
