// nolint
//go:build darwin && !cgo
// +build darwin,!cgo

package sandboxec

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/go-webgpu/goffi/ffi"
	"github.com/go-webgpu/goffi/types"
)

const (
	seatbeltLibPath = "/usr/lib/libsandbox.1.dylib"
	libSystemPath   = "/usr/lib/libSystem.B.dylib"
)

var (
	seatbeltInitOnce sync.Once
	seatbeltInitErr  error
	seatbeltRuntime  seatbeltSymbols
)

type seatbeltSymbols struct {
	sandboxLib unsafe.Pointer
	libSystem  unsafe.Pointer

	sandboxInit unsafe.Pointer
	libcFree    unsafe.Pointer

	sandboxInitCIF types.CallInterface
	freeCIF        types.CallInterface
}

func applySeatbelt(policy string, flags uint64) error {
	if err := initSeatbeltRuntime(); err != nil {
		return err
	}

	policyBytes := append([]byte(policy), 0)
	policyPtr := unsafe.Pointer(&policyBytes[0])

	flagsArg := flags
	var errBuf uintptr
	var result int32

	err := ffi.CallFunction(
		&seatbeltRuntime.sandboxInitCIF,
		seatbeltRuntime.sandboxInit,
		unsafe.Pointer(&result),
		[]unsafe.Pointer{policyPtr, unsafe.Pointer(&flagsArg), unsafe.Pointer(&errBuf)},
	)
	runtime.KeepAlive(policyBytes)
	if err != nil {
		return fmt.Errorf("%w: call sandbox_init: %v", ErrSeatbeltUnavailable, err)
	}

	if errBuf != 0 {
		defer func() {
			_ = callLibcFree(unsafe.Pointer(errBuf))
		}()
	}

	if result != 0 {
		if errBuf != 0 {
			return fmt.Errorf("%w: sandbox_init returned %d: %s", ErrSeatbeltUnavailable, result, cString(unsafe.Pointer(errBuf)))
		}

		return fmt.Errorf("%w: sandbox_init returned %d", ErrSeatbeltUnavailable, result)
	}

	return nil
}

func initSeatbeltRuntime() error {
	seatbeltInitOnce.Do(func() {
		var err error

		seatbeltRuntime.sandboxLib, err = ffi.LoadLibrary(seatbeltLibPath)
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: load seatbelt library %q: %v", ErrSeatbeltUnavailable, seatbeltLibPath, err)
			return
		}

		seatbeltRuntime.libSystem, err = ffi.LoadLibrary(libSystemPath)
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: load libc %q: %v", ErrSeatbeltUnavailable, libSystemPath, err)
			return
		}

		seatbeltRuntime.sandboxInit, err = ffi.GetSymbol(seatbeltRuntime.sandboxLib, "sandbox_init")
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: resolve sandbox_init: %v", ErrSeatbeltUnavailable, err)
			return
		}

		seatbeltRuntime.libcFree, err = ffi.GetSymbol(seatbeltRuntime.libSystem, "free")
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: resolve free: %v", ErrSeatbeltUnavailable, err)
			return
		}

		err = ffi.PrepareCallInterface(
			&seatbeltRuntime.sandboxInitCIF,
			types.DefaultCall,
			types.SInt32TypeDescriptor,
			[]*types.TypeDescriptor{
				types.PointerTypeDescriptor,
				types.UInt64TypeDescriptor,
				types.PointerTypeDescriptor,
			},
		)
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: prepare sandbox_init interface: %v", ErrSeatbeltUnavailable, err)
			return
		}

		err = ffi.PrepareCallInterface(
			&seatbeltRuntime.freeCIF,
			types.DefaultCall,
			types.VoidTypeDescriptor,
			[]*types.TypeDescriptor{types.PointerTypeDescriptor},
		)
		if err != nil {
			seatbeltInitErr = fmt.Errorf("%w: prepare free interface: %v", ErrSeatbeltUnavailable, err)
			return
		}
	})

	return seatbeltInitErr
}

func callLibcFree(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}

	return ffi.CallFunction(
		&seatbeltRuntime.freeCIF,
		seatbeltRuntime.libcFree,
		nil,
		[]unsafe.Pointer{ptr},
	)
}

func cString(ptr unsafe.Pointer) string {
	if ptr == nil {
		return ""
	}

	bytes := make([]byte, 0, 64)
	for idx := uintptr(0); ; idx++ {
		c := *(*byte)(unsafe.Add(ptr, idx))
		if c == 0 {
			break
		}
		bytes = append(bytes, c)
	}

	return string(bytes)
}
