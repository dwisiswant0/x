//go:build darwin && !cgo
// +build darwin,!cgo

package seatbelt

import (
	"fmt"
	"runtime"
	"sync"
	"unsafe"

	"github.com/go-webgpu/goffi/ffi"
	"github.com/go-webgpu/goffi/types"
)

const libPath = "/usr/lib/libsandbox.1.dylib"

var (
	loadOnce sync.Once
	loadErr  error
	lib      symbols
)

type symbols struct {
	handle unsafe.Pointer

	sandboxInit      unsafe.Pointer
	sandboxFreeError unsafe.Pointer

	sandboxInitCIF      types.CallInterface
	sandboxFreeErrorCIF types.CallInterface
}

func sandboxInit(profile string) error {
	if err := load(); err != nil {
		return err
	}

	profileBytes := append([]byte(profile), 0)
	profileArg := unsafe.Pointer(&profileBytes[0])

	flagsArg := uint64(sbplFlags)
	var errBuf unsafe.Pointer
	errBufArg := unsafe.Pointer(&errBuf)
	var result int32

	_, err := ffi.CallFunction(
		&lib.sandboxInitCIF,
		lib.sandboxInit,
		unsafe.Pointer(&result),
		[]unsafe.Pointer{unsafe.Pointer(&profileArg), unsafe.Pointer(&flagsArg), unsafe.Pointer(&errBufArg)},
	)
	runtime.KeepAlive(profileBytes)
	if err != nil {
		return fmt.Errorf("call sandbox_init: %v", err)
	}

	if errBuf != nil {
		defer func() {
			_ = freeError(errBuf)
		}()
	}

	if result != 0 {
		return initError(result, cString(errBuf))
	}

	return nil
}

// load resolves sandbox_init and sandbox_free_error. They live in
// libsystem_sandbox, which dlsym finds through libsandbox's dependencies.
func load() error {
	loadOnce.Do(func() {
		var err error

		lib.handle, err = ffi.LoadLibrary(libPath)
		if err != nil {
			loadErr = fmt.Errorf("load seatbelt library %q: %v", libPath, err)
			return
		}

		lib.sandboxInit, err = ffi.GetSymbol(lib.handle, "sandbox_init")
		if err != nil {
			loadErr = fmt.Errorf("resolve sandbox_init: %v", err)
			return
		}

		lib.sandboxFreeError, err = ffi.GetSymbol(lib.handle, "sandbox_free_error")
		if err != nil {
			loadErr = fmt.Errorf("resolve sandbox_free_error: %v", err)
			return
		}

		err = ffi.PrepareCallInterface(
			&lib.sandboxInitCIF,
			types.DefaultCall,
			types.SInt32TypeDescriptor,
			[]*types.TypeDescriptor{
				types.PointerTypeDescriptor,
				types.UInt64TypeDescriptor,
				types.PointerTypeDescriptor,
			},
		)
		if err != nil {
			loadErr = fmt.Errorf("prepare sandbox_init interface: %v", err)
			return
		}

		err = ffi.PrepareCallInterface(
			&lib.sandboxFreeErrorCIF,
			types.DefaultCall,
			types.VoidTypeDescriptor,
			[]*types.TypeDescriptor{types.PointerTypeDescriptor},
		)
		if err != nil {
			loadErr = fmt.Errorf("prepare sandbox_free_error interface: %v", err)
			return
		}
	})

	return loadErr
}

func freeError(ptr unsafe.Pointer) error {
	if ptr == nil {
		return nil
	}

	_, err := ffi.CallFunction(
		&lib.sandboxFreeErrorCIF,
		lib.sandboxFreeError,
		nil,
		[]unsafe.Pointer{unsafe.Pointer(&ptr)},
	)

	return err
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
