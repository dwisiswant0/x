package gctuner

import (
	"runtime"
	"runtime/debug"
	"sync/atomic"
	"testing"
)

func TestFinalizer(t *testing.T) {
	var count int32

	// disable gc
	debug.SetGCPercent(-1)
	defer debug.SetGCPercent(100)

	maxCount := int32(16)
	f := newFinalizer(func() {
		n := atomic.AddInt32(&count, 1)
		if n > maxCount {
			t.Fatalf("cannot exec finalizer callback after f has been gc")
		}
	})

	for atomic.LoadInt32(&count) < maxCount {
		runtime.GC()
	}

	if f.ref != nil {
		t.Fatalf("expected finalizer ref to be nil")
	}

	f.stop()

	// when f stopped, finalizer callback will not be called
	lastCount := atomic.LoadInt32(&count)
	for i := 0; i < 10; i++ {
		runtime.GC()
		if atomic.LoadInt32(&count) != lastCount {
			t.Fatalf("expected finalizer count to remain %d, got %d", lastCount, atomic.LoadInt32(&count))
		}
	}
}
