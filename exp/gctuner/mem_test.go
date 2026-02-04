package gctuner

import (
	"runtime"
	"testing"
)

func TestMem(t *testing.T) {
	defer runtime.GC() // make it will not affect other tests

	const mb = 1024 * 1024

	heap := make([]byte, 100*mb+1)
	inuse := readMemoryInuse()
	t.Logf("mem inuse: %d MB", inuse/mb)

	if inuse < uint64(100*mb) {
		t.Fatalf("expected inuse >= %d, got %d", 100*mb, inuse)
	}

	heap[0] = 0
}
