// nolint
//go:build !go1.19
// +build !go1.19

package gctuner

import (
	"os"
	"testing"
)

func TestReadGOMEMLIMITPreGo119(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	_ = os.Setenv("GOMEMLIMIT", "128MiB")
	if got := readGOMEMLIMIT(); got != 0 {
		t.Fatalf("expected readGOMEMLIMIT to return 0 on pre-go1.19, got %d", got)
	}
}

func TestSetMemoryLimitPreGo119(t *testing.T) {
	if got := setMemoryLimit(12345); got != 0 {
		t.Fatalf("expected setMemoryLimit to return 0 on pre-go1.19, got %d", got)
	}
}
