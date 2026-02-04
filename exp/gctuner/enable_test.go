package gctuner

import (
	"os"
	"sync"
	"sync/atomic"
	"testing"
)

func saveAndResetState(t *testing.T) func() {
	t.Helper()

	oldMin := atomic.LoadUint32(&minGCPercent)
	oldMax := atomic.LoadUint32(&maxGCPercent)
	oldDefault := defaultGCPercent
	oldGlobal := globalTuner
	oldOverride := atomic.LoadUint64(&memLimitOverride)
	oldOverrideSet := atomic.LoadUint32(&memLimitOverrideSet)
	oldGOGC := os.Getenv("GOGC")
	oldGOMEMLIMIT := os.Getenv("GOMEMLIMIT")

	return func() {
		if globalTuner != nil {
			globalTuner.stop()
		}

		globalTuner = oldGlobal
		atomic.StoreUint32(&minGCPercent, oldMin)
		atomic.StoreUint32(&maxGCPercent, oldMax)
		defaultGCPercent = oldDefault
		defaultGCOnce = sync.Once{}
		atomic.StoreUint64(&memLimitOverride, oldOverride)
		atomic.StoreUint32(&memLimitOverrideSet, oldOverrideSet)

		if oldGOGC == "" {
			_ = os.Unsetenv("GOGC")
		} else {
			_ = os.Setenv("GOGC", oldGOGC)
		}

		if oldGOMEMLIMIT == "" {
			_ = os.Unsetenv("GOMEMLIMIT")
		} else {
			_ = os.Setenv("GOMEMLIMIT", oldGOMEMLIMIT)
		}
	}
}

func TestGetDefaultGCPercentFromEnv(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	_ = os.Setenv("GOGC", "200")
	defaultGCOnce = sync.Once{}
	if got := getDefaultGCPercent(); got != 200 {
		t.Fatalf("expected default gc percent 200, got %d", got)
	}

	_ = os.Setenv("GOGC", "-1")
	defaultGCOnce = sync.Once{}
	if got := getDefaultGCPercent(); got != 100 {
		t.Fatalf("expected default gc percent 100 for negative, got %d", got)
	}

	_ = os.Setenv("GOGC", "not-a-number")
	defaultGCOnce = sync.Once{}
	if got := getDefaultGCPercent(); got != 100 {
		t.Fatalf("expected default gc percent 100 for invalid, got %d", got)
	}
}

func TestValidateGCPercentRange(t *testing.T) {
	cases := []struct {
		name    string
		min     uint32
		max     uint32
		wantErr bool
	}{
		{"min-zero", 0, 100, true},
		{"max-zero", 50, 0, true},
		{"min-greater", 200, 100, true},
		{"ok", 50, 500, false},
	}

	for _, tc := range cases {
		if err := validateGCPercentRange(tc.min, tc.max); (err != nil) != tc.wantErr {
			t.Fatalf("%s: expected error=%v, got %v", tc.name, tc.wantErr, err)
		}
	}
}

func TestNormalizeThreshold(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	if got, disable, err := normalizeThreshold(0); err != nil || !disable || got != 0 {
		t.Fatalf("expected disable with zero threshold, got %d disable=%v err=%v", got, disable, err)
	}

	atomic.StoreUint64(&memLimitOverride, 12345)
	atomic.StoreUint32(&memLimitOverrideSet, 1)
	if got, disable, err := normalizeThreshold(-1); err != nil || disable || got != 12345 {
		t.Fatalf("expected override threshold 12345, got %d disable=%v err=%v", got, disable, err)
	}

	if got, disable, err := normalizeThreshold(2048); err != nil || disable || got != 2048 {
		t.Fatalf("expected threshold 2048, got %d disable=%v err=%v", got, disable, err)
	}
}

func TestEnableDisableAndUpdate(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	atomic.StoreUint64(&memLimitOverride, 4096)
	atomic.StoreUint32(&memLimitOverrideSet, 1)

	if err := Enable(-1); err != nil {
		t.Fatalf("expected Enable(-1) to succeed, got %v", err)
	}
	if globalTuner == nil || globalTuner.getThreshold() != 4096 {
		t.Fatalf("expected global tuner threshold 4096, got %v", globalTuner)
	}

	if err := Enable(8192); err != nil {
		t.Fatalf("expected Enable(8192) to succeed, got %v", err)
	}
	if globalTuner == nil || globalTuner.getThreshold() != 8192 {
		t.Fatalf("expected global tuner threshold 8192, got %v", globalTuner)
	}

	if err := Enable(0); err != nil {
		t.Fatalf("expected Enable(0) to succeed, got %v", err)
	}
	if globalTuner != nil {
		t.Fatalf("expected global tuner to be nil after disable")
	}
}

func TestEnableOptionValidation(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	if err := Enable(1024, WithMinGCPercent(0)); err == nil {
		t.Fatalf("expected error for min gc percent 0")
	}

	if err := Enable(1024, WithMinGCPercent(200), WithMaxGCPercent(100)); err == nil {
		t.Fatalf("expected error for min > max")
	}
}
