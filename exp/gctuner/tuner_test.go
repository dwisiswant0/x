package gctuner

import (
	"runtime"
	"runtime/debug"
	"sync"
	"testing"
)

var testHeap []byte

func TestTuner(t *testing.T) {
	memLimit := uint64(100 * 1024 * 1024) //100 MB
	threshold := memLimit / 2
	tn := newTuner(threshold)
	currentGCPercent := tn.getGCPercent()
	if tn.threshold != threshold {
		t.Fatalf("expected threshold %d, got %d", threshold, tn.threshold)
	}

	if currentGCPercent != defaultGCPercent {
		t.Fatalf("expected default gc percent %d, got %d", defaultGCPercent, currentGCPercent)
	}

	// wait for tuner set gcPercent to maxGCPercent
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	for tn.getGCPercent() != maxGCPercent {
		runtime.GC()
		t.Logf("new gc percent after gc: %d", tn.getGCPercent())
	}

	// 1/4 threshold
	testHeap = make([]byte, threshold/4)

	// wait for tuner set gcPercent to ~= 300
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	for tn.getGCPercent() == maxGCPercent {
		runtime.GC()
		t.Logf("new gc percent after gc: %d", tn.getGCPercent())
	}

	currentGCPercent = tn.getGCPercent()
	if currentGCPercent < uint32(250) {
		t.Fatalf("expected gc percent >= 250, got %d", currentGCPercent)
	}

	if currentGCPercent > uint32(300) {
		t.Fatalf("expected gc percent <= 300, got %d", currentGCPercent)
	}

	// 1/2 threshold
	testHeap = make([]byte, threshold/2)

	// wait for tuner set gcPercent to ~= 100
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	for tn.getGCPercent() == currentGCPercent {
		runtime.GC()
		t.Logf("new gc percent after gc: %d", tn.getGCPercent())
	}

	currentGCPercent = tn.getGCPercent()
	if currentGCPercent < uint32(50) {
		t.Fatalf("expected gc percent >= 50, got %d", currentGCPercent)
	}

	if currentGCPercent > uint32(100) {
		t.Fatalf("expected gc percent <= 100, got %d", currentGCPercent)
	}

	// 3/4 threshold
	testHeap = make([]byte, threshold/4*3)

	// wait for tuner set gcPercent to minGCPercent
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	for tn.getGCPercent() != minGCPercent {
		runtime.GC()
		t.Logf("new gc percent after gc: %d", tn.getGCPercent())
	}

	if tn.getGCPercent() != minGCPercent {
		t.Fatalf("expected min gc percent %d, got %d", minGCPercent, tn.getGCPercent())
	}

	// out of threshold
	testHeap = make([]byte, threshold+1024)
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	runtime.GC()

	for i := 0; i < 8; i++ {
		runtime.GC()
		if tn.getGCPercent() != minGCPercent {
			t.Fatalf("expected min gc percent %d, got %d", minGCPercent, tn.getGCPercent())
		}
	}

	// no heap
	testHeap = nil

	// wait for tuner set gcPercent to maxGCPercent
	t.Logf("old gc percent before gc: %d", tn.getGCPercent())
	for tn.getGCPercent() != maxGCPercent {
		runtime.GC()
		t.Logf("new gc percent after gc: %d", tn.getGCPercent())
	}
}

func TestCalcGCPercent(t *testing.T) {
	const gb = 1024 * 1024 * 1024

	// use default value when invalid params
	if calcGCPercent(0, 0) != defaultGCPercent {
		t.Fatalf("expected default gc percent %d for (0,0)", defaultGCPercent)
	}

	if calcGCPercent(0, 1) != defaultGCPercent {
		t.Fatalf("expected default gc percent %d for (0,1)", defaultGCPercent)
	}

	if calcGCPercent(1, 0) != defaultGCPercent {
		t.Fatalf("expected default gc percent %d for (1,0)", defaultGCPercent)
	}

	if calcGCPercent(1, 3*gb) != maxGCPercent {
		t.Fatalf("expected max gc percent %d for (1,3gb)", maxGCPercent)
	}

	if calcGCPercent(gb/10, 4*gb) != maxGCPercent {
		t.Fatalf("expected max gc percent %d for (gb/10,4gb)", maxGCPercent)
	}

	if calcGCPercent(gb/2, 4*gb) != maxGCPercent {
		t.Fatalf("expected max gc percent %d for (gb/2,4gb)", maxGCPercent)
	}

	if calcGCPercent(1*gb, 4*gb) != uint32(300) {
		t.Fatalf("expected gc percent 300 for (1gb,4gb)")
	}

	if calcGCPercent(1.5*gb, 4*gb) != uint32(166) {
		t.Fatalf("expected gc percent 166 for (1.5gb,4gb)")
	}

	if calcGCPercent(2*gb, 4*gb) != uint32(100) {
		t.Fatalf("expected gc percent 100 for (2gb,4gb)")
	}

	if calcGCPercent(3*gb, 4*gb) != minGCPercent {
		t.Fatalf("expected min gc percent %d for (3gb,4gb)", minGCPercent)
	}

	if calcGCPercent(4*gb, 4*gb) != minGCPercent {
		t.Fatalf("expected min gc percent %d for (4gb,4gb)", minGCPercent)
	}

	if calcGCPercent(5*gb, 4*gb) != minGCPercent {
		t.Fatalf("expected min gc percent %d for (5gb,4gb)", minGCPercent)
	}
}

func TestTunerSetGetThresholdAndGCPercent(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	prev := debug.SetGCPercent(100)
	defer debug.SetGCPercent(prev)

	tn := newTuner(1024)
	defer tn.stop()

	if got := tn.getThreshold(); got != 1024 {
		t.Fatalf("expected threshold 1024, got %d", got)
	}

	tn.setThreshold(2048)
	if got := tn.getThreshold(); got != 2048 {
		t.Fatalf("expected threshold 2048, got %d", got)
	}

	old := tn.setGCPercent(150)
	if old != 100 {
		t.Fatalf("expected previous gc percent 100, got %d", old)
	}

	if got := tn.getGCPercent(); got != 150 {
		t.Fatalf("expected gc percent 150, got %d", got)
	}
}

func TestGetGCPercentWhenDisabled(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	if err := Enable(0); err != nil {
		t.Fatalf("unexpected error disabling tuner: %v", err)
	}
	if globalTuner != nil {
		globalTuner.stop()
		globalTuner = nil
	}

	defaultGCPercent = 123
	defaultGCOnce = sync.Once{}
	defaultGCOnce.Do(func() {})
	if got := GetGCPercent(); got != 123 {
		t.Fatalf("expected gc percent 123 when disabled, got %d", got)
	}
}

func TestGetGCPercentWhenEnabled(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	tn := newTuner(4096)
	defer tn.stop()

	prev := tn.setGCPercent(222)
	defer debug.SetGCPercent(int(prev))

	globalTuner = tn
	if got := GetGCPercent(); got != 222 {
		t.Fatalf("expected gc percent 222 when enabled, got %d", got)
	}
}
