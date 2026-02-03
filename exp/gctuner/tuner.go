package gctuner

import (
	"fmt"
	"math"
	"math/bits"
	"os"
	"runtime/debug"
	"strconv"
	"sync"
	"sync/atomic"
)

var (
	maxGCPercent uint32 = 500
	minGCPercent uint32 = 50

	defaultGCPercent uint32 = 100
	defaultGCOnce    sync.Once

	tunerMu sync.Mutex

	memLimitOverride    uint64
	memLimitOverrideSet uint32
)

func getDefaultGCPercent() uint32 {
	defaultGCOnce.Do(func() {
		defaultGCPercent = readGOGC()
	})

	return defaultGCPercent
}

func readGOGC() uint32 {
	gogc, err := strconv.ParseInt(os.Getenv("GOGC"), 10, 32)
	if err != nil || gogc < 0 {
		return 100
	}

	return uint32(gogc)
}

// Enable starts or updates GC tuning with the given threshold and options.
//
// Threshold semantics:
//   - 0 disables the tuner
//   - -1 derives the threshold from the effective memory limit (or a
//     [SetMemLimitPercent] override, if set)
//   - >0 uses the provided byte value directly
//
// Enable returns an error if the threshold cannot be resolved (for -1), or if
// any provided options are invalid.
func Enable(threshold int64, opts ...Option) error {
	tunerMu.Lock()
	defer tunerMu.Unlock()

	cfg := &options{}
	for _, opt := range opts {
		if opt != nil {
			opt(cfg)
		}
	}

	if err := validateOptions(cfg); err != nil {
		return err
	}

	if cfg.minGCPercent != nil {
		setMinGCPercent(*cfg.minGCPercent)
	}

	if cfg.maxGCPercent != nil {
		setMaxGCPercent(*cfg.maxGCPercent)
	}

	if err := validateGCPercentRange(GetMinGCPercent(), GetMaxGCPercent()); err != nil {
		return err
	}

	resolvedThreshold, disable, err := normalizeThreshold(threshold)
	if err != nil {
		return err
	}

	// disable gc tuner if percent is zero
	if disable && globalTuner != nil {
		globalTuner.stop()
		globalTuner = nil

		return nil
	}

	if globalTuner == nil {
		globalTuner = newTuner(resolvedThreshold)

		return nil
	}

	globalTuner.setThreshold(resolvedThreshold)

	return nil
}

// MustEnable is like Enable but panics on error.
func MustEnable(threshold int64, opts ...Option) {
	if err := Enable(threshold, opts...); err != nil {
		panic(err)
	}
}

func normalizeThreshold(threshold int64) (uint64, bool, error) {
	if threshold == 0 {
		return 0, true, nil
	}

	if threshold < 0 {
		if override, ok := getMemLimitOverride(); ok {
			return override, false, nil
		}

		limit := GetMemLimitPercent(-1)
		if limit == 0 {
			return 0, false, fmt.Errorf("unable to resolve memory limit for threshold")
		}

		return limit, false, nil
	}

	return uint64(threshold), false, nil
}

// GetGCPercent returns the current effective GC percent used by the tuner.
// If the tuner is disabled, it returns the process default (GOGC or 100).
func GetGCPercent() uint32 {
	tunerMu.Lock()
	defer tunerMu.Unlock()

	if globalTuner == nil {
		return getDefaultGCPercent()
	}

	return globalTuner.getGCPercent()
}

// GetMaxGCPercent returns the current maximum GC percent allowed.
func GetMaxGCPercent() uint32 {
	return atomic.LoadUint32(&maxGCPercent)
}

// setMaxGCPercent sets the maximum GC percent allowed and returns the old value.
func setMaxGCPercent(n uint32) uint32 {
	return atomic.SwapUint32(&maxGCPercent, n)
}

// GetMinGCPercent returns the current minimum GC percent allowed.
func GetMinGCPercent() uint32 {
	return atomic.LoadUint32(&minGCPercent)
}

// setMinGCPercent sets the minimum GC percent allowed and returns the old value.
func setMinGCPercent(n uint32) uint32 {
	return atomic.SwapUint32(&minGCPercent, n)
}

// GetMemLimitPercent gets the memory limit based on the given percentage of the
// detected memory limit and returns the value in bytes.
//
// If percent < 0, it returns the total memory limit in bytes. If percent == 0,
// it returns 0. If percent > 100, it is clamped to 100. On Go 1.19 and newer,
// a valid GOMEMLIMIT value (if set) overrides the detected system or cgroup
// limit.
func GetMemLimitPercent(percent float64) uint64 {
	limit := getMemoryLimit()
	if limit == 0 {
		return 0
	}

	if percent < 0 {
		return limit
	}

	if percent == 0 {
		return 0
	}

	if percent > 100 {
		percent = 100
	}

	value := percent / 100 * float64(limit)
	if value > float64(math.MaxUint64) {
		return math.MaxUint64
	}

	return uint64(value)
}

// SetMemLimitPercent sets the Go memory limit based on a percentage of the
// detected memory limit.
//
// On Go <= 1.19, it is a no-op. If percent resolves to 0, the override is
// cleared. If percent > 100, it is clamped to 100.
func SetMemLimitPercent(percent float64) {
	limit := GetMemLimitPercent(percent)
	if limit == 0 {
		atomic.StoreUint32(&memLimitOverrideSet, 0)

		return
	}

	atomic.StoreUint64(&memLimitOverride, limit)
	atomic.StoreUint32(&memLimitOverrideSet, 1)

	setMemoryLimit(limit)
}

func getMemLimitOverride() (uint64, bool) {
	if atomic.LoadUint32(&memLimitOverrideSet) == 0 {
		return 0, false
	}

	return atomic.LoadUint64(&memLimitOverride), true
}

func validateOptions(cfg *options) error {
	min := GetMinGCPercent()
	max := GetMaxGCPercent()

	if cfg.minGCPercent != nil {
		min = *cfg.minGCPercent
	}

	if cfg.maxGCPercent != nil {
		max = *cfg.maxGCPercent
	}

	return validateGCPercentRange(min, max)
}

func validateGCPercentRange(min, max uint32) error {
	if min == 0 {
		return fmt.Errorf("invalid min gc percent: %d", min)
	}

	if max == 0 {
		return fmt.Errorf("invalid max gc percent: %d", max)
	}

	if min > max {
		return fmt.Errorf("min gc percent %d is greater than max gc percent %d", min, max)
	}

	return nil
}

// only allow one gc tuner in one process
var globalTuner *tuner = nil

/*
	Heap

________________  => limit: host/cgroup memory hard limit
|               |
|---------------| => threshold: increase GCPercent when gc_trigger < threshold
|               |
|---------------| => gc_trigger: heap_live + heap_live * GCPercent / 100
|               |
|---------------|
|   heap_live   |
|_______________|

Go runtime only trigger GC when hit gc_trigger which affected by GCPercent and heap_live.
So we can change GCPercent dynamically to tuning GC performance.
*/
type tuner struct {
	finalizer *finalizer
	gcPercent uint32
	threshold uint64 // high water level, in bytes
}

// threshold = inuse + inuse * (gcPercent / 100)
// => gcPercent = (threshold - inuse) / inuse * 100
// if threshold < inuse*2, so gcPercent < 100, and GC positively to avoid OOM
// if threshold > inuse*2, so gcPercent > 100, and GC negatively to reduce GC times
func calcGCPercent(inuse, threshold uint64) uint32 {
	// invalid params
	if inuse == 0 || threshold == 0 {
		return getDefaultGCPercent()
	}

	minPercent := GetMinGCPercent()
	maxPercent := GetMaxGCPercent()

	// inuse heap larger than threshold, use min percent
	if threshold <= inuse {
		return minPercent
	}

	diff := threshold - inuse
	hi, lo := bits.Mul64(diff, 100)
	q, _ := bits.Div64(hi, lo, inuse)

	gcPercent := uint32(q)
	if gcPercent < minPercent {
		return minPercent
	} else if gcPercent > maxPercent {
		return maxPercent
	}

	return gcPercent
}

func newTuner(threshold uint64) *tuner {
	t := &tuner{
		gcPercent: getDefaultGCPercent(),
		threshold: threshold,
	}
	t.finalizer = newFinalizer(t.tuning) // start tuning

	return t
}

func (t *tuner) stop() {
	t.finalizer.stop()
}

func (t *tuner) setThreshold(threshold uint64) {
	atomic.StoreUint64(&t.threshold, threshold)
}

func (t *tuner) getThreshold() uint64 {
	return atomic.LoadUint64(&t.threshold)
}

func (t *tuner) setGCPercent(percent uint32) uint32 {
	atomic.StoreUint32(&t.gcPercent, percent)

	return uint32(debug.SetGCPercent(int(percent)))
}

func (t *tuner) getGCPercent() uint32 {
	return atomic.LoadUint32(&t.gcPercent)
}
