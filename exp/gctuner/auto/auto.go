package auto

import "go.dw1.io/x/exp/gctuner"

var (
	// MemLimitPercent is the default memory limit (bytes) used by auto.
	// It is derived from 70% of the effective memory limit at init time.
	MemLimitPercent = gctuner.GetMemLimitPercent(70)

	// MinGCPercent is the default minimum GOGC bound used by auto.
	MinGCPercent = gctuner.GetMinGCPercent()

	// MaxGCPercent is the default maximum GOGC bound used by auto.
	MaxGCPercent = gctuner.GetMaxGCPercent()
)

func init() {
	gctuner.SetMemLimitPercent(float64(MemLimitPercent))
	gctuner.MustEnable(
		-1,
		gctuner.WithMinGCPercent(MinGCPercent),
		gctuner.WithMaxGCPercent(MaxGCPercent),
	)
}
