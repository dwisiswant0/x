// nolint
//go:build go1.19
// +build go1.19

package gctuner

// tuning check the memory inuse and tune GC percent dynamically.
// Go runtime ensure that it will be called serially.
func (t *tuner) tuning() {
	inuse := readMemoryInuse()
	threshold := t.getThreshold()

	// stop gc tuning
	if threshold <= 0 {
		return
	}

	setMemoryLimit(threshold)

	// keep adjusting GOGC to cooperate with memory limit
	t.setGCPercent(calcGCPercent(inuse, threshold))
}
