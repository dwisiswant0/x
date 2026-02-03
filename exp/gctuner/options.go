package gctuner

type options struct {
	minGCPercent *uint32
	maxGCPercent *uint32
}

// Option configures behavior for [Enable].
type Option func(*options)

// WithMinGCPercent sets the minimum GC percent used by the tuner.
// Values of 0 are invalid.
func WithMinGCPercent(percent uint32) Option {
	return func(o *options) {
		o.minGCPercent = &percent
	}
}

// WithMaxGCPercent sets the maximum GC percent used by the tuner.
// Values of 0 are invalid.
func WithMaxGCPercent(percent uint32) Option {
	return func(o *options) {
		o.maxGCPercent = &percent
	}
}
