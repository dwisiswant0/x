// Package auto enables gctuner on import with reasonable defaults.
//
// Importing this package has side effects: it configures a memory limit and
// starts the tuner during init. Defaults are captured at init time and can be
// overridden by changing the exported variables before import.
// See [MemLimitPercent], [MinGCPercent], and [MaxGCPercent].
package auto
