//go:build linux
// +build linux

package config

// MaxABI is the highest Landlock ABI version sandboxec supports.
const MaxABI = 7

// Config is the Landlock sandbox configuration.
type Config struct {
	// ABI is the Landlock ABI version to enforce. 0 selects the highest
	// version supported by both the kernel and sandboxec.
	ABI             int
	BestEffort      bool
	IgnoreIfMissing bool
	RestrictScoped  bool
	FSRules         []FSRule
	NetRules        []NetRule
}
