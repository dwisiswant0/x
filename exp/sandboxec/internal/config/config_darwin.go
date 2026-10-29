//go:build darwin
// +build darwin

package config

// Config is the Seatbelt sandbox configuration.
type Config struct {
	BestEffort bool
	FSRules    []FSRule
	NetRules   []NetRule
}
