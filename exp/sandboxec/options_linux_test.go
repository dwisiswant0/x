// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"errors"
	"sync"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

// The landlock package imports this one, so tests here can't use its options.
// These set the same fields directly.

func withABI(version int) Option {
	return func(cfg *config.Config) error {
		cfg.ABI = version

		return nil
	}
}

func withIgnoreIfMissing() Option {
	return func(cfg *config.Config) error {
		cfg.IgnoreIfMissing = true

		return nil
	}
}

func withRestrictScoped() Option {
	return func(cfg *config.Config) error {
		cfg.RestrictScoped = true

		return nil
	}
}

func setLandlockABICacheForTest(version int, err error) {
	landlockABIVersion = version
	landlockABIError = err
	landlockABIOnce = sync.Once{}
	landlockABIOnce.Do(func() {})
}

func resetLandlockABICacheForTest() {
	landlockABIVersion = 0
	landlockABIError = nil
	landlockABIOnce = sync.Once{}
}

func TestLinuxToLandlockConfig(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	for version := 1; version <= config.MaxABI; version++ {
		if _, err := toLandlockConfig(version); err != nil {
			t.Fatalf("expected ABI %d to be supported, got %v", version, err)
		}
	}

	if _, err := toLandlockConfig(0); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for ABI 0, got %v", err)
	}

	if _, err := toLandlockConfig(config.MaxABI + 1); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for ABI %d, got %v", config.MaxABI+1, err)
	}
}

func TestLinuxDefaultABIVersion(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(0, errors.New("unavailable"))
	if got := defaultABIVersion(); got != config.MaxABI {
		t.Fatalf("defaultABIVersion on ABI query error = %d, want %d", got, config.MaxABI)
	}

	setLandlockABICacheForTest(0, nil)
	if got := defaultABIVersion(); got != 1 {
		t.Fatalf("defaultABIVersion below minimum = %d, want 1", got)
	}

	setLandlockABICacheForTest(config.MaxABI+3, nil)
	if got := defaultABIVersion(); got != config.MaxABI {
		t.Fatalf("defaultABIVersion above max = %d, want %d", got, config.MaxABI)
	}

	setLandlockABICacheForTest(5, nil)
	if got := defaultABIVersion(); got != 5 {
		t.Fatalf("defaultABIVersion = %d, want 5", got)
	}
}

func TestLinuxLandlockABI(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(6, nil)

	if got := landlockABI(&config.Config{}); got != 6 {
		t.Fatalf("landlockABI with ABI 0 = %d, want 6", got)
	}

	if got := landlockABI(&config.Config{ABI: 3}); got != 3 {
		t.Fatalf("landlockABI with ABI 3 = %d, want 3", got)
	}
}

func TestLinuxValidateCompatibility(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(config.MaxABI, nil)

	cfg := config.Config{NetRules: []config.NetRule{{Port: 443, Rights: access.NETWORK_CONNECT_TCP}}}
	if err := validateCompatibility(&cfg, 3); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported for network rule on ABI 3, got %v", err)
	}

	cfg = config.Config{RestrictScoped: true}
	if err := validateCompatibility(&cfg, 5); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported for scoped restriction on ABI 5, got %v", err)
	}

	setLandlockABICacheForTest(0, errors.New("kernel missing"))
	cfg = config.Config{BestEffort: true}
	if err := validateCompatibility(&cfg, 7); err != nil {
		t.Fatalf("best-effort compatibility check returned error: %v", err)
	}

	cfg = config.Config{}
	err := validateCompatibility(&cfg, 7)
	if !errors.Is(err, ErrLandlockUnavailable) {
		t.Fatalf("expected ErrLandlockUnavailable, got %v", err)
	}
	if !errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected ErrLandlockUnavailable to match ErrUnavailable, got %v", err)
	}

	setLandlockABICacheForTest(4, nil)
	if err := validateCompatibility(&cfg, 6); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported when requested ABI > supported ABI, got %v", err)
	}

	setLandlockABICacheForTest(6, nil)
	if err := validateCompatibility(&cfg, 6); err != nil {
		t.Fatalf("expected compatibility validation success, got %v", err)
	}
}

func TestLinuxRuleOptionsValidation(t *testing.T) {
	var cfg config.Config

	if err := WithFSRule("", access.FS_READ)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for empty FS path, got %v", err)
	}

	if err := WithFSRule("/tmp", 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero FS rights, got %v", err)
	}

	if err := WithFSRule("/tmp", access.FS_READ_WRITE)(&cfg); err != nil {
		t.Fatalf("WithFSRule valid input returned error: %v", err)
	}

	if len(cfg.FSRules) != 1 || cfg.FSRules[0].Path != "/tmp" || cfg.FSRules[0].Rights != access.FS_READ_WRITE {
		t.Fatalf("unexpected FSRules contents: %+v", cfg.FSRules)
	}

	if err := WithNetworkRule(80, 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero network rights, got %v", err)
	}

	if err := WithNetworkRule(443, access.NETWORK_BIND_TCP|access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule valid input returned error: %v", err)
	}

	if len(cfg.NetRules) != 1 || cfg.NetRules[0].Port != 443 {
		t.Fatalf("unexpected NetRules contents: %+v", cfg.NetRules)
	}
}
