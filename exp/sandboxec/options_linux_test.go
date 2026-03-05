// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"errors"
	"sync"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
)

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

	for version := 1; version <= maxABIVersion; version++ {
		if _, err := toLandlockConfig(version); err != nil {
			t.Fatalf("expected ABI %d to be supported, got %v", version, err)
		}
	}

	if _, err := toLandlockConfig(0); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for ABI 0, got %v", err)
	}

	if _, err := toLandlockConfig(maxABIVersion + 1); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for ABI %d, got %v", maxABIVersion+1, err)
	}
}

func TestLinuxDefaultABIVersion(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(0, errors.New("unavailable"))
	if got := defaultABIVersion(); got != maxABIVersion {
		t.Fatalf("defaultABIVersion on ABI query error = %d, want %d", got, maxABIVersion)
	}

	setLandlockABICacheForTest(0, nil)
	if got := defaultABIVersion(); got != 1 {
		t.Fatalf("defaultABIVersion below minimum = %d, want 1", got)
	}

	setLandlockABICacheForTest(maxABIVersion+3, nil)
	if got := defaultABIVersion(); got != maxABIVersion {
		t.Fatalf("defaultABIVersion above max = %d, want %d", got, maxABIVersion)
	}

	setLandlockABICacheForTest(5, nil)
	if got := defaultABIVersion(); got != 5 {
		t.Fatalf("defaultABIVersion = %d, want 5", got)
	}
}

func TestLinuxWithABI(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(6, nil)
	cfg := config{}

	if err := WithABI(0)(&cfg); err != nil {
		t.Fatalf("WithABI(0) returned error: %v", err)
	}

	if cfg.abi != 6 {
		t.Fatalf("WithABI(0) selected abi %d, want 6", cfg.abi)
	}

	if err := WithABI(maxABIVersion + 1)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for unsupported ABI, got %v", err)
	}
}

func TestLinuxValidateCompatibility(t *testing.T) {
	t.Cleanup(resetLandlockABICacheForTest)

	setLandlockABICacheForTest(maxABIVersion, nil)

	cfg := config{abi: 3, netRules: []netRule{{port: 443, rights: access.NETWORK_CONNECT_TCP}}}
	if err := cfg.validateCompatibility(); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported for network rule on ABI 3, got %v", err)
	}

	cfg = config{abi: 5, restrictScoped: true}
	if err := cfg.validateCompatibility(); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported for scoped restriction on ABI 5, got %v", err)
	}

	setLandlockABICacheForTest(0, errors.New("kernel missing"))
	cfg = config{abi: 7, bestEffort: true}
	if err := cfg.validateCompatibility(); err != nil {
		t.Fatalf("best-effort compatibility check returned error: %v", err)
	}

	cfg = config{abi: 7}
	if err := cfg.validateCompatibility(); !errors.Is(err, ErrLandlockUnavailable) {
		t.Fatalf("expected ErrLandlockUnavailable, got %v", err)
	}

	setLandlockABICacheForTest(4, nil)
	cfg = config{abi: 6}
	if err := cfg.validateCompatibility(); !errors.Is(err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported when requested ABI > supported ABI, got %v", err)
	}

	setLandlockABICacheForTest(6, nil)
	cfg = config{abi: 6}
	if err := cfg.validateCompatibility(); err != nil {
		t.Fatalf("expected compatibility validation success, got %v", err)
	}
}

func TestLinuxRuleOptionsValidation(t *testing.T) {
	cfg := defaultConfig()

	if err := WithFSRule("", access.FS_READ)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for empty FS path, got %v", err)
	}

	if err := WithFSRule("/tmp", 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero FS rights, got %v", err)
	}

	if err := WithFSRule("/tmp", access.FS_READ_WRITE)(&cfg); err != nil {
		t.Fatalf("WithFSRule valid input returned error: %v", err)
	}

	if len(cfg.fsRules) != 1 || cfg.fsRules[0].path != "/tmp" || cfg.fsRules[0].rights != access.FS_READ_WRITE {
		t.Fatalf("unexpected fsRules contents: %+v", cfg.fsRules)
	}

	if err := WithNetworkRule(80, 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero network rights, got %v", err)
	}

	if err := WithNetworkRule(443, access.NETWORK_BIND_TCP|access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule valid input returned error: %v", err)
	}

	if len(cfg.netRules) != 1 || cfg.netRules[0].port != 443 {
		t.Fatalf("unexpected netRules contents: %+v", cfg.netRules)
	}
}
