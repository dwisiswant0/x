//go:build linux
// +build linux

package landlock

import (
	"errors"
	"testing"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

func TestWithABI(t *testing.T) {
	for _, version := range []int{0, 1, config.MaxABI} {
		cfg := config.Config{ABI: -1}
		if err := WithABI(version)(&cfg); err != nil {
			t.Fatalf("WithABI(%d) returned error: %v", version, err)
		}

		if cfg.ABI != version {
			t.Fatalf("WithABI(%d) set ABI %d", version, cfg.ABI)
		}
	}

	for _, version := range []int{-1, config.MaxABI + 1} {
		var cfg config.Config
		if err := WithABI(version)(&cfg); !errors.Is(err, sandboxec.ErrInvalidOption) {
			t.Fatalf("expected ErrInvalidOption for ABI %d, got %v", version, err)
		}
	}
}

func TestWithFlags(t *testing.T) {
	var cfg config.Config

	if err := WithIgnoreIfMissing()(&cfg); err != nil || !cfg.IgnoreIfMissing {
		t.Fatalf("WithIgnoreIfMissing: err=%v, IgnoreIfMissing=%v", err, cfg.IgnoreIfMissing)
	}

	if err := WithRestrictScoped()(&cfg); err != nil || !cfg.RestrictScoped {
		t.Fatalf("WithRestrictScoped: err=%v, RestrictScoped=%v", err, cfg.RestrictScoped)
	}
}
