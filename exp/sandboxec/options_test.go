// nolint
//go:build linux || darwin
// +build linux darwin

package sandboxec

import (
	"os"
	"path/filepath"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

func TestWithUnsafeHostRuntimeDedupesAndNormalizes(t *testing.T) {
	base := t.TempDir()

	oldPATH := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPATH)
	})

	dupPath := base + "/"
	if err := os.Setenv("PATH", dupPath+":"+base); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	var cfg config.Config
	if err := WithUnsafeHostRuntime()(&cfg); err != nil {
		t.Fatalf("WithUnsafeHostRuntime returned error: %v", err)
	}

	if len(cfg.FSRules) != 1 {
		t.Fatalf("expected one deduped fs rule, got %d: %+v", len(cfg.FSRules), cfg.FSRules)
	}

	if cfg.FSRules[0].Path != filepath.Clean(base) {
		t.Fatalf("deduped path = %q, want %q", cfg.FSRules[0].Path, filepath.Clean(base))
	}

	if cfg.FSRules[0].Rights != access.FS_READ_EXEC {
		t.Fatalf("fs rule rights = %v, want FS_READ_EXEC", cfg.FSRules[0].Rights)
	}
}
