// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"errors"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
)

func TestDarwinUnsupportedOptionErrors(t *testing.T) {
	tests := []struct {
		name string
		opt  Option
	}{
		{name: "WithABI", opt: WithABI(1)},
		{name: "WithIgnoreIfMissing", opt: WithIgnoreIfMissing()},
		{name: "WithRestrictScoped", opt: WithRestrictScoped()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			err := tt.opt(&cfg)
			if !errors.Is(err, ErrInvalidOption) {
				t.Fatalf("expected ErrInvalidOption, got %v", err)
			}
		})
	}
}

func TestDarwinWithFSRuleValidationAndCleanPath(t *testing.T) {
	cfg := defaultConfig()

	if err := WithFSRule("", access.FS_READ)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for empty path, got %v", err)
	}

	if err := WithFSRule("/tmp", 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero rights, got %v", err)
	}

	inputPath := "/tmp/../tmp/."
	if err := WithFSRule(inputPath, access.FS_READ_EXEC)(&cfg); err != nil {
		t.Fatalf("WithFSRule valid input returned error: %v", err)
	}

	if len(cfg.fsRules) != 1 {
		t.Fatalf("expected 1 fs rule, got %d", len(cfg.fsRules))
	}

	if cfg.fsRules[0].path != filepath.Clean(inputPath) {
		t.Fatalf("fs rule path = %q, want %q", cfg.fsRules[0].path, filepath.Clean(inputPath))
	}
}

func TestDarwinWithNetworkRuleValidation(t *testing.T) {
	cfg := defaultConfig()

	if err := WithNetworkRule(80, 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero rights, got %v", err)
	}

	if err := WithNetworkRule(443, access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule valid input returned error: %v", err)
	}

	if len(cfg.netRules) != 1 || cfg.netRules[0].port != 443 || cfg.netRules[0].rights != access.NETWORK_CONNECT_TCP {
		t.Fatalf("unexpected netRules contents: %+v", cfg.netRules)
	}
}

func TestDarwinWithUnsafeHostRuntimeDedupesAndNormalizes(t *testing.T) {
	base := t.TempDir()

	oldPATH := os.Getenv("PATH")
	t.Cleanup(func() {
		_ = os.Setenv("PATH", oldPATH)
	})

	dupPath := base + "/"
	if err := os.Setenv("PATH", dupPath+":"+base); err != nil {
		t.Fatalf("failed to set PATH: %v", err)
	}

	cfg := defaultConfig()
	if err := WithUnsafeHostRuntime()(&cfg); err != nil {
		t.Fatalf("WithUnsafeHostRuntime returned error: %v", err)
	}

	if len(cfg.fsRules) != 1 {
		t.Fatalf("expected one deduped fs rule, got %d: %+v", len(cfg.fsRules), cfg.fsRules)
	}

	if cfg.fsRules[0].path != filepath.Clean(base) {
		t.Fatalf("deduped path = %q, want %q", cfg.fsRules[0].path, filepath.Clean(base))
	}

	if cfg.fsRules[0].rights != access.FS_READ_EXEC {
		t.Fatalf("fs rule rights = %v, want FS_READ_EXEC", cfg.fsRules[0].rights)
	}
}

func TestDarwinResolveSeatbeltPath(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}

	// root/hop1 -> root/hop2 -> root/real
	if err := os.MkdirAll(filepath.Join(root, "real", "dir"), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Symlink("real", filepath.Join(root, "hop2")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "hop2"), filepath.Join(root, "hop1")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	resolved, links := resolveSeatbeltPath(filepath.Join(root, "hop1", "dir"))
	if want := filepath.Join(root, "real", "dir"); resolved != want {
		t.Fatalf("resolved = %q, want %q", resolved, want)
	}
	if want := []string{filepath.Join(root, "hop1"), filepath.Join(root, "hop2")}; !slices.Equal(links, want) {
		t.Fatalf("links = %q, want %q", links, want)
	}

	missing := filepath.Join(root, "hop1", "missing")
	if resolved, links := resolveSeatbeltPath(missing); resolved != missing || links != nil {
		t.Fatalf("missing path resolved to %q with links %q, want it unchanged", resolved, links)
	}
}

func TestDarwinSeatbeltPolicyFromRules(t *testing.T) {
	cfg := defaultConfig()

	if err := WithFSRule("/tmp", access.FS_READ_EXEC)(&cfg); err != nil {
		t.Fatalf("WithFSRule returned error: %v", err)
	}

	if err := WithNetworkRule(8443, access.NETWORK_BIND_TCP|access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule returned error: %v", err)
	}

	policy := cfg.seatbeltPolicy()

	checks := []string{
		"(deny file-read*)",
		"(deny file-write*)",
		"(deny file-map-executable)",
		// /tmp is a symlink to /private/tmp, the path Seatbelt matches.
		`(allow file-read* (subpath "/private/tmp"))`,
		`(allow file-map-executable (subpath "/private/tmp"))`,
		"(deny network-inbound)",
		"(deny network-outbound)",
		`(allow network-inbound (local tcp "*:8443"))`,
		`(allow network-outbound (remote tcp "*:8443"))`,
	}

	for _, want := range checks {
		if !strings.Contains(policy, want) {
			t.Fatalf("policy missing %q:\n%s", want, policy)
		}
	}
}
