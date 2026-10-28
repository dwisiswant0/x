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
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

func TestDarwinWithFSRuleValidationAndCleanPath(t *testing.T) {
	var cfg config.Config

	if err := WithFSRule("", access.FS_READ)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for empty path, got %v", err)
	}

	if err := WithFSRule("/tmp", 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero rights, got %v", err)
	}

	// The first component does not exist, so symlink resolution leaves the
	// path as it is and only cleaning can reduce it to /x.
	inputPath := "/nonexistent-sandboxec/../x/."
	if err := WithFSRule(inputPath, access.FS_READ_EXEC)(&cfg); err != nil {
		t.Fatalf("WithFSRule valid input returned error: %v", err)
	}

	if len(cfg.FSRules) != 1 {
		t.Fatalf("expected 1 fs rule, got %d", len(cfg.FSRules))
	}

	policy := seatbeltPolicy(&cfg)
	if want := `(allow file-read* (subpath "/x"))`; !strings.Contains(policy, want) {
		t.Fatalf("policy missing %q for rule path %q:\n%s", want, inputPath, policy)
	}
}

func TestDarwinWithNetworkRuleValidation(t *testing.T) {
	var cfg config.Config

	if err := WithNetworkRule(80, 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero rights, got %v", err)
	}

	if err := WithNetworkRule(443, access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule valid input returned error: %v", err)
	}

	if len(cfg.NetRules) != 1 || cfg.NetRules[0].Port != 443 || cfg.NetRules[0].Rights != access.NETWORK_CONNECT_TCP {
		t.Fatalf("unexpected netRules contents: %+v", cfg.NetRules)
	}
}

// A truncated Mach-O file on PATH makes dependency resolution fail. The host
// sandbox still works, so the error must not report it as unavailable.
func TestDarwinWithUnsafeHostRuntimeResolveError(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "truncated"), []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	t.Setenv("PATH", dir)

	var cfg config.Config
	err := WithUnsafeHostRuntime()(&cfg)
	if !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption, got %v", err)
	}

	if errors.Is(err, ErrUnavailable) {
		t.Fatalf("expected no match for ErrUnavailable, got %v", err)
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
	var cfg config.Config

	if err := WithFSRule("/tmp", access.FS_READ_EXEC)(&cfg); err != nil {
		t.Fatalf("WithFSRule returned error: %v", err)
	}

	if err := WithNetworkRule(8443, access.NETWORK_BIND_TCP|access.NETWORK_CONNECT_TCP)(&cfg); err != nil {
		t.Fatalf("WithNetworkRule returned error: %v", err)
	}

	policy := seatbeltPolicy(&cfg)

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
