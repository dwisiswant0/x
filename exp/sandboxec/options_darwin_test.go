//go:build darwin
// +build darwin

package sandboxec

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"slices"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
	"go.dw1.io/x/exp/sandboxec/internal/seatbelt"
)

func TestDarwinWithFSRuleValidationAndCleanPath(t *testing.T) {
	var cfg config.Config

	if err := WithFSRule("", access.FS_READ)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for empty path, got %v", err)
	}

	if err := WithFSRule("/tmp", 0)(&cfg); !errors.Is(err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption for zero rights, got %v", err)
	}

	// The first component does not exist, so symlink resolution gives up and
	// only cleaning removes the extra slash and the trailing ".".
	inputPath := "/nonexistent-sandboxec//x/."
	if err := WithFSRule(inputPath, access.FS_READ_EXEC)(&cfg); err != nil {
		t.Fatalf("WithFSRule valid input returned error: %v", err)
	}

	if len(cfg.FSRules) != 1 {
		t.Fatalf("expected 1 fs rule, got %d", len(cfg.FSRules))
	}

	policy := seatbeltPolicy(&cfg)
	if want := seatbelt.Allow(seatbelt.FileRead, seatbelt.Subpath("/nonexistent-sandboxec/x")); !slices.Contains(policy, want) {
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

// Files on PATH that are not loadable Mach-O images, such as scripts, add no
// dependency files and do not make the option fail.
func TestDarwinWithUnsafeHostRuntimeSkipsNonMachO(t *testing.T) {
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "script"), []byte("#!/bin/sh\nexit 0\n"), 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.WriteFile(filepath.Join(dir, "truncated"), []byte{0xcf, 0xfa, 0xed, 0xfe}, 0o755); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	t.Setenv("PATH", dir)

	var cfg config.Config
	if err := WithUnsafeHostRuntime()(&cfg); err != nil {
		t.Fatalf("WithUnsafeHostRuntime returned error: %v", err)
	}

	if len(cfg.FSRules) != 1 {
		t.Fatalf("expected one fs rule, got %d: %+v", len(cfg.FSRules), cfg.FSRules)
	}

	if cfg.FSRules[0].Path != filepath.Clean(dir) {
		t.Fatalf("fs rule path = %q, want %q", cfg.FSRules[0].Path, filepath.Clean(dir))
	}

	if cfg.FSRules[0].Rights != access.FS_READ_EXEC {
		t.Fatalf("fs rule rights = %v, want FS_READ_EXEC", cfg.FSRules[0].Rights)
	}
}

// The default macOS PATH holds universal binaries and scripts, neither of
// which may make the option fail.
func TestDarwinWithUnsafeHostRuntimeDefaultPATH(t *testing.T) {
	t.Setenv("PATH", "/usr/bin:/bin:/usr/sbin:/sbin")

	var cfg config.Config
	if err := WithUnsafeHostRuntime()(&cfg); err != nil {
		t.Fatalf("WithUnsafeHostRuntime returned error: %v", err)
	}

	if len(cfg.FSRules) == 0 {
		t.Fatal("expected fs rules for the default PATH, got none")
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

// root/link/.. names root/target, the parent of link's target, as it does for
// the kernel. Cleaning the path first would grant all of root instead.
func TestDarwinSeatbeltPolicyDotDotAfterSymlink(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}

	if err := os.MkdirAll(filepath.Join(root, "target", "inner"), 0o755); err != nil {
		t.Fatalf("MkdirAll returned error: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target", "inner"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	rulePath := filepath.Join(root, "link") + "/.."
	want, err := filepath.EvalSymlinks(rulePath)
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}

	resolved, links := resolveSeatbeltPath(rulePath)
	if resolved != want {
		t.Fatalf("resolved = %q, want %q", resolved, want)
	}
	if wantLinks := []string{filepath.Join(root, "link")}; !slices.Equal(links, wantLinks) {
		t.Fatalf("links = %q, want %q", links, wantLinks)
	}

	cfg := config.Config{FSRules: []config.FSRule{{Path: rulePath, Rights: access.FS_READ}}}
	policy := seatbeltPolicy(&cfg)
	if grant := seatbelt.Allow(seatbelt.FileRead, seatbelt.Subpath(root)); slices.Contains(policy, grant) {
		t.Fatalf("policy grants the directory holding the symlink:\n%s", policy)
	}
	if grant := seatbelt.Allow(seatbelt.FileRead, seatbelt.Subpath(want)); !slices.Contains(policy, grant) {
		t.Fatalf("policy missing %q:\n%s", grant, policy)
	}
}

// A ".." path that the kernel cannot open stays as written, which Seatbelt
// never matches, rather than becoming the directory its cleaned form names.
func TestDarwinResolveSeatbeltPathUnresolvableDotDot(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}

	// root/link -> root/target/inner, root/flink -> root/target/file
	for _, dir := range []string{filepath.Join(root, "target", "inner"), filepath.Join(root, "existing")} {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			t.Fatalf("MkdirAll returned error: %v", err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "target", "file"), nil, 0o644); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target", "inner"), filepath.Join(root, "link")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}
	if err := os.Symlink(filepath.Join(root, "target", "file"), filepath.Join(root, "flink")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	for _, path := range []string{
		// The kernel looks for root/target/missing.
		filepath.Join(root, "link") + "/../missing",
		// Cleaning would name root/existing; the kernel looks in root/target.
		filepath.Join(root, "link") + "/../existing",
		// ".." after a file fails with ENOTDIR.
		filepath.Join(root, "flink") + "/..",
	} {
		if resolved, links := resolveSeatbeltPath(path); resolved != path || links != nil {
			t.Errorf("resolveSeatbeltPath(%q) = %q with links %q, want it unchanged", path, resolved, links)
		}
	}
}

// The kernel follows at most MAXSYMLINKS (32) symlinks in a path.
func TestDarwinResolveSeatbeltPathHopLimit(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatalf("EvalSymlinks returned error: %v", err)
	}

	real := filepath.Join(root, "real")
	if err := os.Mkdir(real, 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}

	// root/l0 -> root/l1 -> ... -> root/l32 -> root/real
	target := real
	for i := maxSymlinkHops; i >= 0; i-- {
		link := filepath.Join(root, fmt.Sprintf("l%d", i))
		if err := os.Symlink(target, link); err != nil {
			t.Fatalf("Symlink returned error: %v", err)
		}
		target = link
	}

	if resolved, links := resolveSeatbeltPath(filepath.Join(root, "l1")); resolved != real || len(links) != maxSymlinkHops {
		t.Fatalf("32 links resolved to %q with %d links, want %q with %d", resolved, len(links), real, maxSymlinkHops)
	}

	path := filepath.Join(root, "l0")
	if resolved, links := resolveSeatbeltPath(path); resolved != path || links != nil {
		t.Fatalf("33 links resolved to %q with links %q, want it unchanged", resolved, links)
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

	checks := []seatbelt.Rule{
		seatbelt.Deny(seatbelt.FileRead, seatbelt.All),
		seatbelt.Deny(seatbelt.FileWrite, seatbelt.All),
		seatbelt.Deny(seatbelt.FileMapExecutable, seatbelt.All),
		// /tmp is a symlink to /private/tmp, the path Seatbelt matches.
		seatbelt.Allow(seatbelt.FileRead, seatbelt.Subpath("/private/tmp")),
		seatbelt.Allow(seatbelt.FileMapExecutable, seatbelt.Subpath("/private/tmp")),
		seatbelt.Deny(seatbelt.NetworkInbound, seatbelt.All),
		seatbelt.Deny(seatbelt.NetworkOutbound, seatbelt.All),
		seatbelt.Allow(seatbelt.NetworkInbound, seatbelt.LocalTCP(8443)),
		seatbelt.Allow(seatbelt.NetworkOutbound, seatbelt.RemoteTCP(8443)),
	}

	for _, want := range checks {
		if !slices.Contains(policy, want) {
			t.Fatalf("policy missing %q:\n%s", want, policy)
		}
	}
}
