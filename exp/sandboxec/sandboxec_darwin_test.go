// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"errors"
	"os"
	"os/exec"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
)

func subprocessDarwin(scenario string, env map[string]string) ([]byte, error) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcessDarwin", "--")
	cmd.Env = append(os.Environ(), "SANDBOXEC_HELPER=1", "SANDBOXEC_SCENARIO="+scenario)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	return cmd.CombinedOutput()
}

func runHelperDarwin(t *testing.T, scenario string, env map[string]string) string {
	t.Helper()

	out, err := subprocessDarwin(scenario, env)
	output := string(out)
	if strings.Contains(output, "SKIP:") {
		t.Skip(strings.TrimSpace(output))
	}
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
	return output
}

func TestDarwinInvalidOptionErrors(t *testing.T) {
	sb := New(WithFSRule("", access.FS_READ))
	cmd := sb.Command("/bin/true")
	if cmd.Err == nil || !errors.Is(cmd.Err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption, got %v", cmd.Err)
	}
}

func TestDarwinUnsupportedOptions(t *testing.T) {
	tests := []struct {
		name string
		opt  Option
	}{
		{name: "WithABI", opt: WithABI(6)},
		{name: "WithIgnoreIfMissing", opt: WithIgnoreIfMissing()},
		{name: "WithRestrictScoped", opt: WithRestrictScoped()},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			if err := tt.opt(&cfg); err == nil {
				t.Fatalf("expected unsupported option error")
			}
		})
	}
}

func TestDarwinSeatbeltPolicyNetworkDeniedByDefault(t *testing.T) {
	policy := defaultConfig().seatbeltPolicy()

	if !strings.Contains(policy, "(deny network-inbound)") {
		t.Fatalf("policy must deny inbound network by default, got:\n%s", policy)
	}

	if !strings.Contains(policy, "(deny network-outbound)") {
		t.Fatalf("policy must deny outbound network by default, got:\n%s", policy)
	}
}

func TestDarwinSeatbeltPolicyFSDeniedByDefault(t *testing.T) {
	policy := defaultConfig().seatbeltPolicy()

	for _, want := range []string{"(deny file-read*)", "(deny file-write*)", "(deny file-map-executable)", "(deny process-exec*)"} {
		if !strings.Contains(policy, want) {
			t.Fatalf("policy without rules must contain %q, got:\n%s", want, policy)
		}
	}
}

func TestDarwinSeatbeltPolicyNetworkOnlyDeniesFS(t *testing.T) {
	cfg := defaultConfig()
	cfg.netRules = append(cfg.netRules, netRule{port: 443, rights: access.NETWORK_CONNECT_TCP})
	policy := cfg.seatbeltPolicy()

	for _, want := range []string{"(deny file-read*)", "(deny file-write*)", "(deny file-map-executable)", "(deny process-exec*)"} {
		if !strings.Contains(policy, want) {
			t.Fatalf("network-only policy must contain %q, got:\n%s", want, policy)
		}
	}
}

func TestDarwinSeatbeltPolicyFSExecDeniedThenAllowlists(t *testing.T) {
	cfg := defaultConfig()
	cfg.fsRules = append(cfg.fsRules, fsRule{path: "/usr", rights: access.FS_READ_EXEC})
	policy := cfg.seatbeltPolicy()

	if !strings.Contains(policy, "(deny file-map-executable)") {
		t.Fatalf("policy must deny file-map-executable when fs rules are present, got:\n%s", policy)
	}

	if !strings.Contains(policy, `(allow file-map-executable (subpath "/usr"))`) {
		t.Fatalf("policy must allowlist executable mapping for explicit FS_READ_EXEC rules, got:\n%s", policy)
	}
}

func TestDarwinSeatbeltPolicyFSRightsAreExact(t *testing.T) {
	ops := []string{"file-read*", "file-write*", "file-map-executable", "process-exec*"}
	tests := []struct {
		name    string
		rights  access.FS
		allowed []string
	}{
		{name: "read", rights: access.FS_READ, allowed: []string{"file-read*"}},
		{name: "read_exec", rights: access.FS_READ_EXEC, allowed: []string{"file-read*", "file-map-executable", "process-exec*"}},
		{name: "write", rights: access.FS_WRITE, allowed: []string{"file-write*"}},
		{name: "read_write", rights: access.FS_READ_WRITE, allowed: []string{"file-read*", "file-write*"}},
		{name: "read_write_exec", rights: access.FS_READ_WRITE_EXEC, allowed: ops},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			cfg := defaultConfig()
			cfg.fsRules = append(cfg.fsRules, fsRule{path: "/x", rights: tt.rights})
			policy := cfg.seatbeltPolicy()

			for _, op := range ops {
				want := slices.Contains(tt.allowed, op)
				got := strings.Contains(policy, `(allow `+op+` (subpath "/x"))`)
				if got != want {
					t.Errorf("%s allowed = %v, want %v; policy:\n%s", op, got, want, policy)
				}
			}
		})
	}
}

func TestDarwinSeatbeltProbeReportsPolicyError(t *testing.T) {
	runHelperDarwin(t, "seatbelt-probe", nil)
}

func TestDarwinParityOutput(t *testing.T) {
	runHelperDarwin(t, "parity-output", nil)
}

func TestDarwinErrDotBehavior(t *testing.T) {
	runHelperDarwin(t, "errdot", nil)
}

func TestDarwinCommandContextCancel(t *testing.T) {
	runHelperDarwin(t, "ctx-cancel", nil)
}

// outsideFile returns a file in its own temporary directory, so no rule in a
// scenario covers it.
func outsideFile(t *testing.T) string {
	t.Helper()

	file := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(file, []byte("sandboxec-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	return file
}

func TestDarwinNoFSRulesDeniesFS(t *testing.T) {
	for _, scenario := range []string{"no-rules", "net-only"} {
		t.Run(scenario, func(t *testing.T) {
			runHelperDarwin(t, scenario, map[string]string{"SANDBOXEC_FILE": outsideFile(t)})
		})
	}
}

func TestDarwinReadRuleDeniesExec(t *testing.T) {
	runHelperDarwin(t, "exec-requires-rx", nil)
}

// A script runs only when its interpreter is executable too, as on Linux.
func TestDarwinScriptInterpreterNeedsExec(t *testing.T) {
	for _, tt := range []struct {
		name     string
		scenario string
	}{
		{name: "denied", scenario: "script-interpreter-denied"},
		{name: "allowed", scenario: "script-interpreter-allowed"},
	} {
		t.Run(tt.name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, "script"), []byte("#!/bin/echo\n"), 0o755); err != nil {
				t.Fatalf("WriteFile returned error: %v", err)
			}

			runHelperDarwin(t, tt.scenario, map[string]string{"SANDBOXEC_DIR": dir, "SANDBOXEC_FILE": outsideFile(t)})
		})
	}
}

func TestDarwinNarrowFSRulesRunCommand(t *testing.T) {
	runHelperDarwin(t, "fs-narrow-exec", map[string]string{"SANDBOXEC_FILE": outsideFile(t)})
}

// t.TempDir is under $TMPDIR, which macOS places behind the /var symlink, so
// these also cover rule paths that differ from the path Seatbelt matches and
// commands that reach a rule through a symlink.
func TestDarwinTouchAllowed(t *testing.T) {
	runHelperDarwin(t, "touch-allowed", map[string]string{"SANDBOXEC_DIR": t.TempDir(), "SANDBOXEC_FILE": outsideFile(t)})
}

func TestDarwinTouchDenied(t *testing.T) {
	runHelperDarwin(t, "touch-denied", map[string]string{"SANDBOXEC_DIR": t.TempDir()})
}

// Symlink targets come from disk, so a crafted name must not alter the policy.
func TestDarwinRulePathCannotInjectPolicy(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, `q"))(allow file-read*)(allow file-write*);\x`)
	if err := os.Mkdir(target, 0o755); err != nil {
		t.Fatalf("Mkdir returned error: %v", err)
	}
	if err := os.Symlink(target, filepath.Join(dir, "link")); err != nil {
		t.Fatalf("Symlink returned error: %v", err)
	}

	runHelperDarwin(t, "fs-path-injection", map[string]string{"SANDBOXEC_DIR": dir})
}
