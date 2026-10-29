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
	"go.dw1.io/x/exp/sandboxec/internal/config"
	"go.dw1.io/x/exp/sandboxec/internal/seatbelt"
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

func TestDarwinSeatbeltPolicyNetworkDeniedByDefault(t *testing.T) {
	policy := seatbeltPolicy(&config.Config{})

	if !slices.Contains(policy, seatbelt.Deny(seatbelt.NetworkInbound, seatbelt.All)) {
		t.Fatalf("policy must deny inbound network by default, got:\n%s", policy)
	}

	if !slices.Contains(policy, seatbelt.Deny(seatbelt.NetworkOutbound, seatbelt.All)) {
		t.Fatalf("policy must deny outbound network by default, got:\n%s", policy)
	}
}

func TestDarwinSeatbeltPolicyFSDeniedByDefault(t *testing.T) {
	policy := seatbeltPolicy(&config.Config{})

	for _, want := range []seatbelt.Rule{
		seatbelt.Deny(seatbelt.FileRead, seatbelt.All),
		seatbelt.Deny(seatbelt.FileWrite, seatbelt.All),
		seatbelt.Deny(seatbelt.FileMapExecutable, seatbelt.All),
		seatbelt.Deny(seatbelt.ProcessExec, seatbelt.All),
	} {
		if !slices.Contains(policy, want) {
			t.Fatalf("policy without rules must contain %q, got:\n%s", want, policy)
		}
	}
}

func TestDarwinSeatbeltPolicyNetworkOnlyDeniesFS(t *testing.T) {
	var cfg config.Config
	cfg.NetRules = append(cfg.NetRules, config.NetRule{Port: 443, Rights: access.NETWORK_CONNECT_TCP})
	policy := seatbeltPolicy(&cfg)

	for _, want := range []seatbelt.Rule{
		seatbelt.Deny(seatbelt.FileRead, seatbelt.All),
		seatbelt.Deny(seatbelt.FileWrite, seatbelt.All),
		seatbelt.Deny(seatbelt.FileMapExecutable, seatbelt.All),
		seatbelt.Deny(seatbelt.ProcessExec, seatbelt.All),
	} {
		if !slices.Contains(policy, want) {
			t.Fatalf("network-only policy must contain %q, got:\n%s", want, policy)
		}
	}
}

func TestDarwinSeatbeltPolicyFSExecDeniedThenAllowlists(t *testing.T) {
	var cfg config.Config
	cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: "/usr", Rights: access.FS_READ_EXEC})
	policy := seatbeltPolicy(&cfg)

	if !slices.Contains(policy, seatbelt.Deny(seatbelt.FileMapExecutable, seatbelt.All)) {
		t.Fatalf("policy must deny file-map-executable when fs rules are present, got:\n%s", policy)
	}

	if !slices.Contains(policy, seatbelt.Allow(seatbelt.FileMapExecutable, seatbelt.Subpath("/usr"))) {
		t.Fatalf("policy must allowlist executable mapping for explicit FS_READ_EXEC rules, got:\n%s", policy)
	}
}

func TestDarwinSeatbeltPolicyFSRightsAreExact(t *testing.T) {
	ops := []seatbelt.Operation{seatbelt.FileRead, seatbelt.FileWrite, seatbelt.FileMapExecutable, seatbelt.ProcessExec}
	tests := []struct {
		name    string
		rights  access.FS
		allowed []seatbelt.Operation
	}{
		{name: "read", rights: access.FS_READ, allowed: []seatbelt.Operation{seatbelt.FileRead}},
		{name: "read_exec", rights: access.FS_READ_EXEC, allowed: []seatbelt.Operation{seatbelt.FileRead, seatbelt.FileMapExecutable, seatbelt.ProcessExec}},
		{name: "write", rights: access.FS_WRITE, allowed: []seatbelt.Operation{seatbelt.FileWrite}},
		{name: "read_write", rights: access.FS_READ_WRITE, allowed: []seatbelt.Operation{seatbelt.FileRead, seatbelt.FileWrite}},
		{name: "read_write_exec", rights: access.FS_READ_WRITE_EXEC, allowed: ops},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var cfg config.Config
			cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: "/x", Rights: tt.rights})
			policy := seatbeltPolicy(&cfg)

			for _, op := range ops {
				want := slices.Contains(tt.allowed, op)
				got := slices.Contains(policy, seatbelt.Allow(op, seatbelt.Subpath("/x")))
				if got != want {
					t.Errorf("%s allowed = %v, want %v; policy:\n%s", op, got, want, policy)
				}
			}
		})
	}
}

// An allow overrides the denial of its own operation only by coming after it.
func TestDarwinSeatbeltPolicyAllowsFollowDenials(t *testing.T) {
	var cfg config.Config
	cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: "/x", Rights: access.FS_READ_WRITE_EXEC})
	cfg.NetRules = append(cfg.NetRules, config.NetRule{Port: 8443, Rights: access.NETWORK_BIND_TCP | access.NETWORK_CONNECT_TCP})
	policy := seatbeltPolicy(&cfg)

	subtree := seatbelt.Subpath("/x")
	tests := []struct {
		op     seatbelt.Operation
		filter seatbelt.Filter
	}{
		{op: seatbelt.FileRead, filter: subtree},
		{op: seatbelt.FileWrite, filter: subtree},
		{op: seatbelt.FileMapExecutable, filter: subtree},
		{op: seatbelt.ProcessExec, filter: subtree},
		{op: seatbelt.NetworkInbound, filter: seatbelt.LocalTCP(8443)},
		{op: seatbelt.NetworkOutbound, filter: seatbelt.RemoteTCP(8443)},
	}

	for _, tt := range tests {
		deny := slices.Index(policy, seatbelt.Deny(tt.op, seatbelt.All))
		allow := slices.Index(policy, seatbelt.Allow(tt.op, tt.filter))
		if deny < 0 || allow < deny {
			t.Errorf("%s: denial at %d, allow at %d, want the allow after the denial; policy:\n%s", tt.op, deny, allow, policy)
		}
	}
}

// os/exec opens /dev/null in the sandboxed process for nil standard streams,
// so every policy allows its data and metadata, and nothing else.
func TestDarwinSeatbeltPolicyAllowsDevNull(t *testing.T) {
	var cfg config.Config
	cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: "/usr", Rights: access.FS_READ_EXEC})

	for name, policy := range map[string]seatbelt.Policy{
		"no rules":   seatbeltPolicy(&config.Config{}),
		"with rules": seatbeltPolicy(&cfg),
	} {
		for _, op := range []seatbelt.Operation{seatbelt.FileReadData, seatbelt.FileReadMetadata, seatbelt.FileWriteData} {
			if !slices.Contains(policy, seatbelt.Allow(op, seatbelt.Literal("/dev/null"))) {
				t.Errorf("%s: policy must allow %s on /dev/null; policy:\n%s", name, op, policy)
			}
		}

		// file-write* would also allow removing or replacing /dev/null.
		for _, op := range []seatbelt.Operation{seatbelt.FileRead, seatbelt.FileWrite} {
			if slices.Contains(policy, seatbelt.Allow(op, seatbelt.Literal("/dev/null"))) {
				t.Errorf("%s: policy must not allow %s on /dev/null; policy:\n%s", name, op, policy)
			}
		}

		for _, rule := range policy {
			if strings.Contains(rule.String(), `"/dev/`) && !strings.Contains(rule.String(), `"/dev/null"`) {
				t.Errorf("%s: policy must allow nothing else under /dev, got %s", name, rule)
			}
		}
	}
}

func TestDarwinSeatbeltPolicyIsDeterministic(t *testing.T) {
	var cfg config.Config
	cfg.FSRules = append(cfg.FSRules, config.FSRule{Path: "/usr", Rights: access.FS_READ_EXEC})

	if first, second := seatbeltPolicy(&cfg).String(), seatbeltPolicy(&cfg).String(); first != second {
		t.Fatalf("identical rules must produce identical policies, got:\n%s\nand:\n%s", first, second)
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

func TestDarwinDevNullWithoutRule(t *testing.T) {
	runHelperDarwin(t, "dev-null", map[string]string{"SANDBOXEC_FILE": outsideFile(t)})
}

func TestDarwinDevNullRuleIsExact(t *testing.T) {
	runHelperDarwin(t, "dev-null-exact", nil)
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

// A process holds one Seatbelt policy, so a later Sandboxec with different
// rules can neither replace nor narrow it.
func TestDarwinOnePolicyPerProcess(t *testing.T) {
	runHelperDarwin(t, "one-policy-per-process", map[string]string{"SANDBOXEC_FILE": outsideFile(t)})
}
