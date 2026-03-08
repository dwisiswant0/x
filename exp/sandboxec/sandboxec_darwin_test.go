// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"errors"
	"os"
	"os/exec"
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

func TestDarwinSeatbeltProbeDoesNotCrash(t *testing.T) {
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
