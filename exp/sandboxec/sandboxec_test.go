// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"errors"
	"os"
	"os/exec"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
)

func runHelper(t *testing.T, scenario string, env map[string]string) string {
	t.Helper()

	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--")
	cmd.Env = append(os.Environ(), "SANDBOXEC_HELPER=1", "SANDBOXEC_SCENARIO="+scenario)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	out, err := cmd.CombinedOutput()
	output := string(out)
	if strings.Contains(output, "SKIP:") {
		t.Skip(strings.TrimSpace(output))
	}
	if err != nil {
		t.Fatalf("helper failed: %v\n%s", err, output)
	}
	return output
}

func TestInvalidOptionErrors(t *testing.T) {
	sb := New(WithFSRule("", access.FS_READ))
	cmd := sb.Command("/bin/true")
	if cmd.Err == nil || !errors.Is(cmd.Err, ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption, got %v", cmd.Err)
	}
}

func TestNetworkRulesRequireV4(t *testing.T) {
	sb := New(WithABI(3), WithNetworkRule(80, access.NETWORK_BIND_TCP))
	cmd := sb.Command("/bin/true")
	if cmd.Err == nil || !errors.Is(cmd.Err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported, got %v", cmd.Err)
	}
}

func TestParityOutput(t *testing.T) {
	runHelper(t, "parity-output", nil)
}

func TestParityPipes(t *testing.T) {
	runHelper(t, "parity-pipes", nil)
}

func TestErrDotBehavior(t *testing.T) {
	runHelper(t, "errdot", nil)
}

func TestBestEffort(t *testing.T) {
	runHelper(t, "best-effort", nil)
}

func TestIgnoreIfMissing(t *testing.T) {
	runHelper(t, "ignore-missing", nil)
}

func TestFSRestrictions(t *testing.T) {
	runHelper(t, "fs-restrict", nil)
}

func TestNetRestrictions(t *testing.T) {
	runHelper(t, "net-restrict", nil)
}

func TestCommandContextCancel(t *testing.T) {
	runHelper(t, "ctx-cancel", nil)
}

func TestWaitDelayBehavior(t *testing.T) {
	runHelper(t, "waitdelay", nil)
}

func TestTouchAllowed(t *testing.T) {
	runHelper(t, "touch-allowed", nil)
}

func TestTouchDenied(t *testing.T) {
	runHelper(t, "touch-denied", nil)
}

func TestCurlAllowed(t *testing.T) {
	runHelper(t, "curl-allowed", nil)
}

func TestCurlDenied(t *testing.T) {
	runHelper(t, "curl-denied", nil)
}
