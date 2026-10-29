// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"strconv"
	"strings"
	"testing"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/config"
)

func subprocess(scenario string, env map[string]string) ([]byte, error) {
	cmd := exec.Command(os.Args[0], "-test.run=TestHelperProcess", "--")
	cmd.Env = append(os.Environ(), "SANDBOXEC_HELPER=1", "SANDBOXEC_SCENARIO="+scenario)
	for key, value := range env {
		cmd.Env = append(cmd.Env, key+"="+value)
	}

	return cmd.CombinedOutput()
}

func runHelper(t *testing.T, scenario string, env map[string]string) string {
	t.Helper()

	out, err := subprocess(scenario, env)
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

func TestNoFSRulesDeniesFS(t *testing.T) {
	for _, scenario := range []string{"no-rules", "net-only", "scoped-only"} {
		t.Run(scenario, func(t *testing.T) {
			runHelper(t, scenario, nil)
		})
	}
}

func TestNetworkRulesRequireV4(t *testing.T) {
	sb := New(withABI(3), WithNetworkRule(80, access.NETWORK_BIND_TCP))
	cmd := sb.Command("/bin/true")
	if cmd.Err == nil || !errors.Is(cmd.Err, ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported, got %v", cmd.Err)
	}
}

// os/exec opens /dev/null in the sandboxed process for nil standard streams.
func TestDevNullWithoutRule(t *testing.T) {
	runHelper(t, "dev-null", nil)
}

func TestDevNullRuleIsExact(t *testing.T) {
	runHelper(t, "dev-null-exact", nil)
}

// The rule asks only for rights that the selected ABI handles, which can be
// fewer than the kernel's.
func TestDevNullAtOlderABIs(t *testing.T) {
	for _, abi := range []int{1, 2, 3, 4} {
		t.Run(fmt.Sprintf("abi%d", abi), func(t *testing.T) {
			runHelper(t, "dev-null-abi", map[string]string{"SANDBOXEC_ABI": strconv.Itoa(abi)})
		})
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

func TestWithUnsafeHostRuntimeIntegration(t *testing.T) {
	runHelper(t, "unsafe-host-runtime", nil)
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

// An FS_READ_WRITE rule applies at every ABI, although it holds rights that
// older ABIs do not handle, such as ioctl_dev below ABI 5.
func TestTouchAllowedAtEveryABI(t *testing.T) {
	for abi := 1; abi <= config.MaxABI; abi++ {
		for _, bestEffort := range []bool{false, true} {
			name := fmt.Sprintf("abi%d", abi)
			env := map[string]string{"SANDBOXEC_ABI": strconv.Itoa(abi)}
			if bestEffort {
				name += "-best-effort"
				env["SANDBOXEC_BEST_EFFORT"] = "1"
			}

			t.Run(name, func(t *testing.T) {
				runHelper(t, "touch-allowed-abi", env)
			})
		}
	}
}

// From ABI 2, an FS_READ_WRITE rule allows moving a file into a subdirectory,
// even when the sandbox also restricts the network or scoped IPC. At ABI 1,
// Landlock always denies the move.
func TestRenameAcrossDirs(t *testing.T) {
	variants := []struct {
		suffix string
		minABI int
		envKey string
	}{
		{"", 1, ""},
		{"-best-effort", 1, "SANDBOXEC_BEST_EFFORT"},
		{"-net-rule", 4, "SANDBOXEC_NET_RULE"},
		{"-scoped", 6, "SANDBOXEC_SCOPED"},
	}

	for abi := 1; abi <= config.MaxABI; abi++ {
		for _, v := range variants {
			if abi < v.minABI {
				continue
			}

			env := map[string]string{"SANDBOXEC_ABI": strconv.Itoa(abi)}
			if v.envKey != "" {
				env[v.envKey] = "1"
			}

			t.Run(fmt.Sprintf("abi%d%s", abi, v.suffix), func(t *testing.T) {
				// The sandboxed helper cannot remove the directory itself.
				env["SANDBOXEC_DIR"] = t.TempDir()
				runHelper(t, "rename-across-dirs", env)
			})
		}
	}
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

func TestCurlNoNetworkRulesDenied(t *testing.T) {
	runHelper(t, "curl-no-net-rules-denied", nil)
}
