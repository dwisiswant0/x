// nolint
//go:build darwin
// +build darwin

package sandboxec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/internal/seatbelt"
)

func TestHelperProcessDarwin(t *testing.T) {
	if os.Getenv("SANDBOXEC_HELPER") != "1" {
		return
	}

	scenario := os.Getenv("SANDBOXEC_SCENARIO")
	var err error

	switch scenario {
	case "parity-output":
		err = helperDarwinParityOutput()
	case "errdot":
		err = helperDarwinErrDot()
	case "ctx-cancel":
		err = helperDarwinCommandCtxCancel()
	case "seatbelt-probe":
		err = helperDarwinSeatbeltProbeReportsPolicyError()
	case "no-rules":
		err = helperDarwinNoFSRules()
	case "net-only":
		err = helperDarwinNoFSRules(WithNetworkRule(443, access.NETWORK_CONNECT_TCP))
	case "exec-requires-rx":
		err = helperDarwinExecRequiresRX()
	case "script-interpreter-denied":
		err = helperDarwinScriptInterpreter(access.FS_READ)
	case "script-interpreter-allowed":
		err = helperDarwinScriptInterpreter(access.FS_READ_EXEC)
	case "fs-narrow-exec":
		err = helperDarwinFSNarrowExec()
	case "touch-allowed":
		err = helperDarwinTouchAllowed()
	case "touch-denied":
		err = helperDarwinTouchDenied()
	case "fs-path-injection":
		err = helperDarwinFSPathInjection()
	case "one-policy-per-process":
		err = helperDarwinOnePolicyPerProcess()
	case "dev-null":
		err = helperDarwinDevNull()
	case "dev-null-exact":
		err = helperDarwinDevNullExact()
	default:
		fmt.Fprintf(os.Stderr, "unknown darwin scenario: %s\n", scenario)
		os.Exit(2)
	}

	if err != nil {
		if strings.HasPrefix(err.Error(), "SKIP:") {
			_, _ = fmt.Fprintln(os.Stdout, err.Error())
			os.Exit(0)
		}
		_, _ = fmt.Fprintln(os.Stderr, err.Error())
		os.Exit(1)
	}

	os.Exit(0)
}

func helperDarwinParityOutput() error {
	expected, err := exec.Command("/bin/echo", "hello").Output()
	if err != nil {
		return fmt.Errorf("baseline exec failed: %w", err)
	}

	sb := New(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
	cmd := sb.Command("/bin/echo", "hello")
	got, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("sandbox exec failed: %w", err)
	}
	if !bytes.Equal(got, expected) {
		return fmt.Errorf("output mismatch: expected %q got %q", string(expected), string(got))
	}

	return nil
}

func helperDarwinErrDot() error {
	dir, err := os.MkdirTemp("", "sandboxec-darwin-errdot-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(dir)
	}()

	prog := filepath.Join(dir, "tool")
	if err := os.WriteFile(prog, []byte("#!/bin/sh\nexit 0\n"), 0755); err != nil {
		return err
	}

	oldPath := os.Getenv("PATH")
	oldWD, _ := os.Getwd()
	if err := os.Chdir(dir); err != nil {
		return err
	}
	defer func() {
		_ = os.Chdir(oldWD)
		_ = os.Setenv("PATH", oldPath)
	}()
	_ = os.Setenv("PATH", ".")

	baseline := exec.Command("tool")
	if !errors.Is(baseline.Err, exec.ErrDot) {
		return fmt.Errorf("baseline expected ErrDot, got %v", baseline.Err)
	}

	sb := New(WithBestEffort(), WithFSRule(dir, access.FS_READ_EXEC))
	cmd := sb.Command("tool")
	if !errors.Is(cmd.Err, exec.ErrDot) && !errors.Is(cmd.Err, exec.ErrNotFound) {
		return fmt.Errorf("sandbox expected ErrDot or ErrNotFound, got %v", cmd.Err)
	}

	return nil
}

func helperDarwinCommandCtxCancel() error {
	baselineErr := runWithTimeout(false)
	sandboxErr := runWithTimeout(true)

	baselineDeadline := errors.Is(baselineErr, context.DeadlineExceeded)
	sandboxDeadline := errors.Is(sandboxErr, context.DeadlineExceeded)
	if baselineDeadline != sandboxDeadline {
		return fmt.Errorf("deadline mismatch: baseline=%v sandbox=%v", baselineErr, sandboxErr)
	}
	if !baselineDeadline {
		if !sameExitSignalDarwin(baselineErr, sandboxErr) {
			return fmt.Errorf("expected same termination signal, got baseline=%v sandbox=%v", baselineErr, sandboxErr)
		}
	}

	return nil
}

func helperDarwinSeatbeltProbeReportsPolicyError() error {
	// sandbox_init rejects an operation it does not know.
	err := applySeatbelt(seatbelt.Policy{seatbelt.Deny("no-such-operation", seatbelt.All)})
	if !errors.Is(err, ErrSeatbeltUnavailable) {
		return fmt.Errorf("expected invalid policy to fail with ErrSeatbeltUnavailable, got %v", err)
	}
	// sandbox_init explains a rejected policy in its error buffer.
	if !strings.Contains(err.Error(), "sandbox_init returned -1: ") {
		return fmt.Errorf("expected sandbox_init error details, got %v", err)
	}

	return nil
}

// helperDarwinNoFSRules checks that a sandbox without filesystem rules
// denies filesystem access, whatever other restrictions opts set.
func helperDarwinNoFSRules(opts ...Option) error {
	file := os.Getenv("SANDBOXEC_FILE")

	cmd := New(opts...).Command("/bin/cat", file)
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	// The nil stdin makes os/exec open /dev/null, which the sandbox allows, so
	// the failure comes from the exec itself.
	if out, err := cmd.CombinedOutput(); !isExecDenied(err) {
		return fmt.Errorf("expected exec without fs rules to be denied, got %v: %s", err, strings.TrimSpace(string(out)))
	}

	return expectReadDenied(file)
}

func helperDarwinExecRequiresRX() error {
	sb := New(
		WithFSRule("/usr", access.FS_READ),
		WithFSRule("/bin", access.FS_READ),
	)
	cmd := sb.Command("/bin/echo", "hello")
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	if out, err := cmd.CombinedOutput(); !isExecDenied(err) {
		return fmt.Errorf("expected exec under read-only rules to be denied, got %v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// helperDarwinScriptInterpreter runs a "#!/bin/echo" script from an rx
// directory, with binRights on /bin, where the interpreter lives.
func helperDarwinScriptInterpreter(binRights access.FS) error {
	dir := os.Getenv("SANDBOXEC_DIR")
	script := filepath.Join(dir, "script")

	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/bin", binRights),
		WithFSRule(dir, access.FS_READ_EXEC),
	)
	cmd := sb.Command(script)
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	out, err := cmd.CombinedOutput()
	if binRights&access.FS_READ_EXEC != access.FS_READ_EXEC {
		if !isExecDenied(err) {
			return fmt.Errorf("expected exec with a non-executable interpreter to be denied, got %v: %s", err, strings.TrimSpace(string(out)))
		}
		return nil
	}
	if err != nil || !strings.Contains(string(out), "script") {
		return fmt.Errorf("expected script to run, got %v: %s", err, strings.TrimSpace(string(out)))
	}

	return expectReadDenied(os.Getenv("SANDBOXEC_FILE"))
}

func helperDarwinFSNarrowExec() error {
	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/bin", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/bin/echo", "hello")
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	out, err := cmd.Output()
	if err != nil {
		return fmt.Errorf("exec under narrow fs rules failed: %w", err)
	}
	if string(out) != "hello\n" {
		return fmt.Errorf("unexpected output: %q", out)
	}

	return expectReadDenied(os.Getenv("SANDBOXEC_FILE"))
}

func helperDarwinTouchAllowed() error {
	dir := os.Getenv("SANDBOXEC_DIR")
	target := filepath.Join(dir, "allowed.txt")

	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule(dir, access.FS_READ_WRITE),
	)
	cmd := sb.Command("/usr/bin/touch", target)
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("touch allowed failed: %v: %s", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("expected file to exist: %w", err)
	}

	return expectReadDenied(os.Getenv("SANDBOXEC_FILE"))
}

func helperDarwinTouchDenied() error {
	target := filepath.Join(os.Getenv("SANDBOXEC_DIR"), "denied.txt")

	sb := New(
		WithFSRule("/", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/usr/bin/touch", target)
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	if err := expectTouchDenied(cmd, target); err != nil {
		return fmt.Errorf("touch under a read_exec rule: %w", err)
	}

	return nil
}

func helperDarwinFSPathInjection() error {
	dir := os.Getenv("SANDBOXEC_DIR")
	link := filepath.Join(dir, "link")
	allowed := filepath.Join(link, "allowed.txt")
	blocked := filepath.Join(dir, "blocked.txt")

	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule(link, access.FS_READ_WRITE),
	)
	cmd := sb.Command("/usr/bin/touch", blocked)
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	if err := expectTouchDenied(cmd, blocked); err != nil {
		return fmt.Errorf("touch outside rule: %w", err)
	}
	if out, err := sb.Command("/usr/bin/touch", allowed).CombinedOutput(); err != nil {
		return fmt.Errorf("touch inside rule failed: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

// helperDarwinDevNull checks that a sandbox without a /dev/null rule still lets
// os/exec open /dev/null for the command's nil standard streams.
func helperDarwinDevNull() error {
	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/bin", access.FS_READ_EXEC),
	)

	// A nil stdin makes os/exec open /dev/null for reading.
	cmd := sb.Command("/bin/echo", "hello")
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	if out, err := cmd.Output(); err != nil || string(out) != "hello\n" {
		return fmt.Errorf("expected output with nil stdin, got %v: %q", err, out)
	}

	// Nil stdout and stderr make it open /dev/null for writing.
	if err := sb.Command("/bin/echo", "hello").Run(); err != nil {
		return fmt.Errorf("expected run with nil streams, got %w", err)
	}

	return expectReadDenied(os.Getenv("SANDBOXEC_FILE"))
}

// helperDarwinDevNullExact checks that the built-in rule allows /dev/null
// alone.
func helperDarwinDevNullExact() error {
	sb := New(
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/bin", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/usr/bin/head", "-c", "1", "/dev/zero")
	if cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	out, err := cmd.CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected read of /dev/zero to be denied, got %q", out)
	}
	if !strings.Contains(string(out), "Operation not permitted") {
		return fmt.Errorf("expected permission denial, got %v: %s", err, strings.TrimSpace(string(out)))
	}

	// Writing to /dev/null is allowed, but changing the file itself is not.
	out, err = sb.Command("/usr/bin/touch", "/dev/null").CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected touch of /dev/null to be denied, got %q", out)
	}
	if !strings.Contains(string(out), "Operation not permitted") {
		return fmt.Errorf("expected permission denial for touch, got %v: %s", err, strings.TrimSpace(string(out)))
	}

	// The sandbox also applies to this process.
	if _, err := os.Open("/dev/zero"); !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("expected open of /dev/zero to be denied, got %v", err)
	}

	return nil
}

// expectReadDenied checks that this process cannot read file, which no fs rule
// covers. The sandbox also applies to this process, so scenarios that expect
// commands to succeed use it to fail when Seatbelt was not enforced.
func expectReadDenied(file string) error {
	if _, err := os.ReadFile(file); !errors.Is(err, os.ErrPermission) {
		return fmt.Errorf("expected read outside fs rules to be denied, got %v", err)
	}

	return nil
}

// expectTouchDenied runs cmd, a touch of target, and checks that Seatbelt
// rejected the write rather than the command failing for another reason.
func expectTouchDenied(cmd *Cmd, target string) error {
	out, err := cmd.CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected denial, got success")
	}
	if !strings.Contains(string(out), "Operation not permitted") {
		return fmt.Errorf("expected permission denial, got %v: %s", err, strings.TrimSpace(string(out)))
	}
	if _, err := os.Stat(target); err == nil {
		return fmt.Errorf("expected file not to be created: %s", target)
	}

	return nil
}

func runWithTimeout(useSandbox bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if useSandbox {
		sb := New(
			WithBestEffort(),
			WithFSRule("/", access.FS_READ_EXEC),
		)
		cmd := sb.CommandContext(ctx, "/bin/sleep", "5")

		return cmd.Run()
	}

	cmd := exec.CommandContext(ctx, "/bin/sleep", "5")

	return cmd.Run()
}

func sameExitSignalDarwin(a, b error) bool {
	aExit, aOK := a.(*exec.ExitError)
	bExit, bOK := b.(*exec.ExitError)
	if !aOK || !bOK || aExit.ProcessState == nil || bExit.ProcessState == nil {
		return false
	}

	aStatus, aOK := aExit.Sys().(syscall.WaitStatus)
	bStatus, bOK := bExit.Sys().(syscall.WaitStatus)
	if !aOK || !bOK {
		return false
	}

	return aStatus.Signal() == bStatus.Signal()
}

// helperDarwinOnePolicyPerProcess enforces broad rules, then tries a second
// Sandboxec with the same rules and one with narrower rules. SANDBOXEC_FILE
// is readable under the broad rules only.
func helperDarwinOnePolicyPerProcess() error {
	file := os.Getenv("SANDBOXEC_FILE")
	broad := []Option{
		WithFSRule("/", access.FS_READ_EXEC),
	}
	narrow := []Option{
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/bin", access.FS_READ_EXEC),
	}

	if cmd := New(broad...).Command("/usr/bin/true"); cmd.Err != nil {
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	if cmd := New(broad...).Command("/usr/bin/true"); cmd.Err != nil {
		return fmt.Errorf("expected identical rules to succeed, got %w", cmd.Err)
	}

	if cmd := New(narrow...).Command("/bin/cat", file); !errors.Is(cmd.Err, ErrSeatbeltUnavailable) {
		return fmt.Errorf("expected different rules to fail with ErrSeatbeltUnavailable, got %v", cmd.Err)
	}

	cmd := New(append(narrow, WithBestEffort())...).Command("/bin/cat", file)
	if cmd.Err != nil {
		return fmt.Errorf("expected WithBestEffort to ignore the failure, got %w", cmd.Err)
	}
	if out, err := cmd.Output(); err != nil || string(out) != "sandboxec-secret\n" {
		return fmt.Errorf("expected the command to run under the first policy and read the file, got %v: %q", err, out)
	}

	return nil
}
