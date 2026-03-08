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
		err = helperDarwinSeatbeltProbeNoCrash()
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

func helperDarwinSeatbeltProbeNoCrash() error {
	_ = applySeatbelt("(", 0)

	return nil
}

func runWithTimeout(useSandbox bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 50*time.Millisecond)
	defer cancel()

	if useSandbox {
		sb := New(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
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
