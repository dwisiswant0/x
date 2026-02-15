// nolint
//go:build linux
// +build linux

package sandboxec

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"

	"go.dw1.io/x/exp/sandboxec/access"
)

func TestHelperProcess(t *testing.T) {
	if os.Getenv("SANDBOXEC_HELPER") != "1" {
		return
	}

	scenario := os.Getenv("SANDBOXEC_SCENARIO")
	var err error
	switch scenario {
	case "parity-output":
		err = helperParityOutput()
	case "parity-pipes":
		err = helperParityPipes()
	case "errdot":
		err = helperErrDot()
	case "best-effort":
		err = helperBestEffort()
	case "ignore-missing":
		err = helperIgnoreMissing()
	case "unsafe-host-runtime":
		err = helperUnsafeHostRuntime()
	case "unsafe-host-runtime-with":
		err = helperUnsafeHostRuntimeWith()
	case "unsafe-host-runtime-without":
		err = helperUnsafeHostRuntimeWithout()
	case "fs-restrict":
		err = helperFSRestrict()
	case "fs-restrict-child":
		err = helperFSRestrictChild()
	case "net-restrict":
		err = helperNetRestrict()
	case "net-restrict-child":
		err = helperNetRestrictChild()
	case "ctx-cancel":
		err = helperCommandContextCancel()
	case "waitdelay":
		err = helperWaitDelay()
	case "touch-allowed":
		err = helperTouchAllowed()
	case "touch-denied":
		err = helperTouchDenied()
	case "curl-allowed":
		err = helperCurlAllowed()
	case "curl-denied":
		err = helperCurlDenied()
	case "curl-no-net-rules-denied":
		err = helperCurlNoNetworkRulesDenied()
	default:
		fmt.Fprintf(os.Stderr, "unknown scenario: %s\n", scenario)
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

func helperParityOutput() error {
	expected, err := exec.Command("/bin/echo", "hello").Output()
	if err != nil {
		return fmt.Errorf("baseline exec failed: %w", err)
	}

	sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
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

func helperParityPipes() error {
	sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
	cmd := sb.Command("/bin/cat")

	stdin, err := cmd.StdinPipe()
	if err != nil {
		return fmt.Errorf("stdin pipe: %w", err)
	}
	stdout, err := cmd.StdoutPipe()
	if err != nil {
		return fmt.Errorf("stdout pipe: %w", err)
	}

	if err := cmd.Start(); err != nil {
		return fmt.Errorf("start: %w", err)
	}

	if _, err := io.WriteString(stdin, "pipe-test"); err != nil {
		return fmt.Errorf("write stdin: %w", err)
	}
	_ = stdin.Close()

	out, err := io.ReadAll(stdout)
	if err != nil {
		return fmt.Errorf("read stdout: %w", err)
	}
	if err := cmd.Wait(); err != nil {
		return fmt.Errorf("wait: %w", err)
	}

	if string(out) != "pipe-test" {
		return fmt.Errorf("pipe output mismatch: %q", string(out))
	}

	return nil
}

func helperErrDot() error {
	dir, err := os.MkdirTemp("", "sandboxec-errdot-")
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
	}()
	_ = os.Setenv("PATH", ".")
	defer func() {
		_ = os.Setenv("PATH", oldPath)
	}()

	baseline := exec.Command("tool")
	if !errors.Is(baseline.Err, exec.ErrDot) {
		return fmt.Errorf("baseline expected ErrDot, got %v", baseline.Err)
	}

	sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule(dir, access.FS_READ_EXEC))
	cmd := sb.Command("tool")
	if !errors.Is(cmd.Err, exec.ErrDot) {
		return fmt.Errorf("sandbox expected ErrDot, got %v", cmd.Err)
	}

	return nil
}

func helperBestEffort() error {
	sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
	cmd := sb.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("best-effort run failed: %w", err)
	}

	return nil
}

func helperIgnoreMissing() error {
	sb := newSandboxWithBaseExec(
		WithBestEffort(),
		WithIgnoreIfMissing(),
		WithFSRule("/does/not/exist", access.FS_READ_EXEC),
		WithFSRule("/bin", access.FS_READ_EXEC),
	)

	cmd := sb.Command("/bin/true")
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("ignore-missing run failed: %w", err)
	}

	return nil
}

func helperUnsafeHostRuntime() error {
	withoutOut, withoutErr := subprocess("unsafe-host-runtime-without", nil)
	if withoutErr == nil {
		return fmt.Errorf("SKIP: baseline succeeded without WithUnsafeHostRuntime on this environment")
	}

	withoutLower := strings.ToLower(string(withoutOut))
	if !(strings.Contains(withoutLower, "permission denied") ||
		strings.Contains(withoutLower, "operation not permitted") ||
		strings.Contains(withoutLower, "error while loading shared libraries") ||
		strings.Contains(withoutLower, "cannot open shared object file")) {
		return fmt.Errorf("unexpected baseline failure without WithUnsafeHostRuntime: %v: %s", withoutErr, strings.TrimSpace(string(withoutOut)))
	}

	withOut, withErr := subprocess("unsafe-host-runtime-with", nil)
	if withErr != nil {
		return fmt.Errorf("expected success with WithUnsafeHostRuntime, got error: %v: %s", withErr, strings.TrimSpace(string(withOut)))
	}

	return nil
}

func helperUnsafeHostRuntimeWithout() error {
	target, err := exec.LookPath("echo")
	if err != nil {
		return fmt.Errorf("SKIP: echo not available")
	}

	targetDir := filepath.Dir(target)

	withoutHostRuntime := New(
		WithFSRule(target, access.FS_READ_EXEC),
		WithFSRule(targetDir, access.FS_READ_EXEC),
		WithFSRule("/dev/null", access.FS_READ_WRITE),
	)

	withoutCmd := withoutHostRuntime.Command(target, "sandboxec")
	if withoutCmd.Err != nil {
		if isLandlockSkip(withoutCmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", withoutCmd.Err)
		}
		return fmt.Errorf("enforce without host runtime failed: %w", withoutCmd.Err)
	}

	withoutOut, withoutErr := withoutCmd.CombinedOutput()
	if withoutErr == nil {
		return fmt.Errorf("expected failure without WithUnsafeHostRuntime")
	}

	return fmt.Errorf("without host runtime failed: %v: %s", withoutErr, strings.TrimSpace(string(withoutOut)))
}

func helperUnsafeHostRuntimeWith() error {
	target, err := exec.LookPath("echo")
	if err != nil {
		return fmt.Errorf("SKIP: echo not available")
	}

	targetDir := filepath.Dir(target)

	withHostRuntime := New(
		WithIgnoreIfMissing(),
		WithFSRule(target, access.FS_READ_EXEC),
		WithFSRule(targetDir, access.FS_READ_EXEC),
		WithFSRule("/dev/null", access.FS_READ_WRITE),
		WithUnsafeHostRuntime(),
	)

	withCmd := withHostRuntime.Command(target, "sandboxec")
	if withCmd.Err != nil {
		if isLandlockSkip(withCmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", withCmd.Err)
		}
		return fmt.Errorf("enforce with host runtime failed: %w", withCmd.Err)
	}

	withOut, withErr := withCmd.CombinedOutput()
	if withErr != nil {
		return fmt.Errorf("expected success with WithUnsafeHostRuntime, got error: %v: %s", withErr, strings.TrimSpace(string(withOut)))
	}

	return nil
}

func helperFSRestrict() error {
	if _, err := os.Stat("/etc/hosts"); err != nil {
		return fmt.Errorf("SKIP: /etc/hosts unavailable: %v", err)
	}

	tmpDir, err := os.MkdirTemp("", "sandboxec-fs-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	testBin, err := os.Executable()
	if err != nil {
		return err
	}

	sb := newSandboxWithBaseExec(
		WithFSRule(tmpDir, access.FS_READ_WRITE),
		WithFSRule(testBin, access.FS_READ_EXEC),
		WithFSRule(filepath.Dir(testBin), access.FS_READ_EXEC),
	)
	cmd := sb.Command(testBin, "-test.run=TestHelperProcess", "--")
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	cmd.Env = append(cmd.Env,
		"SANDBOXEC_HELPER=1",
		"SANDBOXEC_SCENARIO=fs-restrict-child",
		"SANDBOXEC_TMPDIR="+tmpDir,
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("child run failed: %v\n%s", err, string(out))
	}

	return nil
}

func helperNetRestrict() error {
	disallowedListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		_ = disallowedListener.Close()
	}()
	disallowedPort := disallowedListener.Addr().(*net.TCPAddr).Port

	allowedPort, err := freeTCPPort()
	if err != nil {
		return err
	}

	disallowedBindPort, err := freeTCPPort()
	if err != nil {
		return err
	}

	testBin, err := os.Executable()
	if err != nil {
		return err
	}

	sb := newSandboxWithBaseExec(
		WithABI(6),
		WithNetworkRule(uint16(allowedPort), access.NETWORK_BIND_TCP|access.NETWORK_CONNECT_TCP),
		WithFSRule(testBin, access.FS_READ_EXEC),
		WithFSRule(filepath.Dir(testBin), access.FS_READ_EXEC),
	)
	cmd := sb.Command(testBin, "-test.run=TestHelperProcess", "--")
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	allowedListener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", allowedPort))
	if err != nil {
		if isLandlockSkip(err) {
			return fmt.Errorf("SKIP: bind not restricted as expected: %v", err)
		}
		return fmt.Errorf("bind allowed port failed: %w", err)
	}
	defer func() {
		_ = allowedListener.Close()
	}()

	go func() {
		conn, _ := allowedListener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()
	go func() {
		conn, _ := disallowedListener.Accept()
		if conn != nil {
			_ = conn.Close()
		}
	}()

	cmd.Env = append(cmd.Env,
		"SANDBOXEC_HELPER=1",
		"SANDBOXEC_SCENARIO=net-restrict-child",
		"SANDBOXEC_ALLOWED_PORT="+strconv.Itoa(allowedPort),
		"SANDBOXEC_DISALLOWED_CONNECT_PORT="+strconv.Itoa(disallowedPort),
		"SANDBOXEC_DISALLOWED_BIND_PORT="+strconv.Itoa(disallowedBindPort),
	)
	out, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("child run failed: %v\n%s", err, string(out))
	}

	return nil
}

func helperFSRestrictChild() error {
	tmpDir := os.Getenv("SANDBOXEC_TMPDIR")
	if tmpDir == "" {
		return fmt.Errorf("missing SANDBOXEC_TMPDIR")
	}

	if _, err := os.Open("/etc/hosts"); err == nil {
		return fmt.Errorf("expected /etc/hosts to be denied")
	} else if !isPermissionDenied(err) {
		return fmt.Errorf("unexpected /etc/hosts error: %v", err)
	}

	allowedFile := filepath.Join(tmpDir, "allowed.txt")
	if err := os.WriteFile(allowedFile, []byte("ok"), 0644); err != nil {
		return fmt.Errorf("write allowed file: %w", err)
	}
	if _, err := os.ReadFile(allowedFile); err != nil {
		return fmt.Errorf("read allowed file: %w", err)
	}

	return nil
}

func helperNetRestrictChild() error {
	allowedPort, err := strconv.Atoi(os.Getenv("SANDBOXEC_ALLOWED_PORT"))
	if err != nil {
		return fmt.Errorf("parse SANDBOXEC_ALLOWED_PORT: %w", err)
	}
	deniedConnectPort, err := strconv.Atoi(os.Getenv("SANDBOXEC_DISALLOWED_CONNECT_PORT"))
	if err != nil {
		return fmt.Errorf("parse SANDBOXEC_DISALLOWED_CONNECT_PORT: %w", err)
	}
	deniedBindPort, err := strconv.Atoi(os.Getenv("SANDBOXEC_DISALLOWED_BIND_PORT"))
	if err != nil {
		return fmt.Errorf("parse SANDBOXEC_DISALLOWED_BIND_PORT: %w", err)
	}

	if err := connectToPort(allowedPort); err != nil {
		return fmt.Errorf("connect allowed port failed: %w", err)
	}

	if err := connectToPort(deniedConnectPort); err == nil {
		return fmt.Errorf("expected connect to disallowed port to be denied")
	} else if !isPermissionDenied(err) {
		return fmt.Errorf("unexpected disallowed connect error: %v", err)
	}

	if err := bindToPort(deniedBindPort); err == nil {
		return nil
	} else if !isPermissionDenied(err) {
		return fmt.Errorf("unexpected disallowed bind error: %v", err)
	}

	return nil
}

func helperCommandContextCancel() error {
	baselineErr := runWithTimeout(false)
	sandboxErr := runWithTimeout(true)

	baselineDeadline := errors.Is(baselineErr, context.DeadlineExceeded)
	sandboxDeadline := errors.Is(sandboxErr, context.DeadlineExceeded)
	if baselineDeadline != sandboxDeadline {
		return fmt.Errorf("deadline mismatch: baseline=%v sandbox=%v", baselineErr, sandboxErr)
	}
	if !baselineDeadline {
		if !sameExitSignal(baselineErr, sandboxErr) {
			return fmt.Errorf("expected same termination signal, got baseline=%v sandbox=%v", baselineErr, sandboxErr)
		}
	}

	return nil
}

func helperWaitDelay() error {
	baselineErr := runWithWaitDelay(false)
	sandboxErr := runWithWaitDelay(true)

	baselineWaitDelay := errors.Is(baselineErr, exec.ErrWaitDelay)
	sandboxWaitDelay := errors.Is(sandboxErr, exec.ErrWaitDelay)
	baselineDeadline := errors.Is(baselineErr, context.DeadlineExceeded)
	sandboxDeadline := errors.Is(sandboxErr, context.DeadlineExceeded)

	if baselineWaitDelay != sandboxWaitDelay || baselineDeadline != sandboxDeadline {
		return fmt.Errorf("waitdelay mismatch: baseline=%v sandbox=%v", baselineErr, sandboxErr)
	}

	return nil
}

func helperTouchAllowed() error {
	tmpDir, err := os.MkdirTemp("", "sandboxec-touch-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	target := filepath.Join(tmpDir, "allowed.txt")
	sb := newSandboxWithBaseExec(
		WithFSRule("/bin", access.FS_READ_EXEC),
		WithFSRule(tmpDir, access.FS_READ_WRITE),
	)
	cmd := sb.Command("/bin/touch", target)
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("touch allowed failed: %w", err)
	}
	if _, err := os.Stat(target); err != nil {
		return fmt.Errorf("expected file to exist: %w", err)
	}

	return nil
}

func helperTouchDenied() error {
	tmpDir, err := os.MkdirTemp("", "sandboxec-touch-")
	if err != nil {
		return err
	}
	defer func() {
		_ = os.RemoveAll(tmpDir)
	}()

	target := filepath.Join(tmpDir, "denied.txt")
	sb := newSandboxWithBaseExec(WithFSRule("/bin", access.FS_READ_EXEC))
	cmd := sb.Command("/bin/touch", target)
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	out, err := cmd.CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected touch to be denied")
	}
	if _, statErr := os.Stat(target); statErr == nil {
		return fmt.Errorf("expected file to be denied but it exists")
	}
	if !isPermissionDenied(err) && !strings.Contains(strings.ToLower(string(out)), "permission denied") {
		return fmt.Errorf("unexpected touch denial: %v: %s", err, strings.TrimSpace(string(out)))
	}

	return nil
}

func helperCurlAllowed() error {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		return fmt.Errorf("SKIP: curl not available")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	allowedPort := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
	}()

	url := fmt.Sprintf("http://127.0.0.1:%d/", allowedPort)
	options := []Option{
		WithABI(6),
		WithFSRule("/etc", access.FS_READ),
		WithNetworkRule(uint16(allowedPort), access.NETWORK_CONNECT_TCP),
	}
	options = append(options, curlAccessOptions(curlPath)...)
	sb := newSandboxWithBaseExec(options...)
	cmd := sb.Command(curlPath, "-sS", "--connect-timeout", "1", "--max-time", "2", "-o", "/dev/null", url)
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("curl allowed failed: %w", err)
	}

	return nil
}

func helperCurlDenied() error {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		return fmt.Errorf("SKIP: curl not available")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	allowedPort := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
	}()

	blockedPort, err := freeTCPPort()
	if err != nil {
		return err
	}

	url := fmt.Sprintf("http://127.0.0.1:%d/", allowedPort)
	options := []Option{
		WithABI(6),
		WithFSRule("/etc", access.FS_READ),
		WithNetworkRule(uint16(blockedPort), access.NETWORK_CONNECT_TCP),
	}
	options = append(options, curlAccessOptions(curlPath)...)
	sb := newSandboxWithBaseExec(options...)
	cmd := sb.Command(curlPath, "-sS", "--connect-timeout", "1", "--max-time", "2", "-o", "/dev/null", url)
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}
	output, err := cmd.CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected curl to be denied")
	}
	outputLower := strings.ToLower(string(output))
	if strings.Contains(outputLower, "permission denied") || strings.Contains(outputLower, "operation not permitted") {
		return nil
	}
	if isPermissionDenied(err) {
		return nil
	}
	if strings.Contains(outputLower, "could not connect to server") || strings.Contains(outputLower, "couldn't connect to server") || strings.Contains(outputLower, "connection refused") {
		return nil
	}
	return fmt.Errorf("unexpected curl denial: %v: %s", err, strings.TrimSpace(string(output)))
}

func helperCurlNoNetworkRulesDenied() error {
	curlPath, err := exec.LookPath("curl")
	if err != nil {
		return fmt.Errorf("SKIP: curl not available")
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}
	defer func() {
		_ = listener.Close()
	}()

	port := listener.Addr().(*net.TCPAddr).Port
	server := &http.Server{Handler: http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = io.WriteString(w, "ok")
	})}
	go func() {
		_ = server.Serve(listener)
	}()
	defer func() {
		_ = server.Close()
	}()

	options := []Option{
		WithABI(6),
		WithFSRule("/etc", access.FS_READ),
	}
	options = append(options, curlAccessOptions(curlPath)...)

	sb := newSandboxWithBaseExec(options...)
	url := fmt.Sprintf("http://127.0.0.1:%d/", port)
	cmd := sb.Command(curlPath, "-sS", "--connect-timeout", "1", "--max-time", "2", "-o", "/dev/null", url)
	if cmd.Err != nil {
		if isLandlockSkip(cmd.Err) {
			return fmt.Errorf("SKIP: landlock unavailable: %v", cmd.Err)
		}
		return fmt.Errorf("enforce failed: %w", cmd.Err)
	}

	output, err := cmd.CombinedOutput()
	if err == nil {
		return fmt.Errorf("expected curl to be denied with no network rules, but request succeeded")
	}

	outputLower := strings.ToLower(string(output))
	if strings.Contains(outputLower, "permission denied") || strings.Contains(outputLower, "operation not permitted") || isPermissionDenied(err) {
		return nil
	}
	if strings.Contains(outputLower, "could not connect to server") || strings.Contains(outputLower, "couldn't connect to server") || strings.Contains(outputLower, "failed to connect") || strings.Contains(outputLower, "connection refused") {
		return nil
	}

	return fmt.Errorf("unexpected curl denial mode: %v: %s", err, strings.TrimSpace(string(output)))
}

func runWithTimeout(useSandbox bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	if useSandbox {
		sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
		cmd := sb.CommandContext(ctx, "/bin/sleep", "5")
		return cmd.Run()
	}

	cmd := exec.CommandContext(ctx, "/bin/sleep", "5")
	return cmd.Run()
}

func runWithWaitDelay(useSandbox bool) error {
	ctx, cancel := context.WithTimeout(context.Background(), 150*time.Millisecond)
	defer cancel()

	if useSandbox {
		sb := newSandboxWithBaseExec(WithBestEffort(), WithFSRule("/", access.FS_READ_EXEC))
		cmd := sb.CommandContext(ctx, "/bin/sleep", "5")
		cmd.WaitDelay = 50 * time.Millisecond
		return cmd.Run()
	}

	cmd := exec.CommandContext(ctx, "/bin/sleep", "5")
	cmd.WaitDelay = 50 * time.Millisecond
	return cmd.Run()
}

func freeTCPPort() (int, error) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return 0, err
	}
	defer func() {
		_ = listener.Close()
	}()

	return listener.Addr().(*net.TCPAddr).Port, nil
}

func connectToPort(port int) error {
	conn, err := net.DialTimeout("tcp", fmt.Sprintf("127.0.0.1:%d", port), 500*time.Millisecond)
	if err != nil {
		return err
	}
	return conn.Close()
}

func bindToPort(port int) error {
	listener, err := net.Listen("tcp", fmt.Sprintf("127.0.0.1:%d", port))
	if err != nil {
		return err
	}
	return listener.Close()
}

func isPermissionDenied(err error) bool {
	if err == nil {
		return false
	}
	if errors.Is(err, os.ErrPermission) {
		return true
	}
	return strings.Contains(strings.ToLower(err.Error()), "permission denied")
}

func isLandlockSkip(err error) bool {
	return errors.Is(err, ErrLandlockUnavailable) || errors.Is(err, ErrABINotSupported)
}

func curlAccessOptions(curlPath string) []Option {
	options := []Option{WithFSRule(curlPath, access.FS_READ_EXEC)}
	prefix := filepath.Dir(filepath.Dir(curlPath))
	if prefix != "/" && prefix != "." {
		options = append(options, WithFSRule(prefix, access.FS_READ_EXEC))
	}
	return options
}

func sameExitSignal(a, b error) bool {
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

func newSandboxWithBaseExec(opts ...Option) *Sandboxec {
	opts = append(opts,
		WithFSRule("/bin", access.FS_READ_EXEC),
		WithFSRule("/usr", access.FS_READ_EXEC),
		WithFSRule("/lib", access.FS_READ_EXEC),
		WithFSRule("/lib64", access.FS_READ_EXEC),
		WithFSRule("/usr/lib", access.FS_READ_EXEC),
		WithFSRule("/usr/lib64", access.FS_READ_EXEC),
		WithFSRule("/dev/null", access.FS_READ_WRITE),
	)
	return New(opts...)
}
