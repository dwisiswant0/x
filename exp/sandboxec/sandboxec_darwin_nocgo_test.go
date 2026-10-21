// nolint
//go:build darwin && !cgo
// +build darwin,!cgo

package sandboxec

import (
	"os"
	"path/filepath"
	"testing"
)

// These tests need Seatbelt enforcement, which cgo builds do not provide.

func TestDarwinNoRulesDeniesFS(t *testing.T) {
	file := filepath.Join(t.TempDir(), "secret.txt")
	if err := os.WriteFile(file, []byte("sandboxec-secret\n"), 0o600); err != nil {
		t.Fatalf("WriteFile returned error: %v", err)
	}

	runHelperDarwin(t, "no-rules", map[string]string{"SANDBOXEC_FILE": file})
}

func TestDarwinNarrowFSRulesRunCommand(t *testing.T) {
	runHelperDarwin(t, "fs-narrow-exec", nil)
}

// t.TempDir is under $TMPDIR, which macOS places behind the /var symlink, so
// these also cover rule paths that differ from the path Seatbelt matches and
// commands that reach a rule through a symlink.
func TestDarwinTouchAllowed(t *testing.T) {
	runHelperDarwin(t, "touch-allowed", map[string]string{"SANDBOXEC_DIR": t.TempDir()})
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
