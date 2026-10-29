//go:build linux
// +build linux

package landlock_test

import (
	"errors"
	"testing"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/access"
	"go.dw1.io/x/exp/sandboxec/landlock"
)

// These fail before enforcement restricts anything, so they are safe to run
// in the test process.

func TestOptionErrorReachesCommand(t *testing.T) {
	sb := sandboxec.New(landlock.WithABI(8))
	cmd := sb.Command("/bin/true")
	if !errors.Is(cmd.Err, sandboxec.ErrInvalidOption) {
		t.Fatalf("expected ErrInvalidOption, got %v", cmd.Err)
	}
}

func TestABIReachesEnforcement(t *testing.T) {
	sb := sandboxec.New(
		landlock.WithABI(3),
		sandboxec.WithNetworkRule(80, access.NETWORK_BIND_TCP),
	)
	cmd := sb.Command("/bin/true")
	if !errors.Is(cmd.Err, sandboxec.ErrABINotSupported) {
		t.Fatalf("expected ErrABINotSupported, got %v", cmd.Err)
	}
}
