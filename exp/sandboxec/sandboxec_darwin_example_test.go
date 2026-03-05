// nolint
//go:build darwin
// +build darwin

package sandboxec_test

import (
	"fmt"

	"go.dw1.io/x/exp/sandboxec"
	"go.dw1.io/x/exp/sandboxec/access"
)

func ExampleSandboxec_darwinBestEffortCompatibility() {
	sb := sandboxec.New(
		sandboxec.WithBestEffort(),
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_darwinFilesystemRules() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
	)
	cmd := sb.Command("/bin/echo", "hello")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_darwinNetworkRules() {
	sb := sandboxec.New(
		sandboxec.WithNetworkRule(53, access.NETWORK_CONNECT_TCP),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}
