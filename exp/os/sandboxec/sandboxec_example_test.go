// nolint
//go:build linux
// +build linux

package sandboxec_test

import (
	"fmt"

	"go.dw1.io/x/exp/os/sandboxec"
	"go.dw1.io/x/exp/os/sandboxec/access"
)

func ExampleSandboxec_minimalReadOnlyExecution() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/bin/ls", "-l")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_readOnlyFileAndReadWriteDir() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/etc/hosts", access.FS_READ),
		sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
	)
	cmd := sb.Command("/bin/sh", "-c", "cat /etc/hosts > /tmp/hosts.copy")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_allowReadWriteTempDir() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/tmp", access.FS_READ_WRITE),
	)
	cmd := sb.Command("/bin/sh", "-c", "echo hi > /tmp/hello.txt")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_ignoreOptionalPaths() {
	sb := sandboxec.New(
		sandboxec.WithIgnoreIfMissing(),
		sandboxec.WithFSRule("/etc/optional.conf", access.FS_READ),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_bestEffortCompatibility() {
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

func ExampleSandboxec_explicitABISelection() {
	sb := sandboxec.New(
		sandboxec.WithABI(6),
		sandboxec.WithFSRule("/usr", access.FS_READ_EXEC),
		sandboxec.WithFSRule("/bin", access.FS_READ_EXEC),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_customPathAccess() {
	sb := sandboxec.New(
		sandboxec.WithFSRule("/opt/data", access.FS_READ),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_restrictNetworkToDNS() {
	sb := sandboxec.New(
		sandboxec.WithABI(6),
		sandboxec.WithNetworkRule(53, access.NETWORK_CONNECT_TCP),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_allowBindLocalPort() {
	sb := sandboxec.New(
		sandboxec.WithABI(6),
		sandboxec.WithNetworkRule(8080, access.NETWORK_BIND_TCP),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}

func ExampleSandboxec_scopedIPCRestrictions() {
	sb := sandboxec.New(
		sandboxec.WithABI(6),
		sandboxec.WithRestrictScoped(),
	)
	cmd := sb.Command("/bin/true")
	_ = cmd.Run()

	fmt.Println("ok")
	// Output: ok
}
