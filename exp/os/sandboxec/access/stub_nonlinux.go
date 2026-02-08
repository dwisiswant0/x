// nolint
//go:build !linux
// +build !linux

package access

// Linux-only package; this stub keeps `go test ./...` non-empty on other OSes.

func init() {
	panic("sandboxec: Landlock is only supported on Linux; sandboxing disabled")
}
