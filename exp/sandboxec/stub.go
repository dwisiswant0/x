// nolint
//go:build !linux && !darwin
// +build !linux,!darwin

package sandboxec

// Linux/Darwin-only package; this stub keeps `go test ./...` non-empty on unsupported OSes.

func init() {
	panic("sandboxec: sandboxing is supported only on Linux (Landlock) and Darwin (Seatbelt)")
}
