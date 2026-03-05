// nolint
//go:build !linux && !darwin
// +build !linux,!darwin

package access

// Linux/Darwin-only package; this stub keeps `go test ./...` non-empty on unsupported OSes.

func init() {
	panic("sandboxec: access rights are supported only on Linux (Landlock) and Darwin (Seatbelt)")
}
