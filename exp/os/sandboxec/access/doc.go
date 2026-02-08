// nolint
//go:build linux
// +build linux

// Package access defines typed Landlock access right sets used by sandboxec.
//
// The exported constants are intended for use with sandboxec.WithFSRule and
// sandboxec.WithNetworkRule to build clear, composable access policies.
package access
