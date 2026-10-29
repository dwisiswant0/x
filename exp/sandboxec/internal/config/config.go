//go:build linux || darwin
// +build linux darwin

// Package config holds the sandbox configuration that sandboxec options set.
//
// It lives apart from sandboxec so that platform option packages, such as
// sandboxec/landlock, can set fields that the platform backend reads.
package config

import "go.dw1.io/x/exp/sandboxec/access"

// FSRule grants rights to a filesystem path.
type FSRule struct {
	Path   string
	Rights access.FS
}

// NetRule grants rights to a TCP port.
type NetRule struct {
	Port   uint16
	Rights access.Network
}
