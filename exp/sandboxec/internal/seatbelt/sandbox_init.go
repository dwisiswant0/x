// nolint
//go:build darwin
// +build darwin

package seatbelt

import (
	"fmt"
	"strings"
)

// Apply sandboxes the current process with p. The sandbox cannot be removed,
// and processes started afterwards inherit it.
func Apply(p Policy) error {
	return sandboxInit(p.String())
}

// sbplFlags is the sandbox_init flags value that makes it read its profile
// argument as SBPL source. sandbox.h documents only SANDBOX_NAMED, for Apple's
// named profiles, and reserves every other value.
const sbplFlags = 0

// initError describes a failed sandbox_init call from its result and the
// contents of its error buffer, which may be empty.
func initError(result int32, detail string) error {
	detail = strings.TrimSpace(detail)
	if detail == "" {
		return fmt.Errorf("sandbox_init returned %d", result)
	}

	return fmt.Errorf("sandbox_init returned %d: %s", result, detail)
}
