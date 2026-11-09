// Package legacy is a go 1.16 module that uses example.com/dep.
package legacy

import "example.com/dep"

// Bad is vulnerable before v1.1.0 (GO-0000-0004).
func Bad() { dep.Check() }
