// Package legacy is a go 1.16 module that uses example.com/dep.
package legacy

import "example.com/dep"

// Bad is fixed in v1.1.0, which requires example.com/dep v1.0.0.
func Bad() { dep.Check() }
