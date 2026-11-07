// Package vuln has functions that the test advisories mark as vulnerable.
package vuln

import "example.com/dep"

// Bad is fixed in v1.1.0.
func Bad() { dep.Check() }

// Other is fixed in v1.2.0.
func Other() {}

// Good is never vulnerable.
func Good() {}
