// Package vuln has functions that the test advisories mark as vulnerable.
package vuln

import "example.com/dep"

// Bad is fixed in v1.1.0, which adds a dependency on example.com/dep.
func Bad() { dep.Check() }

// Other is vulnerable in v1.1.0 only (GO-0000-0002).
func Other() {}

// Good is never vulnerable.
func Good() {}
