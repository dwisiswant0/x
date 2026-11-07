// Package vuln has functions that the test advisories mark as vulnerable.
package vuln

// Bad is vulnerable before v1.1.0 (GO-0000-0001).
func Bad() {}

// Other is vulnerable in v1.1.0 only (GO-0000-0002).
func Other() {}

// Good is never vulnerable.
func Good() {}
