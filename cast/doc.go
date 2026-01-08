// Package cast provides functions to convert between different types.
//
// It uses [safemath] for integer conversions to ensure safety against
// overflows/underflows, silent truncation, and other common pitfalls when
// converting between numeric types.
//
// For non-integer types, it uses [cast] for robust and flexible
// casting capabilities.
package cast
