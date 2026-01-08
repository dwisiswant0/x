package cast

import (
	"github.com/spf13/cast"
	"go.dw1.io/safemath"
)

// Basic is an alias for [cast.Basic].
type Basic = cast.Basic

// Integer is an alias for [safemath.Integer].
type Integer = safemath.Integer

// IntersectionType is a type constraint that matches types that are both
// [cast.Basic] and [safemath.Integer].
type IntersectionType interface {
	cast.Basic
	safemath.Integer
}

// Type is a constraint that matches all types supported by [cast.To] or
// [safemath.ConvertAny].
type Type interface {
	Basic | Integer
}
