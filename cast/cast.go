package cast

import (
	"fmt"
	"time"

	"github.com/spf13/cast"
	"go.dw1.io/safemath"
)

// To converts v to type T.
func To[T Type](v any) (T, error) {
	var zero T

	switch t := any(zero).(type) {
	case int:
		return toIntOrBase[T, int](v)
	case int8:
		return toIntOrBase[T, int8](v)
	case int16:
		return toIntOrBase[T, int16](v)
	case int32:
		return toIntOrBase[T, int32](v)
	case int64:
		return toIntOrBase[T, int64](v)
	case uint:
		return toIntOrBase[T, uint](v)
	case uint8:
		return toIntOrBase[T, uint8](v)
	case uint16:
		return toIntOrBase[T, uint16](v)
	case uint32:
		return toIntOrBase[T, uint32](v)
	case uint64:
		return toIntOrBase[T, uint64](v)
	case uintptr:
		if !isIntVal(v) {
			return zero, fmt.Errorf("unsupported conversion to %T from %T", t, v)
		}

		return toInt[T, uintptr](v)
	case string:
		return toBase[T, string](v)
	case bool:
		return toBase[T, bool](v)
	case float32:
		return toBase[T, float32](v)
	case float64:
		return toBase[T, float64](v)
	case time.Time:
		return toBase[T, time.Time](v)
	case time.Duration:
		return toBase[T, time.Duration](v)
	default:
		var zero T
		return zero, nil
	}
}

// ToMust converts v to type T and panics on error.
func ToMust[T Type](v any) T {
	to, err := To[T](v)
	if err != nil {
		panic(err)
	}

	return to
}

// toInt converts to the integer type I using safemath to avoid
// overflow/underflow and then re-types the result as T (which is the caller's
// type parameter).
func toInt[T any, I Integer](v any) (T, error) {
	converted, err := safemath.ConvertAny[I](v)
	if err != nil {
		var zero T
		return zero, err
	}

	return any(converted).(T), nil
}

// toBase converts to the basic type B using spf13/cast and re-types the
// result as T (which is the caller's type parameter).
func toBase[T any, B Basic](v any) (T, error) {
	converted, err := cast.ToE[B](v)
	if err != nil {
		var zero T
		return zero, err
	}

	return any(converted).(T), nil
}

// toIntOrBase converts v to the integer type I. If v is an integer, it uses
// safemath. If v is not an integer, it uses cast.ToE.
func toIntOrBase[T any, I IntersectionType](v any) (T, error) {
	if isIntVal(v) {
		return toInt[T, I](v)
	}

	return toBase[T, I](v)
}

// isIntType reports whether the type argument T is one of the integer types
// we route through safemath for overflow/underflow protection.
func isIntType[T any]() bool {
	switch any(*new(T)).(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr:
		return true
	default:
		return false
	}
}

// isIntVal reports whether v's dynamic type is one of the integer types
// eligible for safemath conversions.
func isIntVal(v any) bool {
	switch v.(type) {
	case int, int8, int16, int32, int64,
		uint, uint8, uint16, uint32, uint64, uintptr:
		return true
	default:
		return false
	}
}
