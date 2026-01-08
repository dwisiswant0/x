package cast

import (
	"errors"
	"math"
	"testing"
	"time"

	"go.dw1.io/safemath"
)

func TestIsIntegerType(t *testing.T) {
	t.Run("integers", func(t *testing.T) {
		integers := map[string]bool{
			"int":     isIntType[int](),
			"int8":    isIntType[int8](),
			"int16":   isIntType[int16](),
			"int32":   isIntType[int32](),
			"int64":   isIntType[int64](),
			"uint":    isIntType[uint](),
			"uint8":   isIntType[uint8](),
			"uint16":  isIntType[uint16](),
			"uint32":  isIntType[uint32](),
			"uint64":  isIntType[uint64](),
			"uintptr": isIntType[uintptr](),
		}

		for name, got := range integers {
			if !got {
				t.Fatalf("expected %s to be an integer type", name)
			}
		}
	})

	t.Run("nonIntegers", func(t *testing.T) {
		cases := map[string]bool{
			"float64":       isIntType[float64](),
			"string":        isIntType[string](),
			"bool":          isIntType[bool](),
			"time.Duration": isIntType[time.Duration](),
		}

		for name, got := range cases {
			if got {
				t.Fatalf("expected %s to not be an integer type", name)
			}
		}
	})
}

func TestToUsesSafemathForIntegerInputs(t *testing.T) {
	t.Run("withinRange", func(t *testing.T) {
		got, err := To[int8](int64(math.MaxInt8))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != int8(math.MaxInt8) {
			t.Fatalf("expected %d, got %d", int8(math.MaxInt8), got)
		}
	})

	t.Run("overflow", func(t *testing.T) {
		_, err := To[int8](int64(math.MaxInt8) + 1)
		if err == nil {
			t.Fatalf("expected error for overflow conversion")
		}

		if !errors.Is(err, safemath.ErrTruncation) {
			t.Fatalf("expected safemath.ErrTruncation, got %v", err)
		}
	})
}

func TestToWithNonIntegerInputs(t *testing.T) {
	t.Run("stringNumber", func(t *testing.T) {
		got, err := To[int]("42")
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != 42 {
			t.Fatalf("expected 42, got %d", got)
		}
	})

	t.Run("floatNumber", func(t *testing.T) {
		got, err := To[int](float64(42.0))
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}

		if got != 42 {
			t.Fatalf("expected 42, got %d", got)
		}
	})

	t.Run("invalidString", func(t *testing.T) {
		_, err := To[int]("not-a-number")
		if err == nil {
			t.Fatalf("expected error for invalid input")
		}
	})
}

func TestToMust(t *testing.T) {
	t.Run("returnsValue", func(t *testing.T) {
		got := ToMust[int](float64(99))
		if got != 99 {
			t.Fatalf("expected 99, got %d", got)
		}
	})

	t.Run("panicsOnError", func(t *testing.T) {
		defer func() {
			if recover() == nil {
				t.Fatalf("expected panic from ToMust on overflow")
			}
		}()

		_ = ToMust[int8](int64(math.MaxInt8) + 1)
	})
}
