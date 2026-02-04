// nolint
//go:build go1.19
// +build go1.19

package gctuner

import (
	"math"
	"os"
	"runtime/debug"
)

// readGOMEMLIMIT reads the GOMEMLIMIT value.
// Returns 0 if unset or "off".
func readGOMEMLIMIT() int64 {
	p := os.Getenv("GOMEMLIMIT")
	if p == "" || p == "off" {
		return 0
	}

	n, ok := parseByteCount(p)
	if !ok || n < 0 {
		return 0
	}

	return n
}

func setMemoryLimit(limit uint64) uint64 {
	effectiveLimit := limit
	if override, ok := getMemLimitOverride(); ok {
		effectiveLimit = override
	} else if envLimit := readGOMEMLIMIT(); envLimit > 0 {
		effectiveLimit = uint64(envLimit)
	}

	if effectiveLimit == 0 {
		return 0
	}

	prev := debug.SetMemoryLimit(toInt64(effectiveLimit))
	if prev < 0 {
		return 0
	}

	return uint64(prev)
}

// toInt64 converts n to int64, capping at math.MaxInt64.
func toInt64(n uint64) int64 {
	if n > math.MaxInt64 {
		return math.MaxInt64
	}

	return int64(n)
}

// parseByteCount parses a string that represents a count of bytes.
//
// s must match the following regular expression:
//
//	^[0-9]+(([KMGT]i)?B)?$
//
// Returns an int64 because that's what its callers want and receive,
// but the result is always non-negative.
func parseByteCount(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}

	last := s[len(s)-1]
	if last >= '0' && last <= '9' {
		n, ok := atoi64(s)
		if !ok || n < 0 {
			return 0, false
		}
		return n, ok
	}

	if last != 'B' || len(s) < 2 {
		return 0, false
	}

	if c := s[len(s)-2]; c >= '0' && c <= '9' {
		n, ok := atoi64(s[:len(s)-1])
		if !ok || n < 0 {
			return 0, false
		}
		return n, ok
	} else if c != 'i' {
		return 0, false
	}

	if len(s) < 4 {
		return 0, false
	}

	power := 0
	switch s[len(s)-3] {
	case 'K':
		power = 1
	case 'M':
		power = 2
	case 'G':
		power = 3
	case 'T':
		power = 4
	default:
		return 0, false
	}

	m := uint64(1)
	for i := 0; i < power; i++ {
		m *= 1024
	}

	n, ok := atoi64(s[:len(s)-3])
	if !ok || n < 0 {
		return 0, false
	}

	un := uint64(n)
	if un > math.MaxInt64/m {
		return 0, false
	}

	un *= m
	if un > uint64(math.MaxInt64) {
		return 0, false
	}

	return int64(un), true
}

// atoi64 parses an int64 from a string s.
// The bool result reports whether s is a number representable by int64.
func atoi64(s string) (int64, bool) {
	if s == "" {
		return 0, false
	}

	neg := false
	if s[0] == '-' {
		neg = true
		s = s[1:]
	}

	un := uint64(0)
	for i := 0; i < len(s); i++ {
		c := s[i]
		if c < '0' || c > '9' {
			return 0, false
		}

		if un > math.MaxUint64/10 {
			return 0, false
		}

		un *= 10

		un1 := un + uint64(c) - '0'
		if un1 < un {
			return 0, false
		}

		un = un1
	}

	if !neg && un > uint64(math.MaxInt64) {
		return 0, false
	}

	if neg && un > uint64(math.MaxInt64)+1 {
		return 0, false
	}

	n := int64(un)
	if neg {
		n = -n
	}

	return n, true
}
