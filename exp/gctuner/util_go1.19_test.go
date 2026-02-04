// nolint
//go:build go1.19
// +build go1.19

package gctuner

import (
	"os"
	"testing"
)

func TestParseByteCount(t *testing.T) {
	cases := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"1", 1, true},
		{"1B", 1, true},
		{"1KiB", 1024, true},
		{"2MiB", 2 * 1024 * 1024, true},
		{"1GiB", 1024 * 1024 * 1024, true},
		{"1TiB", 1024 * 1024 * 1024 * 1024, true},
		{"", 0, false},
		{"K", 0, false},
		{"1KB", 0, false},
		{"1Ki", 0, false},
		{"1XiB", 0, false},
		{"-1", 0, false},
		{"999999999999999999999999", 0, false},
	}

	for _, tc := range cases {
		got, ok := parseByteCount(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("parseByteCount(%q) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestAtoi64(t *testing.T) {
	cases := []struct {
		in     string
		want   int64
		wantOK bool
	}{
		{"0", 0, true},
		{"123", 123, true},
		{"-1", -1, true},
		{"", 0, false},
		{"1a", 0, false},
		{"999999999999999999999999", 0, false},
	}

	for _, tc := range cases {
		got, ok := atoi64(tc.in)
		if ok != tc.wantOK || got != tc.want {
			t.Fatalf("atoi64(%q) = (%d,%v), want (%d,%v)", tc.in, got, ok, tc.want, tc.wantOK)
		}
	}
}

func TestToInt64(t *testing.T) {
	if got := toInt64(1); got != 1 {
		t.Fatalf("expected toInt64(1) = 1, got %d", got)
	}

	max := uint64(^uint64(0))
	if got := toInt64(max); got != int64(^uint64(0)>>1) {
		t.Fatalf("expected toInt64(max) = MaxInt64, got %d", got)
	}
}

func TestReadGOMEMLIMIT(t *testing.T) {
	cleanup := saveAndResetState(t)
	defer cleanup()

	_ = os.Setenv("GOMEMLIMIT", "off")
	if got := readGOMEMLIMIT(); got != 0 {
		t.Fatalf("expected readGOMEMLIMIT off to be 0, got %d", got)
	}

	_ = os.Setenv("GOMEMLIMIT", "128MiB")
	if got := readGOMEMLIMIT(); got != 128*1024*1024 {
		t.Fatalf("expected readGOMEMLIMIT 128MiB, got %d", got)
	}
}
