package wyhash_test

import (
	"encoding/binary"
	"testing"

	"go.dw1.io/x/wyhash"
)

func TestHash64StreamingMatchesOneShot(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		seed uint64
	}{
		{name: "empty", data: nil, seed: 0},
		{name: "small", data: []byte("abc"), seed: 1},
		{name: "medium", data: []byte("hello wyhash"), seed: 123456789},
		{name: "repeated", data: bytesOf(128, 0x5a), seed: ^uint64(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := wyhash.Sum64WithSeed(tt.data, tt.seed)

			h := wyhash.New64WithSeed(tt.seed)
			n := len(tt.data)
			if _, err := h.Write(tt.data[:n/3]); err != nil {
				t.Fatalf("write chunk 1: %v", err)
			}
			if _, err := h.Write(tt.data[n/3 : n*2/3]); err != nil {
				t.Fatalf("write chunk 2: %v", err)
			}
			if _, err := h.Write(tt.data[n*2/3:]); err != nil {
				t.Fatalf("write chunk 3: %v", err)
			}
			if got := h.Sum64(); got != expected {
				t.Fatalf("streamed sum64 mismatch: got %d want %d", got, expected)
			}

			h.Reset()
			if _, err := h.Write(tt.data); err != nil {
				t.Fatalf("write full reset: %v", err)
			}
			if got := h.Sum64(); got != expected {
				t.Fatalf("reset sum64 mismatch: got %d want %d", got, expected)
			}

			prefix := []byte{0xaa, 0xbb}
			out := h.Sum(prefix)
			want := append(prefix, u64(expected)...)
			if string(out) != string(want) {
				t.Fatalf("sum64 append mismatch: got %x want %x", out, want)
			}
		})
	}
}

func TestHash32StreamingMatchesOneShot(t *testing.T) {
	tests := []struct {
		name string
		data []byte
		seed uint32
	}{
		{name: "empty", data: nil, seed: 0},
		{name: "small", data: []byte("abc"), seed: 1},
		{name: "medium", data: []byte("hello wyhash"), seed: 123456789},
		{name: "repeated", data: bytesOf(128, 0xa5), seed: ^uint32(0)},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			expected := wyhash.Sum32WithSeed(tt.data, tt.seed)

			h := wyhash.New32WithSeed(tt.seed)
			n := len(tt.data)
			if _, err := h.Write(tt.data[:n/2]); err != nil {
				t.Fatalf("write chunk 1: %v", err)
			}
			if _, err := h.Write(tt.data[n/2:]); err != nil {
				t.Fatalf("write chunk 2: %v", err)
			}
			if got := h.Sum32(); got != expected {
				t.Fatalf("streamed sum32 mismatch: got %d want %d", got, expected)
			}

			h.Reset()
			if _, err := h.Write(tt.data); err != nil {
				t.Fatalf("write full reset: %v", err)
			}
			if got := h.Sum32(); got != expected {
				t.Fatalf("reset sum32 mismatch: got %d want %d", got, expected)
			}

			prefix := []byte{0xaa}
			out := h.Sum(prefix)
			want := append(prefix, u32(expected)...)
			if string(out) != string(want) {
				t.Fatalf("sum32 append mismatch: got %x want %x", out, want)
			}
		})
	}
}

func bytesOf(n int, b byte) []byte {
	buf := make([]byte, n)
	for i := range buf {
		buf[i] = b
	}
	return buf
}

func u64(v uint64) []byte {
	var buf [8]byte
	binary.BigEndian.PutUint64(buf[:], v)
	return buf[:]
}

func u32(v uint32) []byte {
	var buf [4]byte
	binary.BigEndian.PutUint32(buf[:], v)
	return buf[:]
}
