package wyhash

import (
	"encoding/binary"
	"hash"
	"math/bits"
)

// Compile-time interface assertions.
var _ hash.Hash = (*Wyhash64)(nil)
var _ hash.Hash64 = (*Wyhash64)(nil)
var _ hash.Hash32 = (*Wayhash32)(nil)

// wyhash secrets from the reference implementation.
// These are fixed so the outputs are deterministic.
const (
	k0 = uint64(0xa0761d6478bd642f)
	k1 = uint64(0xe7037ed1a0b428db)
	k2 = uint64(0x8ebc6af09c88c6e3)
	k3 = uint64(0x589965cc75374cc3)
	k4 = uint64(0x1d8e4e27c47d124f)

	k0_32 = uint32(0x78bd642f)
	k1_32 = uint32(0xa0b428db)
	k2_32 = uint32(0x9c88c6e3)
)

// Wyhash64 implements [hash.Wyhash64] using wyhash.
type Wyhash64 struct {
	seed uint64
	buf  []byte
}

// Wayhash32 implements [hash.Wayhash32] using the 32-bit wyhash mix.
type Wayhash32 struct {
	seed uint32
	buf  []byte
}

// New64 returns a 64-bit wyhash hasher with seed 0.
func New64() *Wyhash64 { return &Wyhash64{seed: 0} }

// New64WithSeed returns a 64-bit wyhash hasher seeded with seed.
func New64WithSeed(seed uint64) *Wyhash64 { return &Wyhash64{seed: seed} }

// New32 returns a 32-bit wyhash hasher with seed 0.
func New32() *Wayhash32 { return &Wayhash32{seed: 0} }

// New32WithSeed returns a 32-bit wyhash hasher seeded with seed.
func New32WithSeed(seed uint32) *Wayhash32 { return &Wayhash32{seed: seed} }

// Sum64 returns the wyhash-64 of data with seed 0.
func Sum64(data []byte) uint64 { return sum64(data, 0) }

// Sum64WithSeed returns the wyhash-64 of data with the provided seed.
func Sum64WithSeed(data []byte, seed uint64) uint64 { return sum64(data, seed) }

// Sum32 returns the wyhash-32 of data with seed 0.
func Sum32(data []byte) uint32 { return sum32(data, 0) }

// Sum32WithSeed returns the wyhash-32 of data with the provided seed.
func Sum32WithSeed(data []byte, seed uint32) uint32 { return sum32(data, seed) }

// Write appends p to the running 64-bit hash state.
func (h *Wyhash64) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

// Sum appends the current 64-bit hash to b.
func (h *Wyhash64) Sum(b []byte) []byte {
	var out [8]byte
	binary.BigEndian.PutUint64(out[:], h.Sum64())
	return append(b, out[:]...)
}

// Sum64 computes the 64-bit hash of the accumulated data.
func (h *Wyhash64) Sum64() uint64 { return sum64(h.buf, h.seed) }

// Reset clears the accumulated data.
func (h *Wyhash64) Reset() { h.buf = h.buf[:0] }

// Size returns the hash size in bytes.
func (h *Wyhash64) Size() int { return 8 }

// BlockSize returns the write block size.
func (h *Wyhash64) BlockSize() int { return 1 }

// Write appends p to the running 32-bit hash state.
func (h *Wayhash32) Write(p []byte) (int, error) {
	h.buf = append(h.buf, p...)
	return len(p), nil
}

// Sum appends the current 32-bit hash to b.
func (h *Wayhash32) Sum(b []byte) []byte {
	var out [4]byte
	binary.BigEndian.PutUint32(out[:], h.Sum32())
	return append(b, out[:]...)
}

// Sum32 computes the 32-bit hash of the accumulated data.
func (h *Wayhash32) Sum32() uint32 { return sum32(h.buf, h.seed) }

// Reset clears the accumulated data.
func (h *Wayhash32) Reset() { h.buf = h.buf[:0] }

// Size returns the hash size in bytes.
func (h *Wayhash32) Size() int { return 4 }

// BlockSize returns the write block size.
func (h *Wayhash32) BlockSize() int { return 1 }

// sum64 is the 64-bit wyhash mixing routine derived from the Go runtime
// fallback implementation.
func sum64(b []byte, seed uint64) uint64 {
	var a, c uint64
	s := len(b)
	seed ^= k0

	switch {
	case s == 0:
		return seed
	case s < 4:
		a = uint64(b[0])
		a |= uint64(b[s>>1]) << 8
		a |= uint64(b[s-1]) << 16
	case s == 4:
		a = uint64(binary.LittleEndian.Uint32(b))
		c = a
	case s < 8:
		a = uint64(binary.LittleEndian.Uint32(b))
		c = uint64(binary.LittleEndian.Uint32(b[s-4:]))
	case s == 8:
		a = binary.LittleEndian.Uint64(b)
		c = a
	case s <= 16:
		a = binary.LittleEndian.Uint64(b)
		c = binary.LittleEndian.Uint64(b[s-8:])
	default:
		l := s
		i := 0
		if l > 48 {
			seed1 := seed
			seed2 := seed
			for ; l > 48; l -= 48 {
				seed = mix64(binary.LittleEndian.Uint64(b[i:])^k1, binary.LittleEndian.Uint64(b[i+8:])^seed)
				seed1 = mix64(binary.LittleEndian.Uint64(b[i+16:])^k2, binary.LittleEndian.Uint64(b[i+24:])^seed1)
				seed2 = mix64(binary.LittleEndian.Uint64(b[i+32:])^k3, binary.LittleEndian.Uint64(b[i+40:])^seed2)
				i += 48
			}
			seed ^= seed1 ^ seed2
		}
		for ; l > 16; l -= 16 {
			seed = mix64(binary.LittleEndian.Uint64(b[i:])^k1, binary.LittleEndian.Uint64(b[i+8:])^seed)
			i += 16
		}
		a = binary.LittleEndian.Uint64(b[i+l-16:])
		c = binary.LittleEndian.Uint64(b[i+l-8:])
	}

	return mix64(k4^uint64(s), mix64(a^k1, c^seed))
}

// sum32 mirrors the 32-bit wyhash fallback used by the Go runtime.
func sum32(b []byte, seed uint32) uint32 {
	s := len(b)
	a, c := mix32(seed, uint32(s)^k0_32)
	if s == 0 {
		return a ^ c
	}

	i := 0
	for ; s > 8; s -= 8 {
		a ^= binary.LittleEndian.Uint32(b[i:])
		c ^= binary.LittleEndian.Uint32(b[i+4:])
		a, c = mix32(a, c)
		i += 8
	}

	if s >= 4 {
		a ^= binary.LittleEndian.Uint32(b[i:])
		c ^= binary.LittleEndian.Uint32(b[i+s-4:])
	} else {
		t := uint32(b[i])
		t |= uint32(b[i+s>>1]) << 8
		t |= uint32(b[i+s-1]) << 16
		c ^= t
	}

	a, c = mix32(a, c)
	a, c = mix32(a, c)
	return a ^ c
}

func mix64(a, b uint64) uint64 {
	hi, lo := bits.Mul64(a, b)
	return hi ^ lo
}

func mix32(a, b uint32) (uint32, uint32) {
	v := uint64(a^k1_32) * uint64(b^k2_32)
	return uint32(v), uint32(v >> 32)
}
