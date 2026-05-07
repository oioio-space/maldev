package poly

import (
	"math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// Subst rewrites "dst ^= key" using one of several instruction sequences
// that produce distinct byte patterns in the emitted decoder while
// performing the same logical operation.
//
// The SUB and ADD variants are NOT algebraic XOR equivalences in general:
// SUB dst, -key computes dst - (-key mod 256) = dst + key mod 256, which
// differs from dst XOR key for most values. They are obfuscation substitutions
// whose correctness relies on the encoder having used XOR with the same key:
// the decoder undoes the encoding by reapplying the same XOR key, regardless
// of which instruction sequence the decoder uses to do so. The stage-1 loop
// enforces that the key is reused unchanged, so the substitution choice affects
// only the decoder's byte pattern, not the decoded result.
//
// All three variants require the upper bits of dst to be zero at the call
// site so that the 64-bit arithmetic operates on the byte value only. The
// stage-1 loop guarantees this by loading a fresh byte before each apply.
//
// New Subst entries can be appended to XorSubsts; the engine indexes
// uniformly into the slice, so all variants are equally likely.
type Subst func(b *amd64.Builder, dst amd64.Reg, key uint8) error

// XorSubsts is the registered set of substitution variants.
var XorSubsts = []Subst{
	canonicalXOR,
	subNegate,
	addComplement,
}

// canonicalXOR emits the straightforward XOR dst, imm.
func canonicalXOR(b *amd64.Builder, dst amd64.Reg, key uint8) error {
	return b.XOR(dst, amd64.Imm(int64(key)))
}

// subNegate emits SUB dst, -key (two's-complement negation). Produces a
// different byte pattern than XOR in the emitted decoder; the decode
// outcome is identical because the encoder used the same key with XOR
// and the stage-1 decoder reapplies the same key to undo it.
// Upper bits of dst must be zero at the call site — the stage-1 loop
// enforces this by loading a fresh byte before each substitution.
func subNegate(b *amd64.Builder, dst amd64.Reg, key uint8) error {
	return b.SUB(dst, amd64.Imm(int64(uint8(-key))))
}

// addComplement emits ADD dst, ^key+1, i.e. ADD dst, two's-complement
// of key. Same byte-width caveat as subNegate: upper bits of dst must
// be zero, which the stage-1 loop guarantees.
func addComplement(b *amd64.Builder, dst amd64.Reg, key uint8) error {
	return b.ADD(dst, amd64.Imm(int64(uint8(^key)+1)))
}

// PickSubst returns one substitution from XorSubsts uniformly at random.
func PickSubst(rng *rand.Rand) Subst {
	return XorSubsts[rng.Intn(len(XorSubsts))]
}
