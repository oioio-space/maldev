package poly

import (
	"math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// Subst pairs a stage-1 decoder asm emitter with matching Go-side Encode and
// Decode functions so the pack-time encoder and the runtime decoder are always
// algebraically inverse.
//
// The three variants in XorSubsts each decode to the SAME byte value for the
// same (input, key) pair. They differ only in which x86 instruction sequence
// appears in the emitted decoder stub, giving per-pack byte-level polymorphism
// without altering semantics.
//
// Encoder math, tracking through each decoder:
//
//	canonicalXOR  decoder: XOR dst, K       (dst ^ K)
//	              encoder: XOR byte with K  (self-inverse)
//
//	subNegate     decoder: SUB dst, -K      (dst - (-K mod 256) = dst + K)
//	              encoder: SUB key from byte (b - K) so decoder adds K back
//
//	addComplement decoder: ADD dst, ^K+1    (dst + (-K mod 256) = dst - K)
//	              encoder: ADD key to byte  (b + K) so decoder subtracts K back
//
// New Subst entries can be appended to XorSubsts; the engine indexes
// uniformly into the slice so all variants are equally likely.
type Subst struct {
	// EmitDecoder emits the runtime decoder asm for one byte stored in dst.
	// Upper bits of dst must be zero at the call site; the stage-1 loop
	// guarantees this by loading a fresh byte before each substitution.
	EmitDecoder func(b *amd64.Builder, dst amd64.Reg, key uint8) error

	// Encode applies the pack-time inverse so the runtime decoder reverses it
	// cleanly. Called once per payload byte during EncodePayload.
	Encode func(b byte, key uint8) byte

	// Decode is the Go-side mirror of EmitDecoder. Used by pre-deploy
	// self-tests and by the round-trip tests to verify correctness without
	// executing the emitted asm.
	Decode func(b byte, key uint8) byte
}

// XorSubsts is the registered set of substitution variants.
var XorSubsts = []Subst{
	{EmitDecoder: emitDecoderXOR, Encode: encodeXOR, Decode: decodeXOR},
	{EmitDecoder: emitDecoderSubNeg, Encode: encodeSubNeg, Decode: decodeSubNeg},
	{EmitDecoder: emitDecoderAddCpl, Encode: encodeAddCpl, Decode: decodeAddCpl},
}

// PickSubst returns one substitution from XorSubsts uniformly at random.
func PickSubst(rng *rand.Rand) Subst {
	return XorSubsts[rng.Intn(len(XorSubsts))]
}

// XOR is self-inverse: encode and decode both XOR with key.
func encodeXOR(b, key uint8) byte { return b ^ key }
func decodeXOR(b, key uint8) byte { return b ^ key }
func emitDecoderXOR(asm *amd64.Builder, dst amd64.Reg, key uint8) error {
	return asm.XOR(dst, amd64.Imm(int64(key)))
}

// subNegate decoder runs SUB dst, -key, which is dst = dst - (-key) = dst + key.
// To reverse, encoder must subtract key (mod 256) so the decoder adds it back.
func encodeSubNeg(b, key uint8) byte { return b - key }
func decodeSubNeg(b, key uint8) byte { return b + key }
func emitDecoderSubNeg(asm *amd64.Builder, dst amd64.Reg, key uint8) error {
	return asm.SUB(dst, amd64.Imm(int64(uint8(-key))))
}

// addComplement decoder runs ADD dst, ^key+1, which is dst = dst + (-key) = dst - key.
// To reverse, encoder must add key (mod 256) so the decoder subtracts it back.
func encodeAddCpl(b, key uint8) byte { return b + key }
func decodeAddCpl(b, key uint8) byte { return b - key }
func emitDecoderAddCpl(asm *amd64.Builder, dst amd64.Reg, key uint8) error {
	return asm.ADD(dst, amd64.Imm(int64(uint8(^key)+1)))
}
