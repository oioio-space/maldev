package packer

import (
	"fmt"
	mathrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// emitNopJunk emits a small random sequence of Intel multi-byte NOPs
// directly into the Builder stream. Used for in-stub polymorphism
// slots (B and C) in V2-family bundle stubs — yara byte-pattern
// signatures across packs differ even when the algorithmic body is
// identical. Caller-supplied rng for test determinism; nil rng emits
// zero bytes (no-op). Total inserted: [4, 16) bytes per call — small
// enough that slots B and C together stay under one cacheline of
// stub-size overhead while still spanning a single yara hit window.
//
// Distinct from [injectStubJunk] which performs a post-Encode byte
// splice at slot A (offset 14). emitNopJunk runs DURING Builder
// emission, so any forward Jcc displacements crossing the junk are
// auto-resolved by Builder's label resolver — no offset bookkeeping
// required.
func emitNopJunk(b *amd64.Builder, r *mathrand.Rand) error {
	if r == nil {
		return nil
	}
	target := 4 + r.Intn(12) // [4, 16)
	junk := make([]byte, 0, target)
	for len(junk) < target {
		remaining := target - len(junk)
		maxSize := remaining
		if maxSize > len(intelNops) {
			maxSize = len(intelNops)
		}
		size := 1 + r.Intn(maxSize)
		junk = append(junk, intelNops[size-1]...)
	}
	if err := b.RawBytes(junk); err != nil {
		return fmt.Errorf("packer: emit nop junk: %w", err)
	}
	return nil
}

// emitDecryptStep emits the 6-instruction SBox-indirection decrypt
// step used by every V2-family bundle stub (plain V2, V2-Negate,
// V2NW). The block consumes one ciphertext byte at [rdi], folds the
// round index in r9b through a 16-entry SBox at [r8], and writes the
// plaintext back. The exact Intel-syntax sequence:
//
//	mov   al, [rdi]
//	mov   dl, r9b
//	and   dl, 15            ; SBox is 16 entries
//	movzx edx, dl
//	xor   al, [r8+rdx]
//	mov   [rdi], al
//
// The 17-byte output is byte-identical to the pre-#2.1 RawBytes blob
// it replaces — encoder unit tests in pe/packer/stubgen/amd64 pin the
// emission for each of the 6 calls.
func emitDecryptStep(b *amd64.Builder) error {
	emit := func(op string, err error) error {
		if err != nil {
			return fmt.Errorf("packer: decrypt step %s: %w", op, err)
		}
		return nil
	}
	if err := emit("mov al [rdi]", b.MOVBReg(amd64.RAX, amd64.MemOp{Base: amd64.RDI})); err != nil {
		return err
	}
	if err := emit("mov dl r9b", b.MOVBReg(amd64.RDX, amd64.R9)); err != nil {
		return err
	}
	if err := emit("and dl 15", b.ANDB(amd64.RDX, amd64.Imm(0x0f))); err != nil {
		return err
	}
	if err := emit("movzx edx dl", b.MOVZBL(amd64.RDX, amd64.RDX)); err != nil {
		return err
	}
	if err := emit("xor al [r8+rdx]", b.XORB(amd64.RAX, amd64.MemOp{Base: amd64.R8, Index: amd64.RDX, Scale: 1})); err != nil {
		return err
	}
	if err := emit("mov [rdi] al", b.MOVB(amd64.MemOp{Base: amd64.RDI}, amd64.RAX)); err != nil {
		return err
	}
	return nil
}
