package stage1

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// ErrNoRounds fires when EmitStub is called with an empty rounds slice.
var ErrNoRounds = errors.New("stage1: no rounds to emit")

// EmitOptions carries optional flags for EmitStub. The zero value
// disables all optional prologues (v0.64.x conservative default).
type EmitOptions struct {
	// AntiDebug, when true, prepends a ~70-byte anti-debug prologue
	// BEFORE the CALL+POP+ADD PIC prologue. Three checks run in order:
	// PEB.BeingDebugged, PEB.NtGlobalFlag (mask 0x70), and RDTSC delta
	// around CPUID. Positive detection exits via RET — the caller's
	// ntdll!RtlUserThreadStart epilogue calls ExitProcess(0), so the
	// process exits cleanly (code 0) without revealing any SGN-decoded
	// bytes. Only effective for Windows PE stubs; ELF stubs ignore the
	// flag.
	AntiDebug bool

	// Compress, when true, appends a backward-memmove preamble + LZ4
	// register-setup + inline LZ4 inflate decoder BETWEEN the last SGN
	// round and the OEP-jump epilogue.
	//
	// Layout invariants when this branch runs:
	//   * filesz = CompressedSize (only the compressed bytes ship on disk)
	//   * memsz  = MemSize         (= originalTextSize + LZ4 intra-seq margin)
	//   * After kernel load: [R15, R15+CompressedSize) = compressed bytes
	//                        [R15+CompressedSize, R15+MemSize)  = BSS zero
	//   * After SGN unwrap: same — SGN runs over filesz bytes only.
	//
	// The stub then:
	//   1. Backward-memmoves compressed bytes to the END of the memsz region
	//      (rep movsb with DF=1) so that LZ4's in-place decode invariant
	//      `src ≥ dst + (M − N)` is satisfied. After the move:
	//        [R15, R15+MemSize-CompressedSize)   = (now zero)
	//        [R15+MemSize-CompressedSize, MemSize) = compressed bytes
	//   2. Calls the inline LZ4 inflate with src = R15+MemSize-CompressedSize,
	//      dst = R15, srcSize = CompressedSize.
	//   3. After inflate, [R15, R15+OriginalTextSize) = plaintext .text;
	//      epilogue ADD+JMP lands at OEP.
	//
	// SafetyMargin retained for diagnostic/back-compat (intra-sequence drift
	// bound, ≈ originalTextSize/256 + 32). CompressedSize and MemSize must
	// both be non-zero when Compress is true; EmitStub returns an error
	// otherwise.
	Compress       bool
	SafetyMargin   uint32 // LZ4 intra-sequence drift bound (informational)
	CompressedSize uint32 // length of the LZ4 block in bytes (= filesz)
	MemSize        uint32 // virtual size of the .text region (= memsz)
}

// baseReg is the callee-saved register the prologue loads with the
// runtime address of the encrypted .text section. R15 is chosen because:
//   - It is not in the SGN engine's typical scratch allocation set,
//     so junk insertion won't accidentally clobber it between rounds.
//   - REX.B encoding for r8–r15 keeps the prologue's byte pattern
//     distinct from legacy-register forms — useful for entropy analysis.
const baseReg = amd64.R15

// BaseReg is the public alias for [baseReg] — stubgen.Generate
// passes it to [poly.Engine.EncodePayloadExcluding] so the poly
// engine's per-round register randomisation cannot clobber the
// runtime TextRVA pointer the prologue loads.
const BaseReg = baseReg

// EmitStub writes a complete polymorphic decoder stub into b.
//
// Layout:
//
//	prologue (CALL+POP+ADD — PIC shellcode idiom):
//	  CALL .after_call                 ; pushes &.after_call onto stack
//	.after_call:
//	  POP  r15                         ; r15 = runtime addr of .after_call
//	  ADD  r15, sentinel(0xCAFEBABE)   ; post-patched to (textRVA − .after_call_RVA)
//	                                   ; by PatchTextDisplacement after Encode
//
//	for each round (rounds[N-1] first, peeling the outermost SGN layer):
//	  MOV  cnt, textSize
//	  MOV  key, round.Key
//	  MOV  src, r15             ; reset src to text base for this round
//	loop_X:
//	  MOVZBQ (src), byte_reg
//	  <substitution applied>
//	  MOVB   byte_reg, (src)
//	  ADD    src, 1
//	  DEC    cnt
//	  JNZ    loop_X
//
//	epilogue:
//	  ADD  r15, (OEPRVA − TextRVA)
//	  JMP  r15
//
// Using CALL+POP+ADD instead of LEA RIP-relative addresses Bug #1 from
// the broken pre-v0.61 architecture (Phase 1e-A/B): golang-asm's RIP-relative LEA
// without a linker symbol emits an absolute address, not a RIP-relative
// displacement, producing stubs that crash on any load address other than
// the pack-time value. See docs/refactor-2026-doc/KNOWN-ISSUES-1e.md §Bug 1.
//
// The CALL is emitted as raw bytes (E8 00 00 00 00) because golang-asm
// cannot resolve a forward-branch CALL to the immediately following
// instruction without a linker symbol. The displacement is 0 because the
// CALL target IS the next instruction; the kernel pushes the return
// address (= address of the POP) onto the stack, which is exactly what
// the POP needs to read. See docs/refactor-2026-doc/KNOWN-ISSUES-1e.md §Bug 2.
func EmitStub(b *amd64.Builder, plan transform.Plan, rounds []poly.Round, opts EmitOptions) error {
	if len(rounds) == 0 {
		return ErrNoRounds
	}

	// Anti-debug prologue runs BEFORE CALL+POP+ADD so positive detection
	// bails without computing TextRVA into R15 — minimises the surface
	// revealed under a debugger. ELF stubs skip it (emitAntiDebug is a
	// no-op for FormatELF).
	if opts.AntiDebug {
		if err := emitAntiDebug(b, plan.Format); err != nil {
			return fmt.Errorf("stage1: anti-debug prologue: %w", err)
		}
	}

	// golang-asm cannot resolve a forward CALL to the immediately following
	// instruction without a linker symbol, so CALL rel32=0 is emitted as raw
	// bytes. E8 00 00 00 00 pushes &.after_call and falls through — exactly
	// what the PIC idiom requires.
	if err := b.RawBytes([]byte{0xE8, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1: prologue CALL: %w", err)
	}
	if err := b.POP(baseReg); err != nil {
		return fmt.Errorf("stage1: prologue POP: %w", err)
	}
	// 0xCAFEBABE is a sentinel replaced by PatchTextDisplacement once
	// Encode() has fixed the byte layout and we know the imm32 file offset.
	if err := b.ADD(baseReg, amd64.Imm(int64(prologueSentinel))); err != nil {
		return fmt.Errorf("stage1: prologue ADD sentinel: %w", err)
	}

	// Emit rounds[N-1] first: outermost SGN layer decodes first, innermost last.
	for i := len(rounds) - 1; i >= 0; i-- {
		round := rounds[i]
		if err := b.MOV(round.CntReg, amd64.Imm(int64(plan.TextSize))); err != nil {
			return fmt.Errorf("stage1: round %d MOV cnt: %w", i, err)
		}
		if err := b.MOV(round.KeyReg, amd64.Imm(int64(round.Key))); err != nil {
			return fmt.Errorf("stage1: round %d MOV key: %w", i, err)
		}
		// src is reset to r15 each round so all N passes iterate the full range.
		if err := b.MOV(round.SrcReg, baseReg); err != nil {
			return fmt.Errorf("stage1: round %d MOV src: %w", i, err)
		}

		loopLbl := b.Label(fmt.Sprintf("loop_%d", i))

		if err := b.MOVZX(round.ByteReg, amd64.MemOp{Base: round.SrcReg}); err != nil {
			return fmt.Errorf("stage1: round %d MOVZBQ: %w", i, err)
		}
		if err := round.Subst.EmitDecoder(b, round.ByteReg, round.Key); err != nil {
			return fmt.Errorf("stage1: round %d subst: %w", i, err)
		}
		// MOVB: write back only 1 byte; MOVQ would corrupt the 7 following bytes.
		if err := b.MOVB(amd64.MemOp{Base: round.SrcReg}, round.ByteReg); err != nil {
			return fmt.Errorf("stage1: round %d MOVB: %w", i, err)
		}
		if err := b.ADD(round.SrcReg, amd64.Imm(1)); err != nil {
			return fmt.Errorf("stage1: round %d ADD src: %w", i, err)
		}
		if err := b.DEC(round.CntReg); err != nil {
			return fmt.Errorf("stage1: round %d DEC: %w", i, err)
		}
		if err := b.JNZ(loopLbl); err != nil {
			return fmt.Errorf("stage1: round %d JNZ: %w", i, err)
		}
	}

	// LZ4 inflate decoder — runs after all SGN rounds have peeled the encoding.
	// At this point R15 = text base:
	//   [R15,              R15+CompressedSize) = LZ4 block (SGN-decoded compressed)
	//   [R15+CompressedSize, R15+MemSize)      = BSS-zero (filesz<memsz slack)
	//
	// Step 1: backward rep-movsb relocates the compressed bytes to the END
	// of the memsz region. Required because LZ4's in-place decode invariant
	// is `src ≥ dst + (M − N)` cumulative, not just intra-sequence — placing
	// compressed at the END gives the decoder the ahead-distance it needs.
	//
	// Step 2: register setup for the inline LZ4 decoder. Go register ABI:
	// RAX=src, RBX=dst, RCX=src_size.
	//
	// Step 3: EmitLZ4InflateInline — no terminal RET so execution falls
	// through to the OEP epilogue.
	//
	// After inflate: [R15, R15+OriginalTextSize) = plaintext .text.
	if opts.Compress {
		if opts.CompressedSize == 0 || opts.MemSize == 0 {
			return fmt.Errorf("stage1: EmitStub Compress=true but CompressedSize=%d MemSize=%d",
				opts.CompressedSize, opts.MemSize)
		}
		if opts.MemSize <= opts.CompressedSize {
			return fmt.Errorf("stage1: EmitStub Compress=true requires MemSize(%d) > CompressedSize(%d)",
				opts.MemSize, opts.CompressedSize)
		}

		// Step 1: backward memmove — std; lea rsi/rdi end-pointers; mov rcx, N;
		// rep movsb; cld. STD/CLD/REP MOVSB have no Builder helpers; emit raw.
		if err := b.RawBytes([]byte{0xfd}); err != nil { // std
			return fmt.Errorf("stage1: lz4 memmove STD: %w", err)
		}
		if err := b.LEA(amd64.RSI, amd64.MemOp{Base: amd64.R15, Disp: int32(opts.CompressedSize) - 1}); err != nil {
			return fmt.Errorf("stage1: lz4 memmove LEA RSI: %w", err)
		}
		if err := b.LEA(amd64.RDI, amd64.MemOp{Base: amd64.R15, Disp: int32(opts.MemSize) - 1}); err != nil {
			return fmt.Errorf("stage1: lz4 memmove LEA RDI: %w", err)
		}
		if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.CompressedSize))); err != nil {
			return fmt.Errorf("stage1: lz4 memmove MOV RCX: %w", err)
		}
		if err := b.RawBytes([]byte{0xf3, 0xa4}); err != nil { // rep movsb
			return fmt.Errorf("stage1: lz4 memmove REP MOVSB: %w", err)
		}
		if err := b.RawBytes([]byte{0xfc}); err != nil { // cld
			return fmt.Errorf("stage1: lz4 memmove CLD: %w", err)
		}

		// Step 2: LZ4 register setup.
		// RAX = R15 + (MemSize - CompressedSize)  -- src (compressed at end)
		// RBX = R15                                -- dst (text base)
		// RCX = CompressedSize                     -- srcSize
		if err := b.LEA(amd64.RAX, amd64.MemOp{Base: amd64.R15, Disp: int32(opts.MemSize - opts.CompressedSize)}); err != nil {
			return fmt.Errorf("stage1: lz4 setup LEA RAX: %w", err)
		}
		if err := b.MOV(amd64.RBX, baseReg); err != nil {
			return fmt.Errorf("stage1: lz4 setup MOV RBX,R15: %w", err)
		}
		if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.CompressedSize))); err != nil {
			return fmt.Errorf("stage1: lz4 setup MOV RCX,CompressedSize: %w", err)
		}
		if err := EmitLZ4InflateInline(b); err != nil {
			return fmt.Errorf("stage1: lz4 inflate inline: %w", err)
		}
	}

	// oepDisp = 0 when OEP == text start; skip the ADD to avoid a no-op imm.
	oepDisp := int64(plan.OEPRVA) - int64(plan.TextRVA)
	if oepDisp != 0 {
		if err := b.ADD(baseReg, amd64.Imm(oepDisp)); err != nil {
			return fmt.Errorf("stage1: epilogue ADD oep: %w", err)
		}
	}
	if err := b.JMP(baseReg); err != nil {
		return fmt.Errorf("stage1: epilogue JMP: %w", err)
	}

	return nil
}

// PatchTextDisplacement scans the assembled stub bytes for the sentinel
// 0xCAFEBABE imm32 emitted by EmitStub's prologue ADD and replaces it
// with the correct text-relative displacement.
//
// The displacement is computed as:
//
//	int32(plan.TextRVA) − int32(plan.StubRVA + popOffset)
//
// where popOffset is the file offset of the POP instruction inside the
// stub (= 5, the byte after the 5-byte CALL). The reference point is
// the POP's address — NOT a RIP-relative offset — because the ADD
// adds its imm32 to %r15, which the POP loaded with the return address
// pushed by CALL (= address of the POP itself). This is the classical
// CALL+POP+ADD shellcode idiom, not RIP-relative addressing.
//
// Returns the number of patches applied. A well-formed stub has exactly
// one sentinel; the function returns an error for zero or more than one.
// prologueSentinel is the imm32 placeholder EmitStub bakes into
// the prologue ADD so PatchTextDisplacement can find and replace
// it with the real text-relative displacement after Encode().
// callPopSentinel is its little-endian byte form for bytes.Index
// scanning. The init derives one from the other so they cannot
// silently drift between what's emitted and what's searched for.
const prologueSentinel uint32 = 0xCAFEBABE

var callPopSentinel = binary.LittleEndian.AppendUint32(nil, prologueSentinel)

func PatchTextDisplacement(stubBytes []byte, plan transform.Plan) (int, error) {
	i := bytes.Index(stubBytes, callPopSentinel)
	if i < 0 {
		return 0, fmt.Errorf("stage1: sentinel 0xCAFEBABE not found in stub bytes")
	}
	// Verify no second occurrence — two matches means a collision in the
	// encoded payload, which breaks the single-patch contract.
	if bytes.Index(stubBytes[i+4:], callPopSentinel) >= 0 {
		return 0, fmt.Errorf("stage1: multiple sentinel 0xCAFEBABE matches; expected exactly 1")
	}

	// CALL+POP+ADD: %r15 = address of POP (= StubRVA + 5) after the
	// 5-byte CALL. ADD imm32 is added to %r15 directly — NOT
	// RIP-relative. Displacement reference point is the POP's address.
	const popOffset = 5
	popAddr := plan.StubRVA + popOffset
	disp := uint32(int32(plan.TextRVA) - int32(popAddr))
	stubBytes[i] = byte(disp)
	stubBytes[i+1] = byte(disp >> 8)
	stubBytes[i+2] = byte(disp >> 16)
	stubBytes[i+3] = byte(disp >> 24)
	return 1, nil
}
