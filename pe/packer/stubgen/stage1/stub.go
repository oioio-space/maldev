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

	// Compress, when true, appends an LZ4 register-setup + inline LZ4
	// inflate decoder + memcpy-back epilogue BETWEEN the last SGN round
	// and the OEP-jump epilogue.
	//
	// Layout invariants when this branch runs:
	//   * .text segment filesz = CompressedSize, memsz = CompressedSize.
	//     [R15, R15+CompressedSize) = SGN-decoded compressed bytes.
	//   * The stub segment has memsz = StubMaxSize + originalTextSize,
	//     filesz = StubMaxSize. Scratch buffer lives in the stub segment's
	//     BSS slack at offset StubMaxSize from StubRVA. ScratchDispFromText
	//     is its displacement from R15 (= TextRVA at runtime).
	//
	// Why scratch-in-stub-segment instead of in-place: Go static-PIE
	// binaries pack PT_LOADs tightly — the .text segment can't grow past
	// the next read-only segment's vaddr. The stub segment we append has
	// no such constraint, so we put the inflate workspace there.
	//
	// The stub:
	//   1. Sets RAX=R15, RBX=R15+ScratchDispFromText, RCX=CompressedSize.
	//   2. Calls inline LZ4 inflate (src=.text, dst=scratch, no overlap).
	//   3. memcpy back: rep movsb from scratch to R15, count=OriginalSize.
	//   4. Falls through to OEP-jump epilogue.
	//
	// CompressedSize, OriginalSize, and ScratchDispFromText must be
	// non-zero when Compress is true; EmitStub returns an error otherwise.
	// SafetyMargin retained as a diagnostic field (informational only).
	Compress            bool
	SafetyMargin        uint32 // (informational) LZ4 intra-seq drift bound
	CompressedSize      uint32 // length of the LZ4 block in bytes
	OriginalSize        uint32 // decompressed .text size (memcpy count)
	ScratchDispFromText int32  // signed displacement from R15 to scratch base
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

	if err := emitTextBasePrologue(b); err != nil {
		return fmt.Errorf("stage1: text-base prologue: %w", err)
	}

	// SGN rounds — outermost layer decodes first (shared helper).
	if err := emitSGNRounds(b, plan, rounds, "loop", "stage1"); err != nil {
		return err
	}

	// LZ4 inflate decoder — runs after all SGN rounds have peeled the encoding.
	// At this point R15 = text base:
	//   [R15,              R15+CompressedSize) = LZ4 block (SGN-decoded compressed)
	//   Scratch buffer at R15+ScratchDispFromText (in stub segment BSS slack)
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
		if opts.CompressedSize == 0 || opts.OriginalSize == 0 || opts.ScratchDispFromText == 0 {
			return fmt.Errorf("stage1: EmitStub Compress=true but CompressedSize=%d OriginalSize=%d ScratchDispFromText=%d",
				opts.CompressedSize, opts.OriginalSize, opts.ScratchDispFromText)
		}

		// LZ4 register setup: src=.text, dst=scratch, srcSize=N. Disjoint
		// regions, so no in-place gymnastics needed.
		// RAX = R15
		if err := b.MOV(amd64.RAX, baseReg); err != nil {
			return fmt.Errorf("stage1: lz4 setup MOV RAX,R15: %w", err)
		}
		// RBX = R15 + ScratchDispFromText  -- scratch base in stub segment
		if err := b.LEA(amd64.RBX, amd64.MemOp{Base: baseReg, Disp: opts.ScratchDispFromText}); err != nil {
			return fmt.Errorf("stage1: lz4 setup LEA RBX,scratch: %w", err)
		}
		// RCX = CompressedSize
		if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.CompressedSize))); err != nil {
			return fmt.Errorf("stage1: lz4 setup MOV RCX,CompressedSize: %w", err)
		}
		if err := EmitLZ4InflateInline(b); err != nil {
			return fmt.Errorf("stage1: lz4 inflate inline: %w", err)
		}

		// memcpy plaintext back to R15: cld; mov rsi, rbx (scratch saved
		// across the asm via callee-saved push/pop); mov rdi, r15;
		// mov rcx, OriginalSize; rep movsb. RBX holds scratch on entry
		// to this block — verify by inspecting EmitLZ4Inflate's prologue
		// (push rbx; push r12) and epilogue (pop r12; pop rbx).
		if err := b.RawBytes([]byte{0xfc}); err != nil { // cld (DF=0)
			return fmt.Errorf("stage1: memcpy CLD: %w", err)
		}
		if err := b.MOV(amd64.RSI, amd64.RBX); err != nil {
			return fmt.Errorf("stage1: memcpy MOV RSI,RBX: %w", err)
		}
		if err := b.MOV(amd64.RDI, baseReg); err != nil {
			return fmt.Errorf("stage1: memcpy MOV RDI,R15: %w", err)
		}
		if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.OriginalSize))); err != nil {
			return fmt.Errorf("stage1: memcpy MOV RCX,OriginalSize: %w", err)
		}
		if err := b.RawBytes([]byte{0xf3, 0xa4}); err != nil { // rep movsb
			return fmt.Errorf("stage1: memcpy REP MOVSB: %w", err)
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
// prologueSentinel is the imm32 placeholder EmitStub and EmitDLLStub
// bake into the prologue ADD so PatchTextDisplacement can find and
// replace it with the real text-relative displacement after Encode().
// callPopSentinel is its little-endian byte form for bytes.Index
// scanning. The init derives one from the other so they cannot
// silently drift between what's emitted and what's searched for.
const prologueSentinel uint32 = 0xCAFEBABE

var callPopSentinel = binary.LittleEndian.AppendUint32(nil, prologueSentinel)

// emitSGNRounds writes the polymorphic-decoder loop body shared
// by [EmitStub] (EXE), [EmitDLLStub] (native DLL), and
// [EmitConvertedDLLStub] (converted DLL). Each round expands to:
//
//	MOV  cnt, TextSize
//	MOV  key, round.Key
//	MOV  src, R15           ; reset src to text base for this round
//	loopLabel:
//	  MOVZBQ byte ptr [src], byteReg
//	  <substitution decoder>
//	  MOVB   byteReg, byte ptr [src]
//	  ADD    src, 1
//	  DEC    cnt
//	  JNZ    loopLabel
//
// Rounds are emitted in REVERSE order (rounds[N-1] first) so the
// outermost SGN layer decodes first at runtime — matches
// [poly.Engine.EncodePayload] ordering. R15 is hardcoded as the
// text-base register (matches [baseReg]; see also the
// EncodePayloadExcluding(BaseReg) protection at the call site).
//
// `labelPrefix` namespaces the per-round loop label so the same
// Builder can hold multiple round-emitting blocks without collision
// (in practice each emitter uses its own Builder, but the prefix
// avoids string-matching hazards in tests). `errPrefix` lets each
// caller surface failures under its own "stage1:" / "stage1/dll:"
// namespace.
func emitSGNRounds(b *amd64.Builder, plan transform.Plan, rounds []poly.Round, labelPrefix, errPrefix string) error {
	for i := len(rounds) - 1; i >= 0; i-- {
		round := rounds[i]
		if err := b.MOV(round.CntReg, amd64.Imm(int64(plan.TextSize))); err != nil {
			return fmt.Errorf("%s: round %d MOV cnt: %w", errPrefix, i, err)
		}
		if err := b.MOV(round.KeyReg, amd64.Imm(int64(round.Key))); err != nil {
			return fmt.Errorf("%s: round %d MOV key: %w", errPrefix, i, err)
		}
		if err := b.MOV(round.SrcReg, baseReg); err != nil {
			return fmt.Errorf("%s: round %d MOV src: %w", errPrefix, i, err)
		}
		loopLbl := b.Label(fmt.Sprintf("%s_%d", labelPrefix, i))
		if err := b.MOVZX(round.ByteReg, amd64.MemOp{Base: round.SrcReg}); err != nil {
			return fmt.Errorf("%s: round %d MOVZBQ: %w", errPrefix, i, err)
		}
		if err := round.Subst.EmitDecoder(b, round.ByteReg, round.Key); err != nil {
			return fmt.Errorf("%s: round %d subst: %w", errPrefix, i, err)
		}
		if err := b.MOVB(amd64.MemOp{Base: round.SrcReg}, round.ByteReg); err != nil {
			return fmt.Errorf("%s: round %d MOVB: %w", errPrefix, i, err)
		}
		if err := b.ADD(round.SrcReg, amd64.Imm(1)); err != nil {
			return fmt.Errorf("%s: round %d ADD src: %w", errPrefix, i, err)
		}
		if err := b.DEC(round.CntReg); err != nil {
			return fmt.Errorf("%s: round %d DEC: %w", errPrefix, i, err)
		}
		if err := b.JNZ(loopLbl); err != nil {
			return fmt.Errorf("%s: round %d JNZ: %w", errPrefix, i, err)
		}
	}
	return nil
}

// emitTextBasePrologue writes the CALL+POP+ADD PIC idiom into b,
// leaving baseReg (R15) loaded with TextRVA at runtime once
// [PatchTextDisplacement] has rewritten the sentinel.
//
// Shared between [EmitStub] (EXE path) and [EmitDLLStub] (DLL path)
// so the popOffset=5 invariant baked into [PatchTextDisplacement]
// can't silently drift apart from the emitter. Both call sites
// pass through the same sentinel + patcher.
//
// Layout (10 bytes):
//
//	E8 00 00 00 00      CALL .next       (next instruction)
//	41 5F               POP  r15
//	49 81 C7 BE BA FE CA  ADD  r15, 0xCAFEBABE (sentinel)
func emitTextBasePrologue(b *amd64.Builder) error {
	// golang-asm cannot resolve a forward CALL to the immediately
	// following instruction without a linker symbol, so CALL rel32=0
	// is emitted as raw bytes. E8 00 00 00 00 pushes the address of
	// the next instruction (the POP) — exactly what the idiom needs.
	if err := b.RawBytes([]byte{0xE8, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1: prologue CALL: %w", err)
	}
	if err := b.POP(baseReg); err != nil {
		return fmt.Errorf("stage1: prologue POP: %w", err)
	}
	if err := b.ADD(baseReg, amd64.Imm(int64(prologueSentinel))); err != nil {
		return fmt.Errorf("stage1: prologue ADD sentinel: %w", err)
	}
	return nil
}

// patchSentinel scans haystack for every occurrence of needle (the
// little-endian byte form of a 4- or 8-byte sentinel), rewrites
// each with value (same length as needle), and returns the byte
// offset of the FIRST match plus the total occurrence count.
//
// When allowMulti is false, exactly one match is required —
// zero or more than one returns an error. When allowMulti is true,
// at least one match is required.
//
// Used by [PatchTextDisplacement] (single uint32 match),
// [PatchDLLStubDisplacements] (uint32 sentinels, multiple matches),
// and [PatchDllMainSlot] (single uint64 match).
func patchSentinel(haystack, needle, value []byte, allowMulti bool, name string) (firstIdx, count int, err error) {
	if len(needle) != len(value) {
		return -1, 0, fmt.Errorf("stage1: patchSentinel %s: needle/value length mismatch (%d vs %d)",
			name, len(needle), len(value))
	}
	// First pass: locate every occurrence. We don't mutate yet so a
	// uniqueness-violation error leaves haystack untouched.
	var positions []int
	off := 0
	for {
		i := bytes.Index(haystack[off:], needle)
		if i < 0 {
			break
		}
		i += off
		positions = append(positions, i)
		off = i + len(needle)
	}
	count = len(positions)
	switch {
	case count == 0:
		return -1, 0, fmt.Errorf("stage1: %s sentinel not found", name)
	case !allowMulti && count > 1:
		return positions[0], count, fmt.Errorf("stage1: %s sentinel matched %d times, want exactly 1", name, count)
	}
	// Second pass: patch each occurrence in place.
	for _, i := range positions {
		copy(haystack[i:i+len(needle)], value)
	}
	return positions[0], count, nil
}

func PatchTextDisplacement(stubBytes []byte, plan transform.Plan) (int, error) {
	// Locate the sentinel imm32 first so we can derive the POP
	// instruction's byte offset within the stub. The CALL+POP+ADD
	// idiom encodes as:
	//   E8 00 00 00 00   ; CALL .next  (5 B)
	//   41 5F            ; POP r15     (2 B)
	//   49 81 C7 <imm32> ; ADD r15, imm32 (7 B, sentinel = imm32)
	// So sentinel starts 5 bytes after POP starts: popOffset =
	// sentinelOff - 5. This works for any CALL+POP+ADD position —
	// the EXE stub places it at the start (sentinelOff=10 →
	// popOffset=5), the DLL stubs place it after a prologue
	// (sentinelOff=34+ → popOffset=29+). Slice 5.5.x: a hardcoded
	// popOffset=5 produced an R15 24 B above textBase on DLL
	// stubs → all flag/slot accesses miss → kernel32!LoadLibrary
	// AV crash on the first MOVB.
	sentinelOff := bytes.Index(stubBytes, callPopSentinel)
	if sentinelOff < 0 {
		return 0, fmt.Errorf("stage1: prologueSentinel 0xCAFEBABE not found")
	}
	popAddr := plan.StubRVA + uint32(sentinelOff) - 5
	disp := uint32(int32(plan.TextRVA) - int32(popAddr))
	value := binary.LittleEndian.AppendUint32(nil, disp)
	_, count, err := patchSentinel(stubBytes, callPopSentinel, value, false, "prologueSentinel 0xCAFEBABE")
	return count, err
}
