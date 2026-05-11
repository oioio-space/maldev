package stage1

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// dllStubSentinel and dllStubSentinelBytes alias the canonical
// definitions in package transform — exported there so the
// transform-side [transform.PatchDLLStubSlot] and the stub
// emitter here can't drift apart silently.
const dllStubSentinel = transform.DLLStubSentinel

var dllStubSentinelBytes = transform.DLLStubSentinelBytes

// flagDispSentinel and slotDispSentinel are imm32 placeholders baked
// into the MOV operands that reference the decrypted_flag byte (R15-relative
// load + store) and the orig_dllmain_slot qword (R15-relative load).
// [PatchDLLStubDisplacements] rewrites every occurrence with the real
// R15-relative displacements once the trailing-data offsets are known.
// Values are out-of-band for typical instruction encodings to avoid
// false-positive matches in surrounding asm bytes.
const (
	flagDispSentinel uint32 = 0x7FFE0001
	slotDispSentinel uint32 = 0x7FFE0002
)

// dllReasonProcessAttach is the DLL_PROCESS_ATTACH reason code passed
// to DllMain by the Windows loader on the FIRST call after LoadLibrary.
// Any other reason (THREAD_ATTACH, THREAD_DETACH, PROCESS_DETACH) is
// forwarded straight to the original DllMain without re-decrypting
// .text — the SGN rounds must run exactly once, on the first call.
const dllReasonProcessAttach = 1

// ErrDLLStubSentinelNotFound + ErrDLLStubSentinelDuplicate are
// aliases of the transform-side sentinels (single source of truth)
// so existing callers can still errors.Is against the stage1 names.
var (
	ErrDLLStubSentinelNotFound  = transform.ErrDLLStubSlotNotFound
	ErrDLLStubSentinelDuplicate = transform.ErrDLLStubSlotDuplicate

	// ErrDLLStubPlanMissing fires when EmitDLLStub is called with a
	// Plan that doesn't have IsDLL=true. Guards against accidentally
	// routing an EXE plan through the DLL emitter.
	ErrDLLStubPlanMissing = errors.New("stage1: EmitDLLStub requires Plan.IsDLL=true")
)

// EmitDLLStub writes a DllMain-shaped decoder stub into b.
//
// The DLL entry contract differs from the EXE stub's in three ways:
//   - The loader calls the stub multiple times (PROCESS_ATTACH,
//     THREAD_ATTACH/DETACH, PROCESS_DETACH) — the SGN decrypt runs
//     EXACTLY once, on the PROCESS_ATTACH (reason=1) call.
//   - The args (rcx=hInst, edx=reason, r8=reserved) must reach the
//     original DllMain intact on every call.
//   - We must tail-call (not jump-then-ExitProcess) so the original
//     DllMain's BOOL return value reaches the loader.
//
// Layout:
//
//	prologue:
//	  push  rbp
//	  mov   rbp, rsp
//	  sub   rsp, 0x30                  ; 0x30 = 4 × 8B slots + 16 align
//	  mov   [rbp-0x08], rcx            ; save hInst
//	  mov   [rbp-0x10], rdx            ; save reason
//	  mov   [rbp-0x18], r8             ; save reserved
//	  mov   [rbp-0x20], r15            ; preserve callee-saved
//
//	CALL+POP+ADD (always runs — R15 needed by the tail-call):
//	  call  .after_call
//	.after_call:
//	  pop   r15
//	  add   r15, sentinel              ; → R15 = textRVA at runtime
//	                                   ; patched by PatchTextDisplacement
//
//	reason check:
//	  cmp   rdx, 1                     ; reason == DLL_PROCESS_ATTACH?
//	  jne   .forward                   ; no — skip decrypt
//
//	decrypted_flag check:
//	  movzx rax, byte ptr [r15+flag_disp]
//	  test  rax, rax
//	  jne   .forward                   ; already decrypted — skip rounds
//	  mov   rax, 1
//	  movb  [r15+flag_disp], al        ; latch — second call sees flag=1
//
//	SGN rounds (identical to the EXE stub body):
//	  for each round[i]:
//	    MOV cnt, TextSize; MOV key, round.Key; MOV src, R15
//	    loop_i: MOVZBQ → subst → MOVB → ADD src,1; DEC cnt; JNZ loop_i
//
//	forward (tail-call to original DllMain):
//	.forward:
//	  mov   rax, qword ptr [r15+slot_disp]   ; load saved DllMain VA
//	  mov   rcx, [rbp-0x08]                  ; restore args
//	  mov   rdx, [rbp-0x10]
//	  mov   r8,  [rbp-0x18]
//	  mov   r15, [rbp-0x20]                  ; restore non-volatile
//	  add   rsp, 0x30
//	  pop   rbp
//	  jmp   rax                              ; the original DllMain's
//	                                         ; RET returns BOOL to the loader
//
//	trailing data (in-stub):
//	.decrypted_flag:   db 0
//	.orig_dllmain_slot: dq dllStubSentinel    ; patched at pack time
//
// The CALL+POP+ADD prologue mirrors EmitStub's — [PatchTextDisplacement]
// finds the same `0xCAFEBABE` sentinel and rewrites it with the right
// text-relative displacement. The new `dllStubSentinel` covers the
// orig-DllMain slot; [PatchDllMainSlot] rewrites it with the absolute
// VA (ImageBase + OEPRVA) at pack time. Both sentinels need to be
// covered by the .reloc table so the loader rebases them under ASLR —
// see [transform.InjectStubDLL] (slice 3).
func EmitDLLStub(b *amd64.Builder, plan transform.Plan, rounds []poly.Round) error {
	if !plan.IsDLL {
		return ErrDLLStubPlanMissing
	}
	if len(rounds) == 0 {
		return ErrNoRounds
	}

	// --- prologue: stack frame + arg/r15 spill ---
	if err := b.RawBytes([]byte{0x55}); err != nil { // push rbp
		return fmt.Errorf("stage1/dll: push rbp: %w", err)
	}
	if err := b.MOV(amd64.RBP, amd64.RSP); err != nil {
		return fmt.Errorf("stage1/dll: mov rbp,rsp: %w", err)
	}
	if err := b.SUB(amd64.RSP, amd64.Imm(0x30)); err != nil {
		return fmt.Errorf("stage1/dll: sub rsp,0x30: %w", err)
	}
	for _, spill := range []struct {
		disp int32
		reg  amd64.Reg
		name string
	}{
		{-0x08, amd64.RCX, "rcx"},
		{-0x10, amd64.RDX, "rdx"},
		{-0x18, amd64.R8, "r8"},
		{-0x20, amd64.R15, "r15"},
	} {
		if err := b.MOV(amd64.MemOp{Base: amd64.RBP, Disp: spill.disp}, spill.reg); err != nil {
			return fmt.Errorf("stage1/dll: spill %s: %w", spill.name, err)
		}
	}

	// CALL+POP+ADD: R15 := textRVA at runtime. Shared with EmitStub —
	// PatchTextDisplacement finds the same 0xCAFEBABE sentinel regardless
	// of which stub emitted it.
	if err := emitTextBasePrologue(b); err != nil {
		return fmt.Errorf("stage1/dll: text-base prologue: %w", err)
	}

	// --- reason != DLL_PROCESS_ATTACH → skip decrypt ---
	// Forward-jump via raw LabelRef; Label() anchors at the destination
	// below. Pattern mirrors emitAntiDebugWindowsPE (antidebug.go:42-44).
	const forwardLabel = "dllmain_forward"
	if err := b.CMP(amd64.RDX, amd64.Imm(dllReasonProcessAttach)); err != nil {
		return fmt.Errorf("stage1/dll: cmp reason: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(forwardLabel)); err != nil {
		return fmt.Errorf("stage1/dll: jnz forward (reason): %w", err)
	}

	// In-stub trailing data lives AFTER the JMP RAX epilogue; the byte
	// offsets aren't known until Encode(). We bake the package-level
	// disp sentinels into the MemOp imm32s and let
	// PatchDLLStubDisplacements rewrite them post-Encode. RIP-relative
	// addressing via labels would be cleaner but golang-asm emits it as
	// absolute under the current ABI (stub.go:104-108).
	if err := b.MOVZX(amd64.RAX, amd64.MemOp{Base: amd64.R15, Disp: int32(flagDispSentinel)}); err != nil {
		return fmt.Errorf("stage1/dll: movzx flag: %w", err)
	}
	if err := b.TEST(amd64.RAX, amd64.RAX); err != nil {
		return fmt.Errorf("stage1/dll: test flag: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(forwardLabel)); err != nil {
		return fmt.Errorf("stage1/dll: jnz forward (flag): %w", err)
	}
	// latch flag so subsequent calls (any reason code) skip the SGN rounds
	if err := b.MOV(amd64.RAX, amd64.Imm(1)); err != nil {
		return fmt.Errorf("stage1/dll: mov al,1: %w", err)
	}
	if err := b.MOVB(amd64.MemOp{Base: amd64.R15, Disp: int32(flagDispSentinel)}, amd64.RAX); err != nil {
		return fmt.Errorf("stage1/dll: movb flag,al: %w", err)
	}

	// --- SGN rounds (clone of EmitStub's loop body) ---
	for i := len(rounds) - 1; i >= 0; i-- {
		round := rounds[i]
		if err := b.MOV(round.CntReg, amd64.Imm(int64(plan.TextSize))); err != nil {
			return fmt.Errorf("stage1/dll: round %d MOV cnt: %w", i, err)
		}
		if err := b.MOV(round.KeyReg, amd64.Imm(int64(round.Key))); err != nil {
			return fmt.Errorf("stage1/dll: round %d MOV key: %w", i, err)
		}
		if err := b.MOV(round.SrcReg, amd64.R15); err != nil {
			return fmt.Errorf("stage1/dll: round %d MOV src: %w", i, err)
		}
		loopLbl := b.Label(fmt.Sprintf("dll_loop_%d", i))
		if err := b.MOVZX(round.ByteReg, amd64.MemOp{Base: round.SrcReg}); err != nil {
			return fmt.Errorf("stage1/dll: round %d MOVZBQ: %w", i, err)
		}
		if err := round.Subst.EmitDecoder(b, round.ByteReg, round.Key); err != nil {
			return fmt.Errorf("stage1/dll: round %d subst: %w", i, err)
		}
		if err := b.MOVB(amd64.MemOp{Base: round.SrcReg}, round.ByteReg); err != nil {
			return fmt.Errorf("stage1/dll: round %d MOVB: %w", i, err)
		}
		if err := b.ADD(round.SrcReg, amd64.Imm(1)); err != nil {
			return fmt.Errorf("stage1/dll: round %d ADD src: %w", i, err)
		}
		if err := b.DEC(round.CntReg); err != nil {
			return fmt.Errorf("stage1/dll: round %d DEC: %w", i, err)
		}
		if err := b.JNZ(loopLbl); err != nil {
			return fmt.Errorf("stage1/dll: round %d JNZ: %w", i, err)
		}
	}

	// --- forward: tail-call to original DllMain ---
	// Anchor the forward label here; all earlier JNZs resolve to this point.
	_ = b.Label(forwardLabel)
	// rax := [R15+slotDisp]  -- absolute VA of original DllMain
	if err := b.MOV(amd64.RAX, amd64.MemOp{Base: amd64.R15, Disp: int32(slotDispSentinel)}); err != nil {
		return fmt.Errorf("stage1/dll: load orig dllmain slot: %w", err)
	}
	// restore args + r15
	for _, restore := range []struct {
		reg  amd64.Reg
		disp int32
		name string
	}{
		{amd64.RCX, -0x08, "rcx"},
		{amd64.RDX, -0x10, "rdx"},
		{amd64.R8, -0x18, "r8"},
		{amd64.R15, -0x20, "r15"},
	} {
		if err := b.MOV(restore.reg, amd64.MemOp{Base: amd64.RBP, Disp: restore.disp}); err != nil {
			return fmt.Errorf("stage1/dll: restore %s: %w", restore.name, err)
		}
	}
	if err := b.ADD(amd64.RSP, amd64.Imm(0x30)); err != nil {
		return fmt.Errorf("stage1/dll: add rsp,0x30: %w", err)
	}
	if err := b.RawBytes([]byte{0x5D}); err != nil { // pop rbp
		return fmt.Errorf("stage1/dll: pop rbp: %w", err)
	}
	if err := b.JMP(amd64.RAX); err != nil {
		return fmt.Errorf("stage1/dll: jmp rax (tail-call): %w", err)
	}

	// --- trailing data: 1B decrypted_flag + 8B orig_dllmain_slot ---
	if err := b.RawBytes([]byte{0x00}); err != nil { // decrypted_flag = 0
		return fmt.Errorf("stage1/dll: emit flag byte: %w", err)
	}
	if err := b.RawBytes(dllStubSentinelBytes); err != nil {
		return fmt.Errorf("stage1/dll: emit dllmain slot sentinel: %w", err)
	}

	return nil
}

// PatchDLLStubDisplacements rewrites the disp sentinels emitted
// by [EmitDLLStub] with the real R15-relative displacements once
// the stub byte layout is finalised.
//
// Trailing data layout: stubBytes[len-9] = decrypted_flag (1B),
// stubBytes[len-8 .. len] = orig_dllmain_slot (8B sentinel).
// Both displacements are computed relative to R15 = textBase at
// runtime, so disp = (stubRVA + offset_in_stub) − textRVA.
//
// The flag disp appears TWICE in the assembled stub (one MOVZX load
// + one MOVB store), the slot disp appears ONCE (the tail-call MOV).
// All occurrences of each sentinel are rewritten with the same value;
// the caller doesn't need to know the asm-level occurrence count.
//
// Returns the total number of imm32 patches applied (≥ 2). At least
// one occurrence of each sentinel is required — missing sentinel
// is an error.
func PatchDLLStubDisplacements(stubBytes []byte, plan transform.Plan) (int, error) {
	if len(stubBytes) < 9 {
		return 0, fmt.Errorf("stage1/dll: stub too short (%d B) — missing trailing data", len(stubBytes))
	}
	flagOff := uint32(len(stubBytes) - 9)
	slotOff := uint32(len(stubBytes) - 8)

	flagDisp := uint32(int32(plan.StubRVA+flagOff) - int32(plan.TextRVA))
	slotDisp := uint32(int32(plan.StubRVA+slotOff) - int32(plan.TextRVA))

	patched := 0
	for _, p := range []struct {
		sentinel uint32
		value    uint32
		name     string
	}{
		{flagDispSentinel, flagDisp, "flag disp"},
		{slotDispSentinel, slotDisp, "slot disp"},
	} {
		needle := binary.LittleEndian.AppendUint32(nil, p.sentinel)
		value := binary.LittleEndian.AppendUint32(nil, p.value)
		_, n, err := patchSentinel(stubBytes, needle, value, true, p.name)
		if err != nil {
			return patched, err
		}
		patched += n
	}
	return patched, nil
}

// PatchDllMainSlot rewrites the 8-byte [dllStubSentinel] placeholder
// with the absolute VA of the original DllMain (= imageBase + OEPRVA).
// Called by transform.InjectStubDLL once the host's imageBase is known
// and the trailing-data offset has been finalised.
//
// **Caller invariant:** stubBytes must be the stub slice ONLY, before
// it is concatenated with the encrypted .text payload. The encrypted
// payload could (with ~2^-64 probability) coincidentally contain
// dllStubSentinel; scanning a joined buffer would corrupt those bytes.
//
// Returns the byte offset where the slot lived in stubBytes (so
// InjectStubDLL can derive its file offset for the reloc table) +
// any error. Errors wrap [ErrDLLStubSentinelNotFound] /
// [ErrDLLStubSentinelDuplicate] so callers can errors.Is them.
func PatchDllMainSlot(stubBytes []byte, absDllMainVA uint64) (int, error) {
	return transform.PatchDLLStubSlot(stubBytes, absDllMainVA)
}
