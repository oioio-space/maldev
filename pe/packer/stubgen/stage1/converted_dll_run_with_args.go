package stage1

import (
	"bytes"
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// prologueSentinelRWA is the imm32 placeholder
// [emitTextBasePrologueRWA] bakes into its ADD instruction. Distinct
// from [prologueSentinel] so the DllMain prologue and the RunWithArgs
// prologue can be patched independently — both live in the same stub
// bytes but require different displacements (each ADD is at a
// different offset, so each needs a different popAddr-to-TextRVA
// distance).
const prologueSentinelRWA uint32 = 0xCAFEBABF

// rwaTextDispNeedle is the little-endian byte form of
// [prologueSentinelRWA], used by [PatchRunWithArgsTextDisplacement]
// for bytes.Index scanning.
var rwaTextDispNeedle = binary.LittleEndian.AppendUint32(nil, prologueSentinelRWA)

// RunWithArgsEntrySentinel is the 8-byte INT3 pattern emitted at the
// very start of the RunWithArgs entry. Used by
// [PatchConvertedDLLRunWithArgsEntry] (added in slice 1.B.1.c.4)
// to locate the entry offset inside the encoded stub bytes. INT3
// (0xCC) never appears in our emitted asm, so the 8-byte run is a
// reliable, collision-free marker. The patcher replaces it with 8
// NOPs once the offset is known so a misdirected GetProcAddress
// caller doesn't trigger a debug break on first byte of the entry.
var RunWithArgsEntrySentinel = [8]byte{0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC, 0xCC}

// runWithArgsFrameSize is the RBP-relative frame the RunWithArgs
// entry allocates after `push rbp; mov rbp, rsp`. Slot layout
// (offsets from RBP, growing downward):
//
//	-0x08  caller args ptr (RCX spill)
//	-0x10  DWORD exit code (out-param for GetExitCodeThread, then returned in EAX)
//	-0x18  unused
//	-0x20  hThread spill (CreateThread return, re-passed to Wait + ExitCode)
//	-0x28  rbx
//	-0x30  rdi
//	-0x38  rsi
//	-0x40  r12
//	-0x48  r13
//	-0x50  r14
//	-0x58  r15
//	[0x08 of trailing pad to keep RSP 16-aligned on the next CALL]
const runWithArgsFrameSize = 0x60

// runWithArgsCalleeSaved lists the registers RunWithArgs must spill
// to honour the Win64 caller's expectation that we preserve them.
// Same set as [convertedExtraSpills] used by the DllMain prologue —
// keeping the spill recipe identical between the two entry points
// avoids per-entry quirks.
var runWithArgsCalleeSaved = []struct {
	reg  amd64.Reg
	disp int32
	name string
}{
	{amd64.RBX, -0x28, "rbx"},
	{amd64.RDI, -0x30, "rdi"},
	{amd64.RSI, -0x38, "rsi"},
	{amd64.R12, -0x40, "r12"},
	{amd64.R13, -0x48, "r13"},
	{amd64.R14, -0x50, "r14"},
	{amd64.R15, -0x58, "r15"},
}

// EmitConvertedDLLRunWithArgsEntry writes the `RunWithArgs` exported
// function body into b. Layout (offsets within the emitted block):
//
//	+0  CC CC CC CC CC CC CC CC     ; sentinel — patched to NOPs by
//	                                  PatchConvertedDLLRunWithArgsEntry
//	+8  push rbp / mov rbp, rsp     ; standard frame
//	    sub rsp, 0x60
//	    mov [rbp-0x08], rcx         ; spill caller's args ptr
//	    mov [rbp-0x28..-0x58], rbx/rdi/rsi/r12-r15
//	    call+pop+add → r15 = textRVA (sentinel = prologueSentinelRWA)
//	    mov rcx, [rbp-0x08]         ; reload args ptr for spawn block
//	    <emitConvertedSpawnBlock with convertedSpawnArgsFromRCX>
//	    mov rbx/.../r15, [rbp-...]  ; restore callee-saved
//	    leave / ret
//
// Register contract (Win64 ABI):
//   - Inputs:  RCX = LPCWSTR args (caller-owned, NUL-terminated)
//   - Output:  RAX = HANDLE hThread from CreateThread (or 0 on failure).
//
//     Slice 1.B.1.c.2 ships this raw hThread return; slice 1.B.1.c.3
//     promotes it to the DWORD exit code by adding WaitForSingleObject
//     + GetExitCodeThread before the epilogue.
//
//   - Preserves: RBX, RBP, RDI, RSI, R12-R15 (Win64 callee-saved).
//
// The entry uses the same convertedSpawnBlock helper as the DllMain
// path with [convertedSpawnArgsFromRCX] — wcslen of RCX runs at
// runtime, PEB.ProcessParameters.CommandLine is rewritten in place,
// then CreateThread spawns the OEP. The two entries share the same
// spawn shape; only the args-source differs.
func EmitConvertedDLLRunWithArgsEntry(b *amd64.Builder, plan transform.Plan, opts EmitOptions) error {
	if !plan.IsConvertedDLL {
		return ErrConvertedDLLPlanMissing
	}

	// --- sentinel marker ---
	if err := b.RawBytes(RunWithArgsEntrySentinel[:]); err != nil {
		return fmt.Errorf("stage1/runwithargs: sentinel: %w", err)
	}

	// --- prologue: push rbp; mov rbp, rsp; sub rsp, 0x60 ---
	// push rbp
	if err := b.RawBytes([]byte{0x55}); err != nil {
		return fmt.Errorf("stage1/runwithargs: push rbp: %w", err)
	}
	// mov rbp, rsp
	if err := b.RawBytes([]byte{0x48, 0x89, 0xE5}); err != nil {
		return fmt.Errorf("stage1/runwithargs: mov rbp,rsp: %w", err)
	}
	// sub rsp, 0x60
	if err := b.SUB(amd64.RSP, amd64.Imm(runWithArgsFrameSize)); err != nil {
		return fmt.Errorf("stage1/runwithargs: sub rsp,0x60: %w", err)
	}

	// --- spill caller's args ptr (rcx) + callee-saved regs ---
	if err := b.MOV(amd64.MemOp{Base: amd64.RBP, Disp: -0x08}, amd64.RCX); err != nil {
		return fmt.Errorf("stage1/runwithargs: spill rcx: %w", err)
	}
	for _, s := range runWithArgsCalleeSaved {
		if err := b.MOV(amd64.MemOp{Base: amd64.RBP, Disp: s.disp}, s.reg); err != nil {
			return fmt.Errorf("stage1/runwithargs: spill %s: %w", s.name, err)
		}
	}

	// --- CALL+POP+ADD → r15 = textRVA at runtime ---
	// Same idiom as emitTextBasePrologue but with a different
	// sentinel so PatchRunWithArgsTextDisplacement (slice 1.B.1.c.4)
	// can patch it independently of the DllMain prologue.
	if err := b.RawBytes([]byte{0xE8, 0x00, 0x00, 0x00, 0x00}); err != nil {
		return fmt.Errorf("stage1/runwithargs: prologue CALL: %w", err)
	}
	if err := b.POP(baseReg); err != nil {
		return fmt.Errorf("stage1/runwithargs: prologue POP: %w", err)
	}
	if err := b.ADD(baseReg, amd64.Imm(int64(prologueSentinelRWA))); err != nil {
		return fmt.Errorf("stage1/runwithargs: prologue ADD sentinel: %w", err)
	}

	// --- reload args ptr into rcx for the spawn block ---
	if err := b.MOV(amd64.RCX, amd64.MemOp{Base: amd64.RBP, Disp: -0x08}); err != nil {
		return fmt.Errorf("stage1/runwithargs: reload rcx: %w", err)
	}

	// --- shared spawn block: resolve + PEB patch (rcx,wcslen) + CreateThread ---
	if err := emitConvertedSpawnBlock(b, plan, opts, convertedSpawnArgsFromRCX{}); err != nil {
		return err
	}

	// --- wait on the spawned OEP thread and return its exit code ---
	// After the spawn block, RAX holds hThread (CreateThread return).
	// Spill it to [rbp-0x20] so we can re-pass it to WaitForSingleObject
	// and GetExitCodeThread after each kernel32 resolve clobbers RAX.
	if err := b.MOV(amd64.MemOp{Base: amd64.RBP, Disp: -0x20}, amd64.RAX); err != nil {
		return fmt.Errorf("stage1/runwithargs: spill hThread: %w", err)
	}

	// Allocate one Win64 shadow frame shared by both kernel32 calls
	// below. Stack stays 16-aligned (frame already 0 mod 16). The
	// resolver runs between them at the same alignment.
	if err := b.SUB(amd64.RSP, amd64.Imm(0x20)); err != nil {
		return fmt.Errorf("stage1/runwithargs: sub rsp (shadow): %w", err)
	}

	// WaitForSingleObject(hThread, INFINITE)
	if err := EmitResolveKernel32Export(b, "WaitForSingleObject"); err != nil {
		return fmt.Errorf("stage1/runwithargs: resolve WaitForSingleObject: %w", err)
	}
	if err := b.MOV(amd64.RCX, amd64.MemOp{Base: amd64.RBP, Disp: -0x20}); err != nil {
		return fmt.Errorf("stage1/runwithargs: load hThread → rcx (Wait): %w", err)
	}
	// rdx = INFINITE (0xFFFFFFFF, encoded as sign-extended -1).
	if err := b.MOV(amd64.RDX, amd64.Imm(-1)); err != nil {
		return fmt.Errorf("stage1/runwithargs: mov rdx,INFINITE: %w", err)
	}
	if err := b.CALL(amd64.R13); err != nil {
		return fmt.Errorf("stage1/runwithargs: call WaitForSingleObject: %w", err)
	}

	// GetExitCodeThread(hThread, &exitCode). GetExitCodeThread always
	// writes the DWORD slot at [rbp-0x10] on success, so no pre-zero.
	if err := EmitResolveKernel32Export(b, "GetExitCodeThread"); err != nil {
		return fmt.Errorf("stage1/runwithargs: resolve GetExitCodeThread: %w", err)
	}
	if err := b.MOV(amd64.RCX, amd64.MemOp{Base: amd64.RBP, Disp: -0x20}); err != nil {
		return fmt.Errorf("stage1/runwithargs: load hThread → rcx (ExitCode): %w", err)
	}
	if err := b.LEA(amd64.RDX, amd64.MemOp{Base: amd64.RBP, Disp: -0x10}); err != nil {
		return fmt.Errorf("stage1/runwithargs: lea rdx,&exitCode: %w", err)
	}
	if err := b.CALL(amd64.R13); err != nil {
		return fmt.Errorf("stage1/runwithargs: call GetExitCodeThread: %w", err)
	}
	if err := b.ADD(amd64.RSP, amd64.Imm(0x20)); err != nil {
		return fmt.Errorf("stage1/runwithargs: add rsp (shadow): %w", err)
	}

	// Return value: mov eax, dword ptr [rbp-0x10]. MOVL forces 32-bit
	// to match the DWORD slot — the Win64 ABI returns ints in EAX/RAX
	// with the upper 32 bits implicitly zeroed.
	if err := b.MOVL(amd64.RAX, amd64.MemOp{Base: amd64.RBP, Disp: -0x10}); err != nil {
		return fmt.Errorf("stage1/runwithargs: load exit code → eax: %w", err)
	}

	// --- restore callee-saved regs ---
	for _, s := range runWithArgsCalleeSaved {
		if err := b.MOV(s.reg, amd64.MemOp{Base: amd64.RBP, Disp: s.disp}); err != nil {
			return fmt.Errorf("stage1/runwithargs: restore %s: %w", s.name, err)
		}
	}

	// --- epilogue: leave / ret ---
	// leave = C9 (mov rsp, rbp; pop rbp)
	if err := b.RawBytes([]byte{0xC9}); err != nil {
		return fmt.Errorf("stage1/runwithargs: leave: %w", err)
	}
	// ret = C3
	if err := b.RawBytes([]byte{0xC3}); err != nil {
		return fmt.Errorf("stage1/runwithargs: ret: %w", err)
	}
	return nil
}

// PatchRunWithArgsTextDisplacement rewrites the [prologueSentinelRWA]
// imm32 in the RunWithArgs entry's CALL+POP+ADD prologue with the
// real text-relative displacement. Counterpart of [PatchTextDisplacement]
// for the second entry.
//
// The disp is computed the same way: textRVA − (stubRVA + popOffset),
// where popOffset is the byte offset of the POP instruction within
// the stub (= sentinelOff − 5, matching the 5-byte CALL preceding
// the POP).
//
// Returns the number of patches applied (always 1 — the sentinel
// appears in exactly one ADD instruction). Zero or more than one
// is an error.
func PatchRunWithArgsTextDisplacement(stubBytes []byte, plan transform.Plan) (int, error) {
	idx := bytes.Index(stubBytes, rwaTextDispNeedle)
	if idx < 0 {
		return 0, fmt.Errorf("stage1: prologueSentinelRWA 0xCAFEBABF not found")
	}
	popAddr := plan.StubRVA + uint32(idx) - 5
	disp := uint32(int32(plan.TextRVA) - int32(popAddr))
	value := binary.LittleEndian.AppendUint32(nil, disp)
	_, count, err := patchSentinel(stubBytes, rwaTextDispNeedle, value, false, "prologueSentinelRWA 0xCAFEBABF")
	return count, err
}
