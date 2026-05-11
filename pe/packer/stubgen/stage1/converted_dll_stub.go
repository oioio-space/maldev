package stage1

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// Frame sizes for the converted-DLL stub. Both keep RSP 16-aligned
// (Windows x64 ABI requirement before any CALL): the outer frame
// holds the 4 register spills (rcx/rdx/r8/r15 = 32 B) plus 16 B
// alignment pad; the inner frame allocated around CreateThread
// holds 32 B shadow space + 16 B for the two stack-passed args.
const (
	convertedDLLFrameSize     = 0x40 // 4 × 8 B spills + 16 B pad
	createThreadCallFrameSize = 0x30 // 32 B shadow + 16 B for 5th/6th args
)

// ErrConvertedDLLPlanMissing fires when [EmitConvertedDLLStub] is
// called with a Plan that doesn't have IsConvertedDLL=true.
// Mirrors the slice-2 [ErrDLLStubPlanMissing] check; routing the
// wrong plan through the converted-DLL emitter would produce a
// stub whose CreateThread spawn would land on bogus bytes.
var ErrConvertedDLLPlanMissing = errors.New("stage1: EmitConvertedDLLStub requires Plan.IsConvertedDLL=true")

// EmitConvertedDLLStub writes a DllMain-shaped stub for the EXE→DLL
// conversion path. Layout differs from [EmitDLLStub] (the native-DLL
// stub) in three ways:
//
//   - There is NO tail-call to an original DllMain. The input was an
//     EXE, so its entry point is `int main(int, char**)`-shaped, not
//     `BOOL DllMain(HINSTANCE, DWORD, LPVOID)`-shaped. We spawn a
//     fresh thread targeting that entry instead.
//   - The thread is spawned via `kernel32!CreateThread`, resolved
//     at runtime by [EmitResolveKernel32Export] (no IAT entry, no
//     LoadLibraryA dependency). On DLL_PROCESS_ATTACH the stub
//     decrypts .text once, calls CreateThread on the original OEP,
//     and returns TRUE to the loader. The thread runs in parallel
//     to whatever the host EXE that loaded us is doing.
//   - Trailing data is just one byte (the decrypted_flag). The
//     native-DLL stub also carries an 8-byte orig_dllmain slot —
//     we don't need one because there's nothing to tail-call.
//
// On reasons other than PROCESS_ATTACH (THREAD_*, PROCESS_DETACH),
// the stub returns TRUE immediately without decrypting or spawning.
//
// Slice 5.3 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
func EmitConvertedDLLStub(b *amd64.Builder, plan transform.Plan, rounds []poly.Round) error {
	if !plan.IsConvertedDLL {
		return ErrConvertedDLLPlanMissing
	}
	if len(rounds) == 0 {
		return ErrNoRounds
	}

	// --- prologue: stack frame + spill rcx/edx/r8/r15 (shared helper) ---
	if err := emitDllMainPrologue(b, convertedDLLFrameSize, "stage1/converted"); err != nil {
		return err
	}

	// --- CALL+POP+ADD: R15 := textRVA at runtime (shared idiom) ---
	if err := emitTextBasePrologue(b); err != nil {
		return fmt.Errorf("stage1/converted: text-base prologue: %w", err)
	}

	// --- reason != DLL_PROCESS_ATTACH → forward (return TRUE) ---
	const returnTrueLabel = "converted_dll_return_true"
	if err := b.CMP(amd64.RDX, amd64.Imm(dllReasonProcessAttach)); err != nil {
		return fmt.Errorf("stage1/converted: cmp reason: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(returnTrueLabel)); err != nil {
		return fmt.Errorf("stage1/converted: jnz return_true (reason): %w", err)
	}

	// --- decrypted_flag check + latch ---
	// Trailing data layout: stubBytes[len-1] = decrypted_flag (1B).
	// PatchConvertedDLLStubDisplacements rewrites flagDispSentinel
	// with the R15-relative disp once the stub byte layout is final.
	if err := b.MOVZX(amd64.RAX, amd64.MemOp{Base: amd64.R15, Disp: int32(flagDispSentinel)}); err != nil {
		return fmt.Errorf("stage1/converted: movzx flag: %w", err)
	}
	if err := b.TEST(amd64.RAX, amd64.RAX); err != nil {
		return fmt.Errorf("stage1/converted: test flag: %w", err)
	}
	if err := b.JNZ(amd64.LabelRef(returnTrueLabel)); err != nil {
		return fmt.Errorf("stage1/converted: jnz return_true (flag): %w", err)
	}
	if err := b.MOV(amd64.RAX, amd64.Imm(1)); err != nil {
		return fmt.Errorf("stage1/converted: mov al,1: %w", err)
	}
	if err := b.MOVB(amd64.MemOp{Base: amd64.R15, Disp: int32(flagDispSentinel)}, amd64.RAX); err != nil {
		return fmt.Errorf("stage1/converted: movb flag,al: %w", err)
	}

	// SGN rounds — shared with EmitStub / EmitDLLStub.
	if err := emitSGNRounds(b, plan, rounds, "converted_loop", "stage1/converted"); err != nil {
		return err
	}

	// --- resolve kernel32!CreateThread → R13 ---
	// EmitResolveKernel32Export clobbers RAX, RBX, RCX, RDX, R8, R9,
	// R10, R11, R12 but preserves R13, R14, R15. R15 (our textBase)
	// stays intact, so the OEP-computation below still works.
	if err := EmitResolveKernel32Export(b, "CreateThread"); err != nil {
		return fmt.Errorf("stage1/converted: resolve CreateThread: %w", err)
	}

	// --- CreateThread(NULL, 0, OEP, NULL, 0, NULL) ---
	// Windows x64 ABI:
	//   rcx = lpThreadAttributes      (NULL)
	//   rdx = dwStackSize             (0)
	//   r8  = lpStartAddress          (OEP absolute VA = R15 + OEPdisp)
	//   r9  = lpParameter             (NULL)
	//   [rsp+0x20] = dwCreationFlags  (0)
	//   [rsp+0x28] = lpThreadId       (NULL)
	if err := b.SUB(amd64.RSP, amd64.Imm(createThreadCallFrameSize)); err != nil {
		return fmt.Errorf("stage1/converted: sub rsp,createThreadCallFrameSize: %w", err)
	}
	if err := b.XOR(amd64.RCX, amd64.RCX); err != nil {
		return fmt.Errorf("stage1/converted: xor rcx,rcx: %w", err)
	}
	if err := b.XOR(amd64.RDX, amd64.RDX); err != nil {
		return fmt.Errorf("stage1/converted: xor rdx,rdx: %w", err)
	}
	// r8 = OEP absolute VA. OEPdisp = OEPRVA - TextRVA, encoded as
	// a signed imm32 ADD. The PE32+ image-size invariant caps
	// SizeOfImage at 2 GiB minus headers, so |OEPdisp| < 2^31 by
	// construction — int32 cast can't overflow on a well-formed PE.
	oepDisp := int32(plan.OEPRVA) - int32(plan.TextRVA)
	if err := b.MOV(amd64.R8, amd64.R15); err != nil {
		return fmt.Errorf("stage1/converted: mov r8,r15: %w", err)
	}
	if oepDisp != 0 {
		if err := b.ADD(amd64.R8, amd64.Imm(int64(oepDisp))); err != nil {
			return fmt.Errorf("stage1/converted: add r8,oepDisp: %w", err)
		}
	}
	if err := b.XOR(amd64.R9, amd64.R9); err != nil {
		return fmt.Errorf("stage1/converted: xor r9,r9: %w", err)
	}
	// [rsp+0x20] = 0  (dwCreationFlags)
	if err := b.MOV(amd64.MemOp{Base: amd64.RSP, Disp: 0x20}, amd64.RCX); err != nil { // RCX==0 already
		return fmt.Errorf("stage1/converted: zero [rsp+0x20]: %w", err)
	}
	// [rsp+0x28] = 0  (lpThreadId)
	if err := b.MOV(amd64.MemOp{Base: amd64.RSP, Disp: 0x28}, amd64.RCX); err != nil {
		return fmt.Errorf("stage1/converted: zero [rsp+0x28]: %w", err)
	}
	// call r13
	if err := b.CALL(amd64.R13); err != nil {
		return fmt.Errorf("stage1/converted: call r13: %w", err)
	}
	// restore the CreateThread frame
	if err := b.ADD(amd64.RSP, amd64.Imm(createThreadCallFrameSize)); err != nil {
		return fmt.Errorf("stage1/converted: add rsp,createThreadCallFrameSize: %w", err)
	}

	// --- return TRUE: restore args + r15, leave rax=1 ---
	_ = b.Label(returnTrueLabel)
	// rax = 1 (BOOL TRUE)
	if err := b.MOV(amd64.RAX, amd64.Imm(1)); err != nil {
		return fmt.Errorf("stage1/converted: mov rax,1: %w", err)
	}
	// restore spilled args + r15, tear down frame (shared helper)
	if err := emitDllMainRestore(b, convertedDLLFrameSize, "stage1/converted"); err != nil {
		return err
	}
	if err := b.RawBytes([]byte{0xC3}); err != nil { // ret
		return fmt.Errorf("stage1/converted: ret: %w", err)
	}

	// --- trailing data: 1B decrypted_flag (no slot — we don't tail-call) ---
	if err := b.RawBytes([]byte{0x00}); err != nil {
		return fmt.Errorf("stage1/converted: emit decrypted_flag byte: %w", err)
	}

	return nil
}

// ConvertedDLLStubFlagByteOffsetFromEnd is the position of the
// decrypted_flag byte counted from the end of the emitted stub.
// Trailing data is just that one byte (the slice-2 DLL stub also
// carries an 8-byte orig_dllmain slot — the converted-DLL stub
// doesn't, because there is no original DllMain to tail-call).
const ConvertedDLLStubFlagByteOffsetFromEnd = 1

// PatchConvertedDLLStubDisplacements rewrites the [flagDispSentinel]
// imm32 in the emitted stub bytes with the real R15-relative
// displacement once the trailing-data offset is known.
//
// The flag byte sits at stubBytes[len-1]. Its R15-relative disp is
// `(StubRVA + flagOff) - TextRVA` where flagOff = len(stubBytes)-1.
// The sentinel appears twice in the assembled stub (one MOVZX load
// + one MOVB store, same byte addressed twice); both occurrences
// are rewritten with the same value.
//
// Returns the patched count (≥ 2). Missing sentinel is an error.
func PatchConvertedDLLStubDisplacements(stubBytes []byte, plan transform.Plan) (int, error) {
	if len(stubBytes) < ConvertedDLLStubFlagByteOffsetFromEnd {
		return 0, fmt.Errorf("stage1/converted: stub too short (%d B) — missing trailing data", len(stubBytes))
	}
	flagOff := uint32(len(stubBytes) - ConvertedDLLStubFlagByteOffsetFromEnd)
	flagDisp := uint32(int32(plan.StubRVA+flagOff) - int32(plan.TextRVA))

	needle := binary.LittleEndian.AppendUint32(nil, flagDispSentinel)
	value := binary.LittleEndian.AppendUint32(nil, flagDisp)
	_, count, err := patchSentinel(stubBytes, needle, value, true, "converted DLL flag disp")
	return count, err
}
