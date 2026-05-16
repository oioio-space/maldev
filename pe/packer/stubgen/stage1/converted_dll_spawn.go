package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// convertedSpawnArgs describes where the runtime args buffer used by
// the PEB.CommandLine patch comes from. The variation axis lets the
// DllMain spawn (fixed stub-trailing buffer addressed off R15) and
// the RunWithArgs export (caller-supplied LPCWSTR via RCX) share the
// same spawn emitter.
//
// nil means "no PEB patch" — the spawn block resolves CreateThread
// and spawns the OEP without touching PEB.ProcessParameters.
type convertedSpawnArgs interface {
	isConvertedSpawnArgs()
}

// convertedSpawnArgsTrailing instructs the spawn block to call
// [EmitPEBCommandLinePatch] with a fixed length. Source is the stub
// trailing-data buffer (LEA src = r15 + pebCommandLineDispSentinel),
// patched by [PatchPEBCommandLineDisp] once the trailing offsets
// are known.
type convertedSpawnArgsTrailing struct {
	lenBytes uint16
}

func (convertedSpawnArgsTrailing) isConvertedSpawnArgs() {}

// emitConvertedSpawnBlock emits the post-decrypt sequence of the
// converted-DLL stub:
//
//  1. kernel32!CreateThread resolution (when [EmitOptions.convertedSpawnEnabled]
//     is true). Result lands in R13.
//  2. Optional PEB.ProcessParameters.CommandLine patch when args != nil.
//  3. CreateThread(NULL, 0, OEP, NULL, 0, NULL) (when spawn enabled).
//
// Caller MUST have R15=textBase and the converted-DLL prologue
// (rcx/edx/r8/r15 spill + extra-callee-saved spill) already emitted.
func emitConvertedSpawnBlock(b *amd64.Builder, plan transform.Plan, opts EmitOptions, args convertedSpawnArgs) error {
	if !opts.DiagSkipConvertedPayload && !opts.DiagSkipConvertedResolver {
		// EmitResolveKernel32Export clobbers RAX, RBX, RCX, RDX, R8, R9,
		// R10, R11, R12 but preserves R13, R14, R15. R15 (our textBase)
		// stays intact for the OEP-disp ADD below.
		if err := EmitResolveKernel32Export(b, "CreateThread"); err != nil {
			return fmt.Errorf("stage1/converted: resolve CreateThread: %w", err)
		}
	}

	if opts.convertedSpawnEnabled() {
		if t, ok := args.(convertedSpawnArgsTrailing); ok && t.lenBytes > 0 {
			if err := EmitPEBCommandLinePatch(b, t.lenBytes); err != nil {
				return fmt.Errorf("stage1/converted: PEB patch: %w", err)
			}
		}

		// CreateThread(NULL, 0, OEP, NULL, 0, NULL). Win64 ABI:
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
		// a signed imm32 ADD. SizeOfImage caps imply |OEPdisp| < 2^31.
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
		// [rsp+0x20] = 0  (dwCreationFlags). RCX == 0 already.
		if err := b.MOV(amd64.MemOp{Base: amd64.RSP, Disp: 0x20}, amd64.RCX); err != nil {
			return fmt.Errorf("stage1/converted: zero [rsp+0x20]: %w", err)
		}
		// [rsp+0x28] = 0  (lpThreadId).
		if err := b.MOV(amd64.MemOp{Base: amd64.RSP, Disp: 0x28}, amd64.RCX); err != nil {
			return fmt.Errorf("stage1/converted: zero [rsp+0x28]: %w", err)
		}
		if err := b.CALL(amd64.R13); err != nil {
			return fmt.Errorf("stage1/converted: call r13: %w", err)
		}
		if err := b.ADD(amd64.RSP, amd64.Imm(createThreadCallFrameSize)); err != nil {
			return fmt.Errorf("stage1/converted: add rsp,createThreadCallFrameSize: %w", err)
		}
	}
	return nil
}
