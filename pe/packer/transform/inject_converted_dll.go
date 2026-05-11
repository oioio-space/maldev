package transform

import (
	"bytes"
	"errors"
	"fmt"
)

// ErrPlanNotConverted fires when [InjectConvertedDLL] gets a Plan
// that wasn't produced by [PlanConvertedDLL] — i.e.
// [Plan.IsConvertedDLL] is false. Routing the wrong plan through
// the converted-DLL injector would emit an EXE-shaped output and
// silently skip the IMAGE_FILE_DLL flip. Mirrors the shape of
// [ErrPlanFormatMismatch].
//
// Distinct from `stage1.ErrConvertedDLLPlanMissing` (the emitter-
// side admission sentinel) — same intent, different layer.
var ErrPlanNotConverted = errors.New("transform: InjectConvertedDLL requires plan.IsConvertedDLL=true")

// ErrConvertedStubLeak fires when [InjectConvertedDLL] receives
// stubBytes carrying the slice-2 [DLLStubSentinel] — meaning the
// caller routed a native-DLL stub through the converted-DLL
// injector. Without this guard the orig_dllmain slot inside the
// native-DLL stub would never get patched (slice-3's
// `PatchDllMainSlot` runs only inside `InjectStubDLL`), producing
// a binary that silently jumps to an unpatched VA at runtime.
var ErrConvertedStubLeak = errors.New("transform: InjectConvertedDLL stubBytes contain DLLStubSentinel — route through InjectStubDLL instead")

// InjectConvertedDLL is the EXE→DLL conversion counterpart of
// [InjectStubPE]. It runs the full EXE injection pipeline (write
// encrypted .text, mark .text RWX, append the stub section,
// rewrite OEP) then flips the IMAGE_FILE_DLL bit in COFF
// Characteristics so the Windows loader treats the output as a
// DLL and calls our stub via the DllMain calling convention.
//
// The stub itself ([stage1.EmitConvertedDLLStub], slice 5.3) is
// shaped to receive `(HINSTANCE, DWORD, LPVOID)` on PROCESS_ATTACH,
// decrypt .text once, spawn `kernel32!CreateThread(NULL, 0, OEP,
// NULL, 0, NULL)`, and return TRUE.
//
// Reloc handling: this function does NOT synthesise a `.reloc`
// section. The slice-5.3 stub has no absolute pointers baked at
// pack time (everything is R15-relative or PEB-walked at runtime),
// and Go static-PIE inputs typically ship without a reloc table
// already. The output loads at the input's preferred ImageBase;
// DllCharacteristics' DYNAMIC_BASE flag is preserved as-is from
// the input. Operators that need ASLR on the converted DLL must
// ensure the source EXE was linked with relocs + DYNAMIC_BASE.
//
// Slice 5.4 of docs/refactor-2026-doc/packer-exe-to-dll-plan.md.
func InjectConvertedDLL(input, encryptedText, stubBytes []byte, plan Plan) ([]byte, error) {
	if !plan.IsConvertedDLL {
		return nil, ErrPlanNotConverted
	}
	// Defensive Format check — symmetric with InjectStubPE/ELF. A
	// hand-crafted Plan{IsConvertedDLL: true, Format: FormatELF}
	// would otherwise slip through to InjectStubPE and produce a
	// misleading "delegated EXE inject" error wrap.
	if plan.Format != FormatPE {
		return nil, ErrPlanFormatMismatch
	}
	// Catch the slice-2 native-DLL stub being routed here by
	// mistake — its orig_dllmain slot patcher only runs inside
	// InjectStubDLL, never reached on this path.
	if bytes.Contains(stubBytes, DLLStubSentinelBytes) {
		return nil, ErrConvertedStubLeak
	}

	// Delegate to the EXE injector — same .text-encrypt + append
	// stub section + OEP rewrite + RWX flip flow. The EXE/DLL
	// distinction at injection time is one byte: the IMAGE_FILE_DLL
	// bit in COFF Characteristics, flipped below.
	out, err := InjectStubPE(input, encryptedText, stubBytes, plan)
	if err != nil {
		return nil, fmt.Errorf("transform/converted: delegated EXE inject: %w", err)
	}

	// Flip IMAGE_FILE_DLL on output. The loader switches calling
	// convention based on this bit: with it set, AddressOfEntryPoint
	// is treated as DllMain(HINSTANCE, DWORD, LPVOID) and called on
	// every reason code; without it, AddressOfEntryPoint is treated
	// as the EXE entry and called once at process start.
	if err := SetIMAGEFILEDLL(out); err != nil {
		return nil, fmt.Errorf("transform/converted: flip IMAGE_FILE_DLL: %w", err)
	}

	return out, nil
}
