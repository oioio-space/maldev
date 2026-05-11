package transform

import (
	"bytes"
	"encoding/binary"
	"errors"
	"fmt"
)

// addStubSectionWrite ORs IMAGE_SCN_MEM_WRITE into the last
// section's Characteristics. InjectStubPE appends the stub section
// as the last one and marks it CODE|EXEC|READ (correct for EXE
// stubs that only decrypt .text in place); the converted-DLL stub
// additionally latches a `decrypted_flag` byte inside its own
// section on PROCESS_ATTACH, which requires writable mapping.
//
// Same byte math as the inline OR-flip InjectStubPE does for .text
// — just targeted at the last section header instead of the
// .text header.
func addStubSectionWrite(buf []byte) error {
	peOff := binary.LittleEndian.Uint32(buf[PEELfanewOffset:])
	coffOff := peOff + PESignatureSize
	if int(coffOff)+PECOFFHdrSize > len(buf) {
		return fmt.Errorf("transform/converted: buffer too short for COFF header")
	}
	numSections := binary.LittleEndian.Uint16(buf[coffOff+COFFNumSectionsOffset:])
	if numSections == 0 {
		return fmt.Errorf("transform/converted: zero sections — nothing to mark RW")
	}
	sizeOfOptHdr := binary.LittleEndian.Uint16(buf[coffOff+COFFSizeOfOptHdrOffset:])
	secTableOff := coffOff + PECOFFHdrSize + uint32(sizeOfOptHdr)
	lastHdrOff := secTableOff + uint32(numSections-1)*PESectionHdrSize
	charsOff := lastHdrOff + SecCharacteristicsOffset
	if int(charsOff)+4 > len(buf) {
		return fmt.Errorf("transform/converted: buffer too short for last section header")
	}
	c := binary.LittleEndian.Uint32(buf[charsOff:])
	binary.LittleEndian.PutUint32(buf[charsOff:], c|0x80000000) // IMAGE_SCN_MEM_WRITE
	return nil
}

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

	// Mark the appended stub section MEM_WRITE. The converted-DLL
	// stub latches a `decrypted_flag` byte INSIDE its own section
	// via a R15-relative MOVB on the first PROCESS_ATTACH call.
	// InjectStubPE created the stub section as CODE|EXEC|READ
	// (read-only executable — fine for EXE stubs that only decrypt
	// .text, never themselves); writing to it triggers a page-level
	// access violation at runtime.
	//
	// Discovered slice 5.5.x at the LoadLibrary E2E: PC inside the
	// stub at the flag-latch MOVB, fault address inside .mldv.
	if err := addStubSectionWrite(out); err != nil {
		return nil, fmt.Errorf("transform/converted: add stub MEM_WRITE: %w", err)
	}

	// Clear DYNAMIC_BASE + HIGH_ENTROPY_VA on the converted output.
	// Mingw / Go EXEs ship with DYNAMIC_BASE set, but converted DLLs
	// don't carry a synthesised BASERELOC table — the loader would
	// try ASLR, fail to relocate (no reloc entries), and reject the
	// image with STATUS_CONFLICTING_ADDRESSES (observed at slice
	// 5.5.x: kernel32!LoadLibrary AV crash on Win10). Forcing the
	// preferred ImageBase is the right semantic until reloc synth
	// lands.
	if err := ClearDllCharacteristics(out, dllCharDynamicBase|dllCharHighEntropyVA); err != nil {
		return nil, fmt.Errorf("transform/converted: clear DYNAMIC_BASE: %w", err)
	}

	return out, nil
}
