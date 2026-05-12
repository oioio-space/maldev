package stage1

import (
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// pebCommandLineDispSentinel is the imm32 placeholder
// EmitPEBCommandLinePatch leaves in the LEA instruction that
// computes the args-buffer address. Patched at finalisation time
// once the stub's trailing-data layout is known.
const pebCommandLineDispSentinel uint32 = 0xCAFEDADE

// EmitPEBCommandLinePatch overwrites PEB.ProcessParameters.CommandLine
// with a stub-baked args buffer. After this runs, GetCommandLineW
// (and downstream callers like Go's os.Args reader / MSVC CRT
// argv parser) will return the operator-supplied bytes.
//
// Win64 PEB layout used:
//
//	gs:[0x60]                       → PEB
//	PEB+0x20                        → ProcessParameters (RTL_USER_PROCESS_PARAMETERS *)
//	ProcessParameters+0x70          → CommandLine UNICODE_STRING:
//	  +0x00 (uint16) Length         (bytes excluding terminator)
//	  +0x02 (uint16) MaximumLength  (bytes including terminator)
//	  +0x08 (uint64) Buffer         (PWSTR)
//
// Inputs:
//   - argsLenBytes: byte length of the wide-char args string,
//     EXCLUDING the terminating NUL pair. Stored verbatim into
//     UNICODE_STRING.Length; MaximumLength = Length + 2.
//
// The buffer pointer is computed at runtime via
// `lea rax, [r15 + disp32]` where disp32 is a sentinel
// (`pebCommandLineDispSentinel`) the caller patches via
// [PatchPEBCommandLineDisp] once the stub's trailing-data
// offset is finalised.
//
// Clobbers: RAX (used as scratch for PEB → ProcessParameters
// → patch target). Other registers untouched. R15 (textBase)
// unchanged.
//
// Emits 36 bytes (9 + 4 + 6 + 6 + 7 + 4). Pinned via
// [EmitPEBCommandLinePatch_ByteBudget].
//
// Item #1.A.1 of docs/refactor-2026-doc/packer-actions-2026-05-12.md.
func EmitPEBCommandLinePatch(b *amd64.Builder, argsLenBytes uint16) error {
	// Build the byte sequence. Documented inline per instruction.
	bytes := make([]byte, 0, 39)

	// mov rax, qword ptr gs:[0x60]    ; PEB pointer
	// 65 (gs prefix) | 48 (REX.W) | 8B (MOV r64, r/m64) | 04 (ModR/M: mod=00, reg=rax(000), r/m=100=SIB)
	// | 25 (SIB: scale=00, index=100=none, base=101=disp32) | 60 00 00 00 (disp32 = 0x60)
	bytes = append(bytes, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00)

	// mov rax, qword ptr [rax + 0x20]  ; ProcessParameters
	// 48 8B 40 20
	bytes = append(bytes, 0x48, 0x8B, 0x40, 0x20)

	// mov word ptr [rax + 0x70], <argsLenBytes>   ; UNICODE_STRING.Length
	// 66 (operand-size 16-bit) | C7 (MOV r/m16, imm16) | 40 (ModR/M: mod=01 disp8, reg=000, r/m=000=RAX)
	// | 70 (disp8) | LL LL (imm16)
	bytes = append(bytes, 0x66, 0xC7, 0x40, 0x70)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes)

	// mov word ptr [rax + 0x72], <argsLenBytes + 2>   ; MaximumLength (incl. NUL terminator)
	bytes = append(bytes, 0x66, 0xC7, 0x40, 0x72)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes+2)

	// lea r10, [r15 + sentinel_disp32]   ; new Buffer pointer
	// 4D (REX.WRB: W=1, R=1, B=1) | 8D (LEA) | 97 (ModR/M: mod=10 disp32, reg=R10(010), r/m=R15(111))
	// | DE DA FE CA (disp32 sentinel — patched later)
	bytes = append(bytes, 0x4D, 0x8D, 0x97)
	bytes = binary.LittleEndian.AppendUint32(bytes, pebCommandLineDispSentinel)

	// mov qword ptr [rax + 0x78], r10   ; UNICODE_STRING.Buffer
	// 4C (REX.WR: W=1, R=1) | 89 (MOV r/m64, r64) | 50 (ModR/M: mod=01 disp8, reg=R10(010), r/m=RAX(000))
	// | 78 (disp8)
	bytes = append(bytes, 0x4C, 0x89, 0x50, 0x78)

	if got := len(bytes); got != EmitPEBCommandLinePatch_ByteBudget {
		return fmt.Errorf("stage1: EmitPEBCommandLinePatch byte count = %d, want %d (drift)",
			got, EmitPEBCommandLinePatch_ByteBudget)
	}
	if err := b.RawBytes(bytes); err != nil {
		return fmt.Errorf("stage1: EmitPEBCommandLinePatch: %w", err)
	}
	return nil
}

// EmitPEBCommandLinePatch_ByteBudget is the exact byte count
// EmitPEBCommandLinePatch emits. Pinned in unit tests so any
// future drift in the asm encoding is caught at compile time
// for callers that pre-allocate stub layout space.
const EmitPEBCommandLinePatch_ByteBudget = 36

// PatchPEBCommandLineDisp rewrites the
// [pebCommandLineDispSentinel] imm32 with the real R15-relative
// displacement of the args buffer once the stub byte layout is
// finalised.
//
// `argsBufferOff` is the byte offset of the args buffer's first
// byte within the stub. The displacement is computed as
// `(StubRVA + argsBufferOff) - TextRVA` since R15 = TextRVA at
// runtime.
//
// Returns the number of patches applied (always 1 — the sentinel
// appears in exactly one LEA instruction). Missing sentinel is
// an error (caller bug — patch ran on wrong stub).
func PatchPEBCommandLineDisp(stubBytes []byte, stubRVA, textRVA, argsBufferOff uint32) (int, error) {
	disp := uint32(int32(stubRVA+argsBufferOff) - int32(textRVA))
	needle := binary.LittleEndian.AppendUint32(nil, pebCommandLineDispSentinel)
	value := binary.LittleEndian.AppendUint32(nil, disp)
	_, n, err := patchSentinel(stubBytes, needle, value, true, "PEB.CommandLine buffer disp")
	return n, err
}
