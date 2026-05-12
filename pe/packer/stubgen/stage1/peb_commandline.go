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

// EmitPEBCommandLinePatch overwrites the *contents* of the
// existing PEB.ProcessParameters.CommandLine.Buffer with the
// stub-baked args, then updates Length / MaximumLength.
//
// Why in-place rewrite (not pointer swap):
// `kernel32!GetCommandLineW` caches its result on first call —
// the cmdline pointer is read from PEB once during process
// initialisation and stashed in a kernel32 BSS global. Every
// later caller (including Go's runtime.args, MSVC CRT, .NET
// startup) reads from that cache, NOT from PEB.CommandLine.Buffer.
// So patching the PEB pointer alone is invisible to anything that
// already initialised cmdline. Mutating the bytes the cached
// pointer references is invisible-proof: the cache still resolves
// to the same address, but the bytes there are now ours.
//
// Win64 PEB layout used:
//
//	gs:[0x60]                       → PEB
//	PEB+0x20                        → ProcessParameters (RTL_USER_PROCESS_PARAMETERS *)
//	ProcessParameters+0x70          → CommandLine UNICODE_STRING:
//	  +0x00 (uint16) Length         (bytes excluding terminator)
//	  +0x02 (uint16) MaximumLength  (bytes including terminator)
//	  +0x08 (uint64) Buffer         (PWSTR — read, NOT overwritten)
//
// Inputs:
//   - argsLenBytes: byte length of the wide-char args string,
//     EXCLUDING the terminating NUL pair. Stored verbatim into
//     UNICODE_STRING.Length; MaximumLength = Length + 2.
//
// The src buffer (in our stub) is computed at runtime via
// `lea rsi, [r15 + disp32]` where disp32 is a sentinel
// (`pebCommandLineDispSentinel`) the caller patches via
// [PatchPEBCommandLineDisp] once the stub's trailing-data
// offset is finalised.
//
// LIMITATION: assumes the existing buffer at PEB.CommandLine.Buffer
// has at least argsLenBytes+2 bytes available. Loaders that hand
// out very short cmdlines (rare) would be overflown — operators
// should size DefaultArgs to fit a typical loader (rundll32 cmdline
// is ~hundreds of bytes; SMSS is bounded by RTL_MAX_DRIVE_LETTERS;
// most >= 64 B is safe).
//
// Clobbers: RAX (PEB → params), RDI (memcpy dst), RSI (memcpy src),
// RCX (memcpy count). RDI/RSI are callee-saved by Win64 ABI but
// the converted-DLL stub prologue spills them at frame entry, so
// the clobber stays inside the stub frame. R15 (textBase) preserved.
//
// Emits 43 bytes (9 + 4 + 4 + 7 + 5 + 2 + 6 + 6). Pinned via
// [EmitPEBCommandLinePatch_ByteBudget].
func EmitPEBCommandLinePatch(b *amd64.Builder, argsLenBytes uint16) error {
	bytes := make([]byte, 0, EmitPEBCommandLinePatch_ByteBudget)

	// mov rax, qword ptr gs:[0x60]      ; PEB
	bytes = append(bytes, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00)
	// mov rax, qword ptr [rax + 0x20]   ; ProcessParameters
	bytes = append(bytes, 0x48, 0x8B, 0x40, 0x20)
	// mov rdi, qword ptr [rax + 0x78]   ; existing CommandLine.Buffer (memcpy dst)
	// 48 (REX.W) | 8B (MOV r64, r/m64) | 78 (ModR/M: mod=01 disp8, reg=RDI(111), r/m=RAX(000)) | 78 (disp8)
	bytes = append(bytes, 0x48, 0x8B, 0x78, 0x78)
	// lea rsi, [r15 + disp32]           ; src = our args in stub
	// 49 (REX.WB: W=1, B=1) | 8D (LEA) | B7 (ModR/M: mod=10 disp32, reg=RSI(110), r/m=R15(111)) | sentinel
	bytes = append(bytes, 0x49, 0x8D, 0xB7)
	bytes = binary.LittleEndian.AppendUint32(bytes, pebCommandLineDispSentinel)
	// mov ecx, imm32                    ; count = argsLenBytes + 2 (incl. NUL)
	// B9 + imm32 (zero-extends to RCX)
	bytes = append(bytes, 0xB9)
	bytes = binary.LittleEndian.AppendUint32(bytes, uint32(argsLenBytes)+2)
	// rep movsb                          ; do the copy
	bytes = append(bytes, 0xF3, 0xA4)
	// mov word ptr [rax + 0x70], argsLenBytes        ; Length
	bytes = append(bytes, 0x66, 0xC7, 0x40, 0x70)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes)
	// mov word ptr [rax + 0x72], argsLenBytes + 2    ; MaximumLength
	bytes = append(bytes, 0x66, 0xC7, 0x40, 0x72)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes+2)

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
const EmitPEBCommandLinePatch_ByteBudget = 43

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
