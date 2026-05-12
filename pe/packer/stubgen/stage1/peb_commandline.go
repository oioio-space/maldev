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
// SAFETY GUARD: the asm reads the existing buffer's
// `MaximumLength` (UNICODE_STRING +0x72) and only commits the
// memcpy if `MaximumLength >= argsLenBytes + 2`. If the loader
// handed out a buffer too small, the patch is silently skipped
// — payload inherits the host's cmdline rather than overflow
// the heap. Also: `MaximumLength` is NEVER overwritten (it
// represents the OS-allocated capacity, not our intent); only
// `Length` changes to reflect our shorter string.
//
// Clobbers: RAX (PEB → params), RDI (memcpy dst), RSI (memcpy src),
// RCX (memcpy count + scratch for the size compare). RDI/RSI are
// callee-saved by Win64 ABI but the converted-DLL stub prologue
// spills them at frame entry, so the clobber stays inside the
// stub frame. R15 (textBase) preserved.
//
// Emits 48 bytes (9 + 4 + 4 + 5 + 2 + 4 + 7 + 5 + 2 + 6). Pinned
// via [EmitPEBCommandLinePatch_ByteBudget].
func EmitPEBCommandLinePatch(b *amd64.Builder, argsLenBytes uint16) error {
	bytes := make([]byte, 0, EmitPEBCommandLinePatch_ByteBudget)

	// mov rax, qword ptr gs:[0x60]      ; PEB
	bytes = append(bytes, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00)
	// mov rax, qword ptr [rax + 0x20]   ; ProcessParameters
	bytes = append(bytes, 0x48, 0x8B, 0x40, 0x20)

	// --- SIZE GUARD ---
	// movzx ecx, word ptr [rax + 0x72]  ; ECX = existing MaximumLength
	// 0F B7 48 72
	bytes = append(bytes, 0x0F, 0xB7, 0x48, 0x72)
	// cmp cx, imm16                      ; vs needed bytes
	// 66 81 F9 LL HH
	bytes = append(bytes, 0x66, 0x81, 0xF9)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes+2)
	// jb +24                              ; existing too small → skip patch
	// 72 18 (signed byte 0x18 = 24 — exactly the byte count of the
	//        guarded block below; recount if you reorder).
	bytes = append(bytes, 0x72, 0x18)

	// --- GUARDED BLOCK (24 bytes) ---
	// mov rdi, qword ptr [rax + 0x78]   ; dst = existing CommandLine.Buffer
	// 48 8B 78 78
	bytes = append(bytes, 0x48, 0x8B, 0x78, 0x78)
	// lea rsi, [r15 + disp32]           ; src = our args in stub
	// 49 8D B7 + disp32 (sentinel patched later)
	bytes = append(bytes, 0x49, 0x8D, 0xB7)
	bytes = binary.LittleEndian.AppendUint32(bytes, pebCommandLineDispSentinel)
	// mov ecx, imm32                    ; count = argsLenBytes + 2
	bytes = append(bytes, 0xB9)
	bytes = binary.LittleEndian.AppendUint32(bytes, uint32(argsLenBytes)+2)
	// rep movsb
	bytes = append(bytes, 0xF3, 0xA4)
	// mov word ptr [rax + 0x70], argsLenBytes   ; Length only — leave MaxLength alone
	bytes = append(bytes, 0x66, 0xC7, 0x40, 0x70)
	bytes = binary.LittleEndian.AppendUint16(bytes, argsLenBytes)

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
const EmitPEBCommandLinePatch_ByteBudget = 48

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
