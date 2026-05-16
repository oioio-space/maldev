package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// EmitPEBCommandLinePatchRCX is the runtime variant of
// [EmitPEBCommandLinePatch]. The source pointer and length are
// discovered at runtime — RCX is the caller-supplied wide-string
// pointer (treated as LPCWSTR), and the byte length is computed
// inline via a wcslen scan loop.
//
// Used by the RunWithArgs exported entry of the converted-DLL stub:
// the operator calls `GetProcAddress(hModule, "RunWithArgs")` then
// invokes the resolved fn with their own args buffer. The stub
// rewrites PEB.ProcessParameters.CommandLine in-place to point at
// the same buffer, then spawns the OEP thread.
//
// Inputs:
//   - RCX: LPCWSTR args (caller-owned, must survive until the spawned
//     thread reads its cmdline cache — kernel32 caches on first
//     GetCommandLineW call, so the lifetime requirement is "until
//     CreateThread + GetCommandLineW runs"). NUL-terminated.
//
// Outputs: PEB.CommandLine bytes rewritten in place (or skipped if
// the existing UNICODE_STRING.MaximumLength is too small to hold
// `argsLenBytes + 2`).
//
// Clobbers: RAX, RCX, RSI, RDI, R8, R9, R10. R15 (textBase)
// preserved. All clobbered registers are volatile under the
// Win64 ABI; the converted-DLL prologue spills RDI/RSI as part
// of the standard converted-DLL frame, so the clobber stays
// inside the stub frame.
//
// Byte budget pinned by [EmitPEBCommandLinePatchRCX_ByteBudget].
//
// Layout (offsets shown for the pinned 66-byte encoding):
//
//	    +0  45 33 D2                xor   r10d, r10d            ; len accumulator (zero-extends to r10)
//	+3  .scan:
//	    +3  66 42 83 3C 11 00       cmp   word ptr [rcx+r10], 0 ; terminator?
//	    +9  74 06                   je    .done                  ; yes → len final
//	    +11 49 83 C2 02             add   r10, 2                 ; advance by one wchar
//	    +15 EB F2                   jmp   .scan                  ; (-14, back to .scan)
//	+17 .done:
//	    +17 65 48 8B 04 25 60..00   mov   rax, gs:[0x60]         ; PEB
//	    +26 48 8B 40 20             mov   rax, [rax+0x20]        ; ProcessParameters
//	    +30 44 0F B7 40 72          movzx r8d, word [rax+0x72]   ; existing MaximumLength
//	    +35 4D 8D 4A 02             lea   r9, [r10+2]            ; needed bytes (incl NUL)
//	    +39 66 45 39 C8             cmp   r8w, r9w               ; existing vs needed
//	    +43 72 15                   jb    .skip                  ; existing too small → skip
//	    +45 48 8B 78 78             mov   rdi, [rax+0x78]        ; dst = existing Buffer
//	    +49 48 89 CE                mov   rsi, rcx               ; src = caller args
//	    +52 4C 89 D1                mov   rcx, r10               ; count = wcslen bytes
//	    +55 48 83 C1 02             add   rcx, 2                 ; +NUL pair
//	    +59 F3 A4                   rep   movsb
//	    +61 66 44 89 50 70          mov   word [rax+0x70], r10w  ; Length (no NUL)
//	+66 .skip:
func EmitPEBCommandLinePatchRCX(b *amd64.Builder) error {
	bytes := make([]byte, 0, EmitPEBCommandLinePatchRCX_ByteBudget)

	// --- wcslen loop ---
	// xor r10d, r10d  (zero-extends to r10)
	bytes = append(bytes, 0x45, 0x33, 0xD2)
	// .scan: cmp word ptr [rcx + r10*1], 0
	bytes = append(bytes, 0x66, 0x42, 0x83, 0x3C, 0x11, 0x00)
	// je .done (+6 = skip add+jmp)
	bytes = append(bytes, 0x74, 0x06)
	// add r10, 2
	bytes = append(bytes, 0x49, 0x83, 0xC2, 0x02)
	// jmp .scan (-14 → back to cmp word)
	bytes = append(bytes, 0xEB, 0xF2)

	// --- PEB load + size guard ---
	// mov rax, gs:[0x60]                ; PEB
	bytes = append(bytes, 0x65, 0x48, 0x8B, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00)
	// mov rax, [rax + 0x20]             ; ProcessParameters
	bytes = append(bytes, 0x48, 0x8B, 0x40, 0x20)
	// movzx r8d, word ptr [rax + 0x72]  ; existing MaximumLength
	bytes = append(bytes, 0x44, 0x0F, 0xB7, 0x40, 0x72)
	// lea r9, [r10 + 2]                 ; needed bytes = wcslen + NUL
	bytes = append(bytes, 0x4D, 0x8D, 0x4A, 0x02)
	// cmp r8w, r9w
	bytes = append(bytes, 0x66, 0x45, 0x39, 0xC8)
	// jb .skip (+21 = guarded block size)
	bytes = append(bytes, 0x72, 0x15)

	// --- guarded block ---
	// mov rdi, [rax + 0x78]             ; dst = existing Buffer
	bytes = append(bytes, 0x48, 0x8B, 0x78, 0x78)
	// mov rsi, rcx                      ; src = caller args
	bytes = append(bytes, 0x48, 0x89, 0xCE)
	// mov rcx, r10                      ; count = wcslen bytes
	bytes = append(bytes, 0x4C, 0x89, 0xD1)
	// add rcx, 2                        ; +NUL pair
	bytes = append(bytes, 0x48, 0x83, 0xC1, 0x02)
	// rep movsb
	bytes = append(bytes, 0xF3, 0xA4)
	// mov word ptr [rax + 0x70], r10w   ; Length (excluding NUL)
	bytes = append(bytes, 0x66, 0x44, 0x89, 0x50, 0x70)

	if got := len(bytes); got != EmitPEBCommandLinePatchRCX_ByteBudget {
		return fmt.Errorf("stage1: EmitPEBCommandLinePatchRCX byte count = %d, want %d (drift)",
			got, EmitPEBCommandLinePatchRCX_ByteBudget)
	}
	if err := b.RawBytes(bytes); err != nil {
		return fmt.Errorf("stage1: EmitPEBCommandLinePatchRCX: %w", err)
	}
	return nil
}

// EmitPEBCommandLinePatchRCX_ByteBudget is the exact byte count
// [EmitPEBCommandLinePatchRCX] emits. Pinned in unit tests so
// any future drift in the asm encoding is caught.
const EmitPEBCommandLinePatchRCX_ByteBudget = 66
