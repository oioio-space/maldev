package stage1

import (
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
)

// Windows-only ExitProcess primitive. Resolves ntdll!RtlExitUserProcess
// at runtime via PEB walk + export-directory traversal, then calls it
// with the supplied exit code. Never returns.
//
// Rationale for picking ntdll!RtlExitUserProcess over kernel32!ExitProcess:
//
//   - ntdll is reliably the SECOND entry in PEB.Ldr.InMemoryOrderModuleList
//     on every Windows version since XP. kernel32 is documented as the
//     third on Win7+ but the load order has historically shifted; ntdll's
//     position is structural to the loader.
//   - kernel32!ExitProcess is a thin shim that ultimately calls
//     ntdll!RtlExitUserProcess. Skipping the shim saves an indirection
//     layer and one DLL lookup.
//
// Asm size: approximately 130 bytes hand-encoded. Caller supplies the
// exit-code immediate so the encoded stream is per-call deterministic
// (different exit codes ⇒ different byte pattern at offset 0x67).
//
// Operational status (2026-05-10): RUNTIME GREEN on Win10 VM.
//
//	- Byte-shape pinned via [TestEmitNtdllRtlExitUserProcess_BytesShape]
//	  + [TestEmitNtdllRtlExitUserProcess_ImmediatePatching].
//	- Runtime exercise via [TestEmitNtdllRtlExitUserProcess_RuntimeExits42Windows]
//	  through the VEH-instrumented `asmtrace` harness. Asm is mmap'd
//	  RX, registered with AddVectoredExceptionHandler, called as a
//	  function pointer; on crash the harness dumps RIP + 16 GP regs
//	  + faulting address + access-violation operation type.
//
// Bug history captured for posterity:
//
//	1. First attempt walked InMemoryOrderModuleList (sorted by memory
//	   address ⇒ ASLR-dependent ordering). Switched to InLoadOrderModuleList
//	   for structurally-stable {EXE, ntdll, kernel32, ...} order.
//	2. Second attempt still ACCESS_VIOLATION'd. VEH harness pinpointed
//	   `mov eax, [r10+r11*4]` at RIP+0x3d with R10 holding an RVA
//	   instead of an absolute pointer — meaning `add r10, rdx` two
//	   instructions earlier had no effect. Root cause: REX byte
//	   `0x4c` (W=1, R=1, B=0) at offset 0x32 encoded `add rdx, r10`
//	   (extending the source register field), not `add r10, rdx`
//	   (which needs B=1, R=0 → REX `0x49`). One-byte fix.
//
// Lesson: AMD64 REX-prefix asymmetry between R (source/reg field
// extension) and B (destination/rm field extension) is an easy
// off-by-one for hand-encoding. The byte-shape unit test cannot
// catch this kind of semantic encoding bug — only runtime + VEH-
// trace can.
//
// NOT YET WIRED into the bundle-stub fallback path. §4
// (WrapBundleAsExecutableWindows) is now unblocked for the
// supervised pickup.

// EmitNtdllRtlExitUserProcess appends the PEB-walk + export-table-walk +
// indirect-call sequence to b. The exit code is baked into the emitted
// bytes as a 32-bit immediate at offset exitCodeImmOffset within the
// emitted asm (caller doesn't need to track it; the offset is internal).
//
// Register usage (by the emitted asm):
//
//   - All GP registers clobbered. Caller must NOT depend on any
//     register state surviving — the asm never returns.
//
// Stack: emits a `sub rsp, 0x28` (32-byte shadow + 8 alignment) to
// satisfy the Microsoft x64 ABI before the indirect call. No matching
// `add rsp, 0x28` because RtlExitUserProcess never returns.
func EmitNtdllRtlExitUserProcess(b *amd64.Builder, exitCode uint32) error {
	asm := assembleExitProcess(exitCode)
	if err := b.RawBytes(asm); err != nil {
		return fmt.Errorf("stage1: EmitNtdllRtlExitUserProcess: %w", err)
	}
	return nil
}

// ExitProcessImmediateOffset is the byte offset within the emitted
// asm where the exit-code uint32 immediate sits. Operators / analysts
// can use this to confirm the immediate is at the expected position
// when reverse-engineering a packed binary.
const ExitProcessImmediateOffset = 0x89

// assembleExitProcess hand-encodes the asm. Layout, with byte counts
// in the leftmost column for offset calculation:
//
//	off  bytes                      asm
//	---  -----                      ---
//	 0   65 48 8b 04 25 60 00 00 00  mov  rax, gs:[0x60]              ; PEB
//	 9   48 8b 40 18                 mov  rax, [rax+0x18]              ; PEB.Ldr
//	13   48 8b 40 20                 mov  rax, [rax+0x20]              ; Ldr.InMemoryOrderModuleList.Flink (1st: EXE)
//	17   48 8b 00                    mov  rax, [rax]                   ; → 2nd entry: ntdll
//	20   48 8b 50 20                 mov  rdx, [rax+0x20]              ; ntdll.DllBase (entry+0x30 - 0x10 list-link offset)
//	24   8b 42 3c                    mov  eax, [rdx+0x3c]              ; e_lfanew
//	27   48 01 d0                    add  rax, rdx                     ; PE header absolute
//	30   8b 80 88 00 00 00           mov  eax, [rax+0x88]              ; ExportDir.VirtualAddress
//	36   48 01 d0                    add  rax, rdx                     ; ExportDir absolute
//	39   49 89 c0                    mov  r8, rax                      ; save ExportDir base
//	42   45 8b 48 18                 mov  r9d, [r8+0x18]               ; NumberOfNames
//	46   45 8b 50 20                 mov  r10d, [r8+0x20]              ; AddressOfNames RVA
//	50   4c 01 d2                    add  r10, rdx                     ; AddressOfNames absolute
//	53   4d 31 db                    xor  r11, r11                     ; i = 0
//
//	; .loop:                                                            ; offset 0x38 = 56
//	56   45 39 cb                    cmp  r11d, r9d                    ; i vs NumberOfNames
//	59   7d 25                       jge  .notfound (rel8 +0x25 → 96)
//	61   43 8b 04 9a                 mov  eax, [r10 + r11*4]           ; nameRVA
//	65   48 01 d0                    add  rax, rdx                     ; absolute name string
//	68   48 bb 52 74 6c 45 78 69 74 55  mov rbx, 'RtlExitU' (LE u64)   ; 0x5574697845_6c_74_52
//	78   48 39 18                    cmp  [rax], rbx                   ; first 8 bytes match?
//	81   75 0e                       jne  .next (rel8 +0x0e → 97)
//	83   48 bb 73 65 72 50 72 6f 63 65  mov rbx, 'serProce' (LE u64)   ; 0x6563_6f72_5072_6573
//	93   48 39 58 08                 cmp  [rax+8], rbx                 ; next 8 bytes match?
//	97   74 04                       je   .found (rel8 +0x04 → 103)
//
//	; .next:                                                            ; offset 0x63 = 99
//	99   49 ff c3                    inc  r11
//	102  eb e8                       jmp  .loop (rel8 -0x18 → 56)
//
//	; .notfound:                                                        ; offset 0x68 = 104 (UNREACHABLE on real ntdll)
//	104  cc                          int3                              ; trap
//	105  0f 0b                       ud2                               ; backstop
//
//	; .found:                                                           ; offset 0x6b = 107
//	107  41 8b 40 24                 mov  eax, [r8+0x24]               ; AddressOfNameOrdinals RVA
//	111  48 01 d0                    add  rax, rdx                     ; absolute
//	114  42 0f b7 04 58              movzx eax, word [rax + r11*2]     ; ordinal at index i
//	119  41 8b 70 1c                 mov  esi, [r8+0x1c]               ; AddressOfFunctions RVA
//	123  48 01 d6                    add  rsi, rdx                     ; absolute
//	126  8b 04 86                    mov  eax, [rsi + rax*4]           ; function RVA
//	129  48 01 d0                    add  rax, rdx                     ; function absolute address
//	132  48 83 ec 28                 sub  rsp, 0x28                    ; shadow space + 16-byte align
//	136  b9 XX XX XX XX              mov  ecx, <exitCode>              ; arg1 (Microsoft x64 ABI) — imm at offset 137
//	141  ff d0                       call rax                          ; → ntdll!RtlExitUserProcess
//	; never returns
//
// Total: 143 bytes.
//
// The exit-code immediate sits at byte offset 137 in the stream
// (5-byte `mov ecx, imm32` opcode 0xb9 followed by 4 little-endian
// bytes). Byte offset 0x80 in the BLOCK above corresponds to that;
// see [exitCodeImmOffset].
//
// Note on the `cmp [mem], reg` direction: when assembling
// `cmp rbx, [rax]` Go's tooling emits the SAME bytes as
// `cmp [rax], rbx` (operand-direction symmetric for CMP). The
// 0x39 opcode chosen here is `CMP r/m64, r64`, semantically
// `[rax] - rbx` — sets ZF=1 iff [rax] == rbx, which is what
// the test wants.
func assembleExitProcess(exitCode uint32) []byte {
	out := []byte{
		// 0x00: mov rax, gs:[0x60]
		0x65, 0x48, 0x8b, 0x04, 0x25, 0x60, 0x00, 0x00, 0x00,
		// 0x09: mov rax, [rax+0x18]   ; PEB.Ldr
		0x48, 0x8b, 0x40, 0x18,
		// 0x0d: mov rax, [rax+0x10]   ; Ldr.InLoadOrderModuleList.Flink
		// (NOT InMemoryOrderModuleList at +0x20 — that list is sorted
		// by memory address, so ntdll's position is ASLR-dependent.
		// InLoadOrder is structural: EXE first, ntdll second, kernel32
		// third on every Windows since XP.)
		0x48, 0x8b, 0x40, 0x10,
		// 0x11: mov rax, [rax]         ; → 2nd entry: ntdll
		0x48, 0x8b, 0x00,
		// 0x14: mov rdx, [rax+0x30]    ; ntdll.DllBase
		// (DllBase is at LDR_DATA_TABLE_ENTRY+0x30. Our walker now
		// points at entry+0x00 since we walked InLoadOrderLinks, so
		// the offset is +0x30 not +0x20.)
		0x48, 0x8b, 0x50, 0x30,
		// 0x18: mov eax, [rdx+0x3c]   ; e_lfanew
		0x8b, 0x42, 0x3c,
		// 0x1b: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x1e: mov eax, [rax+0x88]   ; ExportDir.VirtualAddress
		0x8b, 0x80, 0x88, 0x00, 0x00, 0x00,
		// 0x24: add rax, rdx          ; ExportDir absolute
		0x48, 0x01, 0xd0,
		// 0x27: mov r8, rax
		0x49, 0x89, 0xc0,
		// 0x2a: mov r9d, [r8+0x18]    ; NumberOfNames
		0x45, 0x8b, 0x48, 0x18,
		// 0x2e: mov r10d, [r8+0x20]   ; AddressOfNames RVA
		0x45, 0x8b, 0x50, 0x20,
		// 0x32: add r10, rdx          ; AddressOfNames absolute
		// REX = 0x49 (W=1, B=1 — extend RM field for r10 destination).
		// PRIOR BUG: 0x4c (R=1) encoded `add rdx, r10` instead — caught
		// 2026-05-10 via VEH diag harness reading R10=0x15479c (RVA, not
		// the expected absolute pointer).
		0x49, 0x01, 0xd2,
		// 0x35: xor r11, r11          ; i = 0
		0x4d, 0x31, 0xdb,

		// 0x38: .loop
		// cmp r11d, r9d
		0x45, 0x39, 0xcb,
		// 0x3b: jge .notfound (rel8 +0x2b → 0x68 = 104)
		0x7d, 0x2b,
		// 0x3d: mov eax, [r10 + r11*4]
		0x43, 0x8b, 0x04, 0x9a,
		// 0x41: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x44: mov rbx, 'RtlExitU' LE u64
		0x48, 0xbb, 0x52, 0x74, 0x6c, 0x45, 0x78, 0x69, 0x74, 0x55,
		// 0x4e: cmp [rax], rbx
		0x48, 0x39, 0x18,
		// 0x51: jne .next (rel8 +0x10 → 0x63 = 99)
		0x75, 0x10,
		// 0x53: mov rbx, 'serProce' LE u64
		0x48, 0xbb, 0x73, 0x65, 0x72, 0x50, 0x72, 0x6f, 0x63, 0x65,
		// 0x5d: cmp [rax+8], rbx
		0x48, 0x39, 0x58, 0x08,
		// 0x61: je .found (rel8 +0x08 → 0x6b = 107)
		0x74, 0x08,

		// 0x63: .next
		// inc r11
		0x49, 0xff, 0xc3,
		// 0x66: jmp .loop (rel8 -0x30 → 0x38)
		0xeb, 0xd0,

		// 0x68: .notfound
		// int3
		0xcc,
		// 0x69: ud2
		0x0f, 0x0b,

		// 0x6b: .found
		// mov eax, [r8+0x24]   ; AddressOfNameOrdinals RVA
		0x41, 0x8b, 0x40, 0x24,
		// 0x6f: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x72: movzx eax, word [rax + r11*2]
		0x42, 0x0f, 0xb7, 0x04, 0x58,
		// 0x77: mov esi, [r8+0x1c]   ; AddressOfFunctions RVA
		0x41, 0x8b, 0x70, 0x1c,
		// 0x7b: add rsi, rdx
		0x48, 0x01, 0xd6,
		// 0x7e: mov eax, [rsi + rax*4]
		0x8b, 0x04, 0x86,
		// 0x81: add rax, rdx
		0x48, 0x01, 0xd0,
		// 0x84: sub rsp, 0x28
		0x48, 0x83, 0xec, 0x28,
		// 0x88: mov ecx, imm32 (exit code) — patched below
		0xb9, 0x00, 0x00, 0x00, 0x00,
		// 0x8d: call rax
		0xff, 0xd0,
	}
	// Patch the exit-code immediate at the well-known offset.
	out[ExitProcessImmediateOffset+0] = byte(exitCode)
	out[ExitProcessImmediateOffset+1] = byte(exitCode >> 8)
	out[ExitProcessImmediateOffset+2] = byte(exitCode >> 16)
	out[ExitProcessImmediateOffset+3] = byte(exitCode >> 24)
	return out
}
