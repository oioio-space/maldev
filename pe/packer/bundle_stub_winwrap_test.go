package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestWrapBundleAsExecutableWindows_RejectsBadInputs covers the two
// fast-path validations: truncated bundle and bad magic.
func TestWrapBundleAsExecutableWindows_RejectsBadInputs(t *testing.T) {
	t.Run("truncated", func(t *testing.T) {
		_, err := packer.WrapBundleAsExecutableWindows([]byte{0x4d, 0x4c, 0x44, 0x56})
		if !errors.Is(err, packer.ErrBundleTruncated) {
			t.Errorf("got %v, want ErrBundleTruncated", err)
		}
	})
	t.Run("bad magic", func(t *testing.T) {
		bad := make([]byte, packer.BundleHeaderSize)
		bad[0] = 'X'
		bad[1] = 'X'
		bad[2] = 'X'
		bad[3] = 'X'
		_, err := packer.WrapBundleAsExecutableWindows(bad)
		if !errors.Is(err, packer.ErrBundleBadMagic) {
			t.Errorf("got %v, want ErrBundleBadMagic", err)
		}
	})
}

// TestWrapBundleAsExecutableWindows_DebugPEParses asserts the wrapped
// output round-trips through Go's stdlib `debug/pe` reader. Strong
// proxy for "the Windows kernel will at least parse this", and the
// minimum bar before VM testing.
func TestWrapBundleAsExecutableWindows_DebugPEParses(t *testing.T) {
	// Build a minimal 1-payload PTMatchAll bundle with placeholder
	// shellcode (the JMP target — the wrap doesn't care what's
	// there, only the wire-format header gates the wrap).
	scPlaceholder := bytes.Repeat([]byte{0x90}, 31)
	scPlaceholder = append(scPlaceholder, 0xc3) // ret

	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary: scPlaceholder,
			Fingerprint: packer.FingerprintPredicate{
				PredicateType: packer.PTMatchAll,
			},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	out, err := packer.WrapBundleAsExecutableWindows(bundle)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindows: %v", err)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want AMD64", f.FileHeader.Machine)
	}
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	if oh.ImageBase != transform.MinimalPE32PlusImageBase {
		t.Errorf("ImageBase = %#x, want %#x (PHASE A canonical)",
			oh.ImageBase, transform.MinimalPE32PlusImageBase)
	}
	if oh.AddressOfEntryPoint == 0 {
		t.Error("AddressOfEntryPoint = 0 (writer didn't set it)")
	}

	// Output must be substantially larger than the bundle alone —
	// the stub adds ~330 bytes of asm.
	if len(out) <= len(bundle)+200 {
		t.Errorf("wrapped %d bytes <= bundle %d + 200 — stub may not have been added",
			len(out), len(bundle))
	}
}

// TestWrapBundleAsExecutableWindowsWithSeed_Deterministic asserts
// the same seed → byte-identical output. The polymorphism injection
// is keyed by seed; duplicate calls must not drift.
func TestWrapBundleAsExecutableWindowsWithSeed_Deterministic(t *testing.T) {
	scPlaceholder := []byte{0x90, 0x90, 0xc3}
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary:      scPlaceholder,
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{
			FixedKey: bytes.Repeat([]byte{0x42}, 16),
		},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	a, err := packer.WrapBundleAsExecutableWindowsWithSeed(bundle, packer.BundleProfile{}, 12345)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindowsWithSeed(a): %v", err)
	}
	b, err := packer.WrapBundleAsExecutableWindowsWithSeed(bundle, packer.BundleProfile{}, 12345)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindowsWithSeed(b): %v", err)
	}
	if !bytes.Equal(a, b) {
		t.Errorf("non-deterministic for same seed:\n  len(a)=%d len(b)=%d\n  diff at first byte: %d",
			len(a), len(b), firstDiff(a, b))
	}

	// Different seeds → different polymorphism pattern → different
	// output (assuming non-zero seed activates injectStubJunk).
	c, err := packer.WrapBundleAsExecutableWindowsWithSeed(bundle, packer.BundleProfile{}, 67890)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindowsWithSeed(c): %v", err)
	}
	if bytes.Equal(a, c) {
		t.Error("identical output for different seeds — polymorphism not active")
	}
}

func firstDiff(a, b []byte) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	if len(a) != len(b) {
		return n
	}
	return -1
}

// TestWrapBundleAsExecutableWindows_HonoursProfileVaddr asserts the
// PHASE B per-build ImageBase derivation: profile.Vaddr (when set)
// is masked to 64 K alignment and used as the wrapped PE's
// ImageBase. Zero / unaligned-low-Vaddr fall back to the canonical
// 0x140000000.
func TestWrapBundleAsExecutableWindows_HonoursProfileVaddr(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary:      []byte{0xc3},
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	cases := []struct {
		name     string
		vaddr    uint64
		wantBase uint64
	}{
		{
			name:     "zero falls back to canonical",
			vaddr:    0,
			wantBase: transform.MinimalPE32PlusImageBase,
		},
		{
			name:     "page-aligned in user half — masked to 64K",
			vaddr:    0x196ef3ddb000,
			wantBase: 0x196ef3dd0000,
		},
		{
			name:     "already 64K-aligned — passes through",
			vaddr:    0x180000000,
			wantBase: 0x180000000,
		},
		{
			name:     "below 64K after masking — fall back to canonical",
			vaddr:    0x1234,
			wantBase: transform.MinimalPE32PlusImageBase,
		},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			profile := packer.BundleProfile{
				Magic:       packer.BundleMagic,
				FooterMagic: packer.BundleFooterMagic,
				Vaddr:       tc.vaddr,
			}
			out, err := packer.WrapBundleAsExecutableWindowsWithSeed(bundle, profile, 0)
			if err != nil {
				t.Fatalf("WrapBundleAsExecutableWindowsWithSeed: %v", err)
			}
			f, err := pe.NewFile(bytes.NewReader(out))
			if err != nil {
				t.Fatalf("debug/pe: %v", err)
			}
			defer f.Close()
			oh := f.OptionalHeader.(*pe.OptionalHeader64)
			if oh.ImageBase != tc.wantBase {
				t.Errorf("ImageBase = %#x, want %#x", oh.ImageBase, tc.wantBase)
			}
		})
	}
}

// TestWrapBundleAsExecutableWindows_StubLayoutSanity asserts the
// scan-stub bytes match the documented Phase-A layout shape: shared
// 115-byte prefix with the Linux stub, then the divergence at the
// .no_match transition.
func TestWrapBundleAsExecutableWindows_StubLayoutSanity(t *testing.T) {
	bundle, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{
			Binary:      []byte{0xc3},
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll},
		}},
		packer.BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	out, err := packer.WrapBundleAsExecutableWindowsWithSeed(bundle, packer.BundleProfile{}, 0)
	if err != nil {
		t.Fatalf("WrapBundleAsExecutableWindowsWithSeed: %v", err)
	}

	// At PE entry-point RVA (the start of .text), the first byte is
	// the 0xe8 of the PIC trampoline `call .pic`. With seed=0 (no
	// junk injection) the byte-shape is deterministic.
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	textSec := f.Sections[0]
	textBytes, err := textSec.Data()
	if err != nil {
		t.Fatalf("read .text: %v", err)
	}

	// Expect: 0xe8, 0x00, 0x00, 0x00, 0x00 at the very start (PIC call).
	wantPrefix := []byte{0xe8, 0x00, 0x00, 0x00, 0x00}
	if !bytes.HasPrefix(textBytes, wantPrefix) {
		t.Errorf(".text prefix = %x, want %x (PIC trampoline call)",
			textBytes[:5], wantPrefix)
	}

	// V2NW (v0.88.0+) emits the entire scan stub via amd64.Builder
	// with label-resolved jumps; the .no_match → §2 transition is no
	// longer at the V1+§2-patch offset 115. Asserting on a specific
	// byte position there would be V1-specific. Instead, assert the
	// stub is substantially larger than V1+§2-patch (V2NW is ~420 B
	// + bundle vs V1's ~340 B + bundle) which catches any accidental
	// fall-back to V1.
	if len(textBytes) < 400 {
		t.Errorf(".text section %d bytes < 400 — may have fallen back to V1+§2-patch instead of V2NW",
			len(textBytes))
	}
}

// stripIfNeeded keeps strings.* import live in case future tests need it.
var _ = strings.Contains
