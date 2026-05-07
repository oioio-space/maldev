package packer_test

import (
	"bytes"
	"crypto/rand"
	"debug/pe"
	"errors"
	"os"
	"runtime"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPack_RoundTrip is the headline correctness check: Pack →
// Unpack → identical bytes. Run across input sizes that exercise
// the boundary cases (empty, small, page-sized, multi-page).
func TestPack_RoundTrip(t *testing.T) {
	sizes := []int{0, 1, 16, 4096, 4096 * 8}
	for _, n := range sizes {
		t.Run("", func(t *testing.T) {
			input := randBytes(t, n)
			packed, key, err := packer.Pack(input, packer.Options{})
			if err != nil {
				t.Fatalf("Pack: %v", err)
			}
			got, err := packer.Unpack(packed, key)
			if err != nil {
				t.Fatalf("Unpack: %v", err)
			}
			if !bytes.Equal(got, input) {
				t.Errorf("round-trip lost bytes: got %d, want %d", len(got), len(input))
			}
		})
	}
}

func TestPack_GeneratesKeyWhenNil(t *testing.T) {
	_, key, err := packer.Pack([]byte("hello"), packer.Options{})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if len(key) != 32 {
		t.Errorf("default key length = %d, want 32", len(key))
	}
}

func TestPack_AcceptsSuppliedKey(t *testing.T) {
	custom := bytes.Repeat([]byte{0xAB}, 32)
	_, key, err := packer.Pack([]byte("hello"), packer.Options{Key: custom})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	if !bytes.Equal(key, custom) {
		t.Error("Pack returned a different key than the one supplied")
	}
}

func TestPack_RejectsUnsupportedCipher(t *testing.T) {
	_, _, err := packer.Pack([]byte("x"), packer.Options{Cipher: packer.CipherChaCha20})
	if !errors.Is(err, packer.ErrUnsupportedCipher) {
		t.Errorf("got %v, want ErrUnsupportedCipher", err)
	}
}

func TestPack_RejectsUnsupportedCompressor(t *testing.T) {
	_, _, err := packer.Pack([]byte("x"), packer.Options{Compressor: packer.CompressorLZMA})
	if !errors.Is(err, packer.ErrUnsupportedCompressor) {
		t.Errorf("got %v, want ErrUnsupportedCompressor", err)
	}
}

func TestUnpack_RejectsShortBlob(t *testing.T) {
	_, err := packer.Unpack([]byte{1, 2, 3}, make([]byte, 32))
	if !errors.Is(err, packer.ErrShortBlob) {
		t.Errorf("got %v, want ErrShortBlob", err)
	}
}

func TestUnpack_RejectsBadMagic(t *testing.T) {
	bogus := make([]byte, packer.HeaderSize+16)
	copy(bogus, "ZZZZ")
	_, err := packer.Unpack(bogus, make([]byte, 32))
	if !errors.Is(err, packer.ErrBadMagic) {
		t.Errorf("got %v, want ErrBadMagic", err)
	}
}

func TestUnpack_RejectsWrongKey(t *testing.T) {
	packed, _, err := packer.Pack([]byte("secrets"), packer.Options{})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	wrongKey := bytes.Repeat([]byte{0xFF}, 32)
	_, err = packer.Unpack(packed, wrongKey)
	if err == nil {
		t.Error("Unpack accepted a wrong key — AEAD auth tag should reject")
	}
}

func TestUnpack_DetectsTamperedCiphertext(t *testing.T) {
	packed, key, err := packer.Pack([]byte("original"), packer.Options{})
	if err != nil {
		t.Fatalf("Pack: %v", err)
	}
	// Flip one byte deep in the ciphertext (skip header).
	packed[len(packed)-1] ^= 0x01
	_, err = packer.Unpack(packed, key)
	if err == nil {
		t.Error("Unpack accepted tampered ciphertext — AEAD auth tag should reject")
	}
}

func TestPack_ProducesUniqueOutputForSameInput(t *testing.T) {
	// AES-GCM nonce randomness alone guarantees ciphertext bytes
	// differ across packs. Polymorphic stub (Phase 1d) will
	// extend this to header + stub bytes too.
	input := []byte("payload")
	a, _, _ := packer.Pack(input, packer.Options{})
	b, _, _ := packer.Pack(input, packer.Options{})
	if bytes.Equal(a, b) {
		t.Error("two Pack calls with same input produced identical bytes — nonce reuse?")
	}
}

func TestCipherString(t *testing.T) {
	cases := []struct {
		c    packer.Cipher
		want string
	}{
		{packer.CipherAESGCM, "aes-gcm"},
		{packer.CipherChaCha20, "chacha20-poly1305"},
		{packer.CipherRC4, "rc4"},
		{packer.Cipher(99), "cipher(99)"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Cipher(%d).String() = %q, want %q", uint8(tc.c), got, tc.want)
		}
	}
}

func TestCompressorString(t *testing.T) {
	cases := []struct {
		c    packer.Compressor
		want string
	}{
		{packer.CompressorNone, "none"},
		{packer.CompressorAPLib, "aplib"},
		{packer.CompressorLZMA, "lzma"},
		{packer.CompressorZstd, "zstd"},
		{packer.CompressorLZ4, "lz4"},
		{packer.Compressor(99), "compressor(99)"},
	}
	for _, tc := range cases {
		if got := tc.c.String(); got != tc.want {
			t.Errorf("Compressor(%d).String() = %q, want %q", uint8(tc.c), got, tc.want)
		}
	}
}

func TestMagic_IsFourBytes(t *testing.T) {
	if got := len(packer.Magic); got != 4 {
		t.Errorf("Magic length = %d, want 4", got)
	}
}

func TestHeaderSize_MatchesSpec(t *testing.T) {
	if packer.HeaderSize != 32 {
		t.Errorf("HeaderSize = %d, want 32 — wire-format change requires version bump", packer.HeaderSize)
	}
}

func TestValidateELF_AcceptsRealFixture(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("fixture is built for linux/amd64")
	}
	elf, err := os.ReadFile("runtime/testdata/hello_static_pie")
	if err != nil {
		t.Fatalf("read fixture: %v", err)
	}
	if err := packer.ValidateELF(elf); err != nil {
		t.Errorf("ValidateELF(fixture): got %v, want nil", err)
	}
}

func TestValidateELF_RejectsGarbage(t *testing.T) {
	if err := packer.ValidateELF([]byte{0x00, 0x00, 0x00, 0x00}); err == nil {
		t.Error("ValidateELF(zeros): got nil, want error")
	}
}

func TestPackBinary_RejectsUnsupportedFormat(t *testing.T) {
	_, _, err := packer.PackBinary([]byte("payload"), packer.PackBinaryOptions{
		Format: packer.FormatUnknown,
	})
	if !errors.Is(err, packer.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

func TestPackBinary_ProducesParsablePE(t *testing.T) {
	payload := []byte("hello payload")
	out, key, err := packer.PackBinary(payload, packer.PackBinaryOptions{
		Format:       packer.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         1,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if len(key) == 0 {
		t.Error("returned key is empty")
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected output: %v", err)
	}
	defer f.Close()
}

func randBytes(t *testing.T, n int) []byte {
	t.Helper()
	b := make([]byte, n)
	if n > 0 {
		if _, err := rand.Read(b); err != nil {
			t.Fatalf("rand.Read: %v", err)
		}
	}
	return b
}
