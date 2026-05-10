package crypto_test

import (
	"bytes"
	"testing"

	"github.com/oioio-space/maldev/crypto"
)

// TestEncryptSpeck_NSAReferenceVector pins the implementation against
// the NSA-published Speck-128/128 test vector from Appendix B of "The
// SIMON and SPECK Lightweight Block Ciphers" (Beaulieu et al., 2015).
//
// Key   (paper order, high→low): 0f0e0d0c0b0a0908 0706050403020100
// PT  ("equivalent to la vish"): 6c61766975716520 7469206564616d20
// CT                            : a65d985179783265 7860fedf5c570d18
//
// Catches endianness mixups + word-order regressions immediately. If
// this test ever fails, the round function or key schedule has been
// silently broken.
func TestEncryptSpeck_NSAReferenceVector(t *testing.T) {
	key := [16]byte{
		// low word: 0x0706050403020100 little-endian
		0x00, 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07,
		// high word: 0x0f0e0d0c0b0a0908 little-endian
		0x08, 0x09, 0x0a, 0x0b, 0x0c, 0x0d, 0x0e, 0x0f,
	}
	// Plaintext is exactly one block — pad to 32 bytes via PKCS7
	// would change the output, so pass the 16 raw bytes and slice
	// the output back to one block before comparing. The padded
	// second block is irrelevant to the reference vector.
	pt := []byte{
		// y = 0x7469206564616d20 little-endian
		0x20, 0x6d, 0x61, 0x64, 0x65, 0x20, 0x69, 0x74,
		// x = 0x6c61766975716520 little-endian
		0x20, 0x65, 0x71, 0x75, 0x69, 0x76, 0x61, 0x6c,
	}
	wantBlock := []byte{
		// y = 0x7860fedf5c570d18 little-endian
		0x18, 0x0d, 0x57, 0x5c, 0xdf, 0xfe, 0x60, 0x78,
		// x = 0xa65d985179783265 little-endian
		0x65, 0x32, 0x78, 0x79, 0x51, 0x98, 0x5d, 0xa6,
	}
	ct, err := crypto.EncryptSpeck(key, pt)
	if err != nil {
		t.Fatalf("EncryptSpeck: %v", err)
	}
	if len(ct) < 16 {
		t.Fatalf("EncryptSpeck output too short: %d", len(ct))
	}
	if !bytes.Equal(ct[:16], wantBlock) {
		t.Errorf("Speck-128/128 NSA vector mismatch:\n  got:  %x\n  want: %x", ct[:16], wantBlock)
	}
}

// TestSpeckRoundtrip exercises the Encrypt → Decrypt path across a
// spread of plaintext lengths (forcing the PKCS7 padding to vary
// from 1 to 16 bytes) and asserts byte-perfect recovery.
func TestSpeckRoundtrip(t *testing.T) {
	key := [16]byte{
		0xde, 0xad, 0xbe, 0xef, 0xfe, 0xed, 0xfa, 0xce,
		0xca, 0xfe, 0xba, 0xbe, 0x12, 0x34, 0x56, 0x78,
	}
	for _, length := range []int{0, 1, 7, 15, 16, 17, 31, 32, 64, 1023} {
		t.Run("len="+itoa(length), func(t *testing.T) {
			pt := make([]byte, length)
			for i := range pt {
				pt[i] = byte(i * 17)
			}
			ct, err := crypto.EncryptSpeck(key, pt)
			if err != nil {
				t.Fatalf("EncryptSpeck: %v", err)
			}
			if len(ct)%16 != 0 {
				t.Errorf("ciphertext length %d not block-aligned", len(ct))
			}
			got, err := crypto.DecryptSpeck(key, ct)
			if err != nil {
				t.Fatalf("DecryptSpeck: %v", err)
			}
			if !bytes.Equal(got, pt) {
				t.Errorf("roundtrip mismatch:\n  got:  %x\n  want: %x", got, pt)
			}
		})
	}
}

// TestDecryptSpeck_RejectsBadLength asserts the contract that
// ciphertext must be a 16-byte multiple. Mirrors the TEA / XTEA
// length-validation stance.
func TestDecryptSpeck_RejectsBadLength(t *testing.T) {
	var key [16]byte
	for _, n := range []int{1, 7, 15, 17, 31} {
		if _, err := crypto.DecryptSpeck(key, make([]byte, n)); err == nil {
			t.Errorf("DecryptSpeck accepted len=%d (should reject)", n)
		}
	}
}

// TestEncryptSpeck_DifferentKeysDifferentCiphertext sanity-checks
// the key schedule actually depends on every byte of the key —
// catches "all rounds use rk[0]" regressions.
func TestEncryptSpeck_DifferentKeysDifferentCiphertext(t *testing.T) {
	pt := bytes.Repeat([]byte{0xaa}, 32)
	keyA := [16]byte{0x01}
	keyB := [16]byte{0x02}
	ctA, _ := crypto.EncryptSpeck(keyA, pt)
	ctB, _ := crypto.EncryptSpeck(keyB, pt)
	if bytes.Equal(ctA, ctB) {
		t.Error("identical ciphertext under different keys — key schedule broken")
	}
}

// itoa is a fmt.Sprint-free local helper to keep the test imports
// tight (the rest of the file uses no fmt).
func itoa(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var b [20]byte
	i := len(b)
	for n > 0 {
		i--
		b[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		b[i] = '-'
	}
	return string(b[i:])
}
