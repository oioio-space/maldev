package crypto

import (
	"encoding/binary"
	"fmt"
	"math/bits"
)

// Speck-128/128: NSA's 2013 lightweight ARX (add-rotate-xor) block
// cipher. 128-bit block, 128-bit key, 32 rounds. Round function is
// three operations on two 64-bit words — the reference implementation
// fits in ~30 bytes of x86-64 asm per round, making it the preferred
// choice when a stage-1 stub needs a real cipher (not just XOR) but
// can't afford AES's S-box.
//
// Trade-offs vs the rest of the package:
//   - vs TEA/XTEA: similar size, similar speed, more recent design,
//     no equivalent-keys weakness in TEA.
//   - vs AES-GCM: ~10x smaller code, no authentication. Pair with
//     [EncryptAESGCM] outer envelope when integrity matters; use
//     standalone for stage-1 stub decryption where the next stage
//     verifies its own integrity.
//   - vs RC4: real block cipher (RC4 is a stream cipher with known
//     biases). Same operational footprint.
//
// Design history: Speck and its sibling Simon were standardized via
// RFC drafts and the NSA's lightweight cryptography portfolio. ISO
// withdrew Speck/Simon from the 29192-2 standardization in 2018
// after disagreement over NSA design rationale; the cipher itself
// has no known practical break against the 32-round 128/128 variant.
//
// Mode: ECB with PKCS7 padding, matching the rest of this package.
// Caller wanting CBC / CTR builds it on top of the block primitive
// — round-trip helpers ([EncryptSpeck] / [DecryptSpeck]) operate on
// padded plaintext directly.

const speckRounds = 32

// speckExpandKey runs the 32-round Speck-128/128 key schedule on a
// 128-bit master key, returning 32 round keys.
func speckExpandKey(key [16]byte) [speckRounds]uint64 {
	// Master key splits into two 64-bit words (low first per the
	// reference C implementation in NSA's 2013 paper, Appendix A).
	var rk [speckRounds]uint64
	rk[0] = binary.LittleEndian.Uint64(key[0:8])
	l := binary.LittleEndian.Uint64(key[8:16])
	for i := uint64(0); i < speckRounds-1; i++ {
		l = (rk[i] + bits.RotateLeft64(l, -8)) ^ i
		rk[i+1] = bits.RotateLeft64(rk[i], 3) ^ l
	}
	return rk
}

// speckEncryptBlock encrypts a single 128-bit block in place.
func speckEncryptBlock(rk *[speckRounds]uint64, x, y *uint64) {
	for i := 0; i < speckRounds; i++ {
		*x = bits.RotateLeft64(*x, -8) + *y
		*x ^= rk[i]
		*y = bits.RotateLeft64(*y, 3) ^ *x
	}
}

// speckDecryptBlock decrypts a single 128-bit block in place.
func speckDecryptBlock(rk *[speckRounds]uint64, x, y *uint64) {
	for i := speckRounds - 1; i >= 0; i-- {
		*y = bits.RotateLeft64(*y^*x, -3)
		*x ^= rk[i]
		*x = bits.RotateLeft64(*x-*y, 8)
	}
}

// EncryptSpeck encrypts data with Speck-128/128 in ECB mode.
// Plaintext is PKCS7-padded to a 16-byte block boundary.
//
// Lightweight, unauthenticated. Pair with an outer AEAD when
// integrity matters; use standalone for stage-1 stub decryption
// where the next stage validates itself.
func EncryptSpeck(key [16]byte, data []byte) ([]byte, error) {
	padded := pkcs7Pad(data, 16)
	rk := speckExpandKey(key)
	out := make([]byte, len(padded))
	for i := 0; i < len(padded); i += 16 {
		x := binary.LittleEndian.Uint64(padded[i+8 : i+16])
		y := binary.LittleEndian.Uint64(padded[i : i+8])
		speckEncryptBlock(&rk, &x, &y)
		binary.LittleEndian.PutUint64(out[i:i+8], y)
		binary.LittleEndian.PutUint64(out[i+8:i+16], x)
	}
	return out, nil
}

// DecryptSpeck decrypts data previously encrypted with [EncryptSpeck].
// Returns an error if the ciphertext is not a multiple of 16 bytes
// or if the PKCS7 padding is malformed.
func DecryptSpeck(key [16]byte, data []byte) ([]byte, error) {
	if len(data)%16 != 0 {
		return nil, fmt.Errorf("speck: ciphertext length %d not a multiple of 16", len(data))
	}
	rk := speckExpandKey(key)
	out := make([]byte, len(data))
	for i := 0; i < len(data); i += 16 {
		x := binary.LittleEndian.Uint64(data[i+8 : i+16])
		y := binary.LittleEndian.Uint64(data[i : i+8])
		speckDecryptBlock(&rk, &x, &y)
		binary.LittleEndian.PutUint64(out[i:i+8], y)
		binary.LittleEndian.PutUint64(out[i+8:i+16], x)
	}
	return pkcs7Unpad(out, 16)
}
