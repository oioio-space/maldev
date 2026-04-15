package crypto

import (
	"encoding/binary"
	"fmt"
)

const (
	teaDelta  uint32 = 0x9E3779B9
	teaRounds        = 64
)

// teaFinalSum = teaDelta * teaRounds/2, precomputed at package init because Go
// rejects the overflowing constant product at compile time. Used as the initial
// sum for both TEA and XTEA decryption (both use 64 rounds).
var teaFinalSum = func() uint32 {
	var s uint32
	for i := 0; i < teaRounds/2; i++ {
		s += teaDelta
	}
	return s
}()

// EncryptTEA encrypts data using TEA (Tiny Encryption Algorithm) with a 16-byte key.
// Data is PKCS7-padded to a multiple of 8 bytes. Not cryptographically recommended
// for high-security use — prefer AES/ChaCha20. Use for lightweight shellcode obfuscation.
func EncryptTEA(key [16]byte, data []byte) ([]byte, error) {
	padded := pkcs7Pad(data, 8)
	out := make([]byte, len(padded))
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	for i := 0; i < len(padded); i += 8 {
		v0 := binary.LittleEndian.Uint32(padded[i:])
		v1 := binary.LittleEndian.Uint32(padded[i+4:])
		var sum uint32
		for j := 0; j < teaRounds/2; j++ {
			sum += teaDelta
			v0 += ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
			v1 += ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
		}
		binary.LittleEndian.PutUint32(out[i:], v0)
		binary.LittleEndian.PutUint32(out[i+4:], v1)
	}
	return out, nil
}

// DecryptTEA decrypts data previously encrypted with EncryptTEA.
func DecryptTEA(key [16]byte, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("tea: ciphertext length %d not a multiple of 8", len(data))
	}
	out := make([]byte, len(data))
	k0 := binary.LittleEndian.Uint32(key[0:4])
	k1 := binary.LittleEndian.Uint32(key[4:8])
	k2 := binary.LittleEndian.Uint32(key[8:12])
	k3 := binary.LittleEndian.Uint32(key[12:16])
	for i := 0; i < len(data); i += 8 {
		v0 := binary.LittleEndian.Uint32(data[i:])
		v1 := binary.LittleEndian.Uint32(data[i+4:])
		sum := teaFinalSum
		for j := 0; j < teaRounds/2; j++ {
			v1 -= ((v0 << 4) + k2) ^ (v0 + sum) ^ ((v0 >> 5) + k3)
			v0 -= ((v1 << 4) + k0) ^ (v1 + sum) ^ ((v1 >> 5) + k1)
			sum -= teaDelta
		}
		binary.LittleEndian.PutUint32(out[i:], v0)
		binary.LittleEndian.PutUint32(out[i+4:], v1)
	}
	return pkcs7Unpad(out, 8)
}

func pkcs7Pad(data []byte, blockSize int) []byte {
	pad := blockSize - len(data)%blockSize
	out := make([]byte, len(data)+pad)
	copy(out, data)
	for i := len(data); i < len(out); i++ {
		out[i] = byte(pad)
	}
	return out
}

func pkcs7Unpad(data []byte, blockSize int) ([]byte, error) {
	if len(data) == 0 || len(data)%blockSize != 0 {
		return nil, fmt.Errorf("pkcs7: invalid data length %d", len(data))
	}
	pad := int(data[len(data)-1])
	if pad == 0 || pad > blockSize {
		return nil, fmt.Errorf("pkcs7: invalid padding byte %d", pad)
	}
	return data[:len(data)-pad], nil
}
