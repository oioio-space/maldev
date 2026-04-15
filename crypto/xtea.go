package crypto

import (
	"encoding/binary"
	"fmt"
)

const xteaRounds = 64

// EncryptXTEA encrypts data using XTEA (eXtended TEA) with a 16-byte key.
// XTEA fixes TEA's equivalent-key weakness. Same block size (8 bytes), PKCS7-padded.
func EncryptXTEA(key [16]byte, data []byte) ([]byte, error) {
	padded := pkcs7Pad(data, 8)
	out := make([]byte, len(padded))
	var k [4]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < len(padded); i += 8 {
		v0 := binary.LittleEndian.Uint32(padded[i:])
		v1 := binary.LittleEndian.Uint32(padded[i+4:])
		var sum uint32
		for j := 0; j < xteaRounds/2; j++ {
			v0 += (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum&3])
			sum += teaDelta
			v1 += (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11)&3])
		}
		binary.LittleEndian.PutUint32(out[i:], v0)
		binary.LittleEndian.PutUint32(out[i+4:], v1)
	}
	return out, nil
}

// DecryptXTEA decrypts data previously encrypted with EncryptXTEA.
func DecryptXTEA(key [16]byte, data []byte) ([]byte, error) {
	if len(data)%8 != 0 {
		return nil, fmt.Errorf("xtea: ciphertext length %d not a multiple of 8", len(data))
	}
	out := make([]byte, len(data))
	var k [4]uint32
	for i := range k {
		k[i] = binary.LittleEndian.Uint32(key[i*4:])
	}
	for i := 0; i < len(data); i += 8 {
		v0 := binary.LittleEndian.Uint32(data[i:])
		v1 := binary.LittleEndian.Uint32(data[i+4:])
		sum := teaFinalSum
		for j := 0; j < xteaRounds/2; j++ {
			v1 -= (((v0 << 4) ^ (v0 >> 5)) + v0) ^ (sum + k[(sum>>11)&3])
			sum -= teaDelta
			v0 -= (((v1 << 4) ^ (v1 >> 5)) + v1) ^ (sum + k[sum&3])
		}
		binary.LittleEndian.PutUint32(out[i:], v0)
		binary.LittleEndian.PutUint32(out[i+4:], v1)
	}
	return pkcs7Unpad(out, 8)
}
