package samdump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
)

// Domain "hashed bootkey" derivation from the SAM hive's
// `Domains\Account\F` value.
//
// The hashed bootkey is the per-domain symmetric key that wraps
// every user's NT/LM hash. Its derivation differs by SAM revision:
//
//   - Legacy (pre-Win 10 1607): MD5(bootkey || salt || qwerty ||
//     bootkey || digit) → RC4 key → RC4-decrypt a 32-byte block; the
//     first 16 bytes are the hashed bootkey.
//
//   - Modern (Win 10 1607+): SAM_KEY_DATA_AES header at F+0x68
//     {Revision, Length, CheckSumLen, DataLen, Salt[16], Data}; the
//     bootkey is the AES-128-CBC key, Salt is the IV, Data is the
//     ciphertext; first 16 plaintext bytes are the hashed bootkey.
//
// Algorithm reference: impacket secretsdump.py LOCAL handler
// (`getHBootKey` + `SAM_KEY_DATA_AES` + `SAM_KEY_DATA` structures).

// ErrSamKey is returned when the F value is malformed or the
// derivation step itself fails (AES bad-padding, length mismatches).
var ErrSamKey = errors.New("samdump: SAM domain-key derivation failed")

// Constants the legacy MD5+RC4 path needs (impacket: `qwerty` and
// `digits` byte arrays). These are immutable Microsoft constants
// hard-coded into every NT credential dumper.
var (
	samKeyQwerty = []byte("!@#$%^&*()qwertyUIOPAzxcvbnmQQQQQQQQQQQQ)(*@&%\x00")
	samKeyDigits = []byte("0123456789012345678901234567890123456789\x00")
)

// samFOffsetKeyHeader is the byte offset inside the SAM
// `Domains\Account\F` value where the SAM key header (legacy or
// AES) starts. impacket calls this `offsetHashedBootKey` and
// hard-codes it at 0x68 — stable across every NT release since the
// SAM hive layout settled.
const samFOffsetKeyHeader = 0x68

// SAM_KEY revision tags at samFOffsetKeyHeader+0..+3 (uint32 LE).
// Cross-checked against impacket SAM_KEY / SAM_KEY_DATA_AES Structure
// definitions: `Revision <L=1` (legacy) or `<L=2` (AES). The V3 form
// observed on some recent Windows installs reports 0x00000003 but
// shares the AES layout — included for forward compatibility.
const (
	samRevisionLegacy uint32 = 1
	samRevisionAES    uint32 = 2
	samRevisionAESV3  uint32 = 3
)

// deriveDomainKey returns the 16-byte hashed bootkey derived from
// the SAM `Domains\Account\F` value `fValue` and the boot key
// `bootkey` (16 bytes, post-permutation from extractBootKey).
//
// Picks the modern AES or legacy RC4 path based on the SAM_KEY_DATA
// revision tag at fValue[0x68].
func deriveDomainKey(bootkey, fValue []byte) ([]byte, error) {
	if len(bootkey) != 16 {
		return nil, fmt.Errorf("%w: bootkey length %d, want 16", ErrSamKey, len(bootkey))
	}
	if len(fValue) < samFOffsetKeyHeader+4 {
		return nil, fmt.Errorf("%w: F value too short for SAM key header (%d bytes)",
			ErrSamKey, len(fValue))
	}
	revision := binary.LittleEndian.Uint32(
		fValue[samFOffsetKeyHeader : samFOffsetKeyHeader+4])
	switch revision {
	case samRevisionAES, samRevisionAESV3:
		return deriveDomainKeyAES(bootkey, fValue)
	case samRevisionLegacy:
		return deriveDomainKeyLegacy(bootkey, fValue)
	default:
		return nil, fmt.Errorf("%w: unknown SAM revision 0x%08X at F+0x%X",
			ErrSamKey, revision, samFOffsetKeyHeader)
	}
}

// deriveDomainKeyAES handles the Win 10 1607+ path. SAM_KEY_DATA_AES
// layout starting at fValue[0x68]:
//
//	+0x00 Revision    uint32 (already validated)
//	+0x04 Length      uint32
//	+0x08 CheckSumLen uint32
//	+0x0C DataLen     uint32
//	+0x10 Salt[16]    — AES IV
//	+0x20 Data[...]   — AES-128-CBC ciphertext (DataLen bytes)
//
// Decrypts Data with AES-128-CBC(bootkey, Salt) and returns the
// first 16 bytes — the hashed bootkey.
func deriveDomainKeyAES(bootkey, fValue []byte) ([]byte, error) {
	const (
		offRevision    = samFOffsetKeyHeader + 0x00
		offLength      = samFOffsetKeyHeader + 0x04
		offCheckSumLen = samFOffsetKeyHeader + 0x08
		offDataLen     = samFOffsetKeyHeader + 0x0C
		offSalt        = samFOffsetKeyHeader + 0x10
		offData        = samFOffsetKeyHeader + 0x20
		hashedBootSize = 16
	)
	if len(fValue) < offData {
		return nil, fmt.Errorf("%w: F value too short for SAM_KEY_DATA_AES header (%d bytes)",
			ErrSamKey, len(fValue))
	}
	dataLen := binary.LittleEndian.Uint32(fValue[offDataLen : offDataLen+4])
	if dataLen == 0 || dataLen > 256 {
		return nil, fmt.Errorf("%w: SAM_KEY_DATA_AES DataLen %d out of expected range",
			ErrSamKey, dataLen)
	}
	if dataLen%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: SAM_KEY_DATA_AES DataLen %d not a multiple of AES block size",
			ErrSamKey, dataLen)
	}
	if uint32(len(fValue)-offData) < dataLen {
		return nil, fmt.Errorf("%w: F value truncated; have %d bytes after header, need %d",
			ErrSamKey, len(fValue)-offData, dataLen)
	}

	salt := fValue[offSalt : offSalt+16]
	ciphertext := fValue[offData : offData+int(dataLen)]

	block, err := aes.NewCipher(bootkey)
	if err != nil {
		return nil, fmt.Errorf("%w: AES NewCipher: %v", ErrSamKey, err)
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	plaintext := make([]byte, len(ciphertext))
	mode.CryptBlocks(plaintext, ciphertext)

	if len(plaintext) < hashedBootSize {
		return nil, fmt.Errorf("%w: plaintext shorter than 16 bytes", ErrSamKey)
	}
	out := make([]byte, hashedBootSize)
	copy(out, plaintext[:hashedBootSize])
	return out, nil
}

// deriveDomainKeyLegacy handles the pre-Win 10 1607 path. SAM_KEY
// layout at fValue[0x68]:
//
//	+0x00 Revision uint32 (=0x00010001, already validated)
//	+0x04 [unused 4 bytes]
//	+0x08 Salt[16]      — MD5 input
//	+0x18 Key[16]       — RC4-encrypted hashed bootkey
//	+0x28 CheckSum[16]  — verifier; we don't validate it
//	+0x38 [unused 8 bytes]
//
// Derivation:
//
//	rc4Key = MD5(bootkey || salt || qwerty || bootkey || digit)
//	hashed = RC4(rc4Key).decrypt(Key)[:16]
//
// The ENTIRE plaintext after RC4 is 16 bytes; impacket truncates to
// 16 anyway as a safety guard.
func deriveDomainKeyLegacy(bootkey, fValue []byte) ([]byte, error) {
	const (
		offSalt = samFOffsetKeyHeader + 0x08
		offKey  = samFOffsetKeyHeader + 0x18
		needed  = samFOffsetKeyHeader + 0x28 // up to end of Key[16]
	)
	if len(fValue) < needed {
		return nil, fmt.Errorf("%w: F value too short for legacy SAM_KEY (%d bytes)",
			ErrSamKey, len(fValue))
	}
	salt := fValue[offSalt : offSalt+16]
	encKey := fValue[offKey : offKey+16]

	h := md5.New()
	h.Write(bootkey)
	h.Write(salt)
	h.Write(samKeyQwerty)
	h.Write(bootkey)
	h.Write(samKeyDigits)
	rc4Key := h.Sum(nil)

	rc, err := rc4.NewCipher(rc4Key)
	if err != nil {
		return nil, fmt.Errorf("%w: RC4 NewCipher: %v", ErrSamKey, err)
	}
	out := make([]byte, len(encKey))
	rc.XORKeyStream(out, encKey)
	return out, nil
}

// samKeyHeaderRevision is exposed for tests so they can detect which
// derivation path a synthetic F value will take without re-coding
// the offset arithmetic.
func samKeyHeaderRevision(fValue []byte) (uint32, error) {
	if len(fValue) < samFOffsetKeyHeader+4 {
		return 0, fmt.Errorf("%w: F value too short", ErrSamKey)
	}
	return binary.LittleEndian.Uint32(
		fValue[samFOffsetKeyHeader : samFOffsetKeyHeader+4]), nil
}

// hashedBootKeyForTest is a no-op assertion helper: returns true
// when `derived` looks plausible (right length, not all zero from a
// zero-IV slip). Used by samkey_test.go to keep assertions DRY.
func hashedBootKeyForTest(derived []byte) bool {
	if len(derived) != 16 {
		return false
	}
	return !bytes.Equal(derived, make([]byte, 16))
}
