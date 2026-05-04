package samdump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/des"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"testing"
)

// fixtureLegacyHashEnc encrypts wantHash through the legacy MD5+RC4
// + DES-permute pipeline so a round-trip via decryptUserHash recovers
// wantHash. Returns the on-disk encrypted blob (SAM_HASH wrapper:
// PekID(2)+Revision=1(2)+Hash[16] = 20 bytes total) ready to feed
// decryptUserNT/decryptUserLM.
func fixtureLegacyHashEnc(t *testing.T, hashedBootkey []byte, rid uint32, wantHash []byte, marker []byte) []byte {
	t.Helper()
	if len(wantHash) != 16 {
		t.Fatalf("fixtureLegacyHashEnc: wantHash length %d, want 16", len(wantHash))
	}
	// Pre-DES-encrypt wantHash with the same RID-derived keys
	// (apply DES-encrypt to invert decryptUserHash's DES-decrypt).
	k1, k2 := desKeysForRID(rid)
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	intermediate := make([]byte, 16)
	c1.Encrypt(intermediate[0:8], wantHash[0:8])
	c2.Encrypt(intermediate[8:16], wantHash[8:16])

	// Then RC4-encrypt with the legacy-derived key.
	rc4Key := deriveLegacyHashKey(hashedBootkey, rid, marker)
	rc, _ := rc4.NewCipher(rc4Key)
	cipherBytes := make([]byte, 16)
	rc.XORKeyStream(cipherBytes, intermediate)

	// Build the SAM_HASH wrapper: PekID=1, Revision=1, then 16-byte
	// ciphertext.
	out := make([]byte, 4+16)
	binary.LittleEndian.PutUint16(out[0:2], 0x0001) // PekID
	binary.LittleEndian.PutUint16(out[2:4], 0x0001) // Revision (legacy)
	copy(out[4:], cipherBytes)
	return out
}

// fixtureAESHashEnc builds a SAM_HASH_AES envelope that decrypts
// through the modern AES + DES-permute pipeline back to wantHash.
// Layout: PekID(2)+Revision=2(2)+DataOffset(4)+Salt[16]+Cipher[16]
// = 40 bytes total for one AES block.
func fixtureAESHashEnc(t *testing.T, hashedBootkey []byte, rid uint32, wantHash []byte) []byte {
	t.Helper()
	if len(wantHash) != 16 {
		t.Fatalf("fixtureAESHashEnc: wantHash length %d, want 16", len(wantHash))
	}
	// Pre-DES-encrypt to invert the desUnwrap stage.
	k1, k2 := desKeysForRID(rid)
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	intermediate := make([]byte, 16)
	c1.Encrypt(intermediate[0:8], wantHash[0:8])
	c2.Encrypt(intermediate[8:16], wantHash[8:16])

	// AES-encrypt with the same hashedBootkey + chosen IV.
	salt := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	block, _ := aes.NewCipher(hashedBootkey)
	mode := cipher.NewCBCEncrypter(block, salt)
	cipherText := make([]byte, 16) // single AES block — same length as plaintext
	mode.CryptBlocks(cipherText, intermediate)

	// Wrap in the SAM_HASH_AES envelope.
	out := make([]byte, 0x18+len(cipherText))
	binary.LittleEndian.PutUint16(out[0:2], 0x0001) // PekID
	binary.LittleEndian.PutUint16(out[2:4], 0x0002) // Revision (AES)
	binary.LittleEndian.PutUint32(out[4:8], 0x14)   // DataOffset (cipher start within struct)
	copy(out[0x08:0x18], salt)
	copy(out[0x18:], cipherText)
	return out
}

func TestDecryptUserNT_LegacyRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x55}, 16)
	rid := uint32(1001)
	wantHash := []byte{
		0x31, 0xD6, 0xCF, 0xE0, 0xD1, 0x6A, 0xE9, 0x31,
		0xB7, 0x3C, 0x59, 0xD7, 0xE0, 0xC0, 0x89, 0xC0, // empty-string NT hash
	}
	enc := fixtureLegacyHashEnc(t, hashedBootkey, rid, wantHash, hashEncNTPassword)
	got, err := decryptUserNT(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserNT: %v", err)
	}
	if !bytes.Equal(got, wantHash) {
		t.Fatalf("NT hash:\n  got  % X\n  want % X", got, wantHash)
	}
}

func TestDecryptUserLM_LegacyRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0xAA}, 16)
	rid := uint32(500) // built-in Administrator RID
	wantHash := []byte{
		0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE,
		0xAA, 0xD3, 0xB4, 0x35, 0xB5, 0x14, 0x04, 0xEE, // empty-string LM hash
	}
	enc := fixtureLegacyHashEnc(t, hashedBootkey, rid, wantHash, hashEncLMPassword)
	got, err := decryptUserLM(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserLM: %v", err)
	}
	if !bytes.Equal(got, wantHash) {
		t.Fatalf("LM hash:\n  got  % X\n  want % X", got, wantHash)
	}
}

func TestDecryptUserNT_AESRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x33}, 16)
	rid := uint32(1234)
	wantHash := []byte{
		0xDE, 0xAD, 0xBE, 0xEF, 0xCA, 0xFE, 0xBA, 0xBE,
		0x12, 0x34, 0x56, 0x78, 0x9A, 0xBC, 0xDE, 0xF0,
	}
	enc := fixtureAESHashEnc(t, hashedBootkey, rid, wantHash)
	got, err := decryptUserNT(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserNT: %v", err)
	}
	if !bytes.Equal(got, wantHash) {
		t.Fatalf("NT hash:\n  got  % X\n  want % X", got, wantHash)
	}
}

func TestDecryptUserHash_EmptyEnc(t *testing.T) {
	got, err := decryptUserNT(make([]byte, 16), 1001, nil)
	if err != nil {
		t.Errorf("err = %v, want nil for empty enc", err)
	}
	if got != nil {
		t.Errorf("got = % X, want nil for empty enc", got)
	}
}

func TestDecryptUserHash_RejectsShortHashedBootkey(t *testing.T) {
	_, err := decryptUserNT(make([]byte, 8), 1001, make([]byte, 16))
	if !errors.Is(err, ErrUserHash) {
		t.Fatalf("err = %v, want wrap of ErrUserHash", err)
	}
}

func TestDecryptUserHash_RejectsTruncatedAESEnvelope(t *testing.T) {
	// PekID=1, Revision=2 (AES), DataOffset=0x14, partial Salt — but
	// truncated before the Salt completes (and well before any Data
	// would land). Length = 26 bytes = past the header-only boundary
	// (24) but short of the 40-byte minimum-with-data envelope.
	enc := make([]byte, 26)
	enc[0] = 0x01 // PekID
	enc[2] = 0x02 // Revision = AES
	enc[4] = 0x14 // DataOffset
	_, err := decryptUserNT(make([]byte, 16), 1001, enc)
	if !errors.Is(err, ErrUserHash) {
		t.Fatalf("err = %v, want wrap of ErrUserHash", err)
	}
}

func TestDecryptUserHash_AESHeaderOnlyReturnsNil(t *testing.T) {
	// 24-byte SAM_HASH_AES envelope with no Data field — Microsoft's
	// "no hash set" encoding for accounts that never had a password
	// (built-in Administrator on a fresh install, Guest, etc.).
	// Should return (nil, nil) rather than failing.
	enc := make([]byte, 0x18)
	enc[0] = 0x01 // PekID
	enc[2] = 0x02 // Revision = AES
	enc[4] = 0x14 // DataOffset
	got, err := decryptUserNT(make([]byte, 16), 500, enc)
	if err != nil {
		t.Fatalf("err = %v, want nil for header-only envelope (no hash)", err)
	}
	if got != nil {
		t.Errorf("got = % X, want nil for header-only envelope", got)
	}
}

func TestDecryptUserHash_RejectsUnknownRevision(t *testing.T) {
	// PekID=1, Revision=0x99 (unknown) — should fall through to
	// the default error path.
	enc := []byte{0x01, 0x00, 0x99, 0x00}
	_, err := decryptUserNT(make([]byte, 16), 1001, enc)
	if !errors.Is(err, ErrUserHash) {
		t.Fatalf("err = %v, want wrap of ErrUserHash", err)
	}
}

func TestDesKeysForRID_KnownVector(t *testing.T) {
	// rid = 0x000001F4 (RID 500, built-in Administrator)
	// rid_le = F4 01 00 00
	// raw1 = F4 01 00 00 F4 01 00  (7 bytes)
	// raw2 = 00 F4 01 00 00 F4 01  (7 bytes)
	k1, k2 := desKeysForRID(500)
	if len(k1) != 8 || len(k2) != 8 {
		t.Fatalf("DES keys length: k1=%d k2=%d, want 8/8", len(k1), len(k2))
	}
	// Sanity: DES NewCipher must accept both — would error on
	// invalid 8-byte keys.
	if _, err := des.NewCipher(k1); err != nil {
		t.Errorf("k1 not a valid DES key: %v", err)
	}
	if _, err := des.NewCipher(k2); err != nil {
		t.Errorf("k2 not a valid DES key: %v", err)
	}
}

func TestTransformKey56to64_BitsExpandedWithParity(t *testing.T) {
	// All-zero input → all-zero output.
	zero := make([]byte, 7)
	got := transformKey56to64(zero)
	for i, b := range got {
		if b != 0 {
			t.Errorf("zero-in: out[%d] = 0x%02X, want 0", i, b)
		}
	}

	// All-0xFF input (56 ones) → all (0xFE? 0xFE is 1111 1110).
	// After collecting 7 bits per output byte from the 56 ones and
	// shifting left by 1, every output byte should be 0xFE.
	ones := bytes.Repeat([]byte{0xFF}, 7)
	got = transformKey56to64(ones)
	for i, b := range got {
		if b != 0xFE {
			t.Errorf("ones-in: out[%d] = 0x%02X, want 0xFE", i, b)
		}
	}
}

func TestDeriveLegacyHashKey_DependsOnRID(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x77}, 16)
	k1 := deriveLegacyHashKey(hashedBootkey, 1001, hashEncNTPassword)
	k2 := deriveLegacyHashKey(hashedBootkey, 1002, hashEncNTPassword)
	if bytes.Equal(k1, k2) {
		t.Fatal("RID-1001 and RID-1002 produce identical legacy hash keys (RID input not bound)")
	}
}

func TestDeriveLegacyHashKey_NTAndLMDiffer(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x88}, 16)
	ntKey := deriveLegacyHashKey(hashedBootkey, 1001, hashEncNTPassword)
	lmKey := deriveLegacyHashKey(hashedBootkey, 1001, hashEncLMPassword)
	if bytes.Equal(ntKey, lmKey) {
		t.Fatal("NT and LM derived keys are identical (encMarker not bound)")
	}
}

// fixtureLegacyHistoryEnc encrypts N hashes through the same legacy
// MD5+RC4+DES pipeline used for a single-hash blob, but the RC4
// keystream covers N×16 bytes (one continuous run) and each plaintext
// 16-byte block is independently DES-permuted with the user's RID-
// derived keys before encryption. Returns the on-disk SAM_HASH
// wrapper (4-byte header + N×16 RC4-encrypted bytes).
func fixtureLegacyHistoryEnc(t *testing.T, hashedBootkey []byte, rid uint32, hashes [][]byte, marker []byte) []byte {
	t.Helper()
	intermediate := make([]byte, 0, len(hashes)*16)
	k1, k2 := desKeysForRID(rid)
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	for i, h := range hashes {
		if len(h) != 16 {
			t.Fatalf("fixtureLegacyHistoryEnc: hashes[%d] length %d, want 16", i, len(h))
		}
		block := make([]byte, 16)
		c1.Encrypt(block[0:8], h[0:8])
		c2.Encrypt(block[8:16], h[8:16])
		intermediate = append(intermediate, block...)
	}
	rc4Key := deriveLegacyHashKey(hashedBootkey, rid, marker)
	rc, _ := rc4.NewCipher(rc4Key)
	cipherBytes := make([]byte, len(intermediate))
	rc.XORKeyStream(cipherBytes, intermediate)
	out := make([]byte, hashWrapperLen+len(cipherBytes))
	binary.LittleEndian.PutUint16(out[0:2], 0x0001) // PekID
	binary.LittleEndian.PutUint16(out[2:4], 0x0001) // Revision (legacy)
	copy(out[hashWrapperLen:], cipherBytes)
	return out
}

// fixtureAESHistoryEnc is the AES counterpart: PekID(2)+Revision=2(2)
// +DataOffset(4)+Salt[16]+Cipher[N*16]. Each plaintext 16-byte block
// is DES-permuted before being concatenated and AES-CBC encrypted as
// a single payload.
func fixtureAESHistoryEnc(t *testing.T, hashedBootkey []byte, rid uint32, hashes [][]byte) []byte {
	t.Helper()
	intermediate := make([]byte, 0, len(hashes)*16)
	k1, k2 := desKeysForRID(rid)
	c1, _ := des.NewCipher(k1)
	c2, _ := des.NewCipher(k2)
	for i, h := range hashes {
		if len(h) != 16 {
			t.Fatalf("fixtureAESHistoryEnc: hashes[%d] length %d, want 16", i, len(h))
		}
		block := make([]byte, 16)
		c1.Encrypt(block[0:8], h[0:8])
		c2.Encrypt(block[8:16], h[8:16])
		intermediate = append(intermediate, block...)
	}
	salt := []byte{
		0xAA, 0xBB, 0xCC, 0xDD, 0xEE, 0xFF, 0x00, 0x11,
		0x22, 0x33, 0x44, 0x55, 0x66, 0x77, 0x88, 0x99,
	}
	block, _ := aes.NewCipher(hashedBootkey)
	mode := cipher.NewCBCEncrypter(block, salt)
	cipherText := make([]byte, len(intermediate))
	mode.CryptBlocks(cipherText, intermediate)
	out := make([]byte, 0x18+len(cipherText))
	binary.LittleEndian.PutUint16(out[0:2], 0x0001) // PekID
	binary.LittleEndian.PutUint16(out[2:4], 0x0002) // Revision (AES)
	binary.LittleEndian.PutUint32(out[4:8], 0x14)   // DataOffset
	copy(out[0x08:0x18], salt)
	copy(out[0x18:], cipherText)
	return out
}

func TestDecryptUserNTHistory_LegacyRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x55}, 16)
	rid := uint32(1001)
	want := [][]byte{
		bytes.Repeat([]byte{0x11}, 16), // most recent prior NT
		bytes.Repeat([]byte{0x22}, 16),
		bytes.Repeat([]byte{0x33}, 16), // oldest in the window
	}
	enc := fixtureLegacyHistoryEnc(t, hashedBootkey, rid, want, hashEncNTPasswordHistory)
	got, err := decryptUserNTHistory(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserNTHistory: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d historical hashes, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("hash[%d]:\n  got  % X\n  want % X", i, got[i], want[i])
		}
	}
}

func TestDecryptUserNTHistory_AESRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0x33}, 16)
	rid := uint32(1234)
	want := [][]byte{
		bytes.Repeat([]byte{0xDE}, 16),
		bytes.Repeat([]byte{0xAD}, 16),
	}
	enc := fixtureAESHistoryEnc(t, hashedBootkey, rid, want)
	got, err := decryptUserNTHistory(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserNTHistory: %v", err)
	}
	if len(got) != len(want) {
		t.Fatalf("got %d historical hashes, want %d", len(got), len(want))
	}
	for i := range want {
		if !bytes.Equal(got[i], want[i]) {
			t.Errorf("hash[%d]:\n  got  % X\n  want % X", i, got[i], want[i])
		}
	}
}

func TestDecryptUserLMHistory_LegacyRoundtrip(t *testing.T) {
	hashedBootkey := bytes.Repeat([]byte{0xAA}, 16)
	rid := uint32(500)
	want := [][]byte{bytes.Repeat([]byte{0xCC}, 16)}
	enc := fixtureLegacyHistoryEnc(t, hashedBootkey, rid, want, hashEncLMPasswordHistory)
	got, err := decryptUserLMHistory(hashedBootkey, rid, enc)
	if err != nil {
		t.Fatalf("decryptUserLMHistory: %v", err)
	}
	if len(got) != 1 || !bytes.Equal(got[0], want[0]) {
		t.Fatalf("LM history hash:\n  got  %X\n  want %X", got, want)
	}
}

func TestDecryptUserHashHistory_EmptyEnc(t *testing.T) {
	got, err := decryptUserNTHistory(make([]byte, 16), 1001, nil)
	if err != nil {
		t.Errorf("err = %v, want nil for empty enc", err)
	}
	if got != nil {
		t.Errorf("got = %X, want nil for empty enc", got)
	}
}

func TestDecryptUserHashHistory_AESHeaderOnlyReturnsNil(t *testing.T) {
	// 24-byte SAM_HASH_AES envelope with no Data field — this is the
	// on-disk encoding when PasswordHistorySize=0 or no history yet.
	enc := make([]byte, 0x18)
	enc[0] = 0x01 // PekID
	enc[2] = 0x02 // Revision = AES
	enc[4] = 0x14 // DataOffset
	got, err := decryptUserNTHistory(make([]byte, 16), 500, enc)
	if err != nil {
		t.Fatalf("err = %v, want nil for header-only history envelope", err)
	}
	if got != nil {
		t.Errorf("got = %X, want nil for header-only history envelope", got)
	}
}

func TestDecryptUserHashHistory_RejectsMisalignedLegacyData(t *testing.T) {
	// 4-byte legacy SAM_HASH header + 17 bytes (not a 16-byte multiple).
	enc := make([]byte, 4+17)
	enc[0] = 0x01 // PekID
	enc[2] = 0x01 // Revision = legacy
	_, err := decryptUserNTHistory(bytes.Repeat([]byte{0x55}, 16), 1001, enc)
	if !errors.Is(err, ErrUserHash) {
		t.Fatalf("err = %v, want wrap of ErrUserHash for misaligned legacy history data", err)
	}
}

func TestDecryptUserHashHistory_RejectsUnknownRevision(t *testing.T) {
	enc := []byte{0x01, 0x00, 0x99, 0x00}
	_, err := decryptUserNTHistory(make([]byte, 16), 1001, enc)
	if !errors.Is(err, ErrUserHash) {
		t.Fatalf("err = %v, want wrap of ErrUserHash for unknown history revision", err)
	}
}
