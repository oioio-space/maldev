package samdump

import (
	"bytes"
	"crypto/aes"
	"crypto/cipher"
	"crypto/md5"
	"crypto/rc4"
	"encoding/binary"
	"errors"
	"testing"
)

// fixtureFValueAES synthesizes a SAM `Domains\Account\F` value with
// the modern SAM_KEY_DATA_AES layout. Returns (fValue, expected
// hashedBootKey) — the expected value is the first 16 bytes of the
// AES-128-CBC plaintext we encrypt into the F value.
func fixtureFValueAES(t *testing.T, bootkey []byte) ([]byte, []byte) {
	t.Helper()
	if len(bootkey) != 16 {
		t.Fatalf("fixtureFValueAES: bootkey length %d, want 16", len(bootkey))
	}
	// Choose a known plaintext for the hashed bootkey + 16 bytes of
	// padding, totaling one AES block aligned to 32 bytes (the
	// minimum DataLen we ever see in the wild).
	wantHashed := []byte{
		0x10, 0x11, 0x12, 0x13, 0x14, 0x15, 0x16, 0x17,
		0x18, 0x19, 0x1A, 0x1B, 0x1C, 0x1D, 0x1E, 0x1F,
	}
	plaintext := make([]byte, 32)
	copy(plaintext, wantHashed)
	// Fill the second AES block with arbitrary bytes — getDomainKey
	// truncates to 16 anyway.
	for i := 16; i < 32; i++ {
		plaintext[i] = byte(i ^ 0x55)
	}

	salt := []byte{
		0x20, 0x21, 0x22, 0x23, 0x24, 0x25, 0x26, 0x27,
		0x28, 0x29, 0x2A, 0x2B, 0x2C, 0x2D, 0x2E, 0x2F,
	}
	block, err := aes.NewCipher(bootkey)
	if err != nil {
		t.Fatalf("aes.NewCipher: %v", err)
	}
	mode := cipher.NewCBCEncrypter(block, salt)
	ciphertext := make([]byte, len(plaintext))
	mode.CryptBlocks(ciphertext, plaintext)

	// Build the F value: 0x68 bytes of zero header (we don't read
	// any of those fields here), then the SAM_KEY_DATA_AES blob.
	f := make([]byte, samFOffsetKeyHeader+0x20+len(ciphertext))
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader:samFOffsetKeyHeader+4], samRevisionAESV3)
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader+4:samFOffsetKeyHeader+8], 0x80) // Length
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader+8:samFOffsetKeyHeader+12], 0)   // CheckSumLen
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader+12:samFOffsetKeyHeader+16], uint32(len(ciphertext)))
	copy(f[samFOffsetKeyHeader+16:samFOffsetKeyHeader+32], salt)
	copy(f[samFOffsetKeyHeader+32:], ciphertext)
	return f, wantHashed
}

func TestDeriveDomainKey_AESModernRoundtrip(t *testing.T) {
	bootkey := bytes.Repeat([]byte{0x42}, 16)
	f, wantHashed := fixtureFValueAES(t, bootkey)

	got, err := deriveDomainKey(bootkey, f)
	if err != nil {
		t.Fatalf("deriveDomainKey: %v", err)
	}
	if !bytes.Equal(got, wantHashed) {
		t.Fatalf("hashedBootKey:\n  got  % X\n  want % X", got, wantHashed)
	}
	if !hashedBootKeyForTest(got) {
		t.Errorf("hashedBootKeyForTest reports the result is implausible")
	}
}

func TestDeriveDomainKey_AESV2RevisionAlsoWorks(t *testing.T) {
	bootkey := bytes.Repeat([]byte{0xAA}, 16)
	f, wantHashed := fixtureFValueAES(t, bootkey)
	// Switch the revision tag to V2 — same layout, alternate value
	// Microsoft uses on some Windows builds.
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader:samFOffsetKeyHeader+4], samRevisionAES)

	got, err := deriveDomainKey(bootkey, f)
	if err != nil {
		t.Fatalf("deriveDomainKey: %v", err)
	}
	if !bytes.Equal(got, wantHashed) {
		t.Fatalf("hashedBootKey:\n  got  % X\n  want % X", got, wantHashed)
	}
}

func TestDeriveDomainKey_LegacyRC4Roundtrip(t *testing.T) {
	bootkey := bytes.Repeat([]byte{0x33}, 16)
	salt := bytes.Repeat([]byte{0x44}, 16)
	wantHashed := []byte{
		0xAB, 0xCD, 0xEF, 0x01, 0x23, 0x45, 0x67, 0x89,
		0xFE, 0xDC, 0xBA, 0x98, 0x76, 0x54, 0x32, 0x10,
	}

	// Encrypt wantHashed with RC4 using the impacket-style derived key.
	h := md5.New()
	h.Write(bootkey)
	h.Write(salt)
	h.Write(samKeyQwerty)
	h.Write(bootkey)
	h.Write(samKeyDigits)
	rc4Key := h.Sum(nil)
	rc, err := rc4.NewCipher(rc4Key)
	if err != nil {
		t.Fatalf("rc4.NewCipher: %v", err)
	}
	encKey := make([]byte, 16)
	rc.XORKeyStream(encKey, wantHashed)

	// Build legacy F value: 0x68 header + revision + 4 unused +
	// salt[16] + key[16] + checksum[16] + 8 unused.
	f := make([]byte, samFOffsetKeyHeader+0x40)
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader:samFOffsetKeyHeader+4], samRevisionLegacy)
	copy(f[samFOffsetKeyHeader+0x08:samFOffsetKeyHeader+0x18], salt)
	copy(f[samFOffsetKeyHeader+0x18:samFOffsetKeyHeader+0x28], encKey)

	got, err := deriveDomainKey(bootkey, f)
	if err != nil {
		t.Fatalf("deriveDomainKey: %v", err)
	}
	if !bytes.Equal(got, wantHashed) {
		t.Fatalf("hashedBootKey:\n  got  % X\n  want % X", got, wantHashed)
	}
}

func TestDeriveDomainKey_RejectsShortBootkey(t *testing.T) {
	_, err := deriveDomainKey(make([]byte, 8), make([]byte, 0x100))
	if !errors.Is(err, ErrSamKey) {
		t.Fatalf("err = %v, want wrap of ErrSamKey", err)
	}
}

func TestDeriveDomainKey_RejectsShortFValue(t *testing.T) {
	_, err := deriveDomainKey(make([]byte, 16), make([]byte, 0x10))
	if !errors.Is(err, ErrSamKey) {
		t.Fatalf("err = %v, want wrap of ErrSamKey", err)
	}
}

func TestDeriveDomainKey_RejectsUnknownRevision(t *testing.T) {
	bootkey := make([]byte, 16)
	f := make([]byte, samFOffsetKeyHeader+0x20)
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader:samFOffsetKeyHeader+4], 0xDEADBEEF)
	_, err := deriveDomainKey(bootkey, f)
	if !errors.Is(err, ErrSamKey) {
		t.Fatalf("err = %v, want wrap of ErrSamKey", err)
	}
}

func TestDeriveDomainKey_AESRejectsUnalignedDataLen(t *testing.T) {
	bootkey := bytes.Repeat([]byte{0x55}, 16)
	f, _ := fixtureFValueAES(t, bootkey)
	// Corrupt DataLen so it's not a multiple of 16.
	binary.LittleEndian.PutUint32(f[samFOffsetKeyHeader+12:samFOffsetKeyHeader+16], 17)

	_, err := deriveDomainKey(bootkey, f)
	if !errors.Is(err, ErrSamKey) {
		t.Fatalf("err = %v, want wrap of ErrSamKey", err)
	}
}

func TestSamKeyHeaderRevision_DetectsAES(t *testing.T) {
	bootkey := make([]byte, 16)
	f, _ := fixtureFValueAES(t, bootkey)
	rev, err := samKeyHeaderRevision(f)
	if err != nil {
		t.Fatalf("samKeyHeaderRevision: %v", err)
	}
	if rev != samRevisionAESV3 {
		t.Errorf("revision = 0x%X, want 0x%X", rev, samRevisionAESV3)
	}
}
