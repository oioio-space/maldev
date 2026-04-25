package sekurlsa

import (
	"errors"
	"testing"
)

// validTemplate returns a syntactically-valid Template for register-
// path tests. The patterns / offsets are placeholders — the registry
// validation only cares about non-empty patterns and a sane build
// range.
func validTemplate(buildMin, buildMax uint32) *Template {
	return &Template{
		BuildMin:        buildMin,
		BuildMax:        buildMax,
		IVPattern:       []byte{0x01, 0x02, 0x03},
		Key3DESPattern:  []byte{0x04, 0x05, 0x06},
		KeyAESPattern:   []byte{0x07, 0x08, 0x09},
		LogonSessionListPattern: []byte{0x0A, 0x0B, 0x0C},
		LogonSessionListCount:   32,
	}
}

// TestRegisterTemplate_AcceptsValid round-trips a valid template
// through Register → templateFor.
func TestRegisterTemplate_AcceptsValid(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	tpl := validTemplate(19045, 19045)
	if err := RegisterTemplate(tpl); err != nil {
		t.Fatalf("RegisterTemplate: %v", err)
	}
	if got := templateFor(19045); got != tpl {
		t.Errorf("templateFor(19045) = %p, want %p", got, tpl)
	}
}

// TestRegisterTemplate_RejectsNil is the nil-receiver guard.
func TestRegisterTemplate_RejectsNil(t *testing.T) {
	t.Cleanup(resetTemplates)
	if err := RegisterTemplate(nil); err == nil {
		t.Error("RegisterTemplate(nil) returned nil error, want non-nil")
	}
}

// TestRegisterTemplate_RejectsInvalid covers the validate() guards.
func TestRegisterTemplate_RejectsInvalid(t *testing.T) {
	t.Cleanup(resetTemplates)
	cases := []struct {
		name string
		t    *Template
	}{
		{"BuildMin=0", &Template{BuildMin: 0, BuildMax: 100, IVPattern: []byte{1}, Key3DESPattern: []byte{1}, KeyAESPattern: []byte{1}}},
		{"BuildMax<Min", &Template{BuildMin: 200, BuildMax: 100, IVPattern: []byte{1}, Key3DESPattern: []byte{1}, KeyAESPattern: []byte{1}}},
		{"empty IVPattern", &Template{BuildMin: 1, BuildMax: 1, Key3DESPattern: []byte{1}, KeyAESPattern: []byte{1}}},
		{"empty 3DESPattern", &Template{BuildMin: 1, BuildMax: 1, IVPattern: []byte{1}, KeyAESPattern: []byte{1}}},
		{"empty AESPattern", &Template{BuildMin: 1, BuildMax: 1, IVPattern: []byte{1}, Key3DESPattern: []byte{1}}},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			if err := RegisterTemplate(c.t); err == nil {
				t.Errorf("RegisterTemplate(%s) accepted, want error", c.name)
			}
		})
	}
}

// TestRegisterTemplate_OrderedByBuildMin asserts registry insertion
// keeps templates sorted ascending by BuildMin so templateFor's
// linear scan finds the right entry first when ranges nest.
func TestRegisterTemplate_OrderedByBuildMin(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	highTpl := validTemplate(22621, 22621)
	lowTpl := validTemplate(19045, 19045)
	midTpl := validTemplate(22000, 22000)
	if err := RegisterTemplate(highTpl); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTemplate(lowTpl); err != nil {
		t.Fatal(err)
	}
	if err := RegisterTemplate(midTpl); err != nil {
		t.Fatal(err)
	}
	templateMu.RLock()
	defer templateMu.RUnlock()
	if len(templateRegistry) != 3 {
		t.Fatalf("len(registry) = %d, want 3", len(templateRegistry))
	}
	want := []uint32{19045, 22000, 22621}
	for i, tpl := range templateRegistry {
		if tpl.BuildMin != want[i] {
			t.Errorf("registry[%d].BuildMin = %d, want %d", i, tpl.BuildMin, want[i])
		}
	}
}

// TestTemplateFor_ReturnsNilForUnknownBuild covers the no-match path.
func TestTemplateFor_ReturnsNilForUnknownBuild(t *testing.T) {
	t.Cleanup(resetTemplates)
	resetTemplates()
	if got := templateFor(99999); got != nil {
		t.Errorf("templateFor(99999) = %v, want nil", got)
	}
}

// TestFindPattern_ExactMatch covers the no-wildcards happy path.
func TestFindPattern_ExactMatch(t *testing.T) {
	haystack := []byte{0x90, 0x90, 0x48, 0x33, 0xC0, 0xC3, 0x90}
	pat := []byte{0x48, 0x33, 0xC0}
	if got := findPattern(haystack, pat, nil); got != 2 {
		t.Errorf("findPattern exact = %d, want 2", got)
	}
}

// TestFindPattern_WildcardMatch confirms wildcard positions are
// treated as "any byte".
func TestFindPattern_WildcardMatch(t *testing.T) {
	haystack := []byte{0x90, 0x48, 0xAB, 0xC0, 0xC3}
	pat := []byte{0x48, 0x00, 0xC0} // 0x00 at index 1 should be ignored thanks to wildcard
	if got := findPattern(haystack, pat, []int{1}); got != 1 {
		t.Errorf("findPattern wildcard = %d, want 1", got)
	}
}

// TestFindPattern_NoMatch on a clean miss.
func TestFindPattern_NoMatch(t *testing.T) {
	if got := findPattern([]byte{1, 2, 3}, []byte{4, 5}, nil); got != -1 {
		t.Errorf("findPattern miss = %d, want -1", got)
	}
}

// TestFindPattern_PatternLongerThanHaystack returns -1 cleanly.
func TestFindPattern_PatternLongerThanHaystack(t *testing.T) {
	if got := findPattern([]byte{1, 2}, []byte{1, 2, 3, 4}, nil); got != -1 {
		t.Errorf("findPattern oversized = %d, want -1", got)
	}
}

// TestParseBCryptKeyDataBlob_AES covers the 16-byte (AES) path.
func TestParseBCryptKeyDataBlob_AES(t *testing.T) {
	blob := buildKDBM(t, []byte("0123456789abcdef")) // 16 bytes
	c, err := parseBCryptKeyDataBlob(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.BlockSize() != 16 {
		t.Errorf("AES block size = %d, want 16", c.BlockSize())
	}
}

// TestParseBCryptKeyDataBlob_3DES covers the 24-byte (3DES) path.
func TestParseBCryptKeyDataBlob_3DES(t *testing.T) {
	blob := buildKDBM(t, []byte("012345670123456701234567")) // 24 bytes — 3 distinct 8-byte halves required by 3DES key check
	c, err := parseBCryptKeyDataBlob(blob)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if c.BlockSize() != 8 {
		t.Errorf("3DES block size = %d, want 8", c.BlockSize())
	}
}

// TestParseBCryptKeyDataBlob_InvalidMagic surfaces ErrKeyExtractFailed.
func TestParseBCryptKeyDataBlob_InvalidMagic(t *testing.T) {
	blob := []byte{0xDE, 0xAD, 0xBE, 0xEF, 1, 0, 0, 0, 16, 0, 0, 0}
	blob = append(blob, make([]byte, 16)...)
	_, err := parseBCryptKeyDataBlob(blob)
	if !errors.Is(err, ErrKeyExtractFailed) {
		t.Errorf("err = %v, want ErrKeyExtractFailed", err)
	}
}

// TestParseBCryptKeyDataBlob_ShortBlob is the truncated-input guard.
func TestParseBCryptKeyDataBlob_ShortBlob(t *testing.T) {
	if _, err := parseBCryptKeyDataBlob([]byte{1, 2, 3}); !errors.Is(err, ErrKeyExtractFailed) {
		t.Errorf("err = %v, want ErrKeyExtractFailed", err)
	}
}

// TestParseBCryptKeyDataBlob_UnsupportedKeyLength rejects sizes other
// than 16 / 24.
func TestParseBCryptKeyDataBlob_UnsupportedKeyLength(t *testing.T) {
	blob := buildKDBM(t, []byte("only-eight-bytes")[:8])
	if _, err := parseBCryptKeyDataBlob(blob); !errors.Is(err, ErrKeyExtractFailed) {
		t.Errorf("err = %v, want ErrKeyExtractFailed", err)
	}
}

// TestDecryptLSA_AESRoundTrip exercises the AES-CBC happy path with
// a known key and IV.
func TestDecryptLSA_AESRoundTrip(t *testing.T) {
	keyBlob := buildKDBM(t, []byte("0123456789abcdef"))
	aes, err := parseBCryptKeyDataBlob(keyBlob)
	if err != nil {
		t.Fatalf("import AES: %v", err)
	}
	k := &lsaKey{IV: []byte("ABCDEFGH01234567"), AES: aes}

	plain := []byte("the quick brown ") // 16 bytes — single AES block
	ct := make([]byte, len(plain))
	encryptCBC(t, aes, k.IV, plain, ct)

	got, err := decryptLSA(ct, k)
	if err != nil {
		t.Fatalf("decryptLSA: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("AES round-trip: got %q want %q", got, plain)
	}
}

// TestDecryptLSA_3DESRoundTrip is the 8-byte-aligned-but-not-16-byte
// branch.
func TestDecryptLSA_3DESRoundTrip(t *testing.T) {
	keyBlob := buildKDBM(t, []byte("012345670123456701234567"))
	des, err := parseBCryptKeyDataBlob(keyBlob)
	if err != nil {
		t.Fatalf("import 3DES: %v", err)
	}
	k := &lsaKey{IV: []byte("ABCDEFGH"), TripleDES: des}

	plain := []byte("12345678") // 8 bytes — single 3DES block, NOT 16-aligned
	ct := make([]byte, len(plain))
	encryptCBC(t, des, k.IV, plain, ct)

	got, err := decryptLSA(ct, k)
	if err != nil {
		t.Fatalf("decryptLSA: %v", err)
	}
	if string(got) != string(plain) {
		t.Errorf("3DES round-trip: got %q want %q", got, plain)
	}
}

// TestDecryptLSA_NilKey surfaces the documented sentinel.
func TestDecryptLSA_NilKey(t *testing.T) {
	if _, err := decryptLSA([]byte{1, 2, 3, 4}, nil); !errors.Is(err, ErrKeyExtractFailed) {
		t.Errorf("err = %v, want ErrKeyExtractFailed", err)
	}
}

// TestDecryptLSA_BadAlignment rejects ciphertext that's not 8- or
// 16-byte aligned.
func TestDecryptLSA_BadAlignment(t *testing.T) {
	keyBlob := buildKDBM(t, []byte("0123456789abcdef"))
	aes, _ := parseBCryptKeyDataBlob(keyBlob)
	k := &lsaKey{IV: make([]byte, 16), AES: aes}
	if _, err := decryptLSA([]byte{1, 2, 3}, k); !errors.Is(err, ErrKeyExtractFailed) {
		t.Errorf("err = %v, want ErrKeyExtractFailed", err)
	}
}

// buildKDBM hand-crafts a BCRYPT_KEY_DATA_BLOB blob — header + raw
// key payload — for round-trip tests.
func buildKDBM(t *testing.T, key []byte) []byte {
	t.Helper()
	out := make([]byte, bcryptKeyDataBlobHeaderSize+len(key))
	// dwMagic = "KDBM" little-endian
	out[0], out[1], out[2], out[3] = 'K', 'D', 'B', 'M'
	out[4] = 1 // dwVersion
	// cbKeyData little-endian
	klen := uint32(len(key))
	out[8] = byte(klen)
	out[9] = byte(klen >> 8)
	out[10] = byte(klen >> 16)
	out[11] = byte(klen >> 24)
	copy(out[12:], key)
	return out
}

// encryptCBC is a test-side helper to produce ciphertext we then
// decrypt — keeps round-trip tests self-contained without pinning
// known-good vectors per platform.
func encryptCBC(t *testing.T, b interface {
	BlockSize() int
	Encrypt(dst, src []byte)
}, iv, plain, ct []byte) {
	t.Helper()
	bs := b.BlockSize()
	if len(plain)%bs != 0 || len(ct) != len(plain) {
		t.Fatalf("encryptCBC: bad alignment plain=%d ct=%d block=%d", len(plain), len(ct), bs)
	}
	prev := make([]byte, bs)
	copy(prev, iv)
	for i := 0; i < len(plain); i += bs {
		var xored [16]byte
		for j := 0; j < bs; j++ {
			xored[j] = plain[i+j] ^ prev[j]
		}
		b.Encrypt(ct[i:i+bs], xored[:bs])
		copy(prev, ct[i:i+bs])
	}
}
