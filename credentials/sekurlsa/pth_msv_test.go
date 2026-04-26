package sekurlsa

import (
	"bytes"
	"errors"
	"testing"
)

// TestMutateMSVPrimary_OverwritesNTHash verifies the NT slot at
// offset 0x20..0x30 is replaced with the target's NTLM bytes.
func TestMutateMSVPrimary_OverwritesNTHash(t *testing.T) {
	plain := make([]byte, msvPrimaryWithSHA1End)
	for i := range plain {
		plain[i] = 0xCC // sentinel — anything non-zero
	}
	target := PTHTarget{
		Domain:   "X",
		Username: "x",
		NTLM:     bytes.Repeat([]byte{0xAB}, msvPrimaryNTHashLen),
	}
	got, err := mutateMSVPrimary(plain, target)
	if err != nil {
		t.Fatalf("mutateMSVPrimary: %v", err)
	}
	for i := msvPrimaryNTHashOffset; i < msvPrimaryLMHashOffset; i++ {
		if got[i] != 0xAB {
			t.Errorf("NT byte %d = 0x%X, want 0xAB", i, got[i])
		}
	}
}

// TestMutateMSVPrimary_ZerosLMHash — Vista+ behavior: LM is always
// zeroed regardless of source plaintext.
func TestMutateMSVPrimary_ZerosLMHash(t *testing.T) {
	plain := bytes.Repeat([]byte{0xFF}, msvPrimaryWithSHA1End)
	target := PTHTarget{
		Domain:   "X",
		Username: "x",
		NTLM:     bytes.Repeat([]byte{0xAB}, msvPrimaryNTHashLen),
	}
	got, err := mutateMSVPrimary(plain, target)
	if err != nil {
		t.Fatalf("mutateMSVPrimary: %v", err)
	}
	for i := msvPrimaryLMHashOffset; i < msvPrimaryNTAndLMEnd; i++ {
		if got[i] != 0 {
			t.Errorf("LM byte %d = 0x%X, want 0 (Vista+ behavior)", i, got[i])
		}
	}
}

// TestMutateMSVPrimary_PreservesSHA1 — SHA1 slot (Win11 DPAPI key)
// is left intact since PTHTarget does not carry a SHA1 input.
func TestMutateMSVPrimary_PreservesSHA1(t *testing.T) {
	plain := make([]byte, msvPrimaryWithSHA1End)
	for i := range plain {
		plain[i] = 0xDD // sentinel byte for the SHA1 region
	}
	target := PTHTarget{
		Domain:   "X",
		Username: "x",
		NTLM:     bytes.Repeat([]byte{0xAB}, msvPrimaryNTHashLen),
	}
	got, err := mutateMSVPrimary(plain, target)
	if err != nil {
		t.Fatalf("mutateMSVPrimary: %v", err)
	}
	for i := msvPrimarySHA1Offset; i < msvPrimaryWithSHA1End; i++ {
		if got[i] != 0xDD {
			t.Errorf("SHA1 byte %d = 0x%X, want 0xDD (preserved)", i, got[i])
		}
	}
}

// TestMutateMSVPrimary_RejectsShortPlaintext — refuses plaintext
// that's too short to contain an MSV primary credential layout.
func TestMutateMSVPrimary_RejectsShortPlaintext(t *testing.T) {
	target := PTHTarget{
		Domain:   "X",
		Username: "x",
		NTLM:     bytes.Repeat([]byte{0xAB}, msvPrimaryNTHashLen),
	}
	_, err := mutateMSVPrimary(make([]byte, 0x10), target)
	if !errors.Is(err, ErrPTHWriteFailed) {
		t.Errorf("err = %v, want wrap of ErrPTHWriteFailed", err)
	}
}

// TestMutateMSVPrimary_DoesNotMutateInput — caller's input slice
// must remain untouched (we return a freshly-allocated copy).
func TestMutateMSVPrimary_DoesNotMutateInput(t *testing.T) {
	plain := bytes.Repeat([]byte{0xCC}, msvPrimaryWithSHA1End)
	original := append([]byte(nil), plain...)
	target := PTHTarget{
		Domain:   "X",
		Username: "x",
		NTLM:     bytes.Repeat([]byte{0xAB}, msvPrimaryNTHashLen),
	}
	if _, err := mutateMSVPrimary(plain, target); err != nil {
		t.Fatalf("mutateMSVPrimary: %v", err)
	}
	if !bytes.Equal(plain, original) {
		t.Errorf("input plaintext was mutated; original=%x got=%x", original, plain)
	}
}

// TestPTHSentinels_AreDistinct guards against accidental aliasing
// when adding new sentinels — each errors.Is check elsewhere relies
// on the wrapped error being uniquely identifiable. Cross-platform
// because the sentinels themselves are.
func TestPTHSentinels_AreDistinct(t *testing.T) {
	all := []error{
		ErrPTHInvalidTarget,
		ErrPTHSpawnFailed,
		ErrPTHWriteFailed,
		ErrPTHNoMatchingLUID,
		ErrPTHNotImplemented,
	}
	for i, a := range all {
		for j, b := range all {
			if i != j && errors.Is(a, b) {
				t.Errorf("sentinel %v unexpectedly Is %v", a, b)
			}
		}
	}
}
