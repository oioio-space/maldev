package packer

import (
	"bytes"
	"errors"
	"testing"
)

// TestBundleAESCTR_RoundTrip pins the Tier 🟡 #2.2 Phase 2 wire-
// format contract: pack a payload with CipherType=2 (AES-CTR),
// confirm the on-disk PayloadEntry.CipherType byte records the
// choice, confirm DataSize includes the 16-byte IV prefix, then
// UnpackBundle decrypts back to the exact plaintext bytes.
func TestBundleAESCTR_RoundTrip(t *testing.T) {
	plain := []byte("a payload that's longer than one AES block so the CTR stream actually iterates a few times")
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{Binary: plain, CipherType: CipherTypeAESCTR}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	info, err := InspectBundle(bundle)
	if err != nil {
		t.Fatalf("InspectBundle: %v", err)
	}
	if len(info.Entries) != 1 {
		t.Fatalf("entries = %d, want 1", len(info.Entries))
	}
	e := info.Entries[0]
	if e.CipherType != CipherTypeAESCTR {
		t.Errorf("CipherType = %d, want %d (CipherTypeAESCTR)", e.CipherType, CipherTypeAESCTR)
	}
	// 16-byte IV prefix means on-disk size > plaintext size.
	if want := uint32(len(plain) + 16); e.DataSize != want {
		t.Errorf("DataSize = %d, want %d (plaintext %d + 16 B IV)", e.DataSize, want, len(plain))
	}
	if e.PlaintextSize != uint32(len(plain)) {
		t.Errorf("PlaintextSize = %d, want %d", e.PlaintextSize, len(plain))
	}

	got, err := UnpackBundle(bundle, 0)
	if err != nil {
		t.Fatalf("UnpackBundle: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("decrypted plaintext mismatch\n got %q\nwant %q", got, plain)
	}
}

// TestBundleAESCTR_MixedTypes confirms the per-entry CipherType
// dispatch — one payload XOR-rolling, the next AES-CTR. Both must
// round-trip via UnpackBundle.
func TestBundleAESCTR_MixedTypes(t *testing.T) {
	pXOR := []byte("xor-payload-fast-path-default-CipherType=0")
	pAES := []byte("aes-payload-stronger-but-needs-AES-NI-runtime-bit")
	bundle, err := PackBinaryBundle(
		[]BundlePayload{
			{Binary: pXOR}, // zero CipherType → CipherTypeXORRolling (backward compat)
			{Binary: pAES, CipherType: CipherTypeAESCTR},
		},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	info, err := InspectBundle(bundle)
	if err != nil {
		t.Fatalf("InspectBundle: %v", err)
	}
	if info.Entries[0].CipherType != CipherTypeXORRolling {
		t.Errorf("entry[0].CipherType = %d, want XORRolling", info.Entries[0].CipherType)
	}
	if info.Entries[1].CipherType != CipherTypeAESCTR {
		t.Errorf("entry[1].CipherType = %d, want AESCTR", info.Entries[1].CipherType)
	}
	got0, err := UnpackBundle(bundle, 0)
	if err != nil || !bytes.Equal(got0, pXOR) {
		t.Errorf("XOR round-trip: %v / %q vs %q", err, got0, pXOR)
	}
	got1, err := UnpackBundle(bundle, 1)
	if err != nil || !bytes.Equal(got1, pAES) {
		t.Errorf("AES-CTR round-trip: %v / %q vs %q", err, got1, pAES)
	}
}

// TestBundleAESCTR_FixedKeyRejected confirms the ErrCipherTypeFixedKey
// guard: AES-CTR needs a per-pack random IV, so combining it with
// BundleOptions.FixedKey (test-determinism mode) must fail loudly
// rather than silently produce an insecure deterministic ciphertext.
func TestBundleAESCTR_FixedKeyRejected(t *testing.T) {
	_, err := PackBinaryBundle(
		[]BundlePayload{{Binary: []byte("anything"), CipherType: CipherTypeAESCTR}},
		BundleOptions{FixedKey: make([]byte, 16)},
	)
	if err == nil {
		t.Fatalf("expected error, got nil")
	}
	if !errors.Is(err, ErrCipherTypeFixedKey) {
		t.Errorf("error = %v, want ErrCipherTypeFixedKey", err)
	}
}

// TestBundleAESCTR_BackwardCompat asserts that bundles packed BEFORE
// #2.2 (which always wrote CipherType=1 directly) still decrypt
// cleanly through the new switch dispatch — the unpack-time switch
// treats CipherType=0 (legacy zero-value reads) and =1 identically.
func TestBundleAESCTR_BackwardCompat(t *testing.T) {
	plain := []byte("legacy XOR-rolling payload")
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{Binary: plain}}, // no CipherType set
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	info, _ := InspectBundle(bundle)
	if info.Entries[0].CipherType != CipherTypeXORRolling {
		t.Errorf("default CipherType = %d, want %d (XORRolling)", info.Entries[0].CipherType, CipherTypeXORRolling)
	}
	got, err := UnpackBundle(bundle, 0)
	if err != nil || !bytes.Equal(got, plain) {
		t.Errorf("legacy round-trip: %v / %q vs %q", err, got, plain)
	}
}
