package packer

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/crypto"
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
	// CipherType=2 wire layout: IV (16) + ciphertext + round keys (176).
	if want := uint32(16 + len(plain) + AESCTRRoundKeysSize); e.DataSize != want {
		t.Errorf("DataSize = %d, want %d (16 IV + %d plaintext + %d round keys)",
			e.DataSize, want, len(plain), AESCTRRoundKeysSize)
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

// TestBundleAESCTR_RoundKeysAppended asserts the stub-side wire-
// format contract: every CipherType=2 entry carries its 11×16=176B
// expanded AES-128 round keys appended IMMEDIATELY AFTER the
// ciphertext. The stub-side AES-NI decrypt loop reads them via
// `MOVDQU XMM, [R8 + 16*round]` so R8 = data_base + 16 (IV) +
// plaintext_len. This test pins (1) the layout, (2) byte-identity
// of the appended round keys against [crypto.ExpandAESKey] for the
// PayloadEntry's recorded key.
func TestBundleAESCTR_RoundKeysAppended(t *testing.T) {
	plain := []byte("payload-for-round-key-tail-pin")
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
	e := info.Entries[0]
	// Round keys live at the tail of the entry's data region.
	rkOff := int(e.DataRVA) + int(e.DataSize) - AESCTRRoundKeysSize
	gotRK := bundle[rkOff : rkOff+AESCTRRoundKeysSize]
	wantRK, err := crypto.ExpandAESKey(e.Key[:])
	if err != nil {
		t.Fatalf("crypto.ExpandAESKey: %v", err)
	}
	if !bytes.Equal(gotRK, wantRK) {
		t.Errorf("round keys at offset %d don't match crypto.ExpandAESKey output:\n got % x\nwant % x",
			rkOff, gotRK[:16], wantRK[:16])
	}
	// Round 0 (first 16 bytes of expansion) must equal the key
	// itself per FIPS 197 § 5.2 — sanity check against the recorded
	// PayloadEntry.Key.
	if !bytes.Equal(gotRK[:16], e.Key[:]) {
		t.Errorf("round 0 != PayloadEntry.Key:\n got % x\nwant % x", gotRK[:16], e.Key)
	}
}

// TestBundleAESCTR_AutoInjectsAESFeatureBit asserts the pack-time
// safety net: a CipherType=2 entry whose Fingerprint does NOT
// already require the AES-NI bit gets it OR'd in (mask + value +
// PTCPUIDFeatures bit) so pre-AES-NI hosts skip the entry cleanly
// instead of crashing on the stub's first `AESENC`.
func TestBundleAESCTR_AutoInjectsAESFeatureBit(t *testing.T) {
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{
			Binary:     []byte("aes-payload"),
			CipherType: CipherTypeAESCTR,
			// No explicit fingerprint — operator left it default.
		}},
		BundleOptions{},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	info, _ := InspectBundle(bundle)
	e := info.Entries[0]
	if e.PredicateType&PTCPUIDFeatures == 0 {
		t.Errorf("PredicateType = %#x — PTCPUIDFeatures bit not auto-injected", e.PredicateType)
	}
	if e.CPUIDFeatureMask&CPUIDFeatureAES == 0 {
		t.Errorf("CPUIDFeatureMask = %#x — AES bit not in mask", e.CPUIDFeatureMask)
	}
	if e.CPUIDFeatureValue&CPUIDFeatureAES == 0 {
		t.Errorf("CPUIDFeatureValue = %#x — AES bit not in value", e.CPUIDFeatureValue)
	}
}

// TestBundleAESCTR_AutoInjectIsOR confirms the auto-injection is a
// strict OR: operator-supplied feature constraints survive
// alongside the auto-injected AES bit, never overwritten.
func TestBundleAESCTR_AutoInjectIsOR(t *testing.T) {
	const (
		opMask  uint32 = 0x00000001 // operator wants SSE3 bit
		opValue uint32 = 0x00000001 // SSE3 must be SET on host
	)
	bundle, _ := PackBinaryBundle(
		[]BundlePayload{{
			Binary:     []byte("aes-payload"),
			CipherType: CipherTypeAESCTR,
			Fingerprint: FingerprintPredicate{
				PredicateType:     PTCPUIDFeatures,
				CPUIDFeatureMask:  opMask,
				CPUIDFeatureValue: opValue,
			},
		}},
		BundleOptions{},
	)
	info, _ := InspectBundle(bundle)
	e := info.Entries[0]
	// Operator's SSE3 constraint survives.
	if e.CPUIDFeatureMask&opMask == 0 {
		t.Errorf("operator SSE3 mask bit dropped: %#x", e.CPUIDFeatureMask)
	}
	// AES bit OR'd in alongside.
	if e.CPUIDFeatureMask&CPUIDFeatureAES == 0 {
		t.Errorf("AES bit not OR'd in: %#x", e.CPUIDFeatureMask)
	}
}

