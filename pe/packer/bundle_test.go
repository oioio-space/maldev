package packer_test

import (
	"bytes"
	"encoding/binary"
	"errors"
	"strings"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestPackBinaryBundle_EmptyPayloads asserts the [packer.ErrEmptyBundle]
// sentinel surfaces for nil + zero-length inputs.
func TestPackBinaryBundle_EmptyPayloads(t *testing.T) {
	for _, p := range [][]packer.BundlePayload{nil, {}} {
		_, err := packer.PackBinaryBundle(p, packer.BundleOptions{})
		if !errors.Is(err, packer.ErrEmptyBundle) {
			t.Errorf("PackBinaryBundle(empty) err = %v, want ErrEmptyBundle", err)
		}
	}
}

// TestPackBinaryBundle_TooLarge asserts the bundle rejects > 255 payloads.
func TestPackBinaryBundle_TooLarge(t *testing.T) {
	huge := make([]packer.BundlePayload, packer.BundleMaxPayloads+1)
	for i := range huge {
		huge[i] = packer.BundlePayload{Binary: []byte("x")}
	}
	_, err := packer.PackBinaryBundle(huge, packer.BundleOptions{})
	if !errors.Is(err, packer.ErrBundleTooLarge) {
		t.Errorf("PackBinaryBundle(256) err = %v, want ErrBundleTooLarge", err)
	}
}

// TestPackBinaryBundle_HeaderLayout asserts the BundleHeader fields are
// serialised at their spec offsets.
func TestPackBinaryBundle_HeaderLayout(t *testing.T) {
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("hello")}},
		packer.BundleOptions{
			FallbackBehaviour: packer.BundleFallbackCrash,
			CipherKey:         bytes.Repeat([]byte{0xAA}, 16),
		},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	if len(out) < packer.BundleHeaderSize {
		t.Fatalf("output truncated: %d < %d", len(out), packer.BundleHeaderSize)
	}

	if got := binary.LittleEndian.Uint32(out[0:4]); got != packer.BundleMagic {
		t.Errorf("magic = %#x, want %#x", got, packer.BundleMagic)
	}
	if got := binary.LittleEndian.Uint16(out[4:6]); got != packer.BundleVersion {
		t.Errorf("version = %#x, want %#x", got, packer.BundleVersion)
	}
	if got := binary.LittleEndian.Uint16(out[6:8]); got != 1 {
		t.Errorf("count = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(out[8:12]); got != packer.BundleHeaderSize {
		t.Errorf("FpTableOffset = %d, want %d", got, packer.BundleHeaderSize)
	}
	if got := binary.LittleEndian.Uint32(out[20:24]); got != uint32(packer.BundleFallbackCrash) {
		t.Errorf("FallbackBehaviour = %d, want %d", got, packer.BundleFallbackCrash)
	}
	// Reserved [24:32] must be zero.
	for i := 24; i < 32; i++ {
		if out[i] != 0 {
			t.Errorf("Reserved byte %d = %#x, want 0", i, out[i])
		}
	}
}

// TestPackBinaryBundle_FingerprintRoundTrip verifies a FingerprintPredicate
// is serialised at the right entry slot and round-trips field-for-field.
func TestPackBinaryBundle_FingerprintRoundTrip(t *testing.T) {
	pred := packer.FingerprintPredicate{
		PredicateType:     packer.PTCPUIDVendor | packer.PTWinBuild,
		VendorString:      [12]byte{'G', 'e', 'n', 'u', 'i', 'n', 'e', 'I', 'n', 't', 'e', 'l'},
		BuildMin:          22000,
		BuildMax:          22631,
		CPUIDFeatureMask:  0xff,
		CPUIDFeatureValue: 0x42,
		Negate:            true,
	}
	out, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("p"), Fingerprint: pred}},
		packer.BundleOptions{CipherKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	off := packer.BundleHeaderSize
	if got := out[off]; got != pred.PredicateType {
		t.Errorf("PredicateType = %#x, want %#x", got, pred.PredicateType)
	}
	if got := out[off+1]; got != 1 { // Negate flag bit 0
		t.Errorf("Flags = %#x, want 0x01 (negate)", got)
	}
	if got := string(out[off+4 : off+16]); got != string(pred.VendorString[:]) {
		t.Errorf("VendorString = %q, want %q", got, pred.VendorString)
	}
	if got := binary.LittleEndian.Uint32(out[off+16 : off+20]); got != pred.BuildMin {
		t.Errorf("BuildMin = %d, want %d", got, pred.BuildMin)
	}
	if got := binary.LittleEndian.Uint32(out[off+20 : off+24]); got != pred.BuildMax {
		t.Errorf("BuildMax = %d, want %d", got, pred.BuildMax)
	}
	if got := binary.LittleEndian.Uint32(out[off+24 : off+28]); got != pred.CPUIDFeatureMask {
		t.Errorf("CPUIDFeatureMask = %#x, want %#x", got, pred.CPUIDFeatureMask)
	}
	if got := binary.LittleEndian.Uint32(out[off+28 : off+32]); got != pred.CPUIDFeatureValue {
		t.Errorf("CPUIDFeatureValue = %#x, want %#x", got, pred.CPUIDFeatureValue)
	}
}

// TestUnpackBundle_RoundTripsTwoPayloads verifies the host-side helper
// UnpackBundle decrypts each entry independently and yields the original
// payload bytes.
func TestUnpackBundle_RoundTripsTwoPayloads(t *testing.T) {
	pls := []packer.BundlePayload{
		{Binary: []byte("payload-AMD-23H2-message"),
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll}},
		{Binary: bytes.Repeat([]byte{0xAB}, 4096),
			Fingerprint: packer.FingerprintPredicate{PredicateType: packer.PTMatchAll}},
	}
	out, err := packer.PackBinaryBundle(pls, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	for i, p := range pls {
		got, err := packer.UnpackBundle(out, i)
		if err != nil {
			t.Fatalf("UnpackBundle(%d): %v", i, err)
		}
		if !bytes.Equal(got, p.Binary) {
			t.Errorf("payload %d: got %d bytes, want %d", i, len(got), len(p.Binary))
		}
	}
}

// TestUnpackBundle_RejectsBadInputs covers truncated blobs, wrong magic,
// out-of-range index — all surfacing wrapped errors.
func TestUnpackBundle_RejectsBadInputs(t *testing.T) {
	good, err := packer.PackBinaryBundle(
		[]packer.BundlePayload{{Binary: []byte("x")}},
		packer.BundleOptions{CipherKey: make([]byte, 16)},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}

	cases := []struct {
		name    string
		input   []byte
		idx     int
		wantSub string
	}{
		{"truncated", []byte{0x4D, 0x4C}, 0, "truncated"},
		{"badMagic", append(append([]byte(nil), make([]byte, 32)...)), 0, "magic"},
		{"idxNeg", good, -1, "out of range"},
		{"idxHigh", good, 5, "out of range"},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := packer.UnpackBundle(c.input, c.idx)
			if err == nil {
				t.Fatalf("UnpackBundle: want error, got nil")
			}
			if !strings.Contains(err.Error(), c.wantSub) {
				t.Errorf("err %v does not contain %q", err, c.wantSub)
			}
		})
	}
}

// TestPackBinaryBundle_PayloadKeysIndependent asserts that successive
// packs without an explicit CipherKey yield distinct ciphertexts even
// when the plaintexts are identical — confirming the per-payload key is
// freshly random each time.
func TestPackBinaryBundle_PayloadKeysIndependent(t *testing.T) {
	pl := []packer.BundlePayload{{Binary: bytes.Repeat([]byte{0x42}, 1024)}}
	a, err := packer.PackBinaryBundle(pl, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("pack a: %v", err)
	}
	b, err := packer.PackBinaryBundle(pl, packer.BundleOptions{})
	if err != nil {
		t.Fatalf("pack b: %v", err)
	}
	if bytes.Equal(a, b) {
		t.Error("two packs produced identical bundles — key randomisation broken")
	}
}
