package packer

import (
	"bytes"
	"errors"
	"testing"
)

// TestBundlePayloadKey_Deterministic asserts the Tier 🟡 #2.4
// wire-in: a non-nil 16-byte BundlePayload.Key reproduces the
// SAME XOR-rolling ciphertext bytes across packs (deterministic
// per the operator's secret). AES-CTR ciphertext differs because
// of the random IV — same key, different IV per pack — but the
// recorded PayloadEntry.Key is byte-identical.
func TestBundlePayloadKey_Deterministic(t *testing.T) {
	plain := []byte("operator-supplied-key-test-payload")
	myKey := []byte("AAAAAAAAAAAAAAAA") // 16 bytes
	mk := func() []byte {
		b, err := PackBinaryBundle(
			[]BundlePayload{{Binary: plain, Key: myKey}},
			BundleOptions{},
		)
		if err != nil {
			t.Fatalf("PackBinaryBundle: %v", err)
		}
		return b
	}
	b1 := mk()
	b2 := mk()
	if !bytes.Equal(b1, b2) {
		t.Errorf("same Key produced different bundle bytes — XOR-rolling not deterministic")
	}
	// Verify the recorded key matches the supplied one.
	info, _ := InspectBundle(b1)
	if !bytes.Equal(info.Entries[0].Key[:], myKey) {
		t.Errorf("PayloadEntry.Key = % x, want % x", info.Entries[0].Key, myKey)
	}
	// Round-trip via UnpackBundle.
	got, err := UnpackBundle(b1, 0)
	if err != nil {
		t.Fatalf("UnpackBundle: %v", err)
	}
	if !bytes.Equal(got, plain) {
		t.Errorf("decrypted = %q, want %q", got, plain)
	}
}

// TestBundlePayloadKey_BadLen pins the size-guard: non-nil keys
// MUST be exactly 16 bytes; 0, 8, 15, 17, 32 are rejected with
// ErrBundleBadKeyLen.
func TestBundlePayloadKey_BadLen(t *testing.T) {
	for _, n := range []int{1, 8, 15, 17, 24, 32} {
		_, err := PackBinaryBundle(
			[]BundlePayload{{Binary: []byte("x"), Key: make([]byte, n)}},
			BundleOptions{},
		)
		if err == nil {
			t.Errorf("len=%d: expected ErrBundleBadKeyLen, got nil", n)
			continue
		}
		if !errors.Is(err, ErrBundleBadKeyLen) {
			t.Errorf("len=%d: got %v, want ErrBundleBadKeyLen", n, err)
		}
	}
}

// TestBundlePayloadKey_FixedKeyWins confirms BundleOptions.FixedKey
// overrides per-payload BundlePayload.Key (matches pre-#2.4 behaviour:
// FixedKey is the test-determinism switch and stays authoritative).
func TestBundlePayloadKey_FixedKeyWins(t *testing.T) {
	fixed := []byte("FFFFFFFFFFFFFFFF")
	per := []byte("PPPPPPPPPPPPPPPP")
	bundle, err := PackBinaryBundle(
		[]BundlePayload{{Binary: []byte("x"), Key: per}},
		BundleOptions{FixedKey: fixed},
	)
	if err != nil {
		t.Fatalf("PackBinaryBundle: %v", err)
	}
	info, _ := InspectBundle(bundle)
	if !bytes.Equal(info.Entries[0].Key[:], fixed) {
		t.Errorf("Key = % x, want fixed % x", info.Entries[0].Key, fixed)
	}
}
