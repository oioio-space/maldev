package crypto

import (
	"bytes"
	"crypto/rand"
	"testing"
)

func TestTEARoundtrip(t *testing.T) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	data := []byte("hello maldev TEA")
	enc, err := EncryptTEA(key, data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptTEA(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("TEA roundtrip failed: got %q, want %q", dec, data)
	}
}

func TestXTEARoundtrip(t *testing.T) {
	var key [16]byte
	if _, err := rand.Read(key[:]); err != nil {
		t.Fatal(err)
	}
	data := []byte("hello maldev XTEA")
	enc, err := EncryptXTEA(key, data)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := DecryptXTEA(key, enc)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("XTEA roundtrip failed: got %q, want %q", dec, data)
	}
}

func TestArithShiftRoundtrip(t *testing.T) {
	key := []byte("shiftkey")
	data := []byte{0x00, 0xFF, 0x90, 0x48, 0x31, 0xC0}
	enc, err := ArithShift(data, key)
	if err != nil {
		t.Fatal(err)
	}
	dec, err := ReverseArithShift(enc, key)
	if err != nil {
		t.Fatal(err)
	}
	if !bytes.Equal(dec, data) {
		t.Fatalf("ArithShift roundtrip failed")
	}
}

func TestSBoxRoundtrip(t *testing.T) {
	sbox, inv, err := NewSBox()
	if err != nil {
		t.Fatal(err)
	}
	data := []byte{0x00, 0x01, 0xFE, 0xFF, 0x90}
	enc := SubstituteBytes(data, sbox)
	dec := ReverseSubstituteBytes(enc, inv)
	if !bytes.Equal(dec, data) {
		t.Fatalf("SBox roundtrip failed")
	}
}

func TestMatrixTransformRoundtrip(t *testing.T) {
	for _, n := range []int{2, 3, 4} {
		key, inv, err := NewMatrixKey(n)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		data := make([]byte, n*9)
		for i := range data {
			data[i] = byte(i)
		}
		enc, err := MatrixTransform(data, key)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		dec, err := ReverseMatrixTransform(enc, inv)
		if err != nil {
			t.Fatalf("n=%d: %v", n, err)
		}
		if !bytes.Equal(dec, data) {
			t.Fatalf("MatrixTransform roundtrip failed for n=%d", n)
		}
	}
}

// TestSeededSBox_Deterministic asserts the central contract: same
// seed → same (sbox, inverse). Stub-side decoders depend on this
// reproducibility; if it ever breaks, every per-pack-seed bundle
// stops decoding.
func TestSeededSBox_Deterministic(t *testing.T) {
	seed := []byte{0xde, 0xad, 0xbe, 0xef, 0xca, 0xfe, 0xba, 0xbe}
	a, ainv, err := SeededSBox(seed)
	if err != nil {
		t.Fatalf("SeededSBox: %v", err)
	}
	b, binv, err := SeededSBox(seed)
	if err != nil {
		t.Fatalf("SeededSBox: %v", err)
	}
	if a != b {
		t.Error("non-deterministic sbox for same seed")
	}
	if ainv != binv {
		t.Error("non-deterministic inverse for same seed")
	}
}

// TestSeededSBox_DifferentSeedsDifferentBoxes catches a regression
// where the seed parameter would be ignored / hashed away.
func TestSeededSBox_DifferentSeedsDifferentBoxes(t *testing.T) {
	a, _, _ := SeededSBox([]byte("seed-a"))
	b, _, _ := SeededSBox([]byte("seed-b"))
	if a == b {
		t.Error("identical sbox for different seeds")
	}
}

// TestSeededSBox_IsValidPermutation checks the output is a valid
// permutation of [0,255] (every value present exactly once) and
// that inverse[sbox[i]] == i for all i.
func TestSeededSBox_IsValidPermutation(t *testing.T) {
	sbox, inv, err := SeededSBox([]byte("any-seed"))
	if err != nil {
		t.Fatalf("SeededSBox: %v", err)
	}
	var seen [256]bool
	for _, v := range sbox {
		if seen[v] {
			t.Errorf("sbox not a permutation — value %d repeats", v)
		}
		seen[v] = true
	}
	for i := 0; i < 256; i++ {
		if int(inv[sbox[i]]) != i {
			t.Errorf("inverse mismatch at %d: inv[sbox[%d]] = %d", i, i, inv[sbox[i]])
		}
	}
}

// TestSeededSBox_RoundtripSubstitute exercises the full pipeline
// expected of operators: SubstituteBytes → ReverseSubstituteBytes
// recovers the plaintext exactly.
func TestSeededSBox_RoundtripSubstitute(t *testing.T) {
	sbox, inv, _ := SeededSBox([]byte("opx"))
	pt := []byte{0x00, 0x01, 0x02, 0x55, 0xaa, 0xff, 0xff, 0xfe}
	ct := SubstituteBytes(pt, sbox)
	got := ReverseSubstituteBytes(ct, inv)
	for i := range pt {
		if pt[i] != got[i] {
			t.Errorf("roundtrip byte %d: pt=%#x → ct=%#x → got=%#x", i, pt[i], ct[i], got[i])
		}
	}
}
