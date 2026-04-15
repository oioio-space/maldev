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
