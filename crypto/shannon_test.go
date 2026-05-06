package crypto

import (
	"crypto/rand"
	"math"
	"strings"
	"testing"
)

func TestShannonEntropy_Empty(t *testing.T) {
	if got := ShannonEntropy(nil); got != 0 {
		t.Errorf("nil input: got %v, want 0", got)
	}
	if got := ShannonEntropy([]byte{}); got != 0 {
		t.Errorf("empty input: got %v, want 0", got)
	}
}

func TestShannonEntropy_Constant(t *testing.T) {
	data := make([]byte, 1024)
	for i := range data {
		data[i] = 0x42
	}
	if got := ShannonEntropy(data); got != 0 {
		t.Errorf("all-same input: got %v, want 0", got)
	}
}

func TestShannonEntropy_TwoSymbol(t *testing.T) {
	// Equal mix of two symbols → log2(2) = 1.0 exactly.
	data := make([]byte, 1024)
	for i := range data {
		if i&1 == 0 {
			data[i] = 0x00
		} else {
			data[i] = 0xFF
		}
	}
	got := ShannonEntropy(data)
	if math.Abs(got-1.0) > 1e-9 {
		t.Errorf("two-symbol equal mix: got %v, want 1.0", got)
	}
}

func TestShannonEntropy_UniformRandom(t *testing.T) {
	data := make([]byte, 256*1024)
	if _, err := rand.Read(data); err != nil {
		t.Fatalf("seed: %v", err)
	}
	got := ShannonEntropy(data)
	if got < 7.95 || got > 8.0 {
		t.Errorf("uniform random: got %v, want ≈8.0", got)
	}
}

func TestShannonEntropy_ASCIIText(t *testing.T) {
	// English prose lands in the 4-5 bits/byte band.
	prose := strings.Repeat("the quick brown fox jumps over the lazy dog. ", 200)
	got := ShannonEntropy([]byte(prose))
	if got < 3.5 || got > 5.0 {
		t.Errorf("repeated prose: got %v, want 3.5..5.0", got)
	}
}
