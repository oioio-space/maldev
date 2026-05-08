package random

import (
	"strings"
	"testing"
)

func TestString(t *testing.T) {
	s, err := String(32)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 32 {
		t.Fatalf("len = %d, want 32", len(s))
	}
	// Should be alphanumeric only
	for _, c := range s {
		if !strings.ContainsRune("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789", c) {
			t.Fatalf("unexpected character: %c", c)
		}
	}
	// Two random strings should differ
	s2, _ := String(32)
	if s == s2 {
		t.Fatal("two random strings are identical")
	}
}

func TestStringZeroLength(t *testing.T) {
	s, err := String(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 {
		t.Fatalf("len = %d, want 0", len(s))
	}
}

func TestBytes(t *testing.T) {
	b, err := Bytes(64)
	if err != nil {
		t.Fatal(err)
	}
	if len(b) != 64 {
		t.Fatalf("len = %d, want 64", len(b))
	}
	// Check not all zeros
	allZero := true
	for _, v := range b {
		if v != 0 {
			allZero = false
			break
		}
	}
	if allZero {
		t.Fatal("all bytes are zero")
	}
}

func TestInt(t *testing.T) {
	for i := 0; i < 100; i++ {
		n, err := Int(10, 20)
		if err != nil {
			t.Fatal(err)
		}
		if n < 10 || n >= 20 {
			t.Fatalf("Int(10, 20) = %d, out of range", n)
		}
	}
}

func TestDuration(t *testing.T) {
	for i := 0; i < 50; i++ {
		d, err := Duration(100, 200)
		if err != nil {
			t.Fatal(err)
		}
		if d < 100 || d >= 200 {
			t.Fatalf("Duration(100, 200) = %d, out of range", d)
		}
	}
}

func TestInt64(t *testing.T) {
	// Two consecutive calls should differ with overwhelming
	// probability (2^-64 collision, treat collision as failure).
	a, err := Int64()
	if err != nil {
		t.Fatal(err)
	}
	b, err := Int64()
	if err != nil {
		t.Fatal(err)
	}
	if a == b {
		t.Errorf("two consecutive Int64() calls returned %d twice — RNG broken or astronomically unlucky", a)
	}
	// Distribution sanity: across 100 samples, at least one
	// should be negative and one positive (full int64 range).
	var sawNeg, sawPos bool
	for i := 0; i < 100; i++ {
		v, err := Int64()
		if err != nil {
			t.Fatal(err)
		}
		if v < 0 {
			sawNeg = true
		}
		if v >= 0 {
			sawPos = true
		}
	}
	if !sawNeg || !sawPos {
		t.Errorf("Int64 distribution skewed: sawNeg=%v sawPos=%v across 100 samples", sawNeg, sawPos)
	}
}
