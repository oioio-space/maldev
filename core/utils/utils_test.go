package utils

import (
	"strings"
	"testing"
)

func TestRandomString(t *testing.T) {
	s, err := RandomString(32)
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
	s2, _ := RandomString(32)
	if s == s2 {
		t.Fatal("two random strings are identical")
	}
}

func TestRandomStringZeroLength(t *testing.T) {
	s, err := RandomString(0)
	if err != nil {
		t.Fatal(err)
	}
	if len(s) != 0 {
		t.Fatalf("len = %d, want 0", len(s))
	}
}

func TestRandomBytes(t *testing.T) {
	b, err := RandomBytes(64)
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

func TestRandomInt(t *testing.T) {
	for i := 0; i < 100; i++ {
		n, err := RandomInt(10, 20)
		if err != nil {
			t.Fatal(err)
		}
		if n < 10 || n >= 20 {
			t.Fatalf("RandomInt(10, 20) = %d, out of range", n)
		}
	}
}

func TestRandomDuration(t *testing.T) {
	for i := 0; i < 50; i++ {
		d, err := RandomDuration(100, 200)
		if err != nil {
			t.Fatal(err)
		}
		if d < 100 || d >= 200 {
			t.Fatalf("RandomDuration(100, 200) = %d, out of range", d)
		}
	}
}

func TestIsFileExist(t *testing.T) {
	// This test file itself should exist
	if !IsFileExist("utils_test.go") {
		t.Fatal("utils_test.go should exist")
	}
	if IsFileExist("nonexistent_file_12345.xyz") {
		t.Fatal("nonexistent file should not exist")
	}
}
