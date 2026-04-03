package hash

import "testing"

func TestMD5(t *testing.T) {
	// Known MD5 of empty string
	got := MD5([]byte(""))
	want := "d41d8cd98f00b204e9800998ecf8427e"
	if got != want {
		t.Fatalf("MD5('') = %s, want %s", got, want)
	}
}

func TestMD5KnownValue(t *testing.T) {
	got := MD5([]byte("hello"))
	want := "5d41402abc4b2a76b9719d911017c592"
	if got != want {
		t.Fatalf("MD5('hello') = %s, want %s", got, want)
	}
}

func TestSHA1(t *testing.T) {
	got := SHA1([]byte("hello"))
	want := "aaf4c61ddcc5e8a2dabede0f3b482cd9aea9434d"
	if got != want {
		t.Fatalf("SHA1('hello') = %s, want %s", got, want)
	}
}

func TestSHA256(t *testing.T) {
	got := SHA256([]byte("hello"))
	want := "2cf24dba5fb0a30e26e83b2ac5b9e29e1b161e5c1fa7425e73043362938b9824"
	if got != want {
		t.Fatalf("SHA256('hello') = %s, want %s", got, want)
	}
}

func TestSHA512(t *testing.T) {
	got := SHA512([]byte("hello"))
	want := "9b71d224bd62f3785d96d46ad3ea3d73319bfbc2890caadae2dff72519673ca72323c3d99ba5c11d7c7acc6e14b8c5da0c4663475c2e5c3adef46f73bcdec043"
	if got != want {
		t.Fatalf("SHA512('hello') = %s, want %s", got, want)
	}
}

func TestROR13KnownValues(t *testing.T) {
	// Canonical shellcode ROR13 reference values (unsigned 32-bit).
	tests := []struct {
		name string
		want uint32
	}{
		{"LoadLibraryA", 0xEC0E4E8E},
		{"GetProcAddress", 0x7C0DFCAA},
	}
	for _, tt := range tests {
		got := ROR13(tt.name)
		if got != tt.want {
			t.Fatalf("ROR13(%q) = 0x%08X, want 0x%08X", tt.name, got, tt.want)
		}
	}
}

func TestROR13Consistency(t *testing.T) {
	// Same input should always give same output
	a := ROR13("LoadLibraryA")
	b := ROR13("LoadLibraryA")
	if a != b {
		t.Fatalf("ROR13 not consistent: %08X != %08X", a, b)
	}
	// Different input should give different output
	c := ROR13("GetProcAddress")
	if a == c {
		t.Fatal("different inputs gave same hash")
	}
}

func TestROR13Module(t *testing.T) {
	// ROR13Module appends a null terminator, so it should differ from plain ROR13
	name := "KERNEL32.DLL"
	if ROR13(name) == ROR13Module(name) {
		t.Fatal("ROR13Module should differ from ROR13 (null terminator)")
	}
}

func TestROR13NonEmpty(t *testing.T) {
	h := ROR13("ntdll.dll")
	if h == 0 {
		t.Fatal("ROR13 of non-empty string should not be zero")
	}
}

func TestROR13CaseSensitive(t *testing.T) {
	// Canonical shellcode ROR13 is case-sensitive
	a := ROR13("kernel32.dll")
	b := ROR13("KERNEL32.DLL")
	if a == b {
		t.Fatal("ROR13 should be case-sensitive")
	}
}
