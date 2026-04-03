package encode

import (
	"testing"
)

func TestBase64Roundtrip(t *testing.T) {
	data := []byte("hello world 1234!@#$")
	encoded := Base64Encode(data)
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("got %q, want %q", decoded, data)
	}
}

func TestBase64URLEncode(t *testing.T) {
	// Data that would produce +/= in standard base64
	data := []byte{0xfb, 0xff, 0xfe}
	encoded := Base64URLEncode(data)
	if encoded == "" {
		t.Fatal("expected non-empty result")
	}
	// URL-safe base64 should not contain + or /
	for _, c := range encoded {
		if c == '+' || c == '/' {
			t.Fatalf("URL-safe base64 contains invalid char: %c", c)
		}
	}
}

func TestBase64URLRoundtrip(t *testing.T) {
	data := []byte{0xfb, 0xff, 0xfe, 0x00, 0x01, 0x80}
	encoded := Base64URLEncode(data)
	decoded, err := Base64URLDecode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	if string(decoded) != string(data) {
		t.Fatalf("Base64URL round-trip failed: got %v, want %v", decoded, data)
	}
}

func TestToUTF16LE(t *testing.T) {
	b := ToUTF16LE("AB")
	// A=0x41, B=0x42 in UTF-16LE: 41 00 42 00
	if len(b) != 4 {
		t.Fatalf("len = %d, want 4", len(b))
	}
	if b[0] != 0x41 || b[1] != 0x00 || b[2] != 0x42 || b[3] != 0x00 {
		t.Fatalf("got %v, want [0x41 0x00 0x42 0x00]", b)
	}
}

func TestToUTF16LEEmpty(t *testing.T) {
	b := ToUTF16LE("")
	if len(b) != 0 {
		t.Fatalf("len = %d, want 0", len(b))
	}
}

func TestEncodePowerShell(t *testing.T) {
	result := EncodePowerShell("Get-Process")
	if result == "" {
		t.Fatal("expected non-empty result")
	}
	// Verify it's valid base64
	_, err := Base64Decode(result)
	if err != nil {
		t.Fatalf("result is not valid base64: %v", err)
	}
}

func TestEncodePowerShellRoundtrip(t *testing.T) {
	script := "Write-Host 'Hello'"
	encoded := EncodePowerShell(script)
	decoded, err := Base64Decode(encoded)
	if err != nil {
		t.Fatal(err)
	}
	// decoded should be UTF-16LE of script
	expected := ToUTF16LE(script)
	if string(decoded) != string(expected) {
		t.Fatalf("decoded PowerShell encoding does not match UTF-16LE of original script")
	}
}

func TestROT13(t *testing.T) {
	tests := []struct{ input, want string }{
		{"hello", "uryyb"},
		{"HELLO", "URYYB"},
		{"Hello World!", "Uryyb Jbeyq!"},
		{"", ""},
		{"123", "123"},
	}
	for _, tt := range tests {
		got := ROT13(tt.input)
		if got != tt.want {
			t.Errorf("ROT13(%q) = %q, want %q", tt.input, got, tt.want)
		}
	}
	// ROT13 is its own inverse
	for _, tt := range tests {
		got := ROT13(ROT13(tt.input))
		if got != tt.input {
			t.Errorf("ROT13(ROT13(%q)) = %q, want %q", tt.input, got, tt.input)
		}
	}
}
