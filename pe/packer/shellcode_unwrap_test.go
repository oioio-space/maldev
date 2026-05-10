package packer_test

import (
	"bytes"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// TestUnwrapShellcode_RoundtripPE — pack then unwrap recovers
// byte-perfect input.
func TestUnwrapShellcode_RoundtripPE(t *testing.T) {
	sc := bytes.Repeat([]byte{0x90}, 31)
	sc = append(sc, 0xc3)
	exe, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatWindowsExe,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	got, err := packer.UnwrapShellcode(exe)
	if err != nil {
		t.Fatalf("UnwrapShellcode: %v", err)
	}
	if !bytes.Equal(got, sc) {
		t.Errorf("roundtrip mismatch:\n  got:  %x\n  want: %x", got, sc)
	}
}

// TestUnwrapShellcode_RoundtripELF same for ELF.
func TestUnwrapShellcode_RoundtripELF(t *testing.T) {
	sc := bytes.Repeat([]byte{0x90}, 31)
	sc = append(sc, 0xc3)
	bin, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatLinuxELF,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	got, err := packer.UnwrapShellcode(bin)
	if err != nil {
		t.Fatalf("UnwrapShellcode: %v", err)
	}
	if !bytes.Equal(got, sc) {
		t.Errorf("roundtrip mismatch:\n  got:  %x\n  want: %x", got, sc)
	}
}

// TestUnwrapShellcode_RejectsEncrypted — encrypted PackShellcode
// outputs have ciphertext at entry, not the operator's bytes.
// UnwrapShellcode MUST refuse to silently return ciphertext.
func TestUnwrapShellcode_RejectsEncrypted(t *testing.T) {
	sc := bytes.Repeat([]byte{0x90}, 31)
	sc = append(sc, 0xc3)
	exe, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:  packer.FormatWindowsExe,
		Encrypt: true,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	_, err = packer.UnwrapShellcode(exe)
	if !errors.Is(err, packer.ErrNotMinimalWrap) {
		t.Errorf("UnwrapShellcode(encrypted) = %v, want ErrNotMinimalWrap", err)
	}
}

// TestUnwrapShellcode_RejectsBadFormat asserts ErrUnsupportedFormat
// for non-PE / non-ELF input.
func TestUnwrapShellcode_RejectsBadFormat(t *testing.T) {
	for _, input := range [][]byte{
		nil,
		{},
		[]byte("garbage"),
		bytes.Repeat([]byte{0xff}, 1024),
	} {
		_, err := packer.UnwrapShellcode(input)
		if !errors.Is(err, packer.ErrUnsupportedFormat) {
			t.Errorf("UnwrapShellcode(%dB) = %v, want ErrUnsupportedFormat", len(input), err)
		}
	}
}
