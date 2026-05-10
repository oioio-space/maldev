package packer_test

import (
	"bytes"
	"debug/elf"
	"debug/pe"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer"
)

// trivialShellcode is 32 bytes of NOP+ret — minimum viable position-
// independent code for the wrapper structural tests.
func trivialShellcode() []byte {
	sc := bytes.Repeat([]byte{0x90}, 31)
	return append(sc, 0xc3)
}

// TestPackShellcode_RejectsEmpty pins the ErrShellcodeEmpty sentinel.
func TestPackShellcode_RejectsEmpty(t *testing.T) {
	for _, c := range [][]byte{nil, {}} {
		_, _, err := packer.PackShellcode(c, packer.PackShellcodeOptions{
			Format: packer.FormatWindowsExe,
		})
		if !errors.Is(err, packer.ErrShellcodeEmpty) {
			t.Errorf("PackShellcode(%v) = %v, want ErrShellcodeEmpty", c, err)
		}
	}
}

// TestPackShellcode_RejectsBadFormat asserts FormatUnknown is rejected
// — operators MUST pick a target OS.
func TestPackShellcode_RejectsBadFormat(t *testing.T) {
	if _, _, err := packer.PackShellcode(trivialShellcode(),
		packer.PackShellcodeOptions{Format: packer.FormatUnknown}); err == nil {
		t.Error("PackShellcode accepted FormatUnknown")
	}
}

// TestPackShellcode_PlainPE asserts the no-encrypt PE path produces
// debug/pe-parseable bytes with the shellcode at the entry point.
func TestPackShellcode_PlainPE(t *testing.T) {
	sc := trivialShellcode()
	out, key, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatWindowsExe,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	if key != nil {
		t.Errorf("plain wrap returned key %x — should be nil", key)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want AMD64", f.FileHeader.Machine)
	}
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	if oh.AddressOfEntryPoint == 0 {
		t.Error("entry point = 0 (writer didn't set it)")
	}
}

// TestPackShellcode_PlainELF asserts the no-encrypt ELF path produces
// debug/elf-parseable bytes with .text bearing the shellcode.
func TestPackShellcode_PlainELF(t *testing.T) {
	sc := trivialShellcode()
	out, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format: packer.FormatLinuxELF,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()
	textSec := f.Section(".text")
	if textSec == nil {
		t.Fatal(".text not found in plain ELF")
	}
	if got := textSec.Size; got != uint64(len(sc)) {
		t.Errorf(".text size = %d, want %d", got, len(sc))
	}
}

// TestPackShellcode_EncryptedPE asserts the encrypted PE path produces
// a debug/pe-parseable AMD64 binary with a polymorphic stub envelope.
// The shellcode itself becomes ciphertext — only the entry point and
// stub layout are observable from the outside.
func TestPackShellcode_EncryptedPE(t *testing.T) {
	sc := trivialShellcode()
	out, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:  packer.FormatWindowsExe,
		Encrypt: true,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want AMD64", f.FileHeader.Machine)
	}
	if got := len(f.Sections); got < 2 {
		t.Errorf("encrypted PE has %d sections — expected ≥ 2 (.text + stub)", got)
	}
	// Plain PE is 1024 bytes; encrypted output should be substantially
	// larger because the stub adds a section.
	if len(out) <= 1024 {
		t.Errorf("encrypted output %d bytes <= plain wrap (1024) — stub may not have been added", len(out))
	}
}

// TestPackShellcode_EncryptedELF asserts the encrypted ELF path
// completes — the section-aware ELF writer + InjectStubELF chain.
func TestPackShellcode_EncryptedELF(t *testing.T) {
	sc := trivialShellcode()
	out, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:  packer.FormatLinuxELF,
		Encrypt: true,
	})
	if err != nil {
		t.Fatalf("PackShellcode: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()
	if got := f.FileHeader.Type; got != elf.ET_EXEC {
		t.Errorf("Type = %v, want ET_EXEC", got)
	}
	// Encrypted output should have an extra PT_LOAD for the stub.
	var ptLoadCount int
	for _, p := range f.Progs {
		if p.Type == elf.PT_LOAD {
			ptLoadCount++
		}
	}
	if ptLoadCount < 2 {
		t.Errorf("encrypted ELF has %d PT_LOAD segments — expected ≥ 2 (.text + stub)", ptLoadCount)
	}
}

// TestPackShellcode_CustomImageBase verifies the per-build ImageBase /
// vaddr override flows through to both PE and ELF paths.
func TestPackShellcode_CustomImageBase(t *testing.T) {
	sc := trivialShellcode()

	// PE: pick a 64K-aligned non-canonical base.
	const peBase = 0x180000000
	out, _, err := packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:    packer.FormatWindowsExe,
		ImageBase: peBase,
	})
	if err != nil {
		t.Fatalf("PE PackShellcode: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	if got := f.OptionalHeader.(*pe.OptionalHeader64).ImageBase; got != peBase {
		t.Errorf("PE ImageBase = %#x, want %#x", got, peBase)
	}
	f.Close()

	// ELF: pick a page-aligned non-canonical vaddr.
	const elfVaddr uint64 = 0x600000
	out, _, err = packer.PackShellcode(sc, packer.PackShellcodeOptions{
		Format:    packer.FormatLinuxELF,
		ImageBase: elfVaddr,
	})
	if err != nil {
		t.Fatalf("ELF PackShellcode: %v", err)
	}
	ef, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer ef.Close()
	textSec := ef.Section(".text")
	if textSec == nil {
		t.Fatal(".text not found")
	}
	if textSec.Addr&^0xfff != elfVaddr {
		t.Errorf("ELF .text on vaddr %#x page, want %#x", textSec.Addr&^0xfff, elfVaddr)
	}
}
