package transform_test

import (
	"bytes"
	"debug/elf"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestBuildMinimalELF64WithSections_RejectsEmpty pins the
// ErrMinimalELFWithSectionsCodeEmpty sentinel.
func TestBuildMinimalELF64WithSections_RejectsEmpty(t *testing.T) {
	for _, c := range [][]byte{nil, {}} {
		_, err := transform.BuildMinimalELF64WithSections(c)
		if !errors.Is(err, transform.ErrMinimalELFWithSectionsCodeEmpty) {
			t.Errorf("BuildMinimalELF64WithSections(%v) = %v, want sentinel", c, err)
		}
	}
}

// TestBuildMinimalELF64WithSections_DebugELFParses asserts the produced
// bytes round-trip through Go's stdlib `debug/elf` reader and that
// the `.text` section is findable — strong proxy for "PlanELF will
// accept this", which is the operational reason this writer exists.
func TestBuildMinimalELF64WithSections_DebugELFParses(t *testing.T) {
	// 64 bytes of NOPs + ret — non-empty, parseable.
	code := bytes.Repeat([]byte{0x90}, 63)
	code = append(code, 0xc3)

	out, err := transform.BuildMinimalELF64WithSections(code)
	if err != nil {
		t.Fatalf("BuildMinimalELF64WithSections: %v", err)
	}

	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf rejected the produced bytes: %v", err)
	}
	defer f.Close()

	if got := f.FileHeader.Class; got != elf.ELFCLASS64 {
		t.Errorf("Class = %v, want ELFCLASS64", got)
	}
	if got := f.FileHeader.Machine; got != elf.EM_X86_64 {
		t.Errorf("Machine = %v, want EM_X86_64", got)
	}
	if got := f.FileHeader.Type; got != elf.ET_EXEC {
		t.Errorf("Type = %v, want ET_EXEC", got)
	}
	textSec := f.Section(".text")
	if textSec == nil {
		t.Fatal(".text section not found in produced ELF")
	}
	if got := textSec.Size; got != uint64(len(code)) {
		t.Errorf(".text size = %d, want %d", got, len(code))
	}
	// Entry must be inside .text.
	entry := f.FileHeader.Entry
	if entry < textSec.Addr || entry >= textSec.Addr+textSec.Size {
		t.Errorf("e_entry %#x outside .text [%#x..%#x)",
			entry, textSec.Addr, textSec.Addr+textSec.Size)
	}
}

// TestBuildMinimalELF64WithSectionsAndVaddr_HonoursVaddr verifies the
// per-build vaddr override lands the PT_LOAD at the chosen address.
func TestBuildMinimalELF64WithSectionsAndVaddr_HonoursVaddr(t *testing.T) {
	const customVaddr uint64 = 0x600000
	code := []byte{0x90, 0x90, 0x90, 0xc3}
	out, err := transform.BuildMinimalELF64WithSectionsAndVaddr(code, customVaddr)
	if err != nil {
		t.Fatalf("BuildMinimalELF64WithSectionsAndVaddr: %v", err)
	}
	f, err := elf.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/elf: %v", err)
	}
	defer f.Close()
	textSec := f.Section(".text")
	if textSec == nil {
		t.Fatal(".text not found")
	}
	if textSec.Addr&^0xfff != customVaddr {
		t.Errorf(".text Addr %#x not on custom vaddr %#x page", textSec.Addr, customVaddr)
	}
}

// TestBuildMinimalELF64WithSectionsAndVaddr_RejectsBadVaddr pins the
// alignment + kernel-half guards.
func TestBuildMinimalELF64WithSectionsAndVaddr_RejectsBadVaddr(t *testing.T) {
	code := []byte{0x90, 0xc3}
	for _, v := range []uint64{
		0x400001,           // not page-aligned
		0x800000_00000000, // kernel half
	} {
		if _, err := transform.BuildMinimalELF64WithSectionsAndVaddr(code, v); err == nil {
			t.Errorf("accepted bad vaddr %#x", v)
		}
	}
}
