package transform_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// peExit42StubBytes is a placeholder x86-64 byte sequence — NOT
// runnable Windows code (no syscall path). Just enough to give the
// PE writer a non-empty .text region for structural tests. The
// actual exit-via-PEB-walk implementation lands with the §2 plan
// item (see docs/superpowers/plans/2026-05-09-windows-tiny-exe.md).
var peExit42StubBytes = []byte{
	0xc3, // ret — stand-in until the PEB walk + ExitProcess stub ships
	0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, 0x90, // pad to 9 bytes
}

// TestBuildMinimalPE32Plus_RejectsEmpty pins the
// [transform.ErrMinimalPECodeEmpty] sentinel.
func TestBuildMinimalPE32Plus_RejectsEmpty(t *testing.T) {
	for _, c := range [][]byte{nil, {}} {
		_, err := transform.BuildMinimalPE32Plus(c)
		if !errors.Is(err, transform.ErrMinimalPECodeEmpty) {
			t.Errorf("BuildMinimalPE32Plus(%v) = %v, want ErrMinimalPECodeEmpty", c, err)
		}
	}
}

// TestBuildMinimalPE32Plus_DebugPEParses asserts the produced bytes
// round-trip through Go's stdlib `debug/pe` reader — strong proxy
// for "the Windows loader will at least parse this", which is the
// minimum bar before runtime testing on a Windows VM.
func TestBuildMinimalPE32Plus_DebugPEParses(t *testing.T) {
	out, err := transform.BuildMinimalPE32Plus(peExit42StubBytes)
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	if got := len(out); got < transform.MinimalPE32PlusHeadersSize {
		t.Fatalf("len(out) = %d, want >= %d", got, transform.MinimalPE32PlusHeadersSize)
	}

	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe rejected the produced bytes: %v", err)
	}
	defer f.Close()

	if f.FileHeader.Machine != pe.IMAGE_FILE_MACHINE_AMD64 {
		t.Errorf("Machine = %#x, want %#x (AMD64)",
			f.FileHeader.Machine, pe.IMAGE_FILE_MACHINE_AMD64)
	}
	if f.FileHeader.NumberOfSections != 1 {
		t.Errorf("NumberOfSections = %d, want 1", f.FileHeader.NumberOfSections)
	}
	if got := len(f.Sections); got != 1 {
		t.Fatalf("len(Sections) = %d, want 1", got)
	}
	sec := f.Sections[0]
	if sec.Name != ".text" {
		t.Errorf("Section name = %q, want %q", sec.Name, ".text")
	}
	// CNT_CODE | MEM_EXECUTE | MEM_READ | MEM_WRITE = 0xe0000020
	if got := sec.Characteristics; got != 0xe0000020 {
		t.Errorf("Section Characteristics = %#x, want 0xe0000020 (RWX code)", got)
	}

	// Optional header is PE32+ (Magic 0x20b).
	oh, ok := f.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("OptionalHeader not *pe.OptionalHeader64 (got %T)", f.OptionalHeader)
	}
	if oh.Magic != 0x20b {
		t.Errorf("Optional header Magic = %#x, want 0x20b (PE32+)", oh.Magic)
	}
	if oh.ImageBase != transform.MinimalPE32PlusImageBase {
		t.Errorf("ImageBase = %#x, want %#x",
			oh.ImageBase, transform.MinimalPE32PlusImageBase)
	}
	if oh.AddressOfEntryPoint == 0 {
		t.Error("AddressOfEntryPoint = 0 — entry should be inside .text")
	}
}

// TestBuildMinimalPE32PlusWithBase_HonoursBase verifies the per-build
// imageBase override lands at the chosen address (not canonical
// 0x140000000). Defenders matching "single-section-RWX PE at
// ImageBase 0x140000000" miss every operator using a non-canonical
// imageBase.
func TestBuildMinimalPE32PlusWithBase_HonoursBase(t *testing.T) {
	const customBase uint64 = 0x180000000
	out, err := transform.BuildMinimalPE32PlusWithBase(peExit42StubBytes, customBase)
	if err != nil {
		t.Fatalf("BuildMinimalPE32PlusWithBase: %v", err)
	}
	f, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe: %v", err)
	}
	defer f.Close()
	oh := f.OptionalHeader.(*pe.OptionalHeader64)
	if oh.ImageBase != customBase {
		t.Errorf("ImageBase = %#x, want %#x", oh.ImageBase, customBase)
	}
}

// TestBuildMinimalPE32PlusWithBase_RejectsBadBase pins the input
// validation: imageBase MUST be 64 KiB-aligned and below the kernel
// half (0xffff800000000000).
func TestBuildMinimalPE32PlusWithBase_RejectsBadBase(t *testing.T) {
	cases := []struct {
		name string
		base uint64
	}{
		{"unaligned", 0x140000123},
		{"kernelHalf", 0xffff800000000000},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			_, err := transform.BuildMinimalPE32PlusWithBase(peExit42StubBytes, c.base)
			if err == nil {
				t.Errorf("imageBase %#x: want error, got nil", c.base)
			}
		})
	}
}
