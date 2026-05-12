package packer_test

import (
	"bytes"
	"debug/pe"
	"errors"
	"testing"

	packerpkg "github.com/oioio-space/maldev/pe/packer"
	"github.com/oioio-space/maldev/pe/packer/stubgen"
	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/testutil"
)

// TestPackBinary_FormatWindowsDLL_HappyPath — pack a synthetic DLL
// through the operator-facing PackBinary entry point with
// Format=FormatWindowsDLL. Validates the slice-4 dispatch:
// PackBinary → stubgen.Generate (detects IsDLL) → PlanDLL +
// EmitDLLStub + PatchDLLStubDisplacements + InjectStubDLL.
//
// Assertions: PackBinary succeeds, output parses as PE32+,
// IMAGE_FILE_DLL preserved, .mldrel section present,
// BASERELOC DataDirectory points at .mldrel.
func TestPackBinary_FormatWindowsDLL_HappyPath(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 0x100)

	out, key, err := packerpkg.PackBinary(dll, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsDLL,
		Stage1Rounds: 3,
		Seed:         42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if len(key) == 0 {
		t.Error("PackBinary returned empty key")
	}

	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile: %v", err)
	}
	defer pf.Close()

	if pf.FileHeader.Characteristics&transform.ImageFileDLL == 0 {
		t.Error("output lost IMAGE_FILE_DLL")
	}

	var mldrel *pe.Section
	for _, s := range pf.Sections {
		if s.Name == ".mldrel" {
			mldrel = s
		}
	}
	if mldrel == nil {
		t.Fatal(".mldrel section missing — InjectStubDLL didn't run")
	}

	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("OptionalHeader type %T, want *pe.OptionalHeader64", pf.OptionalHeader)
	}
	relocDir := oh.DataDirectory[transform.DirBaseReloc]
	if relocDir.VirtualAddress != mldrel.VirtualAddress {
		t.Errorf("BASERELOC dir VA = %#x, want %#x (.mldrel start)",
			relocDir.VirtualAddress, mldrel.VirtualAddress)
	}
}

// TestPackBinary_FormatWindowsDLL_RejectsEXEInput — feeding an EXE
// through the DLL format must fail at the IsDLL cross-check.
func TestPackBinary_FormatWindowsDLL_RejectsEXEInput(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	_, _, err = packerpkg.PackBinary(exe, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsDLL,
		Stage1Rounds: 3,
		Seed:         1,
	})
	if !errors.Is(err, packerpkg.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// TestPackBinary_FormatWindowsExe_RejectsDLLInput — mirror of
// the above. Feeding a DLL through FormatWindowsExe must fail at
// the IsDLL cross-check, not silently route through PlanPE.
func TestPackBinary_FormatWindowsExe_RejectsDLLInput(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 0x100)
	_, _, err := packerpkg.PackBinary(dll, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsExe,
		Stage1Rounds: 3,
		Seed:         1,
	})
	if !errors.Is(err, packerpkg.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// TestPackBinary_FormatWindowsDLL_RejectsCompress — slice-4
// limitation: the DllMain stub doesn't support LZ4 inflate yet.
// Must surface stubgen.ErrCompressDLLUnsupported, not a string error.
func TestPackBinary_FormatWindowsDLL_RejectsCompress(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 0x100)
	_, _, err := packerpkg.PackBinary(dll, packerpkg.PackBinaryOptions{
		Format:       packerpkg.FormatWindowsDLL,
		Stage1Rounds: 3,
		Seed:         1,
		Compress:     true,
	})
	if !errors.Is(err, stubgen.ErrCompressDLLUnsupported) {
		t.Errorf("got %v, want ErrCompressDLLUnsupported", err)
	}
}

// TestPackBinary_ConvertEXEtoDLL_HappyPath — slice 5.5 wired the
// full EXE→DLL pipeline end-to-end. Packing a minimal EXE with
// ConvertEXEtoDLL=true must produce a parseable PE that carries
// IMAGE_FILE_DLL and routes its entry point to the slice-5.3
// converted-DLL stub.
func TestPackBinary_ConvertEXEtoDLL_HappyPath(t *testing.T) {
	// Build a non-trivial EXE so the SGN-encode loop has bytes to
	// chew — a single RET would fall below the 0x100 .text size
	// the minimal PE template emits anyway, but explicit RET-fill
	// keeps the fixture intent obvious.
	body := make([]byte, 0x100)
	for i := range body {
		body[i] = 0xC3 // RET
	}
	exe, err := transform.BuildMinimalPE32Plus(body)
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	out, key, err := packerpkg.PackBinary(exe, packerpkg.PackBinaryOptions{
		Format:          packerpkg.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
		Seed:            42,
	})
	if err != nil {
		t.Fatalf("PackBinary: %v", err)
	}
	if len(key) == 0 {
		t.Error("PackBinary returned empty key")
	}

	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile: %v", err)
	}
	defer pf.Close()

	if pf.FileHeader.Characteristics&transform.ImageFileDLL == 0 {
		t.Error("output missing IMAGE_FILE_DLL — slice 5.4's flip didn't run")
	}
	// Entry point should land inside the appended stub section
	// (not the original EXE's OEP — that's reached via CreateThread
	// at runtime).
	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("OptionalHeader type %T, want *pe.OptionalHeader64", pf.OptionalHeader)
	}
	// The stub section is the last one InjectStubPE appended.
	last := pf.Sections[len(pf.Sections)-1]
	if oh.AddressOfEntryPoint < last.VirtualAddress ||
		oh.AddressOfEntryPoint >= last.VirtualAddress+last.VirtualSize {
		t.Errorf("AddressOfEntryPoint = %#x outside stub section [%#x..%#x)",
			oh.AddressOfEntryPoint, last.VirtualAddress, last.VirtualAddress+last.VirtualSize)
	}
}

// TestPackBinary_ConvertEXEtoDLL_RejectsCompress — slice 5.7 partial:
// the converted-DLL LZ4 inflate path is emitted by
// EmitConvertedDLLStub but runtime VM E2E currently wedges the host
// inside the inflate block; the gate stays in place until that's
// bisected. Pack-time still surfaces ErrConvertEXEtoDLLUnsupported.
func TestPackBinary_ConvertEXEtoDLL_RejectsCompress(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	_, _, err = packerpkg.PackBinary(exe, packerpkg.PackBinaryOptions{
		Format:          packerpkg.FormatWindowsExe,
		ConvertEXEtoDLL: true,
		Compress:        true,
		Stage1Rounds:    3,
	})
	if !errors.Is(err, stubgen.ErrConvertEXEtoDLLUnsupported) {
		t.Errorf("got %v, want stubgen.ErrConvertEXEtoDLLUnsupported", err)
	}
}

// TestPackBinary_ConvertEXEtoDLL_RejectsDLLInput — slice 5.1
// cross-check: ConvertEXEtoDLL requires an EXE input. Feeding a
// DLL must fail at the admission stage with ErrUnsupportedFormat
// before the "not implemented yet" sentinel fires.
func TestPackBinary_ConvertEXEtoDLL_RejectsDLLInput(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 0x100)
	_, _, err := packerpkg.PackBinary(dll, packerpkg.PackBinaryOptions{
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
	})
	if !errors.Is(err, packerpkg.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// TestPackBinary_ConvertEXEtoDLL_RejectsNonPE — ELF / garbage
// inputs must also fail at admission with ErrUnsupportedFormat.
func TestPackBinary_ConvertEXEtoDLL_RejectsNonPE(t *testing.T) {
	elfMagic := []byte{0x7F, 'E', 'L', 'F', 0, 0, 0, 0}
	_, _, err := packerpkg.PackBinary(elfMagic, packerpkg.PackBinaryOptions{
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
	})
	if !errors.Is(err, packerpkg.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// TestPackBinary_ConvertEXEtoDLL_RejectsFormatWindowsDLL — the
// two opts are mutually exclusive: FormatWindowsDLL assumes a
// native DLL input, ConvertEXEtoDLL transforms an EXE input.
// Asking for both is a programming error.
func TestPackBinary_ConvertEXEtoDLL_RejectsFormatWindowsDLL(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	_, _, err = packerpkg.PackBinary(exe, packerpkg.PackBinaryOptions{
		Format:          packerpkg.FormatWindowsDLL,
		ConvertEXEtoDLL: true,
		Stage1Rounds:    3,
	})
	if !errors.Is(err, packerpkg.ErrUnsupportedFormat) {
		t.Errorf("got %v, want ErrUnsupportedFormat", err)
	}
}

// TestIsDLL_DetectsBitCorrectly — package-level guard for the
// dispatcher's IsDLL pre-flight.
func TestIsDLL_DetectsBitCorrectly(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 0x100)
	if !transform.IsDLL(dll) {
		t.Error("IsDLL(dll) = false; want true")
	}
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	if transform.IsDLL(exe) {
		t.Error("IsDLL(exe) = true; want false")
	}
	if transform.IsDLL([]byte{0x7F, 'E', 'L', 'F'}) {
		t.Error("IsDLL(elf) = true; want false")
	}
	if transform.IsDLL(nil) {
		t.Error("IsDLL(nil) = true; want false")
	}
}
