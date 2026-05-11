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
