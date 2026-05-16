package transform_test

import (
	"encoding/binary"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

func TestBuildDirectRVAExportData_HeaderShape(t *testing.T) {
	const (
		entryRVA   uint32 = 0x4321
		sectionRVA uint32 = 0x9000
	)
	out, size, err := transform.BuildDirectRVAExportData("packed.dll", "RunWithArgs", entryRVA, sectionRVA)
	if err != nil {
		t.Fatalf("BuildDirectRVAExportData: %v", err)
	}
	if int(size) != len(out) {
		t.Fatalf("size %d != len(out) %d", size, len(out))
	}

	// Base / NumberOfFunctions / NumberOfNames = 1.
	if got := binary.LittleEndian.Uint32(out[16:]); got != 1 {
		t.Errorf("Base = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(out[20:]); got != 1 {
		t.Errorf("NumberOfFunctions = %d, want 1", got)
	}
	if got := binary.LittleEndian.Uint32(out[24:]); got != 1 {
		t.Errorf("NumberOfNames = %d, want 1", got)
	}

	// AddressOfFunctions / AddressOfNames / AddressOfNameOrdinals point into our section.
	afRVA := binary.LittleEndian.Uint32(out[28:])
	anRVA := binary.LittleEndian.Uint32(out[32:])
	aoRVA := binary.LittleEndian.Uint32(out[36:])
	if afRVA != sectionRVA+40 || anRVA != sectionRVA+44 || aoRVA != sectionRVA+48 {
		t.Errorf("table RVAs = %#x/%#x/%#x, want %#x/%#x/%#x",
			afRVA, anRVA, aoRVA, sectionRVA+40, sectionRVA+44, sectionRVA+48)
	}

	// AddressOfFunctions[0] is the code RVA (NOT a string RVA).
	if got := binary.LittleEndian.Uint32(out[40:]); got != entryRVA {
		t.Errorf("AddressOfFunctions[0] = %#x, want %#x", got, entryRVA)
	}
	// AddressOfNameOrdinals[0] = 0 (Base=1 → ordinal 1 maps to slot 0).
	if got := binary.LittleEndian.Uint16(out[48:]); got != 0 {
		t.Errorf("AddressOfNameOrdinals[0] = %d, want 0", got)
	}

	// Module-name RVA + export-name RVA point into the strings region.
	nameDirRVA := binary.LittleEndian.Uint32(out[12:])
	if nameDirRVA != sectionRVA+50 {
		t.Errorf("Name RVA = %#x, want %#x", nameDirRVA, sectionRVA+50)
	}
	if got := string(out[50 : 50+len("packed.dll")]); got != "packed.dll" {
		t.Errorf("module name string = %q, want %q", got, "packed.dll")
	}
	// Verify export name follows after the NUL terminator.
	exportNameOff := 50 + len("packed.dll") + 1
	if got := string(out[exportNameOff : exportNameOff+len("RunWithArgs")]); got != "RunWithArgs" {
		t.Errorf("export name string = %q, want %q", got, "RunWithArgs")
	}
	exportNameRVA := binary.LittleEndian.Uint32(out[44:])
	if exportNameRVA != sectionRVA+uint32(exportNameOff) {
		t.Errorf("AddressOfNames[0] = %#x, want %#x", exportNameRVA, sectionRVA+uint32(exportNameOff))
	}
}

func TestBuildDirectRVAExportData_RejectsEmpty(t *testing.T) {
	if _, _, err := transform.BuildDirectRVAExportData("", "RunWithArgs", 0x1000, 0x9000); err == nil {
		t.Error("expected error for empty moduleName")
	}
	if _, _, err := transform.BuildDirectRVAExportData("packed.dll", "", 0x1000, 0x9000); err == nil {
		t.Error("expected error for empty exportName")
	}
}
