package transform_test

import (
	"bytes"
	"debug/pe"
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestInjectConvertedDLL_HappyPath — round-trip a synthetic EXE
// through InjectConvertedDLL and verify the output is a valid PE
// that debug/pe parses, with IMAGE_FILE_DLL flipped on and the
// stub section appended. The stub bytes themselves are dummy 0xCC
// fillers — slice 5.4 only validates the byte-level transform
// (slice 5.5 wires the slice-5.3 stub through stubgen.Generate).
func TestInjectConvertedDLL_HappyPath(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3}) // RET
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}

	encrypted := make([]byte, plan.TextSize)
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))

	out, err := transform.InjectConvertedDLL(exe, encrypted, stub, plan)
	if err != nil {
		t.Fatalf("InjectConvertedDLL: %v", err)
	}

	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile: %v", err)
	}
	defer pf.Close()

	if pf.FileHeader.Characteristics&transform.ImageFileDLL == 0 {
		t.Error("output missing IMAGE_FILE_DLL — the flip didn't happen")
	}
	// EXE-derived DLLs keep IMAGE_FILE_EXECUTABLE_IMAGE (0x0002).
	// Confirms the flip is OR-only, not replace.
	if pf.FileHeader.Characteristics&0x0002 == 0 {
		t.Error("output lost IMAGE_FILE_EXECUTABLE_IMAGE — flip clobbered other flags")
	}

	// AddressOfEntryPoint must point at the stub RVA (loader will
	// call our stub as DllMain on every reason).
	oh, ok := pf.OptionalHeader.(*pe.OptionalHeader64)
	if !ok {
		t.Fatalf("OptionalHeader type %T, want *pe.OptionalHeader64", pf.OptionalHeader)
	}
	if oh.AddressOfEntryPoint != plan.StubRVA {
		t.Errorf("AddressOfEntryPoint = %#x, want stub RVA %#x", oh.AddressOfEntryPoint, plan.StubRVA)
	}
}

// TestInjectConvertedDLL_RejectsNonConvertedPlan — a plan with
// IsConvertedDLL=false must be refused with ErrPlanNotConverted.
// Catches the slice-2 / slice-5.3 / slice-5.4 dispatch mistake of
// routing the wrong plan through the wrong injector.
func TestInjectConvertedDLL_RejectsNonConvertedPlan(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	// Plain PlanPE — no IsConvertedDLL flag.
	plan, err := transform.PlanPE(exe, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))
	_, err = transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if !errors.Is(err, transform.ErrPlanNotConverted) {
		t.Errorf("got %v, want ErrPlanNotConverted", err)
	}
}

// TestInjectConvertedDLL_RejectsNativeDLLStub — a slice-2 stub
// carrying the DLLStubSentinel (8-byte orig_dllmain slot) must
// NOT be routed here: its slot patcher only fires inside
// InjectStubDLL. Silently accepting it would produce a binary
// that jumps to an unpatched VA on PROCESS_ATTACH.
func TestInjectConvertedDLL_RejectsNativeDLLStub(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	// Build a stub buffer that ends with the slice-2 sentinel
	// (mimicking EmitDLLStub's trailing data layout).
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize)-8)
	stub = append(stub, transform.DLLStubSentinelBytes...)

	_, err = transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if !errors.Is(err, transform.ErrConvertedStubLeak) {
		t.Errorf("got %v, want ErrConvertedStubLeak", err)
	}
}

// TestInjectConvertedDLL_RejectsELFPlan — defensive: a hand-rolled
// Plan with IsConvertedDLL=true but Format=FormatELF must fail at
// the Format check, not via a misleading "delegated EXE inject"
// error from the InjectStubPE downstream.
func TestInjectConvertedDLL_RejectsELFPlan(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	plan.Format = transform.FormatELF
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))
	_, err = transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if !errors.Is(err, transform.ErrPlanFormatMismatch) {
		t.Errorf("got %v, want ErrPlanFormatMismatch", err)
	}
}

// TestInjectConvertedDLL_StubSectionIsWritable — slice 5.5.x fix:
// the appended stub section must carry IMAGE_SCN_MEM_WRITE.
// InjectStubPE creates it CODE|EXEC|READ (right for EXE stubs);
// the converted-DLL stub latches a decrypted_flag byte INSIDE the
// section on PROCESS_ATTACH and would page-fault under the loader
// if the section weren't writable. Discovered at the slice 5.5.x
// LoadLibrary E2E (AV at the flag-latch MOVB).
func TestInjectConvertedDLL_StubSectionIsWritable(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))
	out, err := transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if err != nil {
		t.Fatalf("InjectConvertedDLL: %v", err)
	}

	pf, err := pe.NewFile(bytes.NewReader(out))
	if err != nil {
		t.Fatalf("debug/pe.NewFile: %v", err)
	}
	defer pf.Close()
	stubSec := pf.Sections[len(pf.Sections)-1]
	if stubSec.Characteristics&transform.ScnMemWrite == 0 {
		t.Errorf("stub section Characteristics %#x lacks MEM_WRITE — loader would AV on the flag latch",
			stubSec.Characteristics)
	}
	// EXEC must still be set — the stub is asm code, not data.
	if stubSec.Characteristics&transform.ScnMemExec == 0 {
		t.Errorf("stub section lost MEM_EXECUTE: %#x", stubSec.Characteristics)
	}
}

// TestInjectConvertedDLL_ClearsDynamicBase — slice 5.5.x fix: the
// converted output must NOT carry DYNAMIC_BASE / HIGH_ENTROPY_VA
// in DllCharacteristics. Modern Windows refuses to load a DLL
// that advertises ASLR but has no BASERELOC entries — the loader
// would relocate it without fixup data and crash on the first
// absolute reference. Cleared bits force the loader to use the
// preferred ImageBase. Discovered at the v0.119.0 LoadLibrary
// E2E (kernel32!LoadLibrary AV).
func TestInjectConvertedDLL_ClearsDynamicBase(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	// BuildMinimalPE32Plus sets DllCharacteristics = 0x8160 (HIGH_ENTROPY_VA |
	// DYNAMIC_BASE | NX_COMPAT | TERMINAL_SERVER_AWARE). Pre-flip
	// assertion guards against the fixture changing under us.
	peOff := binary.LittleEndian.Uint32(exe[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	optOff := coffOff + transform.PECOFFHdrSize
	const dllCharOff = 0x46
	preDllChars := binary.LittleEndian.Uint16(exe[optOff+dllCharOff:])
	if preDllChars&0x0040 == 0 {
		t.Skipf("fixture doesn't set DYNAMIC_BASE — nothing to clear (pre=%#x)", preDllChars)
	}

	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))
	out, err := transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if err != nil {
		t.Fatalf("InjectConvertedDLL: %v", err)
	}

	postPeOff := binary.LittleEndian.Uint32(out[transform.PEELfanewOffset:])
	postOptOff := postPeOff + transform.PESignatureSize + transform.PECOFFHdrSize
	postDllChars := binary.LittleEndian.Uint16(out[postOptOff+dllCharOff:])
	if postDllChars&0x0040 != 0 {
		t.Errorf("DYNAMIC_BASE still set in DllCharacteristics %#x — loader would crash on missing relocs", postDllChars)
	}
	if postDllChars&0x0020 != 0 {
		t.Errorf("HIGH_ENTROPY_VA still set in DllCharacteristics %#x", postDllChars)
	}
	// NX_COMPAT (0x100) and other non-ASLR bits must survive.
	if preDllChars&0x0100 != 0 && postDllChars&0x0100 == 0 {
		t.Error("NX_COMPAT was cleared — only ASLR-related bits should drop")
	}
}

// TestClearDllCharacteristics_HappyPath — the helper must AND
// out only the requested bits, preserve the rest.
func TestClearDllCharacteristics_HappyPath(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	peOff := binary.LittleEndian.Uint32(exe[transform.PEELfanewOffset:])
	optOff := peOff + transform.PESignatureSize + transform.PECOFFHdrSize
	const dllCharOff = 0x46
	pre := binary.LittleEndian.Uint16(exe[optOff+dllCharOff:])

	if err := transform.ClearDllCharacteristics(exe, 0x0040); err != nil {
		t.Fatalf("ClearDllCharacteristics: %v", err)
	}
	post := binary.LittleEndian.Uint16(exe[optOff+dllCharOff:])
	if post != pre&^0x0040 {
		t.Errorf("DllCharacteristics post = %#x, want %#x (pre %#x &^ 0x40)", post, pre&^0x0040, pre)
	}
}

// TestSetIMAGEFILEDLL_RejectsShortBuffer — SetIMAGEFILEDLL must
// surface a bounded-buffer error instead of panicking with an
// index out of range. Tests only buffers that fail the function's
// explicit bounds checks; validation of "is this a real PE" is
// deliberately out of scope (callers always supply well-formed
// PE bytes from BuildMinimalPE32Plus or InjectStubPE output).
func TestSetIMAGEFILEDLL_RejectsShortBuffer(t *testing.T) {
	for _, buf := range [][]byte{
		nil,
		{0x4D, 0x5A}, // MZ only, missing e_lfanew
	} {
		err := transform.SetIMAGEFILEDLL(buf)
		if err == nil {
			t.Errorf("SetIMAGEFILEDLL(%d-byte buf) = nil; want error", len(buf))
		}
	}
}

// TestInjectConvertedDLL_PreservesInputCharacteristics — flipping
// the DLL bit must OR onto the existing Characteristics, not
// replace them. The minimal PE carries 0x0022 (EXECUTABLE +
// LARGE_ADDRESS_AWARE); after the flip it should be 0x2022 (those
// two + IMAGE_FILE_DLL=0x2000).
func TestInjectConvertedDLL_PreservesInputCharacteristics(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	// Snapshot pre-injection Characteristics.
	peOff := binary.LittleEndian.Uint32(exe[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	preChars := binary.LittleEndian.Uint16(exe[coffOff+0x12:])

	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	stub := bytes.Repeat([]byte{0xCC}, int(plan.StubMaxSize))
	out, err := transform.InjectConvertedDLL(exe, make([]byte, plan.TextSize), stub, plan)
	if err != nil {
		t.Fatalf("InjectConvertedDLL: %v", err)
	}

	postPeOff := binary.LittleEndian.Uint32(out[transform.PEELfanewOffset:])
	postCoffOff := postPeOff + transform.PESignatureSize
	postChars := binary.LittleEndian.Uint16(out[postCoffOff+0x12:])

	want := preChars | transform.ImageFileDLL
	if postChars != want {
		t.Errorf("post-flip Characteristics = %#x, want %#x (pre %#x | ImageFileDLL %#x)",
			postChars, want, preChars, transform.ImageFileDLL)
	}
}
