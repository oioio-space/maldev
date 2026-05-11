package transform_test

import (
	"encoding/binary"
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
)

// TestPlanPE_RejectsDLL guards the v0.108.0 rejection: PE inputs
// with IMAGE_FILE_DLL (0x2000) set in COFF Characteristics must
// fail PlanPE with ErrIsDLL upfront. PackBinary's stub follows
// EXE semantics; a DLL's DllMain contract is incompatible.
//
// Empirical motivator: testing a mingw-built no-CRT DLL through
// PackBinary previously succeeded at pack-time and then failed
// at LoadLibrary with "A dynamic link library (DLL) initialization
// routine failed." — a confusing late failure. ErrIsDLL turns
// that into a clear pack-time error.
func TestPlanPE_RejectsDLL(t *testing.T) {
	const (
		peOff   = 0x40
		coffOff = peOff + 4
	)
	pe := make([]byte, 0x100)
	pe[0] = 'M'
	pe[1] = 'Z'
	binary.LittleEndian.PutUint32(pe[transform.PEELfanewOffset:], peOff)
	binary.LittleEndian.PutUint32(pe[peOff:], 0x00004550)
	// Set IMAGE_FILE_DLL = 0x2000 in COFF Characteristics (+0x12).
	binary.LittleEndian.PutUint16(pe[coffOff+0x12:], 0x2000)
	_, err := transform.PlanPE(pe, 4096)
	if !errors.Is(err, transform.ErrIsDLL) {
		t.Errorf("got %v, want ErrIsDLL", err)
	}
}

// setDLLBit ORs IMAGE_FILE_DLL into the COFF Characteristics field
// of a PE buffer, converting a synthetic EXE built by
// [transform.BuildMinimalPE32Plus] into a synthetic DLL.
func setDLLBit(t *testing.T, pe []byte) {
	t.Helper()
	peOff := binary.LittleEndian.Uint32(pe[transform.PEELfanewOffset:])
	coffOff := peOff + transform.PESignatureSize
	off := coffOff + 0x12
	c := binary.LittleEndian.Uint16(pe[off:])
	binary.LittleEndian.PutUint16(pe[off:], c|transform.ImageFileDLL)
}

// TestPlanDLL_AcceptsDLL — the symmetric of TestPlanPE_RejectsDLL.
// PlanDLL must accept inputs that carry IMAGE_FILE_DLL and surface
// the bit through [transform.Plan.IsDLL].
func TestPlanDLL_AcceptsDLL(t *testing.T) {
	pe, err := transform.BuildMinimalPE32Plus([]byte{0xC3}) // RET
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	setDLLBit(t, pe)

	plan, err := transform.PlanDLL(pe, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	if !plan.IsDLL {
		t.Error("Plan.IsDLL = false, want true")
	}
	if plan.Format != transform.FormatPE {
		t.Errorf("Plan.Format = %v, want FormatPE", plan.Format)
	}
	if plan.OEPRVA == 0 {
		t.Error("Plan.OEPRVA = 0; PlanDLL must surface the original DllMain RVA")
	}
}

// TestPlanDLL_RejectsEXE — PlanDLL fails fast on EXE inputs with
// [transform.ErrIsEXE], the mirror of PlanPE's [transform.ErrIsDLL].
func TestPlanDLL_RejectsEXE(t *testing.T) {
	pe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	_, err = transform.PlanDLL(pe, 4096)
	if !errors.Is(err, transform.ErrIsEXE) {
		t.Errorf("got %v, want ErrIsEXE", err)
	}
}

// TestPlanDLL_PreservesLayoutFields — PlanDLL must compute the
// same TextRVA / TextSize / StubRVA / OEPRVA as PlanPE on an
// identically-shaped input. Guards against accidental divergence
// between the EXE and DLL planning code paths now that they share
// planPECore.
func TestPlanDLL_PreservesLayoutFields(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	exePlan, err := transform.PlanPE(exe, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}

	dll, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	setDLLBit(t, dll)
	dllPlan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}

	if exePlan.TextRVA != dllPlan.TextRVA ||
		exePlan.TextSize != dllPlan.TextSize ||
		exePlan.StubRVA != dllPlan.StubRVA ||
		exePlan.OEPRVA != dllPlan.OEPRVA {
		t.Errorf("layout drift: exe=%+v dll=%+v", exePlan, dllPlan)
	}
	if exePlan.IsDLL {
		t.Error("PlanPE leaked IsDLL=true")
	}
	if !dllPlan.IsDLL {
		t.Error("PlanDLL didn't set IsDLL=true")
	}
}
