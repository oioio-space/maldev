package transform_test

import (
	"errors"
	"testing"

	"github.com/oioio-space/maldev/pe/packer/transform"
	"github.com/oioio-space/maldev/testutil"
)

// TestPlanConvertedDLL_AcceptsEXE — PlanConvertedDLL must accept EXE
// inputs (no IMAGE_FILE_DLL bit) and set Plan.IsConvertedDLL
// without setting Plan.IsDLL. Slice 5.1.
func TestPlanConvertedDLL_AcceptsEXE(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3}) // RET
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}

	plan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	if plan.IsDLL {
		t.Error("Plan.IsDLL = true; want false (input is an EXE)")
	}
	if !plan.IsConvertedDLL {
		t.Error("Plan.IsConvertedDLL = false; want true")
	}
	if plan.Format != transform.FormatPE {
		t.Errorf("Plan.Format = %v, want FormatPE", plan.Format)
	}
	if plan.OEPRVA == 0 {
		t.Error("Plan.OEPRVA = 0; PlanConvertedDLL must surface the original entry RVA")
	}
}

// TestPlanConvertedDLL_RejectsDLL — handing a DLL to PlanConvertedDLL must
// fail with ErrIsDLL (same sentinel as PlanPE — same admission
// rule, same failure mode).
func TestPlanConvertedDLL_RejectsDLL(t *testing.T) {
	dll := testutil.BuildDLLWithReloc(t, 1)
	_, err := transform.PlanConvertedDLL(dll, 4096)
	if !errors.Is(err, transform.ErrIsDLL) {
		t.Errorf("got %v, want ErrIsDLL", err)
	}
}

// TestPlanConvertedDLL_ExclusiveWithIsDLL — IsDLL and IsConvertedDLL
// must be mutually exclusive on every successful Plan. Catches
// any future refactor that conflates the two flags.
func TestPlanConvertedDLL_ExclusiveWithIsDLL(t *testing.T) {
	exe, err := transform.BuildMinimalPE32Plus([]byte{0xC3})
	if err != nil {
		t.Fatalf("BuildMinimalPE32Plus: %v", err)
	}
	dll := testutil.BuildDLLWithReloc(t, 1)

	exeAsDLLPlan, err := transform.PlanConvertedDLL(exe, 4096)
	if err != nil {
		t.Fatalf("PlanConvertedDLL: %v", err)
	}
	if exeAsDLLPlan.IsDLL {
		t.Error("converted-EXE plan leaked IsDLL=true")
	}

	dllPlan, err := transform.PlanDLL(dll, 4096)
	if err != nil {
		t.Fatalf("PlanDLL: %v", err)
	}
	if dllPlan.IsConvertedDLL {
		t.Error("native-DLL plan leaked IsConvertedDLL=true")
	}

	exePlan, err := transform.PlanPE(exe, 4096)
	if err != nil {
		t.Fatalf("PlanPE: %v", err)
	}
	if exePlan.IsDLL || exePlan.IsConvertedDLL {
		t.Errorf("plain-EXE plan has IsDLL=%v IsConvertedDLL=%v; want both false",
			exePlan.IsDLL, exePlan.IsConvertedDLL)
	}
}
