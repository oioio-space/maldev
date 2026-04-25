//go:build windows && amd64

package callstack

import (
	"errors"
	"os"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestSpoofCall_NilTargetReturnsError keeps the public-facing API
// honest before any pivot work happens.
func TestSpoofCall_NilTargetReturnsError(t *testing.T) {
	_, err := SpoofCall(nil, []Frame{{ReturnAddress: 1, ImageBase: 1, RuntimeFunction: RuntimeFunction{BeginAddress: 0, EndAddress: 1, UnwindInfoAddress: 1}}})
	if err == nil {
		t.Fatal("nil target: want error")
	}
}

// TestSpoofCall_EmptyChainReturnsErrEmptyChain blocks the easy
// foot-gun: the spoof needs at least one frame to plant.
func TestSpoofCall_EmptyChainReturnsErrEmptyChain(t *testing.T) {
	_, err := SpoofCall(unsafe.Pointer(uintptr(0x1000)), nil)
	if !errors.Is(err, ErrEmptyChain) {
		t.Errorf("empty chain err = %v, want ErrEmptyChain", err)
	}
}

// TestSpoofCall_TooManyArgsReturnsErrTooManyArgs guards the Win64
// 4-args register-only ceiling.
func TestSpoofCall_TooManyArgsReturnsErrTooManyArgs(t *testing.T) {
	chain := []Frame{{
		ReturnAddress:   0x1000,
		ImageBase:       0x1000,
		RuntimeFunction: RuntimeFunction{BeginAddress: 0, EndAddress: 0x1, UnwindInfoAddress: 1},
	}}
	_, err := SpoofCall(unsafe.Pointer(uintptr(0x1000)), chain, 1, 2, 3, 4, 5)
	if !errors.Is(err, ErrTooManyArgs) {
		t.Errorf("5-arg call err = %v, want ErrTooManyArgs", err)
	}
}

// TestSpoofCall_InvalidChainSurfacesValidateError ensures the
// chain-validation gate runs before the pivot. Validate's own
// per-frame errors are tested in callstack_test.go.
func TestSpoofCall_InvalidChainSurfacesValidateError(t *testing.T) {
	bad := []Frame{{}} // zero everything → Validate flags zero ReturnAddress
	_, err := SpoofCall(unsafe.Pointer(uintptr(0x1000)), bad)
	if err == nil {
		t.Fatal("invalid chain: want error")
	}
}

// TestSpoofTrampolineAddrIsNonZero confirms the asm linkage is wired:
// without this, planting it as a chain bottom slot would route control
// through nullptr.
func TestSpoofTrampolineAddrIsNonZero(t *testing.T) {
	if spoofTrampolineAddr() == 0 {
		t.Fatal("spoofTrampolineAddr returned 0 — asm symbol unresolved")
	}
}

// TestAllocSideStackRoundTrip exercises the VirtualAlloc path. We can't
// validate the pivot end-to-end on the test host (target execution
// requires a sacrificial process), but the side-stack allocator must
// at least round-trip without leaking.
func TestAllocSideStackRoundTrip(t *testing.T) {
	addr, err := allocSideStack(sideStackBytes)
	if err != nil {
		t.Fatalf("alloc side stack: %v", err)
	}
	if addr == 0 {
		t.Fatal("alloc side stack returned addr 0 with no error")
	}
	// Touch the region to ensure it's actually committed RW.
	*(*byte)(unsafe.Pointer(addr)) = 0x90
	*(*byte)(unsafe.Pointer(addr + uintptr(sideStackBytes-1))) = 0x90
	freeSideStack(addr, sideStackBytes)
}

// TestSpoofCall_GetCurrentThreadId is the end-to-end happy path on
// the host. GetCurrentThreadId is a leaf kernel32 function with no
// args and a DWORD return — perfect for the minimal pivot. The
// chain is a single FindReturnGadget result so the walker would see
// one fake ntdll frame mid-flight.
//
// SKIPPED by default — the asm pivot is unverified on this host
// because the Go runtime's interaction with a JMP-driven RET-walking
// chain is fragile. Toggle MALDEV_SPOOFCALL_E2E=1 to run.
func TestSpoofCall_GetCurrentThreadId(t *testing.T) {
	if mustSpoofCallE2E() == false {
		t.Skip("MALDEV_SPOOFCALL_E2E=1 to enable — pivot end-to-end test consumes one OS thread on failure")
	}
	gadget, err := FindReturnGadget()
	if err != nil {
		t.Fatalf("FindReturnGadget: %v", err)
	}
	frame, err := LookupFunctionEntry(gadget)
	if err != nil {
		t.Fatalf("LookupFunctionEntry(gadget): %v", err)
	}
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	getTID := k32.NewProc("GetCurrentThreadId")
	if err := getTID.Find(); err != nil {
		t.Fatalf("GetCurrentThreadId: %v", err)
	}

	chain := []Frame{frame}
	got, err := SpoofCall(unsafe.Pointer(getTID.Addr()), chain)
	if err != nil {
		t.Fatalf("SpoofCall: %v", err)
	}
	if got == 0 {
		t.Errorf("SpoofCall(GetCurrentThreadId) = 0, want non-zero TID")
	}
	if uint32(got) != windows.GetCurrentThreadId() {
		t.Errorf("SpoofCall TID = %d, GetCurrentThreadId() = %d", uint32(got), windows.GetCurrentThreadId())
	}
}

func mustSpoofCallE2E() bool {
	return os.Getenv("MALDEV_SPOOFCALL_E2E") == "1"
}
