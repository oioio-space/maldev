//go:build windows && amd64

package callstack

import (
	"errors"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// TestLookupFunctionEntry_KnownNtdllExport resolves a well-known ntdll
// export and asserts the returned Frame carries sane fields. We pick
// ntdll exports (NtClose, RtlUserThreadStart) because kernel32 hot-patch
// thunks / forwarders may lack their own RUNTIME_FUNCTION on Win10+,
// while ntdll's syscall stubs and runtime helpers always carry unwind
// metadata.
func TestLookupFunctionEntry_KnownNtdllExport(t *testing.T) {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	for _, name := range []string{"NtClose", "RtlUserThreadStart", "RtlAllocateHeap"} {
		p := ntdll.NewProc(name)
		if err := p.Find(); err != nil {
			t.Fatalf("load ntdll.%s: %v", name, err)
		}
		addr := p.Addr()
		f, err := LookupFunctionEntry(addr)
		if err != nil {
			t.Fatalf("LookupFunctionEntry(%s @ 0x%X): %v", name, addr, err)
		}
		if f.ReturnAddress != addr {
			t.Fatalf("%s ReturnAddress mismatch: got 0x%X want 0x%X", name, f.ReturnAddress, addr)
		}
		if f.ImageBase == 0 {
			t.Fatalf("%s ImageBase is zero", name)
		}
		// ControlPc must lie within [ImageBase+Begin, ImageBase+End).
		begin := f.ImageBase + uintptr(f.RuntimeFunction.BeginAddress)
		end := f.ImageBase + uintptr(f.RuntimeFunction.EndAddress)
		if addr < begin || addr >= end {
			t.Fatalf("%s 0x%X not bounded by RUNTIME_FUNCTION [0x%X, 0x%X)", name, addr, begin, end)
		}
		if f.RuntimeFunction.UnwindInfoAddress == 0 {
			t.Fatalf("%s: UnwindInfoAddress is zero", name)
		}
	}
}

// TestLookupFunctionEntry_UnknownAddressFails asks about a stack-local
// address (by definition outside every loaded PE's .pdata range) and
// expects ErrFunctionEntryNotFound.
func TestLookupFunctionEntry_UnknownAddressFails(t *testing.T) {
	var stackLocal int32
	addr := uintptr(unsafe.Pointer(&stackLocal))
	_, err := LookupFunctionEntry(addr)
	if !errors.Is(err, ErrFunctionEntryNotFound) {
		t.Fatalf("stack address 0x%X: got err=%v, want ErrFunctionEntryNotFound", addr, err)
	}
}

// TestStandardChain_ShapeAndBounds asserts the 2-frame chain resolves
// to kernel32!BaseThreadInitThunk + ntdll!RtlUserThreadStart with
// non-zero ImageBase and RUNTIME_FUNCTION bounds enclosing each
// ControlPc.
func TestStandardChain_ShapeAndBounds(t *testing.T) {
	chain, err := StandardChain()
	if err != nil {
		t.Fatalf("StandardChain: %v", err)
	}
	if len(chain) != 2 {
		t.Fatalf("chain length: got %d want 2", len(chain))
	}
	for i, f := range chain {
		if f.ReturnAddress == 0 || f.ImageBase == 0 {
			t.Errorf("frame[%d] zero field: %+v", i, f)
		}
		begin := f.ImageBase + uintptr(f.RuntimeFunction.BeginAddress)
		end := f.ImageBase + uintptr(f.RuntimeFunction.EndAddress)
		if f.ReturnAddress < begin || f.ReturnAddress >= end {
			t.Errorf("frame[%d] ControlPc 0x%X outside [0x%X, 0x%X)",
				i, f.ReturnAddress, begin, end)
		}
	}
}

// TestStandardChain_Cached verifies the Once cache returns equivalent
// frames on repeated calls (same addresses + unwind metadata).
func TestStandardChain_Cached(t *testing.T) {
	a, err := StandardChain()
	if err != nil {
		t.Fatal(err)
	}
	b, err := StandardChain()
	if err != nil {
		t.Fatal(err)
	}
	if len(a) != len(b) {
		t.Fatalf("lengths differ: %d vs %d", len(a), len(b))
	}
	for i := range a {
		if a[i] != b[i] {
			t.Errorf("frame[%d] differs across calls: %+v vs %+v", i, a[i], b[i])
		}
	}
}

// TestFindReturnGadget_HasUnwindCoverage asserts the discovered RET
// gadget lies inside an ntdll function with its own RUNTIME_FUNCTION
// — critical property for chain validity: a stack walker landing on
// the gadget via a fake return must find unwind metadata, otherwise
// the spoof shows as a broken frame.
func TestFindReturnGadget_HasUnwindCoverage(t *testing.T) {
	addr, err := FindReturnGadget()
	if err != nil {
		t.Fatalf("FindReturnGadget: %v", err)
	}
	if addr == 0 {
		t.Fatal("nil gadget address")
	}
	// Dereference the byte at addr — should be 0xC3 (RET).
	got := *(*byte)(unsafe.Pointer(addr))
	if got != 0xC3 {
		t.Fatalf("gadget @ 0x%X: byte is 0x%X, want 0xC3", addr, got)
	}
	if _, err := LookupFunctionEntry(addr); err != nil {
		t.Fatalf("gadget @ 0x%X lacks RUNTIME_FUNCTION coverage: %v", addr, err)
	}
}
