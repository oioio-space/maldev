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
