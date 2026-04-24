//go:build windows && amd64

package callstack

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// LookupFunctionEntry wraps RtlLookupFunctionEntry (ntdll) for the
// given instruction address. The returned Frame is populated with the
// RUNTIME_FUNCTION row and the owning image's base address, ready to
// drop into a synthetic call-stack chain.
//
// Returns ErrFunctionEntryNotFound when the address is outside every
// loaded PE's .pdata range (JIT code, freshly-allocated shellcode,
// etc.) — such addresses can't back a spoofed frame because
// RtlVirtualUnwind would have no metadata to follow.
func LookupFunctionEntry(addr uintptr) (Frame, error) {
	var imageBase uintptr
	r, _, _ := procRtlLookupFunctionEntry.Call(
		uintptr(addr),
		uintptr(unsafe.Pointer(&imageBase)),
		0, // HistoryTable (optional) — nil is fine for one-shot lookups
	)
	if r == 0 {
		return Frame{}, ErrFunctionEntryNotFound
	}
	// Copy the RUNTIME_FUNCTION by value so the Frame keeps living if
	// the target module unloads later.
	rf := *(*RuntimeFunction)(unsafe.Pointer(r))
	return Frame{
		ReturnAddress:   addr,
		ImageBase:       imageBase,
		RuntimeFunction: rf,
	}, nil
}

var (
	modNtdll                  = windows.NewLazySystemDLL("ntdll.dll")
	procRtlLookupFunctionEntry = modNtdll.NewProc("RtlLookupFunctionEntry")
)
