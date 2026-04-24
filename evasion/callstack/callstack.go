package callstack

import "errors"

// ErrUnsupportedPlatform is returned by every entry point on non-Windows
// or non-amd64 builds. Stack spoofing relies on the x64 unwind-metadata
// format (UNWIND_INFO) emitted by the MSVC toolchain for Windows PEs;
// we don't attempt a cross-platform equivalent.
var ErrUnsupportedPlatform = errors.New("callstack: windows/amd64 only")

// ErrFunctionEntryNotFound is returned when RtlLookupFunctionEntry has no
// RUNTIME_FUNCTION for the given address — usually means the caller
// asked about a non-PE / dynamically-generated range (JIT, stackwalker
// trampoline, …) or the address is not loaded in the current process.
var ErrFunctionEntryNotFound = errors.New("callstack: no RUNTIME_FUNCTION for address")

// Frame pairs a return address with its function-table entry. Callers
// typically build chains via StandardChain or by hand-rolling a slice
// of Frames rooted at a thread-init sequence.
type Frame struct {
	// ReturnAddress is the value placed on the stack so RtlVirtualUnwind
	// resumes unwinding here. MUST point inside an executable image
	// that has a RUNTIME_FUNCTION covering it.
	ReturnAddress uintptr

	// ImageBase is the module's base address (HMODULE). Used to resolve
	// RVAs inside RuntimeFunction; cached here so unwinders don't have
	// to re-lookup per chain entry.
	ImageBase uintptr

	// RuntimeFunction is the entry RtlLookupFunctionEntry returned for
	// ReturnAddress, copied out so the chain survives the target
	// module reloading.
	RuntimeFunction RuntimeFunction
}

// RuntimeFunction mirrors the Windows amd64 RUNTIME_FUNCTION struct
// (winnt.h). All three fields are RVAs relative to the owning module's
// ImageBase.
type RuntimeFunction struct {
	BeginAddress      uint32
	EndAddress        uint32
	UnwindInfoAddress uint32
}
