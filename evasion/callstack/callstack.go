package callstack

import (
	"errors"
	"fmt"
)

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

// String renders a Frame for debug output. Format:
// "RIP=0x... base=0x... [0x..+0x..-0x..] unwind=0x..".
func (f Frame) String() string {
	return fmt.Sprintf("RIP=0x%X base=0x%X [0x%X+0x%X-0x%X] unwind=0x%X",
		f.ReturnAddress, f.ImageBase,
		f.ImageBase+uintptr(f.RuntimeFunction.BeginAddress),
		f.RuntimeFunction.BeginAddress,
		f.RuntimeFunction.EndAddress,
		f.RuntimeFunction.UnwindInfoAddress,
	)
}

// Validate checks a chain's structural consistency: every frame must
// carry a non-zero ReturnAddress + ImageBase + UnwindInfoAddress, and
// the ControlPc must fall inside [ImageBase+Begin, ImageBase+End) so
// RtlVirtualUnwind can find a RUNTIME_FUNCTION row when walking the
// fake stack. Returns nil when every frame is safe to drop into a
// synthetic return chain.
func Validate(chain []Frame) error {
	for i, f := range chain {
		if f.ReturnAddress == 0 {
			return fmt.Errorf("callstack: frame[%d]: zero ReturnAddress", i)
		}
		if f.ImageBase == 0 {
			return fmt.Errorf("callstack: frame[%d]: zero ImageBase", i)
		}
		if f.RuntimeFunction.UnwindInfoAddress == 0 {
			return fmt.Errorf("callstack: frame[%d]: zero UnwindInfoAddress", i)
		}
		begin := f.ImageBase + uintptr(f.RuntimeFunction.BeginAddress)
		end := f.ImageBase + uintptr(f.RuntimeFunction.EndAddress)
		if f.ReturnAddress < begin || f.ReturnAddress >= end {
			return fmt.Errorf("callstack: frame[%d]: ControlPc 0x%X outside [0x%X, 0x%X)",
				i, f.ReturnAddress, begin, end)
		}
	}
	return nil
}
