//go:build windows && amd64

package callstack

import (
	"bytes"
	"debug/pe"
	"errors"
	"fmt"
	"sync"
	"unsafe"

	"golang.org/x/sys/windows"
)

// ErrGadgetNotFound is returned when FindReturnGadget scans ntdll's .text
// range without locating a lone RET (0xC3) — practically impossible on
// a sane Windows host, but we surface the case cleanly.
var ErrGadgetNotFound = errors.New("callstack: no RET gadget found in ntdll")

// StandardChain returns a plausible 2-frame return chain rooted at the
// Windows thread-init sequence: kernel32!BaseThreadInitThunk (inner,
// [0]) → ntdll!RtlUserThreadStart (outer, [1]).
//
// Both frames are computed once at first call and cached. Callers
// drop them into a synthetic stack layout (see SpoofCall) or use
// them as reference metadata when building custom chains.
//
// Fails if either symbol is missing (shouldn't happen on any
// supported Windows build).
func StandardChain() ([]Frame, error) {
	chainOnce.Do(initStandardChain)
	if chainErr != nil {
		return nil, chainErr
	}
	out := make([]Frame, len(chainFrames))
	copy(out, chainFrames)
	return out, nil
}

var (
	chainOnce   sync.Once
	chainFrames []Frame
	chainErr    error
)

func initStandardChain() {
	k32 := windows.NewLazySystemDLL("kernel32.dll")
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	for _, step := range []struct {
		mod  *windows.LazyDLL
		name string
	}{
		{k32, "BaseThreadInitThunk"},
		{ntdll, "RtlUserThreadStart"},
	} {
		p := step.mod.NewProc(step.name)
		if err := p.Find(); err != nil {
			chainErr = fmt.Errorf("callstack: load %s: %w", step.name, err)
			return
		}
		f, err := LookupFunctionEntry(p.Addr())
		if err != nil {
			chainErr = fmt.Errorf("callstack: lookup %s: %w", step.name, err)
			return
		}
		chainFrames = append(chainFrames, f)
	}
}

// FindReturnGadget scans ntdll's .text range for a lone RET (0xC3)
// aligned on an instruction boundary and returns its absolute address.
// The result is cached so repeat callers pay one scan per process.
//
// The returned address is guaranteed to carry its own RUNTIME_FUNCTION
// (ntdll's .pdata covers every .text byte), so stack walkers that
// dereference the fake return address find a valid function entry.
func FindReturnGadget() (uintptr, error) {
	gadgetOnce.Do(initReturnGadget)
	return gadgetAddr, gadgetErr
}

var (
	gadgetOnce sync.Once
	gadgetAddr uintptr
	gadgetErr  error
)

func initReturnGadget() {
	ntdll := windows.NewLazySystemDLL("ntdll.dll")
	if err := ntdll.Load(); err != nil {
		gadgetErr = fmt.Errorf("load ntdll: %w", err)
		return
	}
	base := ntdll.Handle()
	textStart, textSize, err := peTextRange(base)
	if err != nil {
		gadgetErr = err
		return
	}
	// Copy the .text slice out of the module mapping so we scan host
	// memory (safe from alignment faults) rather than mapping memory.
	buf := unsafe.Slice((*byte)(unsafe.Pointer(base+uintptr(textStart))), textSize)
	// First byte that is 0xC3 and followed by a padding byte (0xCC
	// int3 or 0x90 nop) is almost certainly a standalone RET. This
	// avoids misfiring on mid-instruction 0xC3 bytes inside a larger
	// opcode (e.g., a displacement).
	for i := 0; i < len(buf)-1; i++ {
		if buf[i] == 0xC3 && (buf[i+1] == 0xCC || buf[i+1] == 0x90) {
			gadgetAddr = base + uintptr(textStart) + uintptr(i)
			return
		}
	}
	gadgetErr = ErrGadgetNotFound
}

// peTextRange parses the PE headers at base and returns the .text
// section's RVA + size.
func peTextRange(base uintptr) (rva uint32, size uint32, err error) {
	// Copy the first 4 KiB of the module so debug/pe can work on a
	// Reader without touching process memory pages through the Go
	// reflection paths.
	header := unsafe.Slice((*byte)(unsafe.Pointer(base)), 0x1000)
	cp := make([]byte, len(header))
	copy(cp, header)

	// Peek e_lfanew + NT headers + section table.
	f, perr := pe.NewFile(bytes.NewReader(cp))
	if perr != nil {
		// Fallback: the 4 KiB prefix might be too small if the section
		// headers spill past it. Grow and retry once.
		header = unsafe.Slice((*byte)(unsafe.Pointer(base)), 0x4000)
		cp = make([]byte, len(header))
		copy(cp, header)
		f, perr = pe.NewFile(bytes.NewReader(cp))
		if perr != nil {
			return 0, 0, fmt.Errorf("parse ntdll PE: %w", perr)
		}
	}
	defer f.Close()
	for _, s := range f.Sections {
		if s.Name == ".text" {
			return s.VirtualAddress, s.VirtualSize, nil
		}
	}
	return 0, 0, errors.New("callstack: .text section not found in ntdll")
}
