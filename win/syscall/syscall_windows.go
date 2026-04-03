//go:build windows

// Package syscall provides multiple strategies for invoking Windows syscalls,
// from standard WinAPI calls to stealthy direct/indirect syscall techniques.
//
// # Choosing a method
//
//	Environment without EDR:       MethodWinAPI (standard, via kernel32/advapi32)
//	EDR hooks kernel32:            MethodNativeAPI (via ntdll NtXxx)
//	EDR hooks ntdll:               MethodDirect + resolver.NewHellsGate()
//	EDR with call-stack analysis:  MethodIndirect + resolver.Chain(HellsGate, Tartarus)
//
// # Detection comparison
//
//	Method       Hook kernel32  Hook ntdll  Memory scan  Stack analysis
//	WinAPI           X              X            -              -
//	NativeAPI        OK             X            -              -
//	Direct           OK             OK           !              -
//	Indirect         OK             OK           OK             OK
package syscall

import (
	"sync"

	"golang.org/x/sys/windows"
)

// Method represents the syscall invocation strategy.
type Method int

const (
	// MethodWinAPI calls through kernel32/advapi32 (standard, hookable).
	MethodWinAPI Method = iota

	// MethodNativeAPI calls through ntdll NtXxx functions (bypass kernel32 hooks).
	MethodNativeAPI

	// MethodDirect uses an in-process syscall stub (bypass all userland hooks).
	// Detectable by memory scanners (syscall instruction outside ntdll).
	MethodDirect

	// MethodIndirect uses a syscall;ret gadget inside ntdll (most stealthy).
	// Call appears to originate from ntdll address space.
	MethodIndirect
)

func (m Method) String() string {
	switch m {
	case MethodWinAPI:
		return "WinAPI"
	case MethodNativeAPI:
		return "NativeAPI"
	case MethodDirect:
		return "Direct"
	case MethodIndirect:
		return "Indirect"
	default:
		return "Unknown"
	}
}

// Caller executes NT syscalls using the configured method and resolver.
// For MethodDirect and MethodIndirect, a single RWX page is pre-allocated
// per stub type and reused across calls, eliminating per-call VirtualAlloc
// overhead. Call Close when the Caller is no longer needed to free the stubs.
type Caller struct {
	method   Method
	resolver SSNResolver

	// Pre-allocated executable stub memory (allocated once, reused).
	directStub   uintptr
	indirectStub uintptr
	mu           sync.Mutex // protects stub rewrites during concurrent calls
}

// New creates a Caller with the given method and SSN resolver.
// The resolver is only used for MethodDirect and MethodIndirect.
// For those methods, executable stub pages are pre-allocated; call Close
// to release them when done.
func New(method Method, r SSNResolver) *Caller {
	c := &Caller{method: method, resolver: r}
	if method == MethodDirect || method == MethodIndirect {
		// Pre-allocate RWX pages for the syscall stubs. 64 bytes each is
		// more than enough for both the direct (11 bytes) and indirect (21 bytes) stubs.
		c.directStub, _ = windows.VirtualAlloc(0, 64,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
		c.indirectStub, _ = windows.VirtualAlloc(0, 64,
			windows.MEM_COMMIT|windows.MEM_RESERVE, windows.PAGE_EXECUTE_READWRITE)
	}
	return c
}

// Close frees the pre-allocated stub memory. Safe to call multiple times.
func (c *Caller) Close() {
	c.mu.Lock()
	defer c.mu.Unlock()
	if c.directStub != 0 {
		windows.VirtualFree(c.directStub, 0, windows.MEM_RELEASE)
		c.directStub = 0
	}
	if c.indirectStub != 0 {
		windows.VirtualFree(c.indirectStub, 0, windows.MEM_RELEASE)
		c.indirectStub = 0
	}
}
