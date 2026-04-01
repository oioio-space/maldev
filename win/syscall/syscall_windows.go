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
type Caller struct {
	method   Method
	resolver SSNResolver
}

// New creates a Caller with the given method and SSN resolver.
// The resolver is only used for MethodDirect and MethodIndirect.
func New(method Method, r SSNResolver) *Caller {
	return &Caller{method: method, resolver: r}
}
