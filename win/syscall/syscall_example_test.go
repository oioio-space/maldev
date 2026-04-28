//go:build windows

package syscall_test

import (
	"fmt"

	wsyscall "github.com/oioio-space/maldev/win/syscall"
)

// New picks an invocation method + an SSN resolver. Operators pass
// the resulting *Caller into any maldev API that takes one
// (`inject.*`, `recon/hwbp.*`, …) — call sites stay identical
// across evasion postures.
func ExampleNew() {
	caller := wsyscall.New(wsyscall.MethodIndirect, wsyscall.NewHashGate())
	defer caller.Close()

	// Pass `caller` to any function whose signature accepts *wsyscall.Caller.
	_ = caller
}

// Caller_Call resolves NtXxx by name and dispatches per the
// configured method — useful when the API surface is a one-off and
// pulling in a typed wrapper would be overkill.
func ExampleCaller_Call() {
	caller := wsyscall.New(wsyscall.MethodDirect, wsyscall.NewHashGate())
	defer caller.Close()

	// NtClose(handle) — single-arg syscall.
	const handle = 0
	if _, err := caller.Call("NtClose", handle); err != nil {
		fmt.Println("syscall:", err)
	}
}

// MethodIndirectAsm dispatches via a Go-assembly stub instead of a
// byte-patched heap stub: no writable code page in the implant, no
// per-call VirtualProtect cycle. Same end effect as MethodIndirect
// (the syscall executes inside ntdll's `.text`).
func ExampleNew_indirectAsm() {
	caller := wsyscall.New(wsyscall.MethodIndirectAsm, wsyscall.NewHashGate())
	defer caller.Close()

	const handle = 0
	if _, err := caller.Call("NtClose", handle); err != nil {
		fmt.Println("syscall:", err)
	}
}

// Caller_WithHashFunc swaps in a custom hash function — every implant
// built with a different fn produces different funcHash constants, so
// static signatures on the well-known ROR13 values stop matching.
// Both ends MUST agree: NewHashGateWith(fn) for the resolver,
// WithHashFunc(fn) for CallByHash.
func ExampleCaller_WithHashFunc() {
	fnv1a := func(s string) uint32 {
		h := uint32(2166136261)
		for i := 0; i < len(s); i++ {
			h ^= uint32(s[i])
			h *= 16777619
		}
		return h
	}

	caller := wsyscall.New(
		wsyscall.MethodIndirectAsm,
		wsyscall.NewHashGateWith(fnv1a),
	).WithHashFunc(fnv1a)
	defer caller.Close()

	if _, err := caller.CallByHash(fnv1a("NtClose"), 0); err != nil {
		fmt.Println("syscall:", err)
	}
}

// Chain tries resolvers in sequence — Hell's Gate first (cheapest),
// fall back to Halo's, then Tartarus, then HashGate. First non-error
// result wins.
func ExampleChain() {
	chain := wsyscall.Chain(
		wsyscall.NewHellsGate(),
		wsyscall.NewHalosGate(),
		wsyscall.NewTartarus(),
		wsyscall.NewHashGate(),
	)
	caller := wsyscall.New(wsyscall.MethodIndirect, chain)
	defer caller.Close()
	_ = caller
}
