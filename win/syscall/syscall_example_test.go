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
